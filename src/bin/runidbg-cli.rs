use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use runidbg_arm64_emu_tracer::tracer::{
    decode_instruction_with_reg, format_ascii_hint, BinaryTracer, TraceReader,
};

fn parse_u64_hex_or_dec(s: &str) -> Result<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).with_context(|| format!("无效的十六进制数: {s}"))
    } else {
        s.parse::<u64>()
            .with_context(|| format!("无效的十进制数: {s}"))
    }
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != ':')
        .collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        bail!("无效的十六进制字节串: {s}");
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .with_context(|| format!("无效的十六进制字节: {}", &cleaned[i..i + 2]))?;
        out.push(byte);
    }
    Ok(out)
}

fn parse_seq_range(s: &str) -> Result<(Option<usize>, Option<usize>)> {
    let (lhs, rhs, inclusive_end) = if let Some((a, b)) = s.split_once("..=") {
        (a, b, true)
    } else if let Some((a, b)) = s.split_once("..") {
        (a, b, false)
    } else {
        bail!("无效的 --seq-range 格式 `{s}`（期望 `<start>..<end>` 半开或 `<start>..=<end>` 闭区间）");
    };
    let start = if lhs.trim().is_empty() {
        None
    } else {
        Some(lhs.trim().parse::<usize>().with_context(|| format!("无效的起始序号: {lhs}"))?)
    };
    let end = if rhs.trim().is_empty() {
        None
    } else {
        let raw_end = rhs.trim().parse::<usize>().with_context(|| format!("无效的结束序号: {rhs}"))?;
        if inclusive_end {
            Some(raw_end)
        } else {
            if raw_end == 0 {
                bail!("--seq-range 半开区间 `{s}` 上界不能为 0");
            }
            Some(raw_end - 1)
        }
    };
    if let (Some(a), Some(b)) = (start, end) {
        if a > b {
            bail!("--seq-range 区间 `{s}` 为空或起始序号大于结束序号");
        }
    }
    Ok((start, end))
}

fn parse_stop_mem(s: &str) -> Result<(u64, usize)> {
    if let Some((a, l)) = s.split_once(':') {
        let addr = parse_u64_hex_or_dec(a.trim())?;
        let len = l.trim().parse::<usize>().with_context(|| format!("无效的 --stop-mem 长度: {l}"))?;
        if len == 0 || len > 65536 {
            bail!("--stop-mem 长度必须在 1..=65536 之间");
        }
        Ok((addr, len))
    } else {
        let addr = parse_u64_hex_or_dec(s.trim())?;
        Ok((addr, 8))
    }
}

fn warn_if_missing_ext(reader: &TraceReader, idx_path: &std::path::Path) {
    if reader.missing_ext_warning() {
        let lvl = reader.recorded_level_name().unwrap_or("full");
        eprintln!(
            "WARN: {} 录制于 {lvl} 级别但未加载到伴生 .ext 文件（扩展事件=0）；请确认同级 .ext 未遗漏或通过 --ext 指定路径",
            idx_path.display()
        );
    }
}

fn print_usage() {
    let compiled_backends = runidbg_arm64_emu_tracer::BackendKind::compiled_names();
    eprintln!(
        "runidbg-arm64-emu-tracer 工具集 (runidbg-cli)\n\
         已编译执行后端: {compiled_backends}（Trace / GDB 模式仅支持 unicorn，其余后端仅限仿真模式）\n\
         全局选项 (置于子命令之前):\n\
           [--log-level <trace|debug|info|warn|error>] [--log-format <compact|json>]\n\
         用法:\n\
           runidbg-cli run [--freeze-layout] <script.js> [-- <args...>]                       运行 QuickJS 仿真脚本（--freeze-layout 隔离宿主分配，稳定 guest 堆地址）\n\
           runidbg-cli serve <script.js> [--listen 127.0.0.1:8080] [--workers 1|auto]         启动异步 HTTP/JSON-RPC 2.0 服务\n\
                     [--max-queue 1024] [--timeout-ms 30000] [--max-insns 0]\n\
                     [--allow-reload] [--allow-eval] [-- <args...>]\n\
           runidbg-cli mcp [--script <init.js>] [--cwd <dir>] [--http 127.0.0.1:8090]         启动 MCP 服务端 (stdio / HTTP)\n\
           runidbg-cli debug <lib.so> <symbol|0xaddr> [--listen 127.0.0.1:1234] [--pkg PKG]   启动 GDB RSP 远程调试服务端（仅 Unicorn）\n\
           runidbg-cli debug --tape <file.rtape> [--checkpoint <idx|label>] [sym|0xaddr]      从 .rtape 磁带启动 GDB RSP（含二期 EVENT_LOG 时自动开启 rs/rc/watch 时间旅行调试）\n\
           runidbg-cli tape info <file.rtape>                                                 查看 .rtape 磁带检查点、时间轴事件与压缩统计\n\
           runidbg-cli asm \"<insns>\" [--pc <hex>]                                             使用内置 good64 汇编器将 ARM64 汇编转为机器码并反汇编校验\n\
           runidbg-cli init-types [dir]                                                       生成 runidbg.d.ts 类型声明\n\
           runidbg-cli dump <trace.idx> [--ext <trace.ext>] [--base <hex>] [--skip N] [--limit N]\n\
           runidbg-cli search|find <trace.idx> [--ext <trace.ext>] [--base <hex>] [--val <hex>] [--addr <hex> [--len N]] [--pc <hex>]\n\
                     [--ascii <text>] [--bytes <hex>] [--seq-range <start>..<end>] [--only-writes|--only-reads] [--no-hle] [--limit N]\n\
           runidbg-cli mem <trace.idx> --addr <hex> --len <N> [--at <seq>] [--ext <trace.ext>] [--hex|--hexdump|--out <file.bin>]\n\
           runidbg-cli diff <a.idx> <b.idx> [--ext-a <a.ext>] [--ext-b <b.ext>] [--base <hex>] [--limit N]\n\
                     [--target-addr <hex> [--len N] [--max-insns N]]\n\
           runidbg-cli taint <trace.idx> [--ext <trace.ext>] [--mode <forward|backward>] (--addr <hex> [--len N] | --reg <x0>)\n\
                     [--at <idx>] [--from-seq <idx>] [--stop-at-pc <hex>] [--stop-mem <hex[:len]>] [--max-insns N] [--limit N] [--base <hex>] [--no-mem-index] [--track-sp]\n\
           runidbg-cli decompile <trace.idx> [--ext <trace.ext>] (--addr <hex> [--len N] | --reg <x0>)\n\
                     [--at <idx>] [--from-seq <idx>] [--stop-at-pc <hex>] [--stop-mem <hex[:len]>] [--fold-rodata] [--fn <name>] [--no-simplify] [--smt2] [--out <slice.c>]\n\
           runidbg-cli vm <trace.idx> [--ext <trace.ext>] [--dispatcher <hex>] [--bc-reg <x23>] [--bc-deref]\n\
                     [--bc-addr <hex>] [--base-reg <x25>] [--reg-count 32] [--reg-size 8]\n\
                     [--layout <op_lsb:w,f0_lsb[:w],...>] [--min-handlers N] [--min-dispatches N] [--seq-range <start>..<end>] [--base <hex>] [--limit N] [--max-insns N]\n\
           runidbg-cli stats <trace.idx> [--base <hex>] [--top N]\n\
           runidbg-cli calltree <trace.idx> [--base <hex>] [--max-depth N] [--min-insns N]\n\
           runidbg-cli crypto-scan <trace.idx> [--ext <trace.ext>] [--base <hex>]\n\
           runidbg-cli ui <trace.idx|.rtrace|file.rtape> [--ext <trace.ext>] [--base <hex>] [--listen 127.0.0.1:8088] [--open]\n\
           runidbg-cli export-ida <trace.idx|.rtrace> [--base <hex>] [--out <script.py>]\n\
           runidbg-cli export-bn  <trace.idx|.rtrace> [--base <hex>] [--out <script.py>]\n\
           runidbg-cli pack <trace.idx> [--ext <trace.ext>|--no-ext] [--out <out.rtrace>] [--base <hex>] [--note <text>] [--level <0..9>]\n\
           runidbg-cli unpack <file.rtrace> [--out-dir <dir>] [--stem <name>] [--force] [--info]\n\
         说明: 全部离线子命令均支持直接读取单文件压缩 `.rtrace` 归档（无需手动解包）。\n\
         Trace 级别说明（JS `emu.trace.start({{ level, capacity }})`）:\n\
           fast      仅记录 PC/Opcode（无 .ext）\n\
           reg_delta 记录 PC/Opcode + 寄存器增量（默认，无内存 .ext）\n\
           full      记录指令 + 寄存器增量 + 访存 R/W + HLE memcpy/memset/malloc/free（唯一产出 .ext，供 taint/search --addr/--bytes 使用）"
    );
}

#[cfg(feature = "js")]
fn run_js_command(args: &[String]) -> Result<()> {
    let mut freeze_layout = false;
    let mut script_path: Option<PathBuf> = None;
    let mut script_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            script_args.extend_from_slice(&args[i + 1..]);
            break;
        }
        if arg == "--freeze-layout" && script_path.is_none() {
            freeze_layout = true;
            i += 1;
            continue;
        }
        if script_path.is_none() {
            if arg.starts_with("--") {
                bail!("run 未知选项: {arg}（支持 --freeze-layout）");
            }
            script_path = Some(PathBuf::from(arg));
            i += 1;
            continue;
        }
        if arg == "--freeze-layout" && script_args.is_empty() {
            freeze_layout = true;
            i += 1;
            continue;
        }
        script_args.push(args[i].clone());
        i += 1;
    }
    let Some(script_path) = script_path else {
        bail!("用法: runidbg-cli run [--freeze-layout] <script.js> [-- <args...>]");
    };
    runidbg_arm64_emu_tracer::script::JsRunner::run_file_with_freeze_layout(
        &script_path,
        &script_args,
        freeze_layout,
    )?;
    Ok(())
}

#[cfg(not(feature = "js"))]
fn run_js_command(_args: &[String]) -> Result<()> {
    bail!("当前构建未启用 QuickJS 脚本引擎，请使用默认 features 或 `--features js` 重新编译")
}

#[cfg(feature = "rpc")]
fn serve_rpc_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!(
            "用法: runidbg-cli serve <script.js> [--listen 127.0.0.1:8080] [--workers 1|auto] [--max-queue 1024] [--timeout-ms 30000] [--max-insns 0] [--allow-reload] [--allow-eval] [-- <args...>]"
        );
    }
    let script_path = PathBuf::from(&args[0]);
    let mut cfg = runidbg_arm64_emu_tracer::script::rpc::RpcServerConfig::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" if i + 1 < args.len() => {
                cfg.listen_addr = args[i + 1].clone();
                i += 2;
            }
            "--workers" if i + 1 < args.len() => {
                let raw = args[i + 1].as_str();
                cfg.workers = if raw.eq_ignore_ascii_case("auto") {
                    std::thread::available_parallelism()
                        .map(std::num::NonZeroUsize::get)
                        .unwrap_or(1)
                } else {
                    raw.parse::<usize>()
                        .with_context(|| format!("无效的 --workers 值: {raw}"))?
                        .max(1)
                };
                i += 2;
            }
            "--max-queue" if i + 1 < args.len() => {
                cfg.max_queue = args[i + 1]
                    .parse::<usize>()
                    .with_context(|| format!("无效的 --max-queue 值: {}", args[i + 1]))?
                    .max(1);
                i += 2;
            }
            "--timeout-ms" if i + 1 < args.len() => {
                cfg.timeout_ms = args[i + 1]
                    .parse::<u64>()
                    .with_context(|| format!("无效的 --timeout-ms 值: {}", args[i + 1]))?;
                i += 2;
            }
            "--max-insns" if i + 1 < args.len() => {
                cfg.max_instructions = args[i + 1]
                    .parse::<usize>()
                    .with_context(|| format!("无效的 --max-insns 值: {}", args[i + 1]))?;
                i += 2;
            }
            "--allow-eval" => {
                cfg.allow_eval = true;
                i += 1;
            }
            "--allow-reload" => {
                cfg.allow_reload = true;
                i += 1;
            }
            "--" => {
                cfg.cli_args = args[i + 1..].to_vec();
                break;
            }
            other => bail!("serve 未知参数: {other}"),
        }
    }
    let handle = runidbg_arm64_emu_tracer::script::rpc::start_rpc_server(
        runidbg_arm64_emu_tracer::script::rpc::RpcSource::File(script_path),
        cfg,
    )?;
    eprintln!(
        "[runidbg-rpc] 已监听 http://{} | workers={} (GET /health, GET /metrics, POST /call/<method>, POST /rpc)",
        handle.local_addr(),
        handle.workers()
    );
    handle.wait();
    Ok(())
}

#[cfg(not(feature = "rpc"))]
fn serve_rpc_command(_args: &[String]) -> Result<()> {
    bail!("当前构建未启用 RPC 服务，请使用默认 features 或 `--features rpc` 重新编译")
}

#[cfg(feature = "mcp")]
fn mcp_command(args: &[String]) -> Result<()> {
    let mut init_script: Option<PathBuf> = None;
    let mut cwd: Option<PathBuf> = None;
    let mut http_addr: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--script" if i + 1 < args.len() => {
                init_script = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--cwd" if i + 1 < args.len() => {
                cwd = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--http" if i + 1 < args.len() => {
                http_addr = Some(args[i + 1].clone());
                i += 2;
            }
            other => bail!("mcp 未知参数: {other}"),
        }
    }
    let base_dir = cwd.unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    if let Some(addr) = http_addr {
        #[cfg(feature = "rpc")]
        {
            let handle = runidbg_arm64_emu_tracer::script::mcp::start_mcp_http_server(
                &addr,
                &base_dir,
                init_script.as_deref(),
            )?;
            eprintln!(
                "[runidbg-mcp] Streamable HTTP 已监听 http://{}/mcp",
                handle.local_addr()
            );
            handle.wait();
            return Ok(());
        }
        #[cfg(not(feature = "rpc"))]
        {
            let _ = addr;
            bail!("HTTP MCP 模式需要同时启用 `rpc` feature");
        }
    }
    let mut server =
        runidbg_arm64_emu_tracer::script::mcp::McpServer::new(&base_dir, init_script.as_deref())?;
    server.run_stdio()
}

#[cfg(not(feature = "mcp"))]
fn mcp_command(_args: &[String]) -> Result<()> {
    bail!("当前构建未启用 MCP 服务，请使用默认 features 或 `--features mcp` 重新编译")
}

fn asm_command(args: &[String]) -> Result<()> {
    let mut source_parts: Vec<String> = Vec::new();
    let mut pc: u64 = 0;
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "-h" || arg == "--help" {
            println!("用法: runidbg-cli asm \"mov x0, #1; ret\" [--pc 0x40001000]");
            return Ok(());
        } else if arg == "--pc" || arg == "--addr" {
            let val = take_flag_value(args, &mut i, "asm", arg)?;
            pc = parse_u64_hex_or_dec(val)?;
        } else if let Some(val) = arg
            .strip_prefix("--pc=")
            .or_else(|| arg.strip_prefix("--addr="))
        {
            pc = parse_u64_hex_or_dec(val)?;
            i += 1;
        } else if arg.starts_with("--") {
            bail!("runidbg-cli asm: 未知选项 '{arg}'（支持 --pc / --addr / --help）");
        } else {
            source_parts.push(arg.to_string());
            i += 1;
        }
    }
    if source_parts.is_empty() {
        bail!("用法: runidbg-cli asm \"mov x0, #1; ret\" [--pc 0x40001000]");
    }
    let src = source_parts.join(" ");
    let bytes = runidbg_arm64_emu_tracer::good64::assemble(&src, pc)?;
    let hex = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    println!("bytes ({}) : {hex}", bytes.len());
    let (chunks, rem) = bytes.as_chunks::<4>();
    for (idx, chunk) in chunks.iter().enumerate() {
        let cur_pc = pc.wrapping_add((idx * 4) as u64);
        let word = u32::from_le_bytes(*chunk);
        let dis = bad64::decode(word, cur_pc)
            .map(|ins| ins.to_string())
            .unwrap_or_else(|_| format!(".word 0x{word:08x}"));
        println!("  0x{cur_pc:016x}: {word:08x}  {dis}");
    }
    if !rem.is_empty() {
        let rem_pc = pc.wrapping_add((chunks.len() * 4) as u64);
        let rem_hex = rem
            .iter()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  0x{rem_pc:016x}: .byte {rem_hex}");
    }
    Ok(())
}

#[cfg(feature = "js")]
fn init_types_command(args: &[String]) -> Result<()> {
    let dir = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let out = runidbg_arm64_emu_tracer::script::write_type_definitions(&dir)?;
    println!("已生成 TypeScript 类型声明: {}", out.display());
    Ok(())
}

#[cfg(not(feature = "js"))]
fn init_types_command(_args: &[String]) -> Result<()> {
    bail!("当前构建未启用 QuickJS 脚本引擎，请使用默认 features 或 `--features js` 重新编译")
}

#[cfg(feature = "ui")]
fn ui_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("用法: runidbg-cli ui <trace.idx|file.rtape> [--ext <trace.ext>] [--base <hex>] [--listen 127.0.0.1:8088] [--open]");
    }
    let input_path = PathBuf::from(&args[0]);
    let mut ext_path: Option<PathBuf> = None;
    let mut base_addr: u64 = 0;
    let mut listen_addr = "127.0.0.1:8088".to_string();
    let mut auto_open = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ext" if i + 1 < args.len() => {
                ext_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--base" if i + 1 < args.len() => {
                base_addr = parse_u64_hex_or_dec(&args[i + 1])?;
                i += 2;
            }
            "--listen" if i + 1 < args.len() => {
                listen_addr = args[i + 1].clone();
                i += 2;
            }
            "--open" => {
                auto_open = true;
                i += 1;
            }
            other => bail!("ui 未知参数: {other}"),
        }
    }

    let is_rtape = input_path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("rtape"))
        || {
            use std::io::Read;
            let magic = runidbg_arm64_emu_tracer::tape::TAPE_MAGIC;
            let mut head = vec![0u8; magic.len()];
            fs::File::open(&input_path)
                .and_then(|mut f| f.read_exact(&mut head))
                .is_ok()
                && head.as_slice() == magic
        };

    if is_rtape {
        let handle =
            runidbg_arm64_emu_tracer::ui::start_timetravel_ui_server(&input_path, &listen_addr)?;
        let url = format!("http://{}/", handle.local_addr());
        println!("[runidbg-ui] Time-Travel Web UI 已启动: {url}");
        println!("[runidbg-ui] 按 Ctrl+C 退出");
        if auto_open {
            runidbg_arm64_emu_tracer::ui::open_in_browser(&url);
        }
        handle.wait();
        return Ok(());
    }

    if ext_path.is_none() {
        ext_path = runidbg_arm64_emu_tracer::tracer::resolve_sibling_ext_path(&input_path);
    }

    let handle = runidbg_arm64_emu_tracer::ui::start_trace_ui_server(
        &input_path,
        ext_path.as_deref(),
        base_addr,
        &listen_addr,
    )?;
    let url = format!("http://{}/", handle.local_addr());
    println!("[runidbg-ui] Trace Web UI 已启动: {url}");
    println!("[runidbg-ui] 按 Ctrl+C 退出");
    if auto_open {
        runidbg_arm64_emu_tracer::ui::open_in_browser(&url);
    }
    handle.wait();
    Ok(())
}

#[cfg(not(feature = "ui"))]
fn ui_command(_args: &[String]) -> Result<()> {
    bail!("当前构建未启用 Web UI（默认关闭以保持精简），请使用 `cargo build --release --features ui` 重新编译")
}

fn tape_command(args: &[String]) -> Result<()> {
    if args.len() != 2 || args[0] != "info" {
        bail!("用法: runidbg-cli tape info <file.rtape>");
    }
    let path = PathBuf::from(&args[1]);
    let summary = runidbg_arm64_emu_tracer::Tape::inspect_file(&path)?;
    println!(
        "RTAPE v{} | 文件: {} | 总大小: {:.2} KB ({} bytes) | 检查点数: {}",
        summary.version,
        path.display(),
        summary.file_size as f64 / 1024.0,
        summary.file_size,
        summary.checkpoints.len()
    );
    println!(
        "{:<4} {:<20} {:<6} {:<11} {:>9} {:>7} {:>6} {:>7} {:>10} {:>10}  MODULES",
        "IDX", "LABEL", "TYPE", "BACKEND", "INSN", "PAGES", "ZERO", "UNMAP", "COMP(KB)", "RAW(KB)"
    );
    for cp in &summary.checkpoints {
        let kind = if cp.is_delta { "DELTA" } else { "BASE" };
        println!(
            "{:<4} {:<20} {:<6} {:<11} {:>9} {:>7} {:>6} {:>7} {:>10.1} {:>10.1}  {}",
            cp.index,
            cp.label,
            kind,
            cp.source_backend,
            cp.insn_count,
            cp.stored_pages,
            cp.zeroed_pages,
            cp.removed_pages,
            cp.compressed_bytes as f64 / 1024.0,
            cp.uncompressed_bytes as f64 / 1024.0,
            cp.modules.join(", ")
        );
    }
    if let Some(tl) = &summary.timeline {
        let bms: Vec<String> = tl
            .bookmarks
            .iter()
            .map(|(ins, l)| format!("{l}@{ins}"))
            .collect();
        println!(
            "TIMELINE | 指令区间: {}..{} | 关键帧间隔: {} | 事件数: {} (clock={}, jni={}, hook={}, host_files={}) | 书签: [{}]",
            tl.start_insn,
            tl.end_insn,
            tl.keyframe_interval,
            tl.event_count,
            tl.clock_events,
            tl.jni_events,
            tl.hook_events,
            tl.host_file_count,
            bms.join(", ")
        );
    }
    Ok(())
}

fn take_flag_value<'a>(
    args: &'a [String],
    i: &mut usize,
    cmd: &str,
    flag: &str,
) -> Result<&'a str> {
    if *i + 1 >= args.len() || args[*i + 1].starts_with("--") {
        bail!("{cmd} 参数 `{flag}` 缺少参数值");
    }
    let val = args[*i + 1].as_str();
    *i += 2;
    Ok(val)
}

fn debug_gdb_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!(
            "用法:\n  runidbg-cli debug <lib.so> <symbol|0xaddr> [--listen 127.0.0.1:1234] [--pkg com.example.app]\n  runidbg-cli debug --tape <file.rtape> [--checkpoint <idx|label>] [<symbol|0xaddr>] [--listen 127.0.0.1:1234]"
        );
    }
    let mut listen_addr = "127.0.0.1:1234".to_string();
    let mut pkg: Option<String> = None;
    let mut tape_path: Option<PathBuf> = None;
    let mut checkpoint_sel: Option<runidbg_arm64_emu_tracer::TapeSelector> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                listen_addr = take_flag_value(args, &mut i, "debug", "--listen")?.to_string();
            }
            "--pkg" => {
                pkg = Some(take_flag_value(args, &mut i, "debug", "--pkg")?.to_string());
            }
            "--tape" => {
                tape_path = Some(PathBuf::from(take_flag_value(args, &mut i, "debug", "--tape")?));
            }
            "--checkpoint" => {
                let raw = take_flag_value(args, &mut i, "debug", "--checkpoint")?;
                checkpoint_sel = Some(runidbg_arm64_emu_tracer::TapeSelector::parse(raw));
            }
            "--backend" => {
                let raw = take_flag_value(args, &mut i, "debug", "--backend")?;
                let kind: runidbg_arm64_emu_tracer::BackendKind = raw.parse()?;
                if !kind.supports_gdb() {
                    bail!(
                        "GDB 调试模式仅支持 `unicorn` 后端，后端 `{kind}` 仅限仿真模式使用"
                    );
                }
            }
            other if other.starts_with("--") => bail!("debug 未知参数: {other}"),
            other => {
                positional.push(other.to_string());
                i += 1;
            }
        }
    }

    if let Some(tape) = tape_path {
        if positional.len() > 1 {
            bail!(
                "debug --tape 最多只接受 1 个目标符号/地址，多余参数: {}",
                positional[1..].join(" ")
            );
        }
        if pkg.is_some() {
            eprintln!("[runidbg-gdb] 警告: --tape 模式沿用磁带内保存的包名，--pkg 参数将被忽略");
        }
        let loaded_tape = runidbg_arm64_emu_tracer::Tape::load_file(&tape)?;
        // 若未显式指定新的目标符号，且该磁带包含二期时间旅行 EVENT_LOG，保持进入时间旅行 GDB 会话（同时支持 --checkpoint / 书签起始定位）
        if positional.is_empty() && loaded_tape.has_time_travel() {
            let checkpoints = loaded_tape.checkpoints();
            let mut player = runidbg_arm64_emu_tracer::TimeTravelPlayer::from_tape(loaded_tape)?;
            if let Some(sel) = checkpoint_sel {
                match sel {
                    runidbg_arm64_emu_tracer::TapeSelector::Latest => {
                        let end = player.total_insns();
                        player.seek_insn(end)?;
                    }
                    runidbg_arm64_emu_tracer::TapeSelector::Index(i) => {
                        let cp = checkpoints.get(i).ok_or_else(|| {
                            anyhow::anyhow!("时间旅行磁带中不存在检查点序号 #{i}")
                        })?;
                        player.seek_insn(cp.insn_count)?;
                    }
                    runidbg_arm64_emu_tracer::TapeSelector::Label(ref lbl) => {
                        if player.seek_bookmark(lbl).is_err() {
                            let cp = checkpoints.iter().rev().find(|c| c.label == *lbl).ok_or_else(
                                || {
                                    anyhow::anyhow!(
                                        "时间旅行磁带中未找到书签或检查点标签 `{lbl}`"
                                    )
                                },
                            )?;
                            player.seek_insn(cp.insn_count)?;
                        }
                    }
                }
            }
            eprintln!(
                "[runidbg-gdb] 已打开二期时间旅行磁带 {} (insn={}/{}, {} 关键帧) -> Unicorn GDB Time-Travel (支持 rs/rc/watch/monitor seek)",
                tape.display(),
                player.current_insn(),
                player.total_insns(),
                player.tape().len()
            );
            return runidbg_arm64_emu_tracer::debug::GdbServer::serve_time_travel(
                &mut player,
                &listen_addr,
            );
        }
        let sel = checkpoint_sel.unwrap_or(runidbg_arm64_emu_tracer::TapeSelector::Latest);
        let (mut emu, info) =
            runidbg_arm64_emu_tracer::AndroidEmulator::from_loaded_tape_with_builder(
                &loaded_tape,
                &sel,
                runidbg_arm64_emu_tracer::AndroidEmulator::builder()
                    .backend(runidbg_arm64_emu_tracer::BackendKind::Unicorn),
            )?;
        if let Some(target) = positional.first() {
            let start_pc = if target.starts_with("0x") || target.starts_with("0X") {
                parse_u64_hex_or_dec(target)?
            } else {
                // 逆序查找模块（主业务库位于 DT_NEEDED 依赖之后，优先命中主库符号）
                emu.linker()
                    .all_modules()
                    .iter()
                    .rev()
                    .find_map(|m| m.find_symbol(target).ok())
                    .with_context(|| format!("磁带已加载模块中未找到导出符号: {target}"))?
            };
            eprintln!(
                "[runidbg-gdb] 已从磁带 {} 接力恢复检查点 #{} `{}` (源后端={}, 模块={}) -> Unicorn GDB @ 0x{:016x}",
                tape.display(),
                info.index,
                info.label,
                info.source_backend,
                info.modules.join(", "),
                start_pc
            );
            return runidbg_arm64_emu_tracer::debug::GdbServer::serve(
                &mut emu,
                &listen_addr,
                start_pc,
                &[],
            );
        } else {
            let saved_pc = runidbg_arm64_emu_tracer::CpuBackend::reg_read(
                emu.cpu(),
                unicorn_engine::RegisterARM64::PC,
            )?;
            if saved_pc == 0 || saved_pc == runidbg_arm64_emu_tracer::cpu::RET_MAGIC_ADDR {
                eprintln!(
                    "[runidbg-gdb] 警告: 该检查点保存的 PC 为 0x{saved_pc:016x}（处于函数返回/空闲态）；如需调试指定函数，请补充 <symbol|0xaddr> 参数"
                );
            }
            eprintln!(
                "[runidbg-gdb] 已从磁带 {} 无损恢复检查点 #{} `{}` (源后端={}, 模块={}) -> Unicorn GDB @ 0x{:016x} (保留原 LR/寄存器)",
                tape.display(),
                info.index,
                info.label,
                info.source_backend,
                info.modules.join(", "),
                saved_pc
            );
            return runidbg_arm64_emu_tracer::debug::GdbServer::serve_resume(
                &mut emu,
                &listen_addr,
            );
        }
    }

    if checkpoint_sel.is_some() {
        bail!("--checkpoint 参数仅可与 --tape 配合使用");
    }
    if positional.len() != 2 {
        bail!("用法: runidbg-cli debug <lib.so> <symbol|0xaddr> [--listen 127.0.0.1:1234] [--pkg com.example.app]");
    }
    let so_path = PathBuf::from(&positional[0]);
    let target = positional[1].as_str();
    let mut emu = runidbg_arm64_emu_tracer::AndroidEmulator::builder()
        .package_name(pkg.unwrap_or_else(|| "com.example.app".to_string()))
        .build()?;
    let module = emu.load_library(&so_path)?;
    let start_pc = if target.starts_with("0x") || target.starts_with("0X") {
        parse_u64_hex_or_dec(target)?
    } else {
        module
            .find_symbol(target)
            .with_context(|| format!("未找到导出符号: {target}"))?
    };
    eprintln!(
        "[runidbg-gdb] 已加载 {} (base=0x{:016x}, size=0x{:x})",
        module.name, module.base_addr, module.image_size
    );
    runidbg_arm64_emu_tracer::debug::GdbServer::serve(&mut emu, &listen_addr, start_pc, &[])
}

fn pack_command(args: &[String]) -> Result<()> {
    let usage = "用法: runidbg-cli pack <trace.idx> [--ext <trace.ext>|--no-ext] [--out <out.rtrace>] [--base <hex>] [--note <text>] [--level <0..9>]";
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        if args.is_empty() {
            bail!("{usage}");
        }
        eprintln!("{usage}");
        return Ok(());
    }
    let idx_path = PathBuf::from(&args[0]);
    let mut ext_path: Option<PathBuf> = None;
    let mut no_ext = false;
    let mut out_path: Option<PathBuf> = None;
    let mut opts = runidbg_arm64_emu_tracer::tracer::TraceArchivePackOptions::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ext" => {
                ext_path = Some(PathBuf::from(take_flag_value(
                    args, &mut i, "pack", "--ext",
                )?));
            }
            "--no-ext" => {
                no_ext = true;
                i += 1;
            }
            "--out" | "-o" => {
                let flag = args[i].as_str();
                out_path = Some(PathBuf::from(take_flag_value(args, &mut i, "pack", flag)?));
            }
            "--base" => {
                let v = take_flag_value(args, &mut i, "pack", "--base")?;
                opts.base_addr = parse_u64_hex_or_dec(v)?;
            }
            "--note" => {
                opts.note = Some(take_flag_value(args, &mut i, "pack", "--note")?.to_string());
            }
            "--level" => {
                let v = take_flag_value(args, &mut i, "pack", "--level")?;
                let lvl: u32 = v.parse().context("无效的 --level 值（支持 0..=9）")?;
                if lvl > 9 {
                    bail!("pack --level 必须在 0..=9 之间");
                }
                opts.compression_level = lvl;
            }
            other => bail!("pack 未知参数: {other}"),
        }
    }

    if no_ext && ext_path.is_some() {
        bail!("pack 的 --ext 与 --no-ext 互斥，请只提供其中一个");
    }
    if !no_ext && ext_path.is_none() {
        ext_path = runidbg_arm64_emu_tracer::tracer::resolve_sibling_ext_path(&idx_path);
    }
    let final_out = out_path.unwrap_or_else(|| idx_path.with_extension("rtrace"));
    let info = runidbg_arm64_emu_tracer::tracer::TraceArchive::pack(
        &idx_path,
        ext_path.as_deref(),
        &final_out,
        &opts,
    )?;
    println!("已打包单文件 Trace 归档到 {}", final_out.display());
    print!("{}", info.format_summary());
    Ok(())
}

fn unpack_command(args: &[String]) -> Result<()> {
    let usage = "用法: runidbg-cli unpack <file.rtrace> [--out-dir <dir>] [--stem <name>] [--force] [--info]";
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        if args.is_empty() {
            bail!("{usage}");
        }
        eprintln!("{usage}");
        return Ok(());
    }
    let archive_path = PathBuf::from(&args[0]);
    let mut out_dir: Option<PathBuf> = None;
    let mut stem: Option<String> = None;
    let mut force = false;
    let mut info_only = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out-dir" | "-o" => {
                let flag = args[i].as_str();
                out_dir = Some(PathBuf::from(take_flag_value(args, &mut i, "unpack", flag)?));
            }
            "--stem" => {
                stem = Some(take_flag_value(args, &mut i, "unpack", "--stem")?.to_string());
            }
            "--force" | "-f" => {
                force = true;
                i += 1;
            }
            "--info" => {
                info_only = true;
                i += 1;
            }
            other => bail!("unpack 未知参数: {other}"),
        }
    }

    if info_only {
        let info = runidbg_arm64_emu_tracer::tracer::TraceArchive::inspect(&archive_path)?;
        print!("{}", info.format_summary());
        return Ok(());
    }
    let dir = out_dir.unwrap_or_else(|| {
        archive_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    });
    let res = runidbg_arm64_emu_tracer::tracer::TraceArchive::unpack(
        &archive_path,
        &dir,
        stem.as_deref(),
        force,
    )?;
    println!("已解包 .idx -> {}", res.idx_path.display());
    if let Some(ref ep) = res.ext_path {
        println!("已解包 .ext -> {}", ep.display());
    }
    print!("{}", res.info.format_summary());
    Ok(())
}

fn diff_command(args: &[String]) -> Result<()> {
    let usage = "用法: runidbg-cli diff <a.idx> <b.idx> [--ext-a <a.ext>] [--ext-b <b.ext>] [--base <hex>] [--limit N] [--target-addr <hex> [--len N] [--max-insns N]]";
    if args
        .first()
        .map(String::as_str)
        .is_some_and(|a| matches!(a, "-h" | "--help"))
    {
        eprintln!("{usage}");
        return Ok(());
    }
    if args.len() < 2 {
        bail!("{usage}");
    }
    let a_idx = PathBuf::from(&args[0]);
    let b_idx = PathBuf::from(&args[1]);
    let mut a_ext: Option<PathBuf> = None;
    let mut b_ext: Option<PathBuf> = None;
    let mut base_addr: u64 = 0;
    let mut limit: usize = 64;
    let mut target_addr: Option<u64> = None;
    let mut target_len: usize = 16;
    let mut max_insns: usize = 0;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--ext-a" => {
                let v = take_flag_value(args, &mut i, "diff", "--ext-a")?;
                a_ext = Some(PathBuf::from(v));
            }
            "--ext-b" => {
                let v = take_flag_value(args, &mut i, "diff", "--ext-b")?;
                b_ext = Some(PathBuf::from(v));
            }
            "--base" => {
                let v = take_flag_value(args, &mut i, "diff", "--base")?;
                base_addr = parse_u64_hex_or_dec(v)?;
            }
            "--limit" => {
                let v = take_flag_value(args, &mut i, "diff", "--limit")?;
                limit = v.parse::<usize>().context("无效的 --limit 值")?;
                if limit == 0 {
                    bail!("--limit 必须 >= 1");
                }
            }
            "--target-addr" | "--addr" => {
                let flag = args[i].as_str();
                let v = take_flag_value(args, &mut i, "diff", flag)?;
                target_addr = Some(parse_u64_hex_or_dec(v)?);
            }
            "--len" => {
                let v = take_flag_value(args, &mut i, "diff", "--len")?;
                target_len = v.parse::<usize>().context("无效的 --len 值")?;
                if target_len == 0 || target_len > 4096 {
                    bail!("diff --len 必须在 1..=4096 之间");
                }
            }
            "--max-insns" => {
                let v = take_flag_value(args, &mut i, "diff", "--max-insns")?;
                max_insns = v.parse::<usize>().context("无效的 --max-insns 值")?;
            }
            other => bail!("diff 未知参数: {other}"),
        }
    }
    if a_ext.is_none() {
        a_ext = runidbg_arm64_emu_tracer::tracer::resolve_sibling_ext_path(&a_idx);
    }
    if b_ext.is_none() {
        b_ext = runidbg_arm64_emu_tracer::tracer::resolve_sibling_ext_path(&b_idx);
    }
    let ra = TraceReader::open(&a_idx, a_ext.as_deref())?;
    let rb = TraceReader::open(&b_idx, b_ext.as_deref())?;
    warn_if_missing_ext(&ra, &a_idx);
    warn_if_missing_ext(&rb, &b_idx);
    if base_addr == 0 {
        base_addr = ra
            .archive_base_addr()
            .or_else(|| rb.archive_base_addr())
            .unwrap_or(0);
    }
    if let Some(taddr) = target_addr {
        let report = TraceReader::diff_taint_bytes(&ra, &rb, taddr, target_len, max_insns);
        print!("{}", report.format_summary());
        return Ok(());
    }
    let summary = TraceReader::diff_traces(&ra, &rb, limit);
    let fmt_rel = |pc: u64| -> String {
        if base_addr != 0 && pc >= base_addr {
            format!(" [+0x{:x}]", pc - base_addr)
        } else {
            String::new()
        }
    };
    println!(
        "# 双跑 Trace Diff: A={} 条 vs B={} 条 | 公共前缀={} 条",
        summary.total_a, summary.total_b, summary.common_prefix_insns
    );
    println!(
        "# 首次控制流分歧: {:?} | 首次数据流分歧: {:?} | 输出差异: {} 条",
        summary.first_control_divergence_idx,
        summary.first_data_divergence_idx,
        summary.diffs.len()
    );
    for d in &summary.diffs {
        println!(
            "  #{:06} [{:<7}] pcA=0x{:016x}{} pcB=0x{:016x}{} | {}",
            d.idx,
            d.kind,
            d.pc_a,
            fmt_rel(d.pc_a),
            d.pc_b,
            fmt_rel(d.pc_b),
            d.detail
        );
    }
    Ok(())
}

fn taint_command(args: &[String]) -> Result<()> {
    let usage = "用法: runidbg-cli taint <trace.idx> [--ext <trace.ext>] [--mode <forward|backward>] (--addr <hex> [--len N] | --reg <x0>) [--at <idx>] [--from-seq <idx>] [--stop-at-pc <hex>] [--stop-mem <hex[:len]>] [--max-insns N] [--limit N] [--base <hex>] [--no-mem-index] [--track-sp]";
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        if args.is_empty() {
            bail!("{usage}");
        }
        eprintln!("{usage}");
        return Ok(());
    }
    let idx_path = PathBuf::from(&args[0]);
    let mut ext_path: Option<PathBuf> = None;
    let mut mode = "backward".to_string();
    let mut target_addr: Option<u64> = None;
    let mut target_len: usize = 8;
    let mut target_reg: Option<String> = None;
    let mut anchor_idx: Option<usize> = None;
    let mut min_idx: Option<usize> = None;
    let mut stop_at_pcs: Vec<u64> = Vec::new();
    let mut stop_mem_ranges: Vec<(u64, usize)> = Vec::new();
    let mut max_insns: usize = 0;
    let mut limit: usize = 256;
    let mut base_addr: u64 = 0;
    let mut track_mem_index = true;
    let mut track_sp = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ext" => {
                let v = take_flag_value(args, &mut i, "taint", "--ext")?;
                ext_path = Some(PathBuf::from(v));
            }
            "--mode" => {
                let v = take_flag_value(args, &mut i, "taint", "--mode")?;
                mode = v.to_ascii_lowercase();
            }
            "--addr" => {
                let v = take_flag_value(args, &mut i, "taint", "--addr")?;
                target_addr = Some(parse_u64_hex_or_dec(v)?);
            }
            "--len" => {
                let v = take_flag_value(args, &mut i, "taint", "--len")?;
                target_len = v.parse::<usize>().context("无效的 --len 值")?;
                if target_len == 0 {
                    bail!("--len 必须 >= 1");
                }
            }
            "--reg" => {
                let v = take_flag_value(args, &mut i, "taint", "--reg")?;
                target_reg = Some(v.to_string());
            }
            "--at" | "--start" => {
                let flag = args[i].as_str();
                let v = take_flag_value(args, &mut i, "taint", flag)?;
                anchor_idx = Some(v.parse().context("无效的 --at 值")?);
            }
            "--from-seq" | "--min-idx" => {
                let flag = args[i].as_str();
                let v = take_flag_value(args, &mut i, "taint", flag)?;
                min_idx = Some(v.parse().context("无效的 --from-seq 值")?);
            }
            "--stop-at-pc" => {
                let v = take_flag_value(args, &mut i, "taint", "--stop-at-pc")?;
                stop_at_pcs.push(parse_u64_hex_or_dec(v)?);
            }
            "--stop-mem" => {
                let v = take_flag_value(args, &mut i, "taint", "--stop-mem")?;
                stop_mem_ranges.push(parse_stop_mem(v)?);
            }
            "--max-insns" => {
                let v = take_flag_value(args, &mut i, "taint", "--max-insns")?;
                max_insns = v.parse().context("无效的 --max-insns 值")?;
            }
            "--limit" => {
                let v = take_flag_value(args, &mut i, "taint", "--limit")?;
                limit = v.parse().context("无效的 --limit 值")?;
            }
            "--base" => {
                let v = take_flag_value(args, &mut i, "taint", "--base")?;
                base_addr = parse_u64_hex_or_dec(v)?;
            }
            "--no-mem-index" => {
                track_mem_index = false;
                i += 1;
            }
            "--track-sp" => {
                track_sp = true;
                i += 1;
            }
            other => bail!("taint 未知参数: {other}"),
        }
    }

    if target_reg.is_some() && target_addr.is_some() {
        bail!("taint 的 --addr 与 --reg 互斥，请只提供其中一个");
    }

    let seed = if let Some(ref reg_name) = target_reg {
        let slot = runidbg_arm64_emu_tracer::tracer::parse_reg_slot(reg_name)
            .ok_or_else(|| anyhow::anyhow!("无效的寄存器名: {reg_name}"))?;
        runidbg_arm64_emu_tracer::tracer::TaintSeed::Reg { reg_id: slot }
    } else if let Some(addr) = target_addr {
        runidbg_arm64_emu_tracer::tracer::TaintSeed::Mem {
            addr,
            len: target_len,
        }
    } else {
        bail!("taint 必须提供 --addr <hex> 或 --reg <x0>");
    };

    if ext_path.is_none() {
        ext_path = runidbg_arm64_emu_tracer::tracer::resolve_sibling_ext_path(&idx_path);
    }
    let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;
    warn_if_missing_ext(&reader, &idx_path);
    if base_addr == 0 {
        if let Some(saved_base) = reader.archive_base_addr() {
            base_addr = saved_base;
        }
    }
    let opts = runidbg_arm64_emu_tracer::tracer::TaintOptions {
        anchor_idx,
        min_idx,
        stop_at_pcs,
        stop_mem_ranges,
        max_insns,
        max_steps: limit,
        track_mem_index,
        track_sp,
    };
    let report = match mode.as_str() {
        "forward" | "fwd" => reader.taint_forward(&seed, &opts),
        "backward" | "bwd" | "slice" => reader.taint_backward(&seed, &opts),
        other => bail!("无效的 --mode `{other}`（支持 forward / backward）"),
    };
    print!("{}", report.format_summary(base_addr));
    Ok(())
}

fn decompile_command(args: &[String]) -> Result<()> {
    let usage = "用法: runidbg-cli decompile <trace.idx> [--ext <trace.ext>] (--addr <hex> [--len N] | --reg <x0>) [--at <idx>] [--from-seq <idx>] [--stop-at-pc <hex>] [--stop-mem <hex[:len]>] [--fold-rodata] [--max-insns N] [--max-steps N] [--fn <name>] [--no-simplify] [--smt2] [--no-mem-index] [--track-sp] [--out <slice.c>]";
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        if args.is_empty() {
            bail!("{usage}");
        }
        eprintln!("{usage}");
        return Ok(());
    }
    let idx_path = PathBuf::from(&args[0]);
    let mut ext_path: Option<PathBuf> = None;
    let mut target_addr: Option<u64> = None;
    let mut target_len: usize = 4;
    let mut target_reg: Option<String> = None;
    let mut opts = runidbg_arm64_emu_tracer::tracer::DecompileOptions::default();
    let mut out_path: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ext" => {
                ext_path = Some(PathBuf::from(take_flag_value(
                    args, &mut i, "decompile", "--ext",
                )?));
            }
            "--addr" => {
                let v = take_flag_value(args, &mut i, "decompile", "--addr")?;
                target_addr = Some(parse_u64_hex_or_dec(v)?);
            }
            "--len" => {
                let v = take_flag_value(args, &mut i, "decompile", "--len")?;
                target_len = v.parse().context("无效的 --len 值")?;
                if target_len == 0 || target_len > 64 {
                    bail!("decompile --len 必须在 1..=64 之间");
                }
            }
            "--reg" => {
                target_reg = Some(
                    take_flag_value(args, &mut i, "decompile", "--reg")?.to_string(),
                );
            }
            "--at" => {
                let v = take_flag_value(args, &mut i, "decompile", "--at")?;
                opts.anchor_idx = Some(v.parse().context("无效的 --at 值")?);
            }
            "--from-seq" | "--min-idx" => {
                let flag = args[i].as_str();
                let v = take_flag_value(args, &mut i, "decompile", flag)?;
                opts.from_idx = Some(v.parse().context("无效的 --from-seq 值")?);
            }
            "--stop-at-pc" => {
                let v = take_flag_value(args, &mut i, "decompile", "--stop-at-pc")?;
                opts.stop_at_pcs.push(parse_u64_hex_or_dec(v)?);
            }
            "--stop-mem" => {
                let v = take_flag_value(args, &mut i, "decompile", "--stop-mem")?;
                opts.stop_mem_ranges.push(parse_stop_mem(v)?);
            }
            "--fold-rodata" => {
                opts.fold_rodata = true;
                i += 1;
            }
            "--fn" => {
                opts.function_name =
                    take_flag_value(args, &mut i, "decompile", "--fn")?.to_string();
            }
            "--max-insns" => {
                let v = take_flag_value(args, &mut i, "decompile", "--max-insns")?;
                opts.max_insns = v.parse().context("无效的 --max-insns 值")?;
            }
            "--max-steps" => {
                let v = take_flag_value(args, &mut i, "decompile", "--max-steps")?;
                opts.max_steps = v.parse().context("无效的 --max-steps 值")?;
            }
            "--no-simplify" => {
                opts.simplify = false;
                i += 1;
            }
            "--smt2" => {
                opts.emit_smt2 = true;
                i += 1;
            }
            "--no-mem-index" => {
                opts.track_mem_index = false;
                i += 1;
            }
            "--track-sp" => {
                opts.track_sp = true;
                i += 1;
            }
            "--out" => {
                out_path = Some(PathBuf::from(take_flag_value(
                    args, &mut i, "decompile", "--out",
                )?));
            }
            other => bail!("decompile 未知参数: {other}"),
        }
    }

    if target_reg.is_some() && target_addr.is_some() {
        bail!("decompile 的 --addr 与 --reg 互斥，请只提供其中一个");
    }
    let seed = if let Some(ref reg_name) = target_reg {
        let slot = runidbg_arm64_emu_tracer::tracer::parse_reg_slot(reg_name)
            .ok_or_else(|| anyhow::anyhow!("无效的寄存器名: {reg_name}"))?;
        runidbg_arm64_emu_tracer::tracer::TaintSeed::Reg { reg_id: slot }
    } else if let Some(addr) = target_addr {
        runidbg_arm64_emu_tracer::tracer::TaintSeed::Mem {
            addr,
            len: target_len,
        }
    } else {
        bail!("decompile 必须提供 --addr <hex> 或 --reg <x0>");
    };

    if ext_path.is_none() {
        ext_path = runidbg_arm64_emu_tracer::tracer::resolve_sibling_ext_path(&idx_path);
    }
    let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;
    warn_if_missing_ext(&reader, &idx_path);
    let report = reader.decompile_slice(&seed, &opts);
    let summary = report.format_summary();
    if let Some(out) = out_path {
        fs::write(&out, &summary)?;
        println!(
            "已导出精简伪 C 到 {}（slice={} insns, dag={}->{} nodes, verified={:?}）",
            out.display(),
            report.slice_insns,
            report.raw_nodes,
            report.simplified_nodes,
            report.verified
        );
    } else {
        print!("{summary}");
    }
    Ok(())
}

fn vm_command(args: &[String]) -> Result<()> {
    let usage = "用法: runidbg-cli vm <trace.idx> [--ext <trace.ext>] [--dispatcher <hex>] [--bc-reg <x23>] [--bc-deref] [--bc-addr <hex>] [--base-reg <x25>] [--reg-count 32] [--reg-size 8] [--layout <op_lsb:w,f0_lsb[:w],...>] [--min-handlers N] [--min-dispatches N] [--seq-range <start>..<end>] [--base <hex>] [--limit N] [--max-insns N]";
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        if args.is_empty() {
            bail!("{usage}");
        }
        eprintln!("{usage}");
        return Ok(());
    }
    let idx_path = PathBuf::from(&args[0]);
    let mut ext_path: Option<PathBuf> = None;
    let mut opts = runidbg_arm64_emu_tracer::tracer::VmAnalysisOptions::default();
    let mut base_reg_name: Option<String> = None;
    let mut reg_count: usize = 32;
    let mut reg_size: u8 = 8;
    let mut base_addr: u64 = 0;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ext" => {
                ext_path = Some(PathBuf::from(take_flag_value(args, &mut i, "vm", "--ext")?));
            }
            "--dispatcher" => {
                let v = take_flag_value(args, &mut i, "vm", "--dispatcher")?;
                opts.dispatcher_pc = Some(parse_u64_hex_or_dec(v)?);
            }
            "--bc-reg" => {
                let v = take_flag_value(args, &mut i, "vm", "--bc-reg")?;
                let slot = runidbg_arm64_emu_tracer::tracer::parse_gpr_slot(v)
                    .ok_or_else(|| anyhow::anyhow!("无效的 --bc-reg 寄存器名: {v}"))?;
                opts.bc_reg = Some(slot);
            }
            "--bc-deref" => {
                opts.bc_deref = true;
                i += 1;
            }
            "--bc-addr" => {
                let v = take_flag_value(args, &mut i, "vm", "--bc-addr")?;
                opts.bc_ptr_addr = Some(parse_u64_hex_or_dec(v)?);
            }
            "--base-reg" => {
                base_reg_name = Some(take_flag_value(args, &mut i, "vm", "--base-reg")?.to_string());
            }
            "--reg-count" => {
                let v = take_flag_value(args, &mut i, "vm", "--reg-count")?;
                reg_count = v.parse::<usize>().context("无效的 --reg-count 值")?;
                if reg_count == 0 || reg_count > 256 {
                    bail!("--reg-count 必须在 1..=256 之间");
                }
            }
            "--reg-size" => {
                let v = take_flag_value(args, &mut i, "vm", "--reg-size")?;
                reg_size = v.parse::<u8>().context("无效的 --reg-size 值")?;
                if reg_size != 4 && reg_size != 8 {
                    bail!("--reg-size 仅支持 4 或 8");
                }
            }
            "--layout" => {
                let v = take_flag_value(args, &mut i, "vm", "--layout")?;
                let layout = runidbg_arm64_emu_tracer::tracer::VmWordLayout::parse_spec(v)
                    .map_err(|e| anyhow::anyhow!("无效的 --layout: {e}"))?;
                opts.layout = Some(layout);
            }
            "--min-handlers" => {
                let v = take_flag_value(args, &mut i, "vm", "--min-handlers")?;
                let mh = v.parse::<usize>().context("无效的 --min-handlers 值")?;
                if mh == 0 {
                    bail!("--min-handlers 必须 >= 1");
                }
                opts.min_handlers = mh;
            }
            "--min-dispatches" => {
                let v = take_flag_value(args, &mut i, "vm", "--min-dispatches")?;
                let md = v.parse::<usize>().context("无效的 --min-dispatches 值")?;
                if md == 0 {
                    bail!("--min-dispatches 必须 >= 1");
                }
                opts.min_dispatches = md;
            }
            "--max-insns" => {
                let v = take_flag_value(args, &mut i, "vm", "--max-insns")?;
                opts.max_insns = v.parse().context("无效的 --max-insns 值")?;
            }
            "--seq-range" => {
                let v = take_flag_value(args, &mut i, "vm", "--seq-range")?;
                let (s, e) = parse_seq_range(v)?;
                opts.min_idx = s;
                opts.max_idx = e;
            }
            "--limit" => {
                let v = take_flag_value(args, &mut i, "vm", "--limit")?;
                let lim = v.parse::<usize>().context("无效的 --limit 值")?;
                if lim == 0 {
                    bail!("--limit 必须 >= 1");
                }
                opts.max_steps = lim;
            }
            "--base" => {
                let v = take_flag_value(args, &mut i, "vm", "--base")?;
                base_addr = parse_u64_hex_or_dec(v)?;
            }
            other => bail!("vm 未知参数: {other}"),
        }
    }

    if opts.bc_reg.is_some() && opts.bc_ptr_addr.is_some() {
        bail!("vm 的 --bc-reg 与 --bc-addr 互斥，请只提供其中一个");
    }
    if opts.bc_deref && opts.bc_reg.is_none() {
        bail!("vm 的 --bc-deref 必须配合 --bc-reg 使用");
    }

    if let Some(ref br) = base_reg_name {
        let base_reg = runidbg_arm64_emu_tracer::tracer::parse_gpr_slot(br)
            .ok_or_else(|| anyhow::anyhow!("无效的 --base-reg 寄存器名: {br}"))?;
        opts.regfile = Some(runidbg_arm64_emu_tracer::tracer::VmRegfileConfig {
            base_reg,
            count: reg_count,
            size: reg_size,
        });
    }

    if ext_path.is_none() {
        ext_path = runidbg_arm64_emu_tracer::tracer::resolve_sibling_ext_path(&idx_path);
    }
    let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;
    warn_if_missing_ext(&reader, &idx_path);
    if base_addr == 0 {
        if let Some(saved_base) = reader.archive_base_addr() {
            base_addr = saved_base;
        }
    }
    let report = reader.analyze_vm(&opts);
    print!("{}", report.format_summary(base_addr));
    Ok(())
}

fn mem_command(args: &[String]) -> Result<()> {
    const MAX_MEM_RECONSTRUCT_LEN: usize = 16 * 1024 * 1024;
    let usage = "用法: runidbg-cli mem <trace.idx> --addr <hex> [--len N] [--at <seq>] [--ext <trace.ext>] [--hex|--hexdump|--out <file.bin>]";
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        if args.is_empty() {
            bail!("{usage}");
        }
        eprintln!("{usage}");
        return Ok(());
    }
    let idx_path = PathBuf::from(&args[0]);
    let mut ext_path: Option<PathBuf> = None;
    let mut addr: Option<u64> = None;
    let mut len: usize = 64;
    let mut at_seq: u32 = u32::MAX;
    let mut hex_only = false;
    let mut out_path: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ext" => {
                ext_path = Some(PathBuf::from(take_flag_value(args, &mut i, "mem", "--ext")?));
            }
            "--addr" => {
                let v = take_flag_value(args, &mut i, "mem", "--addr")?;
                addr = Some(parse_u64_hex_or_dec(v)?);
            }
            "--len" => {
                let v = take_flag_value(args, &mut i, "mem", "--len")?;
                len = v.parse::<usize>().context("无效的 --len 值")?;
                if len == 0 || len > MAX_MEM_RECONSTRUCT_LEN {
                    bail!("mem --len 必须在 1..={MAX_MEM_RECONSTRUCT_LEN} 之间");
                }
            }
            "--at" | "--at-seq" => {
                let flag = args[i].as_str();
                let v = take_flag_value(args, &mut i, "mem", flag)?;
                let n = parse_u64_hex_or_dec(v)?;
                at_seq = n.min(u32::MAX as u64) as u32;
            }
            "--hex" => {
                hex_only = true;
                i += 1;
            }
            "--hexdump" => {
                hex_only = false;
                i += 1;
            }
            "--out" => {
                out_path = Some(PathBuf::from(take_flag_value(args, &mut i, "mem", "--out")?));
            }
            other => bail!("mem 未知参数: {other}"),
        }
    }
    let target_addr = addr.ok_or_else(|| anyhow::anyhow!("mem 必须提供 --addr <hex>"))?;
    if ext_path.is_none() {
        ext_path = runidbg_arm64_emu_tracer::tracer::resolve_sibling_ext_path(&idx_path);
    }
    let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;
    warn_if_missing_ext(&reader, &idx_path);
    let bytes = reader.reconstruct_mem_at(target_addr, len, at_seq);
    let known = bytes.iter().filter(|b| b.is_some()).count();
    let seq_label = if at_seq == u32::MAX {
        "END".to_string()
    } else {
        at_seq.to_string()
    };

    if let Some(out) = out_path {
        let raw: Vec<u8> = bytes.iter().map(|b| b.unwrap_or(0)).collect();
        fs::write(&out, &raw)?;
        println!(
            "已导出重建内存 0x{target_addr:016x} ({len}B, 已知 {known}/{len}B, at_seq={seq_label}) 到 {}",
            out.display()
        );
        return Ok(());
    }
    if hex_only {
        let cap = len
            .checked_mul(2)
            .ok_or_else(|| anyhow::anyhow!("mem --len 过大导致缓冲区溢出"))?;
        let mut s = String::with_capacity(cap);
        for b in &bytes {
            match b {
                Some(v) => s.push_str(&format!("{v:02x}")),
                None => s.push_str("??"),
            }
        }
        println!("{s}");
        return Ok(());
    }
    println!(
        "# 内存重建: addr=0x{target_addr:016x} len={len}B at_seq={seq_label} known={known}/{len}"
    );
    for row in (0..len).step_by(16) {
        let row_addr = target_addr.wrapping_add(row as u64);
        let mut hex_col = String::with_capacity(48);
        let mut ascii_col = String::with_capacity(16);
        for col in 0..16 {
            if let Some(mb) = bytes.get(row + col) {
                match *mb {
                    Some(v) => {
                        hex_col.push_str(&format!("{v:02x} "));
                        ascii_col.push(if v.is_ascii_graphic() || v == b' ' {
                            v as char
                        } else {
                            '.'
                        });
                    }
                    None => {
                        hex_col.push_str("?? ");
                        ascii_col.push('?');
                    }
                }
            } else {
                hex_col.push_str("   ");
            }
        }
        println!("0x{row_addr:016x}: {hex_col} |{ascii_col}|");
    }
    Ok(())
}

fn main() -> Result<()> {
    let raw_args: Vec<String> = env::args().collect();
    let mut log_level: Option<String> = None;
    let mut log_format = "compact".to_string();
    let mut args = Vec::with_capacity(raw_args.len());
    if let Some(bin) = raw_args.first() {
        args.push(bin.clone());
    }
    let mut idx = 1;
    while idx < raw_args.len() {
        match raw_args[idx].as_str() {
            "--log-level" if idx + 1 < raw_args.len() => {
                log_level = Some(raw_args[idx + 1].clone());
                idx += 2;
            }
            "--log-format" if idx + 1 < raw_args.len() => {
                log_format = raw_args[idx + 1].clone();
                idx += 2;
            }
            _ => {
                args.extend_from_slice(&raw_args[idx..]);
                break;
            }
        }
    }

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let cmd = args[1].as_str();
    let default_level = match cmd {
        "serve" | "debug" => "info",
        _ => "warn",
    };
    runidbg_arm64_emu_tracer::logging::init_logging(
        log_level.as_deref().unwrap_or(default_level),
        &log_format,
    );

    match cmd {
        "run" => return run_js_command(&args[2..]),
        "serve" => return serve_rpc_command(&args[2..]),
        "mcp" => return mcp_command(&args[2..]),
        "debug" => return debug_gdb_command(&args[2..]),
        "tape" => return tape_command(&args[2..]),
        "asm" => return asm_command(&args[2..]),
        "diff" => return diff_command(&args[2..]),
        "taint" => return taint_command(&args[2..]),
        "decompile" => return decompile_command(&args[2..]),
        "vm" => return vm_command(&args[2..]),
        "mem" => return mem_command(&args[2..]),
        "pack" => return pack_command(&args[2..]),
        "unpack" => return unpack_command(&args[2..]),
        "ui" => return ui_command(&args[2..]),
        "init-types" => return init_types_command(&args[2..]),
        "-h" | "--help" | "help" => {
            print_usage();
            return Ok(());
        }
        _ => {}
    }

    if args.len() < 3 {
        print_usage();
        return Ok(());
    }

    let idx_path = PathBuf::from(&args[2]);
    let mut ext_path: Option<PathBuf> = None;
    let mut skip: usize = 0;
    let mut limit: usize = usize::MAX;
    let mut val_filter: Option<u64> = None;
    let mut addr_filter: Option<u64> = None;
    let mut addr_len: u64 = 1;
    let mut min_seq: Option<usize> = None;
    let mut max_seq: Option<usize> = None;
    let mut only_writes = false;
    let mut only_reads = false;
    let mut include_hle = true;
    let mut pc_filter: Option<u64> = None;
    let mut ascii_filter: Option<String> = None;
    let mut bytes_filter: Option<Vec<u8>> = None;
    let mut base_addr: u64 = 0;
    let mut top_n: usize = 20;
    let mut max_depth: usize = 4;
    let mut min_insns: usize = 1000;
    let mut out_path: Option<PathBuf> = None;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--ext" => {
                ext_path = Some(PathBuf::from(take_flag_value(&args, &mut i, cmd, "--ext")?));
            }
            "--skip" => {
                skip = take_flag_value(&args, &mut i, cmd, "--skip")?
                    .parse()
                    .context("无效的 --skip 值")?;
            }
            "--limit" => {
                limit = take_flag_value(&args, &mut i, cmd, "--limit")?
                    .parse()
                    .context("无效的 --limit 值")?;
            }
            "--val" => {
                val_filter = Some(parse_u64_hex_or_dec(take_flag_value(
                    &args, &mut i, cmd, "--val",
                )?)?);
            }
            "--addr" => {
                addr_filter = Some(parse_u64_hex_or_dec(take_flag_value(
                    &args, &mut i, cmd, "--addr",
                )?)?);
            }
            "--len" => {
                addr_len = take_flag_value(&args, &mut i, cmd, "--len")?
                    .parse::<u64>()
                    .context("无效的 --len 值")?;
                if addr_len == 0 {
                    bail!("--len 必须 >= 1");
                }
            }
            "--seq-range" => {
                let v = take_flag_value(&args, &mut i, cmd, "--seq-range")?;
                let (s, e) = parse_seq_range(v)?;
                min_seq = s;
                max_seq = e;
            }
            "--min-seq" => {
                min_seq = Some(
                    take_flag_value(&args, &mut i, cmd, "--min-seq")?
                        .parse()
                        .context("无效的 --min-seq 值")?,
                );
            }
            "--max-seq" => {
                max_seq = Some(
                    take_flag_value(&args, &mut i, cmd, "--max-seq")?
                        .parse()
                        .context("无效的 --max-seq 值")?,
                );
            }
            "--only-writes" => {
                only_writes = true;
                i += 1;
            }
            "--only-reads" => {
                only_reads = true;
                i += 1;
            }
            "--no-hle" => {
                include_hle = false;
                i += 1;
            }
            "--pc" => {
                pc_filter = Some(parse_u64_hex_or_dec(take_flag_value(
                    &args, &mut i, cmd, "--pc",
                )?)?);
            }
            "--ascii" => {
                ascii_filter = Some(take_flag_value(&args, &mut i, cmd, "--ascii")?.to_string());
            }
            "--bytes" => {
                bytes_filter = Some(parse_hex_bytes(take_flag_value(
                    &args, &mut i, cmd, "--bytes",
                )?)?);
            }
            "--base" => {
                base_addr = parse_u64_hex_or_dec(take_flag_value(
                    &args, &mut i, cmd, "--base",
                )?)?;
            }
            "--top" => {
                top_n = take_flag_value(&args, &mut i, cmd, "--top")?
                    .parse()
                    .context("无效的 --top 值")?;
            }
            "--max-depth" => {
                max_depth = take_flag_value(&args, &mut i, cmd, "--max-depth")?
                    .parse()
                    .context("无效的 --max-depth 值")?;
            }
            "--min-insns" => {
                min_insns = take_flag_value(&args, &mut i, cmd, "--min-insns")?
                    .parse()
                    .context("无效的 --min-insns 值")?;
            }
            "--out" => {
                out_path = Some(PathBuf::from(take_flag_value(&args, &mut i, cmd, "--out")?));
            }
            other => bail!("未知参数: {other}"),
        }
    }

    if ext_path.is_none() {
        ext_path = runidbg_arm64_emu_tracer::tracer::resolve_sibling_ext_path(&idx_path);
    }

    let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;
    warn_if_missing_ext(&reader, &idx_path);
    if base_addr == 0 {
        if let Some(saved_base) = reader.archive_base_addr() {
            base_addr = saved_base;
        }
    }

    let format_rel = |pc: u64| -> String {
        if base_addr != 0 && pc >= base_addr {
            format!(" [+0x{:x}]", pc - base_addr)
        } else {
            String::new()
        }
    };

    match cmd {
        "dump" => {
            println!(
                "# trace.idx: {} 条指令 | trace.ext: {} 条扩展事件",
                reader.len(),
                reader.ext_len()
            );
            let end = reader.len().min(skip.saturating_add(limit));
            for idx in skip..end {
                if let Some(rec) = reader.get(idx) {
                    let pc = rec.pc;
                    let op = rec.opcode;
                    let deltas = reader.reg_deltas_for(idx);
                    let primary = deltas.first().copied();
                    println!(
                        "#{idx:06}{} {}",
                        format_rel(pc),
                        decode_instruction_with_reg(pc, op, primary)
                    );
                    for &(reg_id, reg_val) in deltas.iter().skip(1) {
                        let name = if reg_id == 31 {
                            "SP".to_string()
                        } else {
                            format!("X{reg_id}")
                        };
                        let hint = format_ascii_hint(reg_val, 8).unwrap_or_default();
                        println!("    [REG] {name} <- 0x{reg_val:016x}{hint}");
                    }
                    if reader.has_ext() {
                        for line in reader.mem_and_hle_lines_for(idx) {
                            println!("{line}");
                        }
                    }
                }
            }
        }
        "search" | "find" => {
            if val_filter.is_none()
                && ascii_filter.is_none()
                && bytes_filter.is_none()
                && addr_filter.is_none()
                && pc_filter.is_none()
            {
                bail!(
                    "{cmd} 需要至少提供一个过滤条件：--val <hex> / --addr <hex> / --pc <hex> / --ascii <str> / --bytes <hex>"
                );
            }
            if only_writes && only_reads {
                bail!("--only-writes 与 --only-reads 互斥，请只提供其中一个");
            }
            if let (Some(lo), Some(hi)) = (min_seq, max_seq) {
                if lo > hi {
                    bail!("--min-seq ({lo}) 不能大于 --max-seq ({hi})");
                }
            }
            let in_seq_range = |s: usize| -> bool {
                if let Some(lo) = min_seq {
                    if s < lo {
                        return false;
                    }
                }
                if let Some(hi) = max_seq {
                    if s > hi {
                        return false;
                    }
                }
                true
            };
            if let Some(target) = val_filter {
                let reg_hits: Vec<_> = reader
                    .search_value_attributed(target)
                    .into_iter()
                    .filter(|(_, rec, _)| in_seq_range(rec.seq_low32 as usize))
                    .collect();
                println!("# 命中寄存器写入值 0x{target:016x}: {} 条", reg_hits.len());
                for (idx, rec, reg_id) in reg_hits.into_iter().take(limit) {
                    let pc = rec.pc;
                    let op = rec.opcode;
                    println!(
                        "#{idx:06}{} {}",
                        format_rel(pc),
                        decode_instruction_with_reg(pc, op, Some((reg_id, target)))
                    );
                }
                if reader.has_ext() {
                    let mem_hits: Vec<_> = reader
                        .search_mem_value(target)
                        .into_iter()
                        .filter(|ext| in_seq_range(ext.seq_low32 as usize))
                        .collect();
                    if !mem_hits.is_empty() {
                        println!("# 命中内存读写值 0x{target:016x}: {} 条", mem_hits.len());
                        for ext in mem_hits.into_iter().take(limit) {
                            let seq = ext.seq_low32;
                            let pc = ext.pc;
                            println!(
                                "seq={seq} pc=0x{pc:016x}{} {}",
                                format_rel(pc),
                                BinaryTracer::format_ext_record(&ext).trim()
                            );
                        }
                    }
                }
            }
            if let Some(ref ascii) = ascii_filter {
                let hits: Vec<_> = reader
                    .search_mem_bytes(ascii.as_bytes())
                    .into_iter()
                    .filter(|h| in_seq_range(h.seq_low32 as usize))
                    .collect();
                println!("# 命中内存写入 ASCII \"{ascii}\": {} 条", hits.len());
                for hit in hits.into_iter().take(limit) {
                    println!(
                        "seq={} pc=0x{:016x}{} [MEM W] addr=0x{:016x} len={} (\"{ascii}\")",
                        hit.seq_low32,
                        hit.pc,
                        format_rel(hit.pc),
                        hit.addr,
                        hit.matched_len
                    );
                }
            }
            if let Some(ref pat) = bytes_filter {
                let hits: Vec<_> = reader
                    .search_mem_bytes(pat)
                    .into_iter()
                    .filter(|h| in_seq_range(h.seq_low32 as usize))
                    .collect();
                let hex_str: String = pat.iter().map(|b| format!("{b:02x}")).collect();
                println!("# 命中内存写入字节序列 {hex_str}: {} 条", hits.len());
                for hit in hits.into_iter().take(limit) {
                    println!(
                        "seq={} pc=0x{:016x}{} [MEM W] addr=0x{:016x} len={} ({hex_str})",
                        hit.seq_low32,
                        hit.pc,
                        format_rel(hit.pc),
                        hit.addr,
                        hit.matched_len
                    );
                }
            }
            if let Some(target_addr) = addr_filter {
                let min_s = min_seq.map(|v| v.min(u32::MAX as usize) as u32);
                let max_s = max_seq.map(|v| v.min(u32::MAX as usize) as u32);
                let include_reads = !only_writes;
                let include_writes = !only_reads;
                let hits = reader.query_addr_history_filtered(
                    target_addr,
                    addr_len,
                    min_s,
                    max_s,
                    include_reads,
                    include_writes,
                    include_hle,
                    limit,
                );
                println!(
                    "# 命中访存地址 0x{target_addr:016x} (+{addr_len}B): {} 条",
                    hits.len()
                );
                for hit in hits {
                    let src_part = if hit.src != 0 {
                        format!(" src=0x{:016x}", hit.src)
                    } else {
                        String::new()
                    };
                    println!(
                        "seq={} pc=0x{:016x}{} [{}] addr=0x{:016x} size={} val=0x{:x}{src_part}",
                        hit.seq_low32,
                        hit.pc,
                        format_rel(hit.pc),
                        hit.kind,
                        hit.addr,
                        hit.size,
                        hit.value,
                    );
                }
            }
            if let Some(target_pc) = pc_filter {
                let mut count = 0usize;
                for idx in 0..reader.len() {
                    if let Some(rec) = reader.get(idx) {
                        if !in_seq_range(rec.seq_low32 as usize) {
                            continue;
                        }
                        let pc = rec.pc;
                        if pc == target_pc {
                            if count < limit {
                                let op = rec.opcode;
                                let primary = reader.reg_deltas_for(idx).first().copied();
                                println!(
                                    "#{idx:06}{} {}",
                                    format_rel(pc),
                                    decode_instruction_with_reg(pc, op, primary)
                                );
                            }
                            count += 1;
                        }
                    }
                }
                println!("# 命中 PC 0x{target_pc:016x}: {count} 条");
            }
        }
        "calltree" => {
            let total = reader.len().max(1);
            let nodes = reader.build_calltree();
            let filtered: Vec<_> = nodes
                .iter()
                .filter(|n| n.depth <= max_depth && (n.depth == 0 || n.insn_count() >= min_insns))
                .collect();
            println!(
                "# 时间轴调用树: 总指令={} | 总调用节点={} | 显示={} (max_depth={}, min_insns={})",
                reader.len(),
                nodes.len(),
                filtered.len(),
                max_depth,
                min_insns
            );
            for node in filtered {
                let indent = "  ".repeat(node.depth);
                let cnt = node.insn_count();
                let pct = (cnt as f64) * 100.0 / (total as f64);
                let caller_str = if node.caller_pc != 0 {
                    format!(" <- from 0x{:016x}{}", node.caller_pc, format_rel(node.caller_pc))
                } else {
                    String::new()
                };
                println!(
                    "{indent}[#{:07}..#{:07}] {:>8} insns ({:>5.1}%) 0x{:016x}{}{caller_str}",
                    node.start_idx,
                    node.end_idx,
                    cnt,
                    pct,
                    node.target_pc,
                    format_rel(node.target_pc),
                );
            }
        }
        "crypto-scan" => {
            let groups = reader.scan_crypto();
            println!(
                "# 密码学特征扫描: 总指令={} | 命中算法窗口={} 个",
                reader.len(),
                groups.len()
            );
            if groups.is_empty() {
                println!("  (未检出已知标准密码学常量)");
            } else {
                for g in groups {
                    let consts: Vec<String> = g
                        .distinct_constants
                        .iter()
                        .map(|c| format!("0x{c:08x}"))
                        .collect();
                    let io_hint = if !g.input_addrs.is_empty() || !g.output_addrs.is_empty() {
                        let ins: Vec<String> = g
                            .input_addrs
                            .iter()
                            .map(|(a, l)| format!("0x{a:x}[{l}B]"))
                            .collect();
                        let outs: Vec<String> = g
                            .output_addrs
                            .iter()
                            .map(|(a, l)| format!("0x{a:x}[{l}B]"))
                            .collect();
                        format!(" | in=[{}] out=[{}]", ins.join(", "), outs.join(", "))
                    } else {
                        String::new()
                    };
                    println!(
                        "  {:<16} [#{:07}..#{:07}] pc=0x{:016x}{} hits={:<4} consts=[{}]{io_hint}",
                        g.algorithm,
                        g.start_idx,
                        g.end_idx,
                        g.first_pc,
                        format_rel(g.first_pc),
                        g.hit_count,
                        consts.join(", ")
                    );
                }
            }
        }
        "stats" => {
            use std::collections::HashMap;
            let mut pc_counts: HashMap<u64, u64> = HashMap::new();
            let mut bl_targets: HashMap<u64, u64> = HashMap::new();
            let total = reader.len();
            for idx in 0..total {
                if let Some(rec) = reader.get(idx) {
                    let pc = rec.pc;
                    let op = rec.opcode;
                    *pc_counts.entry(pc).or_insert(0) += 1;
                    // ARM64 `BL imm26` 编码: top 6 bits == 0b100101 (0x9400_0000..0x97ff_ffff)
                    if (op & 0xFC00_0000) == 0x9400_0000 {
                        let imm26 = ((op & 0x03FF_FFFF) as i32) << 6 >> 6;
                        let target = pc.wrapping_add((imm26 as i64 * 4) as u64);
                        *bl_targets.entry(target).or_insert(0) += 1;
                    }
                }
            }
            println!(
                "# Trace 统计: 总指令={total} | 唯一 PC={} | 扩展事件={} | 唯一 BL 目标={}",
                pc_counts.len(),
                reader.ext_len(),
                bl_targets.len()
            );
            let mut top_bl: Vec<(u64, u64)> = bl_targets.into_iter().collect();
            top_bl.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            println!("\n=== Top {} 热点调用目标 (BL) ===", top_n.min(top_bl.len()));
            for (addr, cnt) in top_bl.into_iter().take(top_n) {
                println!("  0x{addr:016x}{}  x{cnt}", format_rel(addr));
            }
            let mut top_pcs: Vec<(u64, u64)> = pc_counts.into_iter().collect();
            top_pcs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            println!("\n=== Top {} 热点指令地址 (PC) ===", top_n.min(top_pcs.len()));
            for (addr, cnt) in top_pcs.into_iter().take(top_n) {
                println!("  0x{addr:016x}{}  x{cnt}", format_rel(addr));
            }
        }
        "export-ida" => {
            let script = reader.export_ida_python(base_addr);
            if let Some(out) = out_path {
                fs::write(&out, &script)?;
                println!("已导出 IDAPython 覆盖率脚本到 {}", out.display());
            } else {
                print!("{script}");
            }
        }
        "export-bn" => {
            let script = reader.export_binja_python(base_addr);
            if let Some(out) = out_path {
                fs::write(&out, &script)?;
                println!("已导出 Binary Ninja 覆盖率脚本到 {}", out.display());
            } else {
                print!("{script}");
            }
        }
        _ => {
            print_usage();
            bail!("不支持的子命令: {cmd}");
        }
    }

    Ok(())
}
