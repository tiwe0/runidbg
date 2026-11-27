use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::script::JsSession;
use crate::tracer::{decode_instruction_with_reg, format_ascii_hint, BinaryTracer, TraceReader};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

const MCP_INIT_JS: &str = r#"
globalThis.__mcp = {
  emus: {},
  mods: {},
  tts: {},
  nextEmuId: 1,
  nextModId: 1,
  nextTtId: 1,
};
"#;

/// Model Context Protocol (MCP) stdio JSON-RPC 2.0 服务端
///
/// 底层持有持久化 `JsSession`（开启 `capture_logs = true` 防止 `console.log` 污染 `stdout` 协议流），
/// 让 Claude / Cursor / Antigravity 等 AI Agent 直接驱动 ARM64 `.so` 仿真、Hook、内存扫描与 Trace 分析。
pub struct McpServer {
    session: JsSession,
}

impl McpServer {
    /// 创建 MCP Server 实例；可选预加载初始化脚本（如环境补丁或 `rpc.exports`）
    pub fn new(base_dir: &Path, init_script: Option<&Path>) -> Result<Self> {
        let session = JsSession::new(&[], base_dir, true)?;
        session.eval_source(MCP_INIT_JS)?;
        if let Some(script) = init_script {
            session.eval_file(script)?;
            let _ = session.take_logs();
        }
        Ok(Self { session })
    }

    /// 阻塞运行 stdio JSON-RPC 2.0 主循环（每行一个 JSON 消息）
    pub fn run_stdio(&mut self) -> Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout().lock();
        for line in stdin.lock().lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(resp) = self.handle_message(trimmed) {
                writeln!(stdout, "{resp}")?;
                stdout.flush()?;
            }
        }
        Ok(())
    }

    /// 处理单条 JSON-RPC 2.0 消息；通知类消息返回 `None`，请求返回序列化后的响应字符串
    pub fn handle_message(&mut self, line: &str) -> Option<String> {
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(
                    json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": { "code": -32700, "message": format!("Parse error: {e}") }
                    })
                    .to_string(),
                );
            }
        };

        let id = req.get("id").cloned();
        let Some(method) = req.get("method").and_then(Value::as_str) else {
            return id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32600, "message": "Invalid Request: missing method" }
                })
                .to_string()
            });
        };

        // MCP 通知（无 id）无需回包
        let id = id?;
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        let resp = match method {
            "initialize" => {
                let client_ver = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(MCP_PROTOCOL_VERSION);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": client_ver,
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "runidbg",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }
                })
            }
            "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": tool_definitions() }
            }),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                match self.dispatch_tool(name, &args) {
                    Ok(payload) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&payload).unwrap_or_default()
                            }],
                            "isError": false
                        }
                    }),
                    Err(err) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": format!("Tool `{name}` failed: {err}")
                            }],
                            "isError": true
                        }
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("Method not found: {method}") }
            }),
        };

        Some(resp.to_string())
    }

    fn eval_js_value(&self, code: &str) -> Result<Value> {
        let json_str = self.session.eval_json_string(code)?;
        Ok(serde_json::from_str(&json_str)?)
    }

    fn dispatch_tool(&mut self, name: &str, args: &Value) -> Result<Value> {
        match name {
            "emu_create" => {
                let opts_json = serde_json::to_string(args)?;
                let code = format!(
                    "(() => {{ \
                        const id = __mcp.nextEmuId++; \
                        __mcp.emus[id] = Emu.create({opts_json}); \
                        return {{ emuId: id }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_load" => {
                let emu_id = req_u64(args, "emuId")?;
                let path = req_str(args, "path")?;
                let path_json = serde_json::to_string(path)?;
                let code = format!(
                    "(() => {{ \
                        const emu = __mcp.emus[{emu_id}]; \
                        if (!emu) throw new Error('unknown emuId: {emu_id}'); \
                        const mod = emu.load({path_json}); \
                        const modId = __mcp.nextModId++; \
                        __mcp.mods[modId] = {{ emuId: {emu_id}, mod }}; \
                        return {{ modId, name: mod.name, base: mod.base, baseHex: '0x' + mod.base.toString(16), size: mod.size, exportCount: mod.exports().length }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_jni_onload" => {
                let mod_id = req_u64(args, "modId")?;
                let code = format!(
                    "(() => {{ \
                        const entry = __mcp.mods[{mod_id}]; \
                        if (!entry) throw new Error('unknown modId: {mod_id}'); \
                        const emu = __mcp.emus[entry.emuId]; \
                        const ver = emu.jniOnLoad(entry.mod); \
                        return {{ version: ver, versionHex: ver !== null ? '0x' + ver.toString(16) : null, registeredNativesCount: emu.jni.registeredNatives().length }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_exports" => {
                let mod_id = req_u64(args, "modId")?;
                let filter = args.get("filter").and_then(Value::as_str).unwrap_or("");
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(100);
                let filter_json = serde_json::to_string(filter)?;
                let code = format!(
                    "(() => {{ \
                        const entry = __mcp.mods[{mod_id}]; \
                        if (!entry) throw new Error('unknown modId: {mod_id}'); \
                        const needle = {filter_json}.toLowerCase(); \
                        const all = entry.mod.exports(); \
                        const filtered = needle ? all.filter(s => s.toLowerCase().includes(needle)) : all; \
                        return {{ total: filtered.length, exports: filtered.slice(0, {limit}) }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_call" => {
                let emu_id = req_u64(args, "emuId")?;
                let mod_id = args.get("modId").and_then(Value::as_u64);
                let target = args
                    .get("target")
                    .ok_or_else(|| anyhow!("缺少参数 target（符号名或地址）"))?;
                let target_json = serde_json::to_string(target)?;
                let call_args_json = args
                    .get("args")
                    .map(serde_json::to_string)
                    .transpose()?
                    .unwrap_or_else(|| "[]".to_string());
                let code = if let Some(mid) = mod_id {
                    format!(
                        "(() => {{ \
                            const entry = __mcp.mods[{mid}]; \
                            if (!entry) throw new Error('unknown modId: {mid}'); \
                            const ret = entry.mod.call({target_json}, ...{call_args_json}); \
                            return {{ retval: ret, retvalHex: '0x' + ret.toString(16) }}; \
                        }})()"
                    )
                } else {
                    format!(
                        "(() => {{ \
                            const emu = __mcp.emus[{emu_id}]; \
                            if (!emu) throw new Error('unknown emuId: {emu_id}'); \
                            const ret = emu.call({target_json}, ...{call_args_json}); \
                            return {{ retval: ret, retvalHex: '0x' + ret.toString(16) }}; \
                        }})()"
                    )
                };
                self.eval_js_value(&code)
            }
            "emu_mem_read" => {
                let emu_id = req_u64(args, "emuId")?;
                let addr = parse_addr_val(args.get("addr"))?;
                let format_kind = args
                    .get("format")
                    .and_then(Value::as_str)
                    .unwrap_or("hex");
                let len = args.get("len").and_then(Value::as_u64).unwrap_or(64);
                let code = match format_kind {
                    "cstring" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return {{ value: e.mem.readCString({addr}, {len}) }}; }})()"
                    ),
                    "u32" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); const v = e.mem.readU32({addr}); return {{ value: v, hex: '0x' + v.toString(16) }}; }})()"
                    ),
                    "u64" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); const v = e.mem.readU64({addr}); return {{ value: v.toString(), hex: '0x' + v.toString(16) }}; }})()"
                    ),
                    _ => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); const b = e.mem.readBytes({addr}, {len}); return {{ hex: hex(b), length: b.length }}; }})()"
                    ),
                };
                self.eval_js_value(&code)
            }
            "emu_mem_scan" => {
                let emu_id = req_u64(args, "emuId")?;
                let start = parse_addr_val(args.get("start"))?;
                let len = req_u64(args, "len")?;
                let pattern = req_str(args, "pattern")?;
                let pat_json = serde_json::to_string(pattern)?;
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(64);
                let code = format!(
                    "(() => {{ \
                        const e = __mcp.emus[{emu_id}]; \
                        if (!e) throw new Error('unknown emuId'); \
                        const hits = e.mem.scan({start}, {len}, {pat_json}); \
                        return {{ total: hits.length, hits: hits.slice(0, {limit}).map(a => ({{ addr: a, hex: '0x' + a.toString(16) }})) }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_regs" => {
                let emu_id = req_u64(args, "emuId")?;
                let code = format!(
                    "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return e.regs.dump(); }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_eval_js" => {
                let code = req_str(args, "code")?;
                let _ = self.session.take_logs();
                let result = self.eval_js_value(code)?;
                let logs = self.session.take_logs();
                Ok(json!({ "result": result, "logs": logs }))
            }
            "trace_inspect" => {
                let idx_path_str = req_str(args, "idxPath")?;
                let idx_path = Path::new(idx_path_str);
                let ext_path = resolve_ext_path(idx_path, args.get("extPath").and_then(Value::as_str));
                let action = args.get("action").and_then(Value::as_str).unwrap_or("dump");
                let mut base_addr = args
                    .get("base")
                    .map(|v| parse_addr_val(Some(v)))
                    .transpose()?
                    .unwrap_or(0);
                let skip = args.get("skip").and_then(Value::as_u64).unwrap_or(0) as usize;
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
                let reader = TraceReader::open(idx_path, ext_path.as_deref())?;
                if base_addr == 0 {
                    base_addr = reader.archive_base_addr().unwrap_or(0);
                }

                let fmt_rel = |pc: u64| -> String {
                    if base_addr != 0 && pc >= base_addr {
                        format!(" [+0x{:x}]", pc - base_addr)
                    } else {
                        String::new()
                    }
                };

                let mut lines = Vec::new();
                match action {
                    "search_val" => {
                        let target = parse_addr_val(args.get("value"))?;
                        for (idx, rec, reg_id) in
                            reader.search_value_attributed(target).into_iter().skip(skip).take(limit)
                        {
                            let pc = rec.pc;
                            let op = rec.opcode;
                            lines.push(format!(
                                "#{idx:06}{} {}",
                                fmt_rel(pc),
                                decode_instruction_with_reg(pc, op, Some((reg_id, target)))
                            ));
                        }
                    }
                    "search_addr" => {
                        let target = parse_addr_val(args.get("addr"))?;
                        for ext in reader.search_mem_addr(target).into_iter().skip(skip).take(limit) {
                            let seq = ext.seq_low32;
                            let pc = ext.pc;
                            lines.push(format!(
                                "seq={seq} pc=0x{pc:016x}{} {}",
                                fmt_rel(pc),
                                BinaryTracer::format_ext_record(&ext).trim()
                            ));
                        }
                    }
                    "search_ascii" => {
                        let ascii = req_str(args, "ascii")?;
                        let cap = skip.saturating_add(limit);
                        for hit in reader
                            .search_mem_bytes_bounded(ascii.as_bytes(), None, None, cap)
                            .into_iter()
                            .skip(skip)
                            .take(limit)
                        {
                            lines.push(format!(
                                "seq={} pc=0x{:016x}{} [MEM W] addr=0x{:016x} len={} (\"{ascii}\")",
                                hit.seq_low32,
                                hit.pc,
                                fmt_rel(hit.pc),
                                hit.addr,
                                hit.matched_len
                            ));
                        }
                    }
                    "search_bytes" => {
                        let hex_str = req_str(args, "bytes")?;
                        let pat = decode_hex_bytes(hex_str)?;
                        let cap = skip.saturating_add(limit);
                        for hit in reader
                            .search_mem_bytes_bounded(&pat, None, None, cap)
                            .into_iter()
                            .skip(skip)
                            .take(limit)
                        {
                            lines.push(format!(
                                "seq={} pc=0x{:016x}{} [MEM W] addr=0x{:016x} len={}",
                                hit.seq_low32,
                                hit.pc,
                                fmt_rel(hit.pc),
                                hit.addr,
                                hit.matched_len
                            ));
                        }
                    }
                    "dump" => {
                        let end = reader.len().min(skip.saturating_add(limit));
                        for idx in skip..end {
                            if let Some(rec) = reader.get(idx) {
                                let pc = rec.pc;
                                let op = rec.opcode;
                                let deltas = reader.reg_deltas_for(idx);
                                let primary = deltas.first().copied();
                                lines.push(format!(
                                    "#{idx:06}{} {}",
                                    fmt_rel(pc),
                                    decode_instruction_with_reg(pc, op, primary)
                                ));
                                for &(reg_id, reg_val) in deltas.iter().skip(1) {
                                    let name = if reg_id == 31 {
                                        "SP".to_string()
                                    } else {
                                        format!("X{reg_id}")
                                    };
                                    let hint = format_ascii_hint(reg_val, 8).unwrap_or_default();
                                    lines.push(format!("    [REG] {name} <- 0x{reg_val:016x}{hint}"));
                                }
                                if reader.has_ext() {
                                    for line in reader.mem_and_hle_lines_for(idx) {
                                        lines.push(line);
                                    }
                                }
                            }
                        }
                    }
                    other => {
                        return Err(anyhow!(
                            "未知的 trace_inspect action `{other}`（支持 dump / search_val / search_addr / search_ascii / search_bytes）"
                        ));
                    }
                }
                Ok(json!({
                    "totalRecords": reader.len(),
                    "totalExtRecords": reader.ext_len(),
                    "missingExtWarning": reader.missing_ext_warning(),
                    "returned": lines.len(),
                    "lines": lines,
                }))
            }
            "trace_calltree" => {
                let idx_path_str = req_str(args, "idxPath")?;
                let mut base_addr = args
                    .get("base")
                    .map(|v| parse_addr_val(Some(v)))
                    .transpose()?
                    .unwrap_or(0);
                let max_depth = args.get("maxDepth").and_then(Value::as_u64).unwrap_or(4) as usize;
                let min_insns = args.get("minInsns").and_then(Value::as_u64).unwrap_or(1000) as usize;
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize;
                let reader = TraceReader::open(Path::new(idx_path_str), None)?;
                if base_addr == 0 {
                    base_addr = reader.archive_base_addr().unwrap_or(0);
                }
                let total = reader.len().max(1);
                let all_nodes = reader.build_calltree();
                let nodes: Vec<Value> = all_nodes
                    .iter()
                    .filter(|n| n.depth <= max_depth && (n.depth == 0 || n.insn_count() >= min_insns))
                    .take(limit)
                    .map(|n| {
                        let cnt = n.insn_count();
                        let pct = ((cnt as f64) * 1000.0 / (total as f64)).round() / 10.0;
                        let target_off = (base_addr != 0 && n.target_pc >= base_addr)
                            .then(|| format!("+0x{:x}", n.target_pc - base_addr));
                        let caller_off = (base_addr != 0 && n.caller_pc >= base_addr)
                            .then(|| format!("+0x{:x}", n.caller_pc - base_addr));
                        json!({
                            "depth": n.depth,
                            "startIdx": n.start_idx,
                            "endIdx": n.end_idx,
                            "insnCount": cnt,
                            "percent": pct,
                            "targetPc": n.target_pc,
                            "targetHex": format!("0x{:016x}", n.target_pc),
                            "targetOffset": target_off,
                            "callerPc": n.caller_pc,
                            "callerHex": format!("0x{:016x}", n.caller_pc),
                            "callerOffset": caller_off,
                        })
                    })
                    .collect();
                Ok(json!({
                    "totalRecords": reader.len(),
                    "totalNodes": all_nodes.len(),
                    "returned": nodes.len(),
                    "nodes": nodes,
                }))
            }
            "trace_crypto_scan" => {
                let idx_path_str = req_str(args, "idxPath")?;
                let idx_path = Path::new(idx_path_str);
                let ext_path = resolve_ext_path(idx_path, args.get("extPath").and_then(Value::as_str));
                let mut base_addr = args
                    .get("base")
                    .map(|v| parse_addr_val(Some(v)))
                    .transpose()?
                    .unwrap_or(0);
                let reader = TraceReader::open(idx_path, ext_path.as_deref())?;
                if base_addr == 0 {
                    base_addr = reader.archive_base_addr().unwrap_or(0);
                }
                let groups: Vec<Value> = reader
                    .scan_crypto()
                    .into_iter()
                    .map(|g| {
                        let first_off = (base_addr != 0 && g.first_pc >= base_addr)
                            .then(|| format!("+0x{:x}", g.first_pc - base_addr));
                        let consts: Vec<String> = g
                            .distinct_constants
                            .iter()
                            .map(|c| format!("0x{c:08x}"))
                            .collect();
                        json!({
                            "algorithm": g.algorithm,
                            "startIdx": g.start_idx,
                            "endIdx": g.end_idx,
                            "firstPc": g.first_pc,
                            "firstPcHex": format!("0x{:016x}", g.first_pc),
                            "firstPcOffset": first_off,
                            "hitCount": g.hit_count,
                            "distinctConstants": consts,
                            "inputAddrs": g.input_addrs.iter().map(|(a, l)| json!({
                                "addrHex": format!("0x{a:016x}"),
                                "len": l,
                            })).collect::<Vec<_>>(),
                            "outputAddrs": g.output_addrs.iter().map(|(a, l)| json!({
                                "addrHex": format!("0x{a:016x}"),
                                "len": l,
                            })).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                Ok(json!({
                    "totalRecords": reader.len(),
                    "totalExtRecords": reader.ext_len(),
                    "missingExtWarning": reader.missing_ext_warning(),
                    "hitGroupCount": groups.len(),
                    "groups": groups,
                }))
            }
            "emu_disasm" => {
                let emu_id = req_u64(args, "emuId")?;
                let addr = parse_addr_val(args.get("addr"))?;
                let count = args.get("count").and_then(Value::as_u64).unwrap_or(16).clamp(1, 256);
                let byte_len = count * 4;
                let code = format!(
                    "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return hex(e.mem.readBytes({addr}, {byte_len})); }})()"
                );
                let hex_val = self.eval_js_value(&code)?;
                let hex_str = hex_val
                    .as_str()
                    .ok_or_else(|| anyhow!("读取内存失败：未返回 hex 字符串"))?;
                let raw = decode_hex_bytes(hex_str)?;
                let mut insns = Vec::with_capacity(count as usize);
                for (i, chunk) in raw.as_chunks::<4>().0.iter().enumerate() {
                    let pc = addr + (i as u64) * 4;
                    let word = u32::from_le_bytes(*chunk);
                    let asm = match bad64::decode(word, pc) {
                        Ok(inst) => format!("{inst}"),
                        Err(_) => format!(".word 0x{word:08x}"),
                    };
                    insns.push(json!({
                        "addr": pc,
                        "addrHex": format!("0x{pc:016x}"),
                        "word": format!("0x{word:08x}"),
                        "asm": asm,
                    }));
                }
                Ok(json!({
                    "start": format!("0x{addr:016x}"),
                    "count": insns.len(),
                    "instructions": insns,
                }))
            }
            "emu_trace_call" => {
                let emu_id = req_u64(args, "emuId")?;
                let mod_id = args.get("modId").and_then(Value::as_u64);
                let target = args
                    .get("target")
                    .ok_or_else(|| anyhow!("缺少参数 `target`"))?;
                let target_json = serde_json::to_string(target)?;
                let call_args_json = args
                    .get("args")
                    .map(serde_json::to_string)
                    .transpose()?
                    .unwrap_or_else(|| "[]".to_string());
                let level = args
                    .get("level")
                    .and_then(Value::as_str)
                    .unwrap_or("reg_delta");
                let level_json = serde_json::to_string(level)?;
                let capacity = args.get("capacity").and_then(Value::as_u64).unwrap_or(65536);

                let invoke_expr = if let Some(mid) = mod_id {
                    format!(
                        "const entry = __mcp.mods[{mid}]; if (!entry) throw new Error('unknown modId'); const ret = entry.mod.call({target_json}, ...{call_args_json});"
                    )
                } else {
                    format!("const ret = e.call({target_json}, ...{call_args_json});")
                };
                let code = format!(
                    "(() => {{ \
                        const e = __mcp.emus[{emu_id}]; \
                        if (!e) throw new Error('unknown emuId'); \
                        e.trace.start({{ level: {level_json}, capacity: {capacity} }}); \
                        let stats; \
                        try {{ \
                            {invoke_expr} \
                            stats = e.trace.stop(); \
                            return {{ retval: ret, retvalHex: '0x' + ret.toString(16), trace: stats }}; \
                        }} catch (err) {{ \
                            try {{ e.trace.stop(); }} catch (_) {{}} \
                            throw err; \
                        }} \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_hook_capture" => {
                let emu_id = req_u64(args, "emuId")?;
                let hook_addr = parse_addr_val(args.get("hookAddr"))?;
                let mod_id = args.get("modId").and_then(Value::as_u64);
                let call_target = args
                    .get("callTarget")
                    .ok_or_else(|| anyhow!("缺少参数 `callTarget`"))?;
                let target_json = serde_json::to_string(call_target)?;
                let call_args_json = args
                    .get("args")
                    .map(serde_json::to_string)
                    .transpose()?
                    .unwrap_or_else(|| "[]".to_string());
                let arg_count = args.get("argCount").and_then(Value::as_u64).unwrap_or(4).min(8);

                let invoke_expr = if let Some(mid) = mod_id {
                    format!(
                        "const entry = __mcp.mods[{mid}]; if (!entry) throw new Error('unknown modId'); const ret = entry.mod.call({target_json}, ...{call_args_json});"
                    )
                } else {
                    format!("const ret = e.call({target_json}, ...{call_args_json});")
                };
                let code = format!(
                    "(() => {{ \
                        const e = __mcp.emus[{emu_id}]; \
                        if (!e) throw new Error('unknown emuId'); \
                        const captures = []; \
                        const h = e.hook.attach({hook_addr}, {{ \
                            onEnter(ctx) {{ \
                                this._cap = {{ args: ctx.args({arg_count}).map(v => '0x' + v.toString(16)), retval: null }}; \
                                captures.push(this._cap); \
                            }}, \
                            onLeave(ctx) {{ \
                                if (this._cap) this._cap.retval = '0x' + ctx.retval.toString(16); \
                            }} \
                        }}); \
                        try {{ \
                            {invoke_expr} \
                            return {{ retval: ret, retvalHex: '0x' + ret.toString(16), hits: captures.length, captures }}; \
                        }} finally {{ \
                            h.detach(); \
                        }} \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_diag_missing" => {
                let emu_id = req_u64(args, "emuId")?;
                let action = args
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or("report");
                let code = match action {
                    "enable" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); e.diag.enable(); return {{ enabled: true }}; }})()"
                    ),
                    "disable" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); e.diag.disable(); return {{ enabled: false }}; }})()"
                    ),
                    "clear" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); e.diag.clear(); return {{ cleared: true }}; }})()"
                    ),
                    _ => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return {{ report: e.diag.report(), patchJs: e.diag.generatePatchJs() }}; }})()"
                    ),
                };
                self.eval_js_value(&code)
            }
            "emu_last_crash" => {
                let emu_id = req_u64(args, "emuId")?;
                let code = format!(
                    "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return e.lastCrash(); }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_load_dex" => {
                let emu_id = req_u64(args, "emuId")?;
                let path_json = if let Some(arr) = args.get("paths").and_then(Value::as_array) {
                    serde_json::to_string(arr)?
                } else {
                    serde_json::to_string(req_str(args, "path")?)?
                };
                let code = format!(
                    "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return e.loadDex({path_json}); }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_dex_class_info" => {
                let emu_id = req_u64(args, "emuId")?;
                if let Some(cls) = args.get("className").and_then(Value::as_str) {
                    let cls_json = serde_json::to_string(cls)?;
                    let code = format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return e.dex.classInfo({cls_json}); }})()"
                    );
                    self.eval_js_value(&code)
                } else {
                    let prefix_json = args
                        .get("prefix")
                        .and_then(Value::as_str)
                        .map(serde_json::to_string)
                        .transpose()?
                        .unwrap_or_else(|| "undefined".to_string());
                    let code = format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return e.dex.classes({prefix_json}); }})()"
                    );
                    self.eval_js_value(&code)
                }
            }
            "emu_jni_set_field" => {
                let emu_id = req_u64(args, "emuId")?;
                let field_name = serde_json::to_string(req_str(args, "fieldName")?)?;
                let val_json = serde_json::to_string(args.get("value").unwrap_or(&Value::Null))?;
                let sig_json = args
                    .get("sig")
                    .and_then(Value::as_str)
                    .map(serde_json::to_string)
                    .transpose()?
                    .unwrap_or_else(|| "undefined".to_string());
                if let Some(obj_ref) = args.get("objRef").and_then(Value::as_u64) {
                    let code = format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); e.jni.setField({obj_ref}, {field_name}, {val_json}, {sig_json}); return {{ ok: true, value: e.jni.getField({obj_ref}, {field_name}) }}; }})()"
                    );
                    self.eval_js_value(&code)
                } else {
                    let cls_json = serde_json::to_string(req_str(args, "className")?)?;
                    let code = format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); e.jni.setStaticField({cls_json}, {field_name}, {val_json}, {sig_json}); return {{ ok: true, value: e.jni.getStaticField({cls_json}, {field_name}) }}; }})()"
                    );
                    self.eval_js_value(&code)
                }
            }
            "emu_jni_call_native" => {
                let emu_id = req_u64(args, "emuId")?;
                let cls_json = serde_json::to_string(req_str(args, "className")?)?;
                let method_json = serde_json::to_string(req_str(args, "methodName")?)?;
                let call_args_json = args
                    .get("args")
                    .map(serde_json::to_string)
                    .transpose()?
                    .unwrap_or_else(|| "[]".to_string());
                let this_opt = args
                    .get("thisObj")
                    .and_then(Value::as_u64)
                    .map(|r| format!("{{ this: {r} }}"))
                    .unwrap_or_else(|| "{}".to_string());
                let code = format!(
                    "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); const ret = e.jni.callNative({cls_json}, {method_json}, {call_args_json}, {this_opt}); return {{ ret }}; }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_save_tape" => {
                let emu_id = req_u64(args, "emuId")?;
                let path_json = serde_json::to_string(req_str(args, "path")?)?;
                let label_json = args
                    .get("label")
                    .and_then(Value::as_str)
                    .map(serde_json::to_string)
                    .transpose()?
                    .unwrap_or_else(|| "undefined".to_string());
                let append = args.get("append").and_then(Value::as_bool).unwrap_or(false);
                let code = if append {
                    format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return e.checkpointTape({path_json}, {label_json}); }})()"
                    )
                } else {
                    format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return e.saveTape({path_json}, {label_json}); }})()"
                    )
                };
                self.eval_js_value(&code)
            }
            "emu_load_tape" => {
                let path_json = serde_json::to_string(req_str(args, "path")?)?;
                let opts_json = serde_json::to_string(args)?;
                let code = format!(
                    "(() => {{ \
                        const id = __mcp.nextEmuId++; \
                        const e = Emu.loadTape({path_json}, {opts_json}); \
                        __mcp.emus[id] = e; \
                        const mods = e.modules().map((m) => {{ \
                            const mid = __mcp.nextModId++; \
                            __mcp.mods[mid] = {{ emuId: id, mod: m }}; \
                            return {{ modId: mid, name: m.name, base: m.base, baseHex: '0x' + m.base.toString(16), size: m.size, exportCount: m.exports().length }}; \
                        }}); \
                        return {{ emuId: id, backend: e.backend, checkpoint: e.tapeCheckpoint, modules: mods }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_seek_tape" => {
                let emu_id = req_u64(args, "emuId")?;
                let path_json = serde_json::to_string(req_str(args, "path")?)?;
                let cp_json = args
                    .get("checkpoint")
                    .map(serde_json::to_string)
                    .transpose()?
                    .unwrap_or_else(|| "undefined".to_string());
                let code = format!(
                    "(() => {{ \
                        const e = __mcp.emus[{emu_id}]; \
                        if (!e) throw new Error('unknown emuId'); \
                        const info = e.seekTape({path_json}, {cp_json}); \
                        const fresh = e.modules(); \
                        const existingByKey = new Map(); \
                        for (const [midStr, entry] of Object.entries(__mcp.mods)) {{ \
                            if (entry && entry.emuId === {emu_id}) {{ \
                                const key = entry.mod.name + '@' + entry.mod.base; \
                                const hit = fresh.find((m) => (m.name + '@' + m.base) === key); \
                                if (hit) {{ \
                                    entry.mod = hit; \
                                    existingByKey.set(key, Number(midStr)); \
                                }} else {{ \
                                    delete __mcp.mods[midStr]; \
                                }} \
                            }} \
                        }} \
                        const mods = fresh.map((m) => {{ \
                            const key = m.name + '@' + m.base; \
                            let mid = existingByKey.get(key); \
                            if (mid === undefined) {{ \
                                mid = __mcp.nextModId++; \
                                __mcp.mods[mid] = {{ emuId: {emu_id}, mod: m }}; \
                            }} \
                            return {{ modId: mid, name: m.name, base: m.base, baseHex: '0x' + m.base.toString(16), size: m.size, exportCount: m.exports().length }}; \
                        }}); \
                        return Object.assign({{}}, info, {{ loadedModules: mods }}); \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "tape_info" => {
                let path_json = serde_json::to_string(req_str(args, "path")?)?;
                let code = format!("Emu.inspectTape({path_json})");
                self.eval_js_value(&code)
            }
            "tt_record_start" => {
                let emu_id = req_u64(args, "emuId")?;
                let opts_json = serde_json::to_string(args)?;
                let code = format!(
                    "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); e.record.start({opts_json}); return {{ ok: true, emuId: {emu_id} }}; }})()"
                );
                self.eval_js_value(&code)
            }
            "tt_record_stop" => {
                let emu_id = req_u64(args, "emuId")?;
                let path_json = serde_json::to_string(req_str(args, "path")?)?;
                let bm_code = if let Some(bm) = args.get("bookmark").and_then(Value::as_str) {
                    let bm_json = serde_json::to_string(bm)?;
                    format!("e.record.bookmark({bm_json}); ")
                } else {
                    String::new()
                };
                let code = format!(
                    "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); {bm_code}return e.record.stop({path_json}); }})()"
                );
                self.eval_js_value(&code)
            }
            "tt_open" => {
                let path_json = serde_json::to_string(req_str(args, "path")?)?;
                let code = format!(
                    "(() => {{ \
                        const id = __mcp.nextTtId++; \
                        const tt = Emu.openTimeTravel({path_json}); \
                        __mcp.tts[id] = tt; \
                        return {{ ttId: id, totalInsns: tt.totalInsns, keyframes: tt.keyframes, bookmarks: tt.bookmarks, modules: tt.modules }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "tt_seek" => {
                let tt_id = req_u64(args, "ttId")?;
                let has_bm = args.get("bookmark").is_some_and(|v| !v.is_null());
                let has_delta = args.get("delta").is_some_and(|v| !v.is_null());
                let has_insn = args.get("insn").is_some_and(|v| !v.is_null());
                let selector_count = usize::from(has_bm) + usize::from(has_delta) + usize::from(has_insn);
                if selector_count == 0 {
                    return Err(anyhow!("tt_seek 需要提供 insn、bookmark 或 delta 参数之一"));
                }
                if selector_count > 1 {
                    return Err(anyhow!(
                        "tt_seek 的 insn、bookmark、delta 参数互斥，每次调用只能提供其中一个"
                    ));
                }
                let action = if has_bm {
                    let bm = args
                        .get("bookmark")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("tt_seek 参数 bookmark 必须为字符串"))?;
                    let bm_json = serde_json::to_string(bm)?;
                    format!("tt.seekBookmark({bm_json})")
                } else if has_delta {
                    let delta = args
                        .get("delta")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| anyhow!("tt_seek 参数 delta 必须为整数"))?;
                    if delta < 0 {
                        format!("tt.stepBack({})", delta.unsigned_abs())
                    } else {
                        format!("tt.stepForward({delta})")
                    }
                } else {
                    let insn = args
                        .get("insn")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| anyhow!("tt_seek 参数 insn 必须为非负整数"))?;
                    format!("tt.seekInsn({insn})")
                };
                let code = format!(
                    "(() => {{ \
                        const tt = __mcp.tts[{tt_id}]; \
                        if (!tt) throw new Error('unknown ttId'); \
                        const stop = {action}; \
                        return {{ stop, regs: tt.regs() }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "tt_reverse_watch" => {
                let tt_id = req_u64(args, "ttId")?;
                let addr = parse_addr_val(args.get("addr"))?;
                let len = match args.get("len") {
                    None | Some(Value::Null) => 1u64,
                    Some(v) => {
                        let l = v
                            .as_u64()
                            .ok_or_else(|| anyhow!("tt_reverse_watch 参数 len 必须为正整数"))?;
                        if l == 0 {
                            return Err(anyhow!("tt_reverse_watch 参数 len 必须 >= 1"));
                        }
                        l
                    }
                };
                let kind = match args.get("kind") {
                    None | Some(Value::Null) => "write".to_string(),
                    Some(v) => v
                        .as_str()
                        .ok_or_else(|| anyhow!("tt_reverse_watch 参数 kind 必须为字符串"))?
                        .to_ascii_lowercase(),
                };
                let method = match kind.as_str() {
                    "write" | "w" => "findPrevWrite",
                    "read" | "r" => "findPrevRead",
                    "access" | "rw" | "a" => "findPrevAccess",
                    other => {
                        return Err(anyhow!(
                            "无效的 tt_reverse_watch kind `{other}`（支持 write / read / access）"
                        ))
                    }
                };
                let preview_len = len.min(256);
                let truncated = len > 256;
                let code = format!(
                    "(() => {{ \
                        const tt = __mcp.tts[{tt_id}]; \
                        if (!tt) throw new Error('unknown ttId'); \
                        const hit = tt.{method}({addr}n, {len}); \
                        if (!hit) return {{ hit: null, currentInsn: tt.currentInsn() }}; \
                        let memHexBeforeInsn = null; \
                        try {{ \
                            memHexBeforeInsn = Array.from(tt.mem.readBytes({addr}n, {preview_len})).map((b) => b.toString(16).padStart(2, '0')).join(''); \
                        }} catch (_) {{}} \
                        return {{ hit, regs: tt.regs(), memHexBeforeInsn, memHexTruncated: {truncated} }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "tt_mem_read" => {
                let tt_id = req_u64(args, "ttId")?;
                let addr = parse_addr_val(args.get("addr"))?;
                let len = args
                    .get("len")
                    .and_then(Value::as_u64)
                    .unwrap_or(64)
                    .clamp(1, 65536);
                let code = format!(
                    "(() => {{ \
                        const tt = __mcp.tts[{tt_id}]; \
                        if (!tt) throw new Error('unknown ttId'); \
                        const bytes = Array.from(tt.mem.readBytes({addr}n, {len})); \
                        const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join(''); \
                        const ascii = bytes.map((b) => (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.').join(''); \
                        return {{ addrHex: '0x' + ({addr}n).toString(16), len: bytes.length, hex, ascii, currentInsn: tt.currentInsn() }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "tt_close" => {
                let tt_id = req_u64(args, "ttId")?;
                let code = format!(
                    "(() => {{ \
                        const tt = __mcp.tts[{tt_id}]; \
                        if (!tt) return {{ closed: false, ttId: {tt_id} }}; \
                        const closed = tt.close(); \
                        delete __mcp.tts[{tt_id}]; \
                        return {{ closed, ttId: {tt_id} }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "trace_taint" => {
                let idx_path = PathBuf::from(req_str(args, "idxPath")?);
                let ext_path = resolve_ext_path(
                    &idx_path,
                    opt_str_strict(args, "extPath")?,
                );
                let mode = opt_str_strict(args, "mode")?
                    .unwrap_or("backward")
                    .to_ascii_lowercase();
                let reg_opt = args.get("reg").filter(|v| !v.is_null());
                let addr_opt = args.get("addr").filter(|v| !v.is_null());
                if reg_opt.is_some() && addr_opt.is_some() {
                    return Err(anyhow!("trace_taint 的 reg 与 addr 参数互斥，请只提供其中一个"));
                }
                let seed = if let Some(rv) = reg_opt {
                    let reg_name = rv
                        .as_str()
                        .ok_or_else(|| anyhow!("trace_taint 参数 reg 必须为字符串"))?;
                    let slot = crate::tracer::parse_reg_slot(reg_name)
                        .ok_or_else(|| anyhow!("无效的寄存器名: {reg_name}"))?;
                    crate::tracer::TaintSeed::Reg { reg_id: slot }
                } else if let Some(av) = addr_opt {
                    let addr = parse_addr_val(Some(av))?;
                    let len = opt_u64_range(args, "len", 1, 4096)?.unwrap_or(8) as usize;
                    crate::tracer::TaintSeed::Mem { addr, len }
                } else {
                    return Err(anyhow!("trace_taint 需要提供 addr 或 reg 参数"));
                };
                let anchor_idx = match opt_u64_strict(args, "atIdx")? {
                    Some(v) => Some(v as usize),
                    None => opt_u64_strict(args, "startIdx")?.map(|v| v as usize),
                };
                let min_idx = match opt_u64_strict(args, "fromIdx")? {
                    Some(v) => Some(v as usize),
                    None => opt_u64_strict(args, "minIdx")?.map(|v| v as usize),
                };
                let mut stop_at_pcs = Vec::new();
                if let Some(v_pcs) = args.get("stopAtPcs").filter(|v| !v.is_null()) {
                    let arr = v_pcs
                        .as_array()
                        .ok_or_else(|| anyhow!("trace_taint 参数 stopAtPcs 必须为地址数组"))?;
                    for v in arr {
                        stop_at_pcs.push(parse_addr_val(Some(v))?);
                    }
                }
                let mut stop_mem_ranges = Vec::new();
                if let Some(v_sm) = args.get("stopMem").filter(|v| !v.is_null()) {
                    let arr = v_sm
                        .as_array()
                        .ok_or_else(|| anyhow!("trace_taint 参数 stopMem 必须为对象数组"))?;
                    for item in arr {
                        if !item.is_object() {
                            return Err(anyhow!("trace_taint stopMem 元素必须为 {{ addr, len? }} 对象"));
                        }
                        let a = parse_addr_val(item.get("addr"))?;
                        let l = match item.get("len").filter(|v| !v.is_null()) {
                            Some(lv) => {
                                let n = lv
                                    .as_u64()
                                    .ok_or_else(|| anyhow!("stopMem[].len 必须为正整数"))?;
                                if n == 0 || n > 65536 {
                                    return Err(anyhow!("stopMem[].len 必须在 1..=65536 之间，收到 {n}"));
                                }
                                n as usize
                            }
                            None => 8,
                        };
                        stop_mem_ranges.push((a, l));
                    }
                }
                let max_insns = opt_u64_strict(args, "maxInsns")?.unwrap_or(0) as usize;
                let max_steps = opt_u64_range(args, "maxSteps", 1, 2000)?.unwrap_or(200) as usize;
                let track_mem_index = opt_bool_strict(args, "trackMemIndex")?.unwrap_or(true);
                let track_sp = opt_bool_strict(args, "trackSp")?.unwrap_or(false);
                let opts = crate::tracer::TaintOptions {
                    anchor_idx,
                    min_idx,
                    stop_at_pcs,
                    stop_mem_ranges,
                    max_insns,
                    max_steps,
                    track_mem_index,
                    track_sp,
                };
                let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;
                let report = match mode.as_str() {
                    "forward" | "fwd" => reader.taint_forward(&seed, &opts),
                    "backward" | "bwd" | "slice" => reader.taint_backward(&seed, &opts),
                    other => {
                        return Err(anyhow!(
                            "无效的 trace_taint mode `{other}`（支持 forward / backward）"
                        ));
                    }
                };
                Ok(json!({
                    "mode": report.mode,
                    "seed": report.seed_desc,
                    "anchorIdx": report.anchor_idx,
                    "stopIdx": report.stop_idx,
                    "scannedInsns": report.scanned_insns,
                    "totalMatchingSteps": report.total_matching_steps,
                    "missingExtWarning": reader.missing_ext_warning(),
                    "originAnnotations": report.origin_annotations,
                    "steps": report.steps.iter().map(|s| json!({
                        "idx": s.idx,
                        "seq": s.seq,
                        "pc": s.pc,
                        "pcHex": format!("0x{:016x}", s.pc),
                        "asm": s.asm,
                        "kind": s.kind,
                        "sources": s.sources,
                        "dests": s.dests,
                        "tagMaskHex": format!("0x{:x}", s.tag_mask),
                        "valueHex": s.value.map(|v| format!("0x{v:x}")),
                    })).collect::<Vec<_>>(),
                    "taintedRegs": report.tainted_regs.iter().map(|(n, m)| json!({
                        "name": n,
                        "tagMaskHex": format!("0x{m:x}"),
                    })).collect::<Vec<_>>(),
                    "taintedMemRanges": report.tainted_mem_ranges.iter().map(|&(a, l, m)| json!({
                        "addr": a,
                        "addrHex": format!("0x{a:016x}"),
                        "len": l,
                        "tagMaskHex": format!("0x{m:x}"),
                    })).collect::<Vec<_>>(),
                }))
            }
            "trace_query" => {
                let idx_path = PathBuf::from(req_str(args, "idxPath")?);
                let ext_path = resolve_ext_path(
                    &idx_path,
                    opt_str_strict(args, "extPath")?,
                );
                let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;
                let limit = opt_u64_range(args, "limit", 1, 1000)?.unwrap_or(100) as usize;
                let min_seq = opt_u64_strict(args, "minSeq")?.map(|v| v.min(u32::MAX as u64) as u32);
                let max_seq = opt_u64_strict(args, "maxSeq")?.map(|v| v.min(u32::MAX as u64) as u32);
                let at_seq = max_seq.or(opt_u64_strict(args, "at")?.map(|v| v.min(u32::MAX as u64) as u32));
                let val_opt = args.get("value").filter(|v| !v.is_null());
                let addr_opt = args.get("addr").filter(|v| !v.is_null());
                if val_opt.is_some() && addr_opt.is_some() {
                    return Err(anyhow!("trace_query 的 value 与 addr 参数互斥，请只提供其中一个"));
                }
                let hits = if let Some(val_v) = val_opt {
                    let target = parse_addr_val(Some(val_v))?;
                    let width_raw = match opt_u64_range(args, "width", 1, 8)? {
                        Some(w) => Some(w),
                        None => opt_u64_range(args, "align", 1, 8)?,
                    };
                    let width = width_raw
                        .map(|w| w as u8)
                        .unwrap_or_else(|| if target > u32::MAX as u64 { 8 } else { 4 });
                    reader.query_writes_by_value(target, width, min_seq, at_seq, limit)
                } else if let Some(addr_v) = addr_opt {
                    let addr = parse_addr_val(Some(addr_v))?;
                    let len = opt_u64_range(args, "len", 1, u64::MAX)?.unwrap_or(1);
                    let writes_only = opt_bool_strict(args, "writesOnly")?;
                    let kind_str = opt_str_strict(args, "kind")?.map(str::to_ascii_lowercase);
                    let (include_reads, include_writes) = match (kind_str.as_deref(), writes_only) {
                        (Some("r" | "read" | "reads"), Some(true)) => {
                            return Err(anyhow!("trace_query 参数 kind=\"r\" 与 writesOnly=true 互斥"));
                        }
                        (Some("r" | "read" | "reads"), _) => (true, false),
                        (Some("w" | "write" | "writes"), _) => (false, true),
                        (Some("rw" | "all"), Some(true)) => {
                            return Err(anyhow!("trace_query 参数 kind=\"rw\" 与 writesOnly=true 互斥"));
                        }
                        (Some("rw" | "all"), _) => (true, true),
                        (None, Some(true)) => (false, true),
                        (None, _) => (true, true),
                        (Some(other), _) => {
                            return Err(anyhow!("无效的 trace_query kind `{other}`（支持 r/w/rw）"));
                        }
                    };
                    let include_hle = opt_bool_strict(args, "includeHle")?.unwrap_or(true);
                    reader.query_addr_history_filtered(
                        addr,
                        len,
                        min_seq,
                        at_seq,
                        include_reads,
                        include_writes,
                        include_hle,
                        limit,
                    )
                } else {
                    return Err(anyhow!("trace_query 需要提供 value 或 addr 参数"));
                };
                Ok(json!({
                    "count": hits.len(),
                    "missingExtWarning": reader.missing_ext_warning(),
                    "hits": hits.iter().map(|h| json!({
                        "seq": h.seq_low32,
                        "pc": h.pc,
                        "pcHex": format!("0x{:016x}", h.pc),
                        "addr": h.addr,
                        "addrHex": format!("0x{:016x}", h.addr),
                        "size": h.size,
                        "kind": h.kind,
                        "value": h.value,
                        "valueHex": format!("0x{:x}", h.value),
                        "srcHex": (h.src != 0).then(|| format!("0x{:016x}", h.src)),
                    })).collect::<Vec<_>>(),
                }))
            }
            "trace_diff" => {
                let idx_a = PathBuf::from(req_str(args, "idxPathA")?);
                let idx_b = PathBuf::from(req_str(args, "idxPathB")?);
                let ext_a = resolve_ext_path(
                    &idx_a,
                    opt_str_strict(args, "extPathA")?,
                );
                let ext_b = resolve_ext_path(
                    &idx_b,
                    opt_str_strict(args, "extPathB")?,
                );
                let limit = opt_u64_range(args, "limit", 1, 500)?.unwrap_or(64) as usize;
                let ra = TraceReader::open(&idx_a, ext_a.as_deref())?;
                let rb = TraceReader::open(&idx_b, ext_b.as_deref())?;
                if let Some(taddr_v) = args.get("targetAddr").filter(|v| !v.is_null()) {
                    let taddr = parse_addr_val(Some(taddr_v))?;
                    let len = opt_u64_range(args, "len", 1, 4096)?.unwrap_or(16) as usize;
                    let max_insns = opt_u64_strict(args, "maxInsns")?.unwrap_or(0) as usize;
                    let dt = TraceReader::diff_taint_bytes(&ra, &rb, taddr, len, max_insns);
                    let fmt_opt_bytes = |bs: &[Option<u8>]| -> String {
                        let mut s = String::with_capacity(bs.len() * 2);
                        for b in bs {
                            match b {
                                Some(v) => s.push_str(&format!("{v:02x}")),
                                None => s.push_str("??"),
                            }
                        }
                        s
                    };
                    return Ok(json!({
                        "targetAddrHex": format!("0x{:016x}", dt.target_addr),
                        "len": dt.len,
                        "identicalBytes": dt.identical_bytes,
                        "differingBytes": dt.differing_bytes,
                        "missingExtWarningA": ra.missing_ext_warning(),
                        "missingExtWarningB": rb.missing_ext_warning(),
                        "summaryText": dt.format_summary(),
                        "spans": dt.spans.iter().map(|sp| json!({
                            "offset": sp.offset,
                            "addrHex": format!("0x{:016x}", sp.addr),
                            "len": sp.len,
                            "bytesAHex": fmt_opt_bytes(&sp.bytes_a),
                            "bytesBHex": fmt_opt_bytes(&sp.bytes_b),
                            "originsARegs": sp.origins_a_regs,
                            "originsAMem": sp.origins_a_mem.iter().map(|(a, l)| format!("0x{a:x}[{l}]")).collect::<Vec<_>>(),
                            "originsAHle": sp.origins_a_hle,
                            "originsBRegs": sp.origins_b_regs,
                            "originsBMem": sp.origins_b_mem.iter().map(|(a, l)| format!("0x{a:x}[{l}]")).collect::<Vec<_>>(),
                            "originsBHle": sp.origins_b_hle,
                        })).collect::<Vec<_>>(),
                    }));
                }
                let summary = TraceReader::diff_traces(&ra, &rb, limit);
                Ok(json!({
                    "totalA": summary.total_a,
                    "totalB": summary.total_b,
                    "missingExtWarningA": ra.missing_ext_warning(),
                    "missingExtWarningB": rb.missing_ext_warning(),
                    "commonPrefixInsns": summary.common_prefix_insns,
                    "firstControlDivergenceIdx": summary.first_control_divergence_idx,
                    "firstDataDivergenceIdx": summary.first_data_divergence_idx,
                    "diffs": summary.diffs.iter().map(|d| json!({
                        "idx": d.idx,
                        "kind": d.kind,
                        "pcA": d.pc_a,
                        "pcAHex": format!("0x{:016x}", d.pc_a),
                        "pcB": d.pc_b,
                        "pcBHex": format!("0x{:016x}", d.pc_b),
                        "detail": d.detail,
                    })).collect::<Vec<_>>(),
                }))
            }
            "trace_vm_analyze" => {
                let idx_path = PathBuf::from(req_str(args, "idxPath")?);
                let ext_path = resolve_ext_path(
                    &idx_path,
                    opt_str_strict(args, "extPath")?,
                );
                let mut opts = crate::tracer::VmAnalysisOptions::default();
                if let Some(v) = args.get("dispatcherPc").filter(|v| !v.is_null()) {
                    opts.dispatcher_pc = Some(parse_addr_val(Some(v))?);
                }
                if let Some(s) = opt_str_strict(args, "bcReg")? {
                    let slot = crate::tracer::parse_gpr_slot(s)
                        .ok_or_else(|| anyhow!("无效的 bcReg 寄存器名: {s}"))?;
                    opts.bc_reg = Some(slot);
                }
                if let Some(b) = opt_bool_strict(args, "bcDeref")? {
                    opts.bc_deref = b;
                }
                if let Some(v) = args.get("bcPtrAddr").filter(|v| !v.is_null()) {
                    opts.bc_ptr_addr = Some(parse_addr_val(Some(v))?);
                }
                if opts.bc_reg.is_some() && opts.bc_ptr_addr.is_some() {
                    return Err(anyhow!("trace_vm_analyze 的 bcReg 与 bcPtrAddr 互斥，请只提供其中一个"));
                }
                if opts.bc_deref && opts.bc_reg.is_none() {
                    return Err(anyhow!("trace_vm_analyze 的 bcDeref: true 必须配合 bcReg 使用"));
                }
                let reg_count = opt_u64_range(args, "regCount", 1, 256)?.unwrap_or(32) as usize;
                let reg_size = match opt_u64_strict(args, "regSize")? {
                    None => 8u8,
                    Some(4) => 4u8,
                    Some(8) => 8u8,
                    Some(other) => return Err(anyhow!("参数 `regSize` 仅支持 4 或 8，收到 {other}")),
                };
                if let Some(s) = opt_str_strict(args, "baseReg")? {
                    let base_reg = crate::tracer::parse_gpr_slot(s)
                        .ok_or_else(|| anyhow!("无效的 baseReg 寄存器名: {s}"))?;
                    opts.regfile = Some(crate::tracer::VmRegfileConfig {
                        base_reg,
                        count: reg_count,
                        size: reg_size,
                    });
                }
                if let Some(spec) = opt_str_strict(args, "layout")? {
                    let lay = crate::tracer::VmWordLayout::parse_spec(spec)
                        .map_err(|e| anyhow!("无效的 layout: {e}"))?;
                    opts.layout = Some(lay);
                }
                if let Some(mh) = opt_u64_range(args, "minHandlers", 1, 10000)? {
                    opts.min_handlers = mh as usize;
                }
                if let Some(md) = opt_u64_range(args, "minDispatches", 1, 1_000_000)? {
                    opts.min_dispatches = md as usize;
                }
                if let Some(mi) = opt_u64_strict(args, "minIdx")? {
                    opts.min_idx = Some(mi as usize);
                }
                if let Some(mx) = opt_u64_strict(args, "maxIdx")? {
                    opts.max_idx = Some(mx as usize);
                }
                if let (Some(lo), Some(hi)) = (opts.min_idx, opts.max_idx) {
                    if lo > hi {
                        return Err(anyhow!("trace_vm_analyze 参数 minIdx ({lo}) 不能大于 maxIdx ({hi})"));
                    }
                }
                if let Some(mi) = opt_u64_strict(args, "maxInsns")? {
                    opts.max_insns = mi as usize;
                }
                opts.max_steps = opt_u64_range(args, "maxSteps", 1, 2000)?.unwrap_or(200) as usize;
                let mut base_addr = args
                    .get("baseAddr")
                    .filter(|v| !v.is_null())
                    .map(|v| parse_addr_val(Some(v)))
                    .transpose()?
                    .unwrap_or(0);

                let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;
                if base_addr == 0 {
                    base_addr = reader.archive_base_addr().unwrap_or(0);
                }
                let report = reader.analyze_vm(&opts);
                Ok(json!({
                    "scannedInsns": report.scanned_insns,
                    "totalVmSteps": report.total_vm_steps,
                    "missingExtWarning": reader.missing_ext_warning(),
                    "selectedDispatcherHex": report.selected_dispatcher.map(|p| format!("0x{p:016x}")),
                    "detectedBcReg": report.detected_bc_reg,
                    "detectedBcMemAddrHex": report.detected_bc_mem_addr.map(|a| format!("0x{a:016x}")),
                    "dispatchers": report.dispatchers.iter().map(|d| json!({
                        "pcHex": format!("0x{:016x}", d.pc),
                        "kind": d.kind,
                        "targetReg": crate::tracer::format_reg_slot(d.target_reg),
                        "totalDispatches": d.total_dispatches,
                        "uniqueHandlers": d.unique_handlers,
                        "score": d.score,
                        "jumpTableBaseHex": d.jump_table_base.map(|b| format!("0x{b:016x}")),
                        "jumpTableEntrySize": d.jump_table_entry_size,
                        "detectedBcReg": d.detected_bc_reg.map(crate::tracer::format_reg_slot),
                        "detectedBcMemAddrHex": d.detected_bc_mem_addr.map(|a| format!("0x{a:016x}")),
                    })).collect::<Vec<_>>(),
                    "handlers": report.handlers.iter().map(|h| json!({
                        "handlerPcHex": format!("0x{:016x}", h.handler_pc),
                        "opcodes": h.opcodes,
                        "hitCount": h.hit_count,
                        "minArm64Insns": h.min_arm64_insns,
                        "maxArm64Insns": h.max_arm64_insns,
                        "avgArm64Insns": h.avg_arm64_insns(),
                        "bcStepHist": h.bc_step_hist,
                        "firstStep": h.first_step,
                        "firstTraceIdx": h.first_trace_idx,
                    })).collect::<Vec<_>>(),
                    "steps": report.steps.iter().map(|s| json!({
                        "step": s.step,
                        "traceIdx": s.trace_idx,
                        "seq": s.seq,
                        "handlerPcHex": format!("0x{:016x}", s.handler_pc),
                        "arm64Insns": s.arm64_insns,
                        "bcPcHex": s.bc_pc.map(|p| format!("0x{p:016x}")),
                        "bcStep": s.bc_step,
                        "rawWordHex": s.raw_word.map(|w| format!("0x{w:x}")),
                        "decodedText": s.decoded.as_ref().map(|d| d.format_compact()),
                        "op": s.decoded.as_ref().map(|d| d.op).or(s.table_opcode),
                        "fields": s.decoded.as_ref().map(|d| &d.fields),
                        "regfileBaseHex": s.regfile_base.map(|b| format!("0x{b:016x}")),
                        "baseRelocated": s.base_relocated,
                        "regDiffs": s.reg_diffs.iter().map(|d| d.format_compact()).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                    "summaryText": report.format_summary(base_addr),
                }))
            }
            "trace_decompile" => {
                let idx_path = PathBuf::from(req_str(args, "idxPath")?);
                let ext_path = resolve_ext_path(&idx_path, opt_str_strict(args, "extPath")?);
                let reg_opt = args.get("reg").filter(|v| !v.is_null());
                let addr_opt = args.get("addr").filter(|v| !v.is_null());
                if reg_opt.is_some() && addr_opt.is_some() {
                    return Err(anyhow!(
                        "trace_decompile 的 reg 与 addr 参数互斥，请只提供其中一个"
                    ));
                }
                let seed = if let Some(rv) = reg_opt {
                    let reg_name = rv
                        .as_str()
                        .ok_or_else(|| anyhow!("trace_decompile 参数 reg 必须为字符串"))?;
                    let slot = crate::tracer::parse_reg_slot(reg_name)
                        .ok_or_else(|| anyhow!("无效的寄存器名: {reg_name}"))?;
                    crate::tracer::TaintSeed::Reg { reg_id: slot }
                } else if let Some(av) = addr_opt {
                    let addr = parse_addr_val(Some(av))?;
                    let len = opt_u64_range(args, "len", 1, 64)?.unwrap_or(4) as usize;
                    crate::tracer::TaintSeed::Mem { addr, len }
                } else {
                    return Err(anyhow!("trace_decompile 需要提供 addr 或 reg 参数"));
                };
                let mut opts = crate::tracer::DecompileOptions::default();
                if let Some(v) = opt_u64_strict(args, "atIdx")? {
                    opts.anchor_idx = Some(v as usize);
                }
                if let Some(v) = opt_u64_strict(args, "fromIdx")?
                    .or(opt_u64_strict(args, "minIdx")?)
                {
                    opts.from_idx = Some(v as usize);
                }
                if let Some(v_pcs) = args.get("stopAtPcs").filter(|v| !v.is_null()) {
                    let arr = v_pcs
                        .as_array()
                        .ok_or_else(|| anyhow!("trace_decompile 参数 stopAtPcs 必须为地址数组"))?;
                    for v in arr {
                        opts.stop_at_pcs.push(parse_addr_val(Some(v))?);
                    }
                }
                if let Some(v_sm) = args.get("stopMem").filter(|v| !v.is_null()) {
                    let arr = v_sm
                        .as_array()
                        .ok_or_else(|| anyhow!("trace_decompile 参数 stopMem 必须为对象数组"))?;
                    for item in arr {
                        if !item.is_object() {
                            return Err(anyhow!(
                                "trace_decompile stopMem 元素必须为 {{ addr, len? }} 对象"
                            ));
                        }
                        let a = parse_addr_val(item.get("addr"))?;
                        let l = match item.get("len").filter(|v| !v.is_null()) {
                            Some(lv) => {
                                let n = lv
                                    .as_u64()
                                    .ok_or_else(|| anyhow!("stopMem[].len 必须为正整数"))?;
                                if n == 0 || n > 65536 {
                                    return Err(anyhow!(
                                        "stopMem[].len 必须在 1..=65536 之间，收到 {n}"
                                    ));
                                }
                                n as usize
                            }
                            None => 8,
                        };
                        opts.stop_mem_ranges.push((a, l));
                    }
                }
                if let Some(v) = opt_bool_strict(args, "foldRodata")? {
                    opts.fold_rodata = v;
                }
                if let Some(v) = opt_u64_strict(args, "maxInsns")? {
                    opts.max_insns = v as usize;
                }
                if let Some(v) = opt_u64_range(args, "maxSteps", 1, 16384)? {
                    opts.max_steps = v as usize;
                }
                if let Some(v) = opt_bool_strict(args, "trackMemIndex")? {
                    opts.track_mem_index = v;
                }
                if let Some(v) = opt_bool_strict(args, "trackSp")? {
                    opts.track_sp = v;
                }
                if let Some(v) = opt_bool_strict(args, "simplify")? {
                    opts.simplify = v;
                }
                if let Some(v) = opt_bool_strict(args, "emitSmt2")? {
                    opts.emit_smt2 = v;
                }
                if let Some(fn_name) = opt_str_strict(args, "functionName")? {
                    if !fn_name.trim().is_empty() {
                        opts.function_name = fn_name.trim().to_string();
                    }
                }
                let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;
                let report = reader.decompile_slice(&seed, &opts);
                Ok(json!({
                    "seed": report.seed_desc,
                    "anchorIdx": report.anchor_idx,
                    "stopIdx": report.stop_idx,
                    "scannedInsns": report.scanned_insns,
                    "sliceInsns": report.slice_insns,
                    "rawNodes": report.raw_nodes,
                    "simplifiedNodes": report.simplified_nodes,
                    "missingExtWarning": reader.missing_ext_warning(),
                    "originAnnotations": report.origin_annotations,
                    "outputLen": report.output_len,
                    "expectedOutputHex": report.expected_output.map(|v| format!("0x{v:x}")),
                    "evaluatedOutputHex": report.evaluated_output.map(|v| format!("0x{v:x}")),
                    "expectedOutputBytesHex": report.expected_output_bytes_hex,
                    "evaluatedOutputBytesHex": report.evaluated_output_bytes_hex,
                    "verified": report.verified,
                    "cCode": report.c_code,
                    "smt2": report.smt2,
                    "inputs": report.inputs.iter().map(|i| json!({
                        "name": i.name,
                        "kind": i.kind,
                        "addrHex": i.addr.map(|a| format!("0x{a:016x}")),
                        "widthBytes": i.width_bytes,
                        "sampleHex": i.sample_hex,
                    })).collect::<Vec<_>>(),
                    "tables": report.tables.iter().map(|t| json!({
                        "name": t.name,
                        "baseAddrHex": format!("0x{:016x}", t.base_addr),
                        "elemBytes": t.elem_bytes,
                        "observedCount": t.observed_entries.len(),
                    })).collect::<Vec<_>>(),
                }))
            }
            "trace_mem" => {
                let idx_path = PathBuf::from(req_str(args, "idxPath")?);
                let ext_path = resolve_ext_path(&idx_path, opt_str_strict(args, "extPath")?);
                let addr = parse_addr_val(args.get("addr"))?;
                let len = opt_u64_range(args, "len", 1, 65536)?.unwrap_or(64) as usize;
                let at_seq = opt_u64_strict(args, "atSeq")?
                    .or(opt_u64_strict(args, "at")?)
                    .map(|v| v.min(u32::MAX as u64) as u32)
                    .unwrap_or(u32::MAX);
                let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;
                let bytes = reader.reconstruct_mem_at(addr, len, at_seq);
                let mut hex = String::with_capacity(len * 2);
                let mut known = 0usize;
                for mb in &bytes {
                    match mb {
                        Some(b) => {
                            known += 1;
                            hex.push_str(&format!("{b:02x}"));
                        }
                        None => hex.push_str("??"),
                    }
                }
                Ok(json!({
                    "addrHex": format!("0x{addr:016x}"),
                    "len": len,
                    "atSeq": at_seq,
                    "knownBytes": known,
                    "hex": hex,
                    "missingExtWarning": reader.missing_ext_warning(),
                }))
            }
            "emu_asm" => {
                const MAX_ASM_SOURCE_LEN: usize = 64 * 1024;
                let source = req_str(args, "source")?;
                if source.len() > MAX_ASM_SOURCE_LEN {
                    return Err(anyhow!(
                        "emu_asm 源码长度 {} 超出上限 ({MAX_ASM_SOURCE_LEN} 字节)",
                        source.len()
                    ));
                }
                let explicit_addr = args
                    .get("addr")
                    .filter(|v| !v.is_null())
                    .or_else(|| args.get("pc").filter(|v| !v.is_null()))
                    .map(|v| parse_addr_val(Some(v)))
                    .transpose()?;
                let patch = args.get("patch").and_then(Value::as_bool).unwrap_or(false);
                if patch && explicit_addr.is_none() {
                    return Err(anyhow!("emu_asm 在 patch=true 时必须显式提供 addr 或 pc"));
                }
                let pc = explicit_addr.unwrap_or(0);
                let bytes = crate::good64::assemble(source, pc)?;
                let hex = bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut disasm = Vec::new();
                let (chunks, rem) = bytes.as_chunks::<4>();
                for (idx, chunk) in chunks.iter().enumerate() {
                    let cur_pc = pc.wrapping_add((idx * 4) as u64);
                    let word = u32::from_le_bytes(*chunk);
                    let text = bad64::decode(word, cur_pc)
                        .map(|ins| ins.to_string())
                        .unwrap_or_else(|_| format!(".word 0x{word:08x}"));
                    disasm.push(format!("0x{cur_pc:016x}: {word:08x}  {text}"));
                }
                if !rem.is_empty() {
                    let rem_pc = pc.wrapping_add((chunks.len() * 4) as u64);
                    let rem_hex = rem
                        .iter()
                        .map(|b| format!("0x{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    disasm.push(format!("0x{rem_pc:016x}: .byte {rem_hex}"));
                }
                let mut patched = false;
                if patch {
                    let emu_id = req_u64(args, "emuId")?;
                    let src_json = serde_json::to_string(source)?;
                    let code = format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return e.mem.patchAsm({pc}n, {src_json}); }})()"
                    );
                    let _ = self.eval_js_value(&code)?;
                    patched = true;
                }
                Ok(json!({
                    "pcHex": format!("0x{pc:016x}"),
                    "byteLen": bytes.len(),
                    "hex": hex,
                    "disasm": disasm,
                    "patched": patched,
                }))
            }
            _ => Err(anyhow!("未知的 MCP 工具: {name}")),
        }
    }
}

fn resolve_ext_path(idx_path: &Path, explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(p));
    }
    crate::tracer::resolve_sibling_ext_path(idx_path)
}

fn opt_u64_strict(args: &Value, key: &str) -> Result<Option<u64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| anyhow!("参数 `{key}` 必须为非负整数")),
    }
}

fn opt_u64_range(args: &Value, key: &str, min: u64, max: u64) -> Result<Option<u64>> {
    let Some(v) = opt_u64_strict(args, key)? else {
        return Ok(None);
    };
    if v < min || v > max {
        return Err(anyhow!("参数 `{key}` 超出合法范围 [{min}, {max}]，实际收到 {v}"));
    }
    Ok(Some(v))
}

fn opt_bool_strict(args: &Value, key: &str) -> Result<Option<bool>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| anyhow!("参数 `{key}` 必须为布尔值")),
    }
}

fn opt_str_strict<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .map(Some)
            .ok_or_else(|| anyhow!("参数 `{key}` 必须为字符串")),
    }
}

fn decode_hex_bytes(hex: &str) -> Result<Vec<u8>> {
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        return Err(anyhow!("无效的十六进制长度"));
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|e| anyhow!("解析十六进制字节失败: {e}"))?;
        out.push(byte);
    }
    Ok(out)
}

fn req_u64(args: &Value, key: &str) -> Result<u64> {
    args.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("缺少整数参数 `{key}`"))
}

fn req_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("缺少字符串参数 `{key}`"))
}

fn parse_addr_val(v: Option<&Value>) -> Result<u64> {
    let v = v.ok_or_else(|| anyhow!("缺少地址/数值参数"))?;
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16)
                .map_err(|_| anyhow!("无效的十六进制数: {s}"));
        }
        return s.parse::<u64>().map_err(|_| anyhow!("无效的整数: {s}"));
    }
    Err(anyhow!("地址/数值参数必须是整数或十六进制字符串"))
}

fn tool_definitions() -> Value {
    let mut tools = json!([
        {
            "name": "emu_create",
            "description": "Create a new Android ARM64 emulator instance in the persistent runidbg session.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "backend": { "type": "string", "description": "CPU backend: unicorn (default; required for trace/GDB/native hooks), dynarmic, kvm (Linux), hypervisor/hyper (macOS). Non-Unicorn backends are emulation-only." },
                    "packageName": { "type": "string", "description": "Android package name (default: com.example.app)" },
                    "searchPaths": { "type": "array", "items": { "type": "string" }, "description": "Sysroot / .so search directories" },
                    "hleAccel": { "type": "boolean", "description": "Enable Rust HLE libc acceleration (default: true)" },
                    "freezeLayout": { "type": "boolean", "description": "Isolate host emu.mem.alloc() into [host-scratch] so guest malloc heap addresses stay deterministic across runs" }
                }
            }
        },
        {
            "name": "emu_load",
            "description": "Load an Android ARM64 ELF .so library and execute its .init_array constructors.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "path"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "path": { "type": "string", "description": "Host path to the ARM64 .so file" }
                }
            }
        },
        {
            "name": "emu_jni_onload",
            "description": "Invoke JNI_OnLoad on a loaded module and return JNI version and RegisterNatives count.",
            "inputSchema": {
                "type": "object",
                "required": ["modId"],
                "properties": {
                    "modId": { "type": "integer" }
                }
            }
        },
        {
            "name": "emu_exports",
            "description": "List exported symbols of a loaded module with optional case-insensitive substring filter.",
            "inputSchema": {
                "type": "object",
                "required": ["modId"],
                "properties": {
                    "modId": { "type": "integer" },
                    "filter": { "type": "string" },
                    "limit": { "type": "integer", "default": 100 }
                }
            }
        },
        {
            "name": "emu_call",
            "description": "Call an exported symbol name or raw ARM64 address with up to 8 integer arguments.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "target"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "modId": { "type": "integer", "description": "Required when target is a symbol name" },
                    "target": { "description": "Exported symbol name (string) or raw address (integer)" },
                    "args": { "type": "array", "items": { "type": "integer" } }
                }
            }
        },
        {
            "name": "emu_mem_read",
            "description": "Read guest memory as hex bytes, C string, u32, or u64.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "addr"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "addr": { "description": "Guest address (integer or '0x...' hex string)" },
                    "format": { "type": "string", "enum": ["hex", "cstring", "u32", "u64"], "default": "hex" },
                    "len": { "type": "integer", "default": 64 }
                }
            }
        },
        {
            "name": "emu_mem_scan",
            "description": "Scan guest memory for a hex byte pattern with '??' wildcards.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "start", "len", "pattern"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "start": { "description": "Start address (integer or '0x...' string)" },
                    "len": { "type": "integer" },
                    "pattern": { "type": "string", "description": "Hex pattern e.g. 'fd 7b ?? a9'" },
                    "limit": { "type": "integer", "default": 64 }
                }
            }
        },
        {
            "name": "emu_regs",
            "description": "Dump current ARM64 registers (x0..x30, sp, pc, nzcv) of an emulator instance.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId"],
                "properties": {
                    "emuId": { "type": "integer" }
                }
            }
        },
        {
            "name": "emu_eval_js",
            "description": "Evaluate arbitrary runidbg QuickJS code in the persistent session (access __mcp.emus[id], __mcp.mods[id], __mcp.tts[id], Emu, hooks, patches, trace, etc.).",
            "inputSchema": {
                "type": "object",
                "required": ["code"],
                "properties": {
                    "code": { "type": "string" }
                }
            }
        },
        {
            "name": "trace_inspect",
            "description": "Inspect offline binary trace files (trace.idx / trace.ext) via dump (with post-exec reg attribution & ASCII hints), search_val, search_addr, search_ascii, or search_bytes.",
            "inputSchema": {
                "type": "object",
                "required": ["idxPath"],
                "properties": {
                    "idxPath": { "type": "string" },
                    "extPath": { "type": "string", "description": "Optional trace.ext path (auto-detected if sibling .ext exists)" },
                    "base": { "description": "Optional module base address for [+0x...] offset annotations (int or '0x...')" },
                    "action": { "type": "string", "enum": ["dump", "search_val", "search_addr", "search_ascii", "search_bytes"], "default": "dump" },
                    "value": { "description": "Target register value for search_val (int or '0x...')" },
                    "addr": { "description": "Target memory address for search_addr (int or '0x...')" },
                    "ascii": { "type": "string", "description": "Target ASCII substring in MemWrite stream for search_ascii" },
                    "bytes": { "type": "string", "description": "Target hex byte sequence in MemWrite stream for search_bytes" },
                    "skip": { "type": "integer", "default": 0 },
                    "limit": { "type": "integer", "default": 50 }
                }
            }
        },
        {
            "name": "trace_calltree",
            "description": "Build a chronological BL/BLR/RET call tree from an offline trace.idx file (automatically folds external .plt calls) to identify major execution phases and instruction budgets.",
            "inputSchema": {
                "type": "object",
                "required": ["idxPath"],
                "properties": {
                    "idxPath": { "type": "string" },
                    "base": { "description": "Optional module base address for [+0x...] offset annotations (int or '0x...')" },
                    "maxDepth": { "type": "integer", "default": 4 },
                    "minInsns": { "type": "integer", "default": 1000 },
                    "limit": { "type": "integer", "default": 200 }
                }
            }
        },
        {
            "name": "trace_crypto_scan",
            "description": "Scan an offline binary trace (trace.idx + optional trace.ext) for standard cryptographic constants (MD5, SHA-1, SHA-256, SM3, SM4, AES, ChaCha20/Salsa20, CRC32, TEA/XTEA, MurmurHash3) and return grouped invocation windows.",
            "inputSchema": {
                "type": "object",
                "required": ["idxPath"],
                "properties": {
                    "idxPath": { "type": "string" },
                    "extPath": { "type": "string", "description": "Optional trace.ext path (auto-detected if sibling .ext exists)" },
                    "base": { "description": "Optional module base address for [+0x...] offset annotations (int or '0x...')" }
                }
            }
        },
        {
            "name": "emu_disasm",
            "description": "Disassemble ARM64 instructions starting at a guest address using bad64.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "addr"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "addr": { "description": "Start guest address (int or '0x...' hex string)" },
                    "count": { "type": "integer", "default": 16, "description": "Number of ARM64 instructions (1..256)" }
                }
            }
        },
        {
            "name": "emu_trace_call",
            "description": "Attach a temporary tracer, invoke a symbol/address, detach tracer, and return return value + trace stats (Unicorn backend only).",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "target"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "modId": { "type": "integer" },
                    "target": { "description": "Exported symbol name or raw address" },
                    "args": { "type": "array", "items": { "type": "integer" } },
                    "level": { "type": "string", "enum": ["fast", "reg_delta", "full"], "default": "reg_delta" },
                    "capacity": { "type": "integer", "default": 65536 }
                }
            }
        },
        {
            "name": "emu_hook_capture",
            "description": "Temporarily attach onEnter/onLeave hook at hookAddr, call callTarget, and return all captured arguments and return values (Unicorn backend only).",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "hookAddr", "callTarget"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "hookAddr": { "description": "Guest address to hook (int or '0x...')" },
                    "modId": { "type": "integer" },
                    "callTarget": { "description": "Exported symbol name or address to invoke" },
                    "args": { "type": "array", "items": { "type": "integer" } },
                    "argCount": { "type": "integer", "default": 4 }
                }
            }
        },
        {
            "name": "emu_diag_missing",
            "description": "Control or query missing-environment diagnostics (missing files, properties, syscalls, JNI) and generate JS patch template.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "action": { "type": "string", "enum": ["enable", "disable", "clear", "report"], "default": "report" }
                }
            }
        },
        {
            "name": "emu_last_crash",
            "description": "Retrieve the last Guest ARM64 crash report (PC, module+offset, bad64 disassembly, registers, FP backtrace, recent breadcrumbs).",
            "inputSchema": {
                "type": "object",
                "required": ["emuId"],
                "properties": {
                    "emuId": { "type": "integer" }
                }
            }
        },
        {
            "name": "emu_load_dex",
            "description": "Load a single .dex file, a directory of classes*.dex files, or an array of .dex paths into the lightweight DEX metadata index.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "path": { "type": "string", "description": "Path to a .dex file or directory containing *.dex" },
                    "paths": { "type": "array", "items": { "type": "string" } }
                }
            }
        },
        {
            "name": "emu_dex_class_info",
            "description": "Query DEX class metadata (superClass, interfaces, fields, methods, staticValues) by className, or list indexed classes by prefix.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "className": { "type": "string" },
                    "prefix": { "type": "string" }
                }
            }
        },
        {
            "name": "emu_jni_set_field",
            "description": "Set a JNI static field (className + fieldName) or instance field (objRef + fieldName), supporting primitives, strings, [C/[B/[I/[J arrays via sig, or jobject handles.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "fieldName", "value"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "className": { "type": "string" },
                    "objRef": { "type": "integer" },
                    "fieldName": { "type": "string" },
                    "value": {},
                    "sig": { "type": "string", "description": "Optional JNI signature e.g. [C, I, J, Ljava/lang/String;" }
                }
            }
        },
        {
            "name": "emu_jni_call_native",
            "description": "Call a RegisterNatives JNI method with optional instance `thisObj` (jobject handle) for instance methods.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "className", "methodName"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "className": { "type": "string" },
                    "methodName": { "type": "string" },
                    "args": { "type": "array", "items": { "type": "integer" } },
                    "thisObj": { "type": "integer", "description": "Optional jobject handle passed as X1 (this) for instance methods" }
                }
            }
        },
        {
            "name": "emu_save_tape",
            "description": "Save full emulator runtime state to a persistent compressed .rtape file (returns TapeSummary {version, fileSize, checkpoints, timeline}), or append an incremental 4KB dirty-page checkpoint when append=true (returns TapeCheckpointInfo).",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "path"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "path": { "type": "string", "description": "Destination .rtape file path" },
                    "label": { "type": "string", "description": "Checkpoint bookmark name (e.g. after_init, before_sign)" },
                    "append": { "type": "boolean", "description": "If true, append an incremental 4KB dirty-page delta checkpoint to an existing tape" }
                }
            }
        },
        {
            "name": "emu_load_tape",
            "description": "Load a .rtape checkpoint into a new emulator instance (supports cross-backend relay, e.g. Dynarmic/Hyper/KVM tape -> Unicorn for tracing/hooks). Returns {emuId, backend, checkpoint, modules}.",
            "inputSchema": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "Path to .rtape file" },
                    "checkpoint": {
                        "anyOf": [
                            { "type": "integer", "minimum": 0 },
                            { "type": "string" }
                        ],
                        "description": "Checkpoint index, bookmark label, or 'latest'"
                    },
                    "backend": { "type": "string", "description": "Target CPU backend (unicorn, dynarmic, kvm, hypervisor)" },
                    "searchPaths": { "type": "array", "items": { "type": "string" }, "description": "Optional additional library search paths" },
                    "device": { "type": "string", "description": "Optional device profile preset override" },
                    "realClock": { "type": "boolean", "description": "Optional real-clock override" },
                    "net": { "type": ["boolean", "object"], "description": "Optional network policy override" },
                    "freezeLayout": { "type": "boolean", "description": "Optional freezeLayout override (isolate host emu.mem.alloc() into [host-scratch])" }
                }
            }
        },
        {
            "name": "emu_seek_tape",
            "description": "Rewind or fast-forward an existing emulator instance to any checkpoint on a .rtape file, refreshing __mcp.mods and returning checkpoint info plus loadedModules.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "path"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "path": { "type": "string" },
                    "checkpoint": {
                        "anyOf": [
                            { "type": "integer", "minimum": 0 },
                            { "type": "string" }
                        ],
                        "description": "Checkpoint index, bookmark label, or 'latest'"
                    }
                }
            }
        },
        {
            "name": "tape_info",
            "description": "Inspect a .rtape file and list all checkpoints, dirty-page counts, compressed sizes, source backends, loaded modules, and Phase 2 time-travel timeline summary if present.",
            "inputSchema": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" }
                }
            }
        }
    ]);
    let extra = json!([
        {
            "name": "tt_record_start",
            "description": "Start Phase 2 deterministic Time-Travel recording on a Unicorn emulator (captures periodic delta keyframes, real-clock reads, host sysroot files, and external JNI callbacks).",
            "inputSchema": {
                "type": "object",
                "required": ["emuId"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "keyframeInterval": { "type": "integer", "minimum": 0, "description": "Auto-keyframe interval in instructions (default 100000)" },
                    "maxInsns": { "type": "integer", "minimum": 0, "description": "Optional max instructions cap (0 = unlimited)" },
                    "captureJni": { "type": "boolean", "description": "Capture external JNI callbacks for offline JS-free replay (default true)" }
                }
            }
        },
        {
            "name": "tt_record_stop",
            "description": "Stop Time-Travel recording and write the complete .rtape file (keyframes + CHUNK_EVENT_LOG) to disk.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "path"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "path": { "type": "string", "description": "Destination .rtape file path" },
                    "bookmark": { "type": "string", "description": "Optional final bookmark label before stopping" }
                }
            }
        },
        {
            "name": "tt_open",
            "description": "Open a recorded Time-Travel .rtape file for offline instruction-exact seeking, reverse stepping, and reverse memory watchpoint hunting.",
            "inputSchema": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" }
                }
            }
        },
        {
            "name": "tt_seek",
            "description": "Seek a Time-Travel session to an exact instruction index, named bookmark, or relative step delta (negative = step back, positive = step forward), returning stop info and registers.",
            "inputSchema": {
                "type": "object",
                "required": ["ttId"],
                "properties": {
                    "ttId": { "type": "integer" },
                    "insn": { "type": "integer", "minimum": 0 },
                    "bookmark": { "type": "string" },
                    "delta": { "type": "integer", "description": "Relative instruction step (e.g. -1 to reverse-stepi)" }
                }
            }
        },
        {
            "name": "tt_reverse_watch",
            "description": "Reverse-search backward from current instruction to the exact ARM64 instruction that last wrote/read [addr, addr+len), jump directly there, and return hit location + registers + pre-instruction memory hex preview (capped at 256B).",
            "inputSchema": {
                "type": "object",
                "required": ["ttId", "addr"],
                "properties": {
                    "ttId": { "type": "integer" },
                    "addr": { "description": "Guest memory address (integer or '0x...' hex string)" },
                    "len": { "type": "integer", "minimum": 1, "description": "Byte length to watch (default 1)" },
                    "kind": { "type": "string", "enum": ["write", "read", "access"], "description": "Watchpoint kind (default write)" }
                }
            }
        },
        {
            "name": "tt_mem_read",
            "description": "Read guest memory at the current instruction position of an open Time-Travel session (returns hex & ASCII dump, max 65536 bytes).",
            "inputSchema": {
                "type": "object",
                "required": ["ttId", "addr"],
                "properties": {
                    "ttId": { "type": "integer" },
                    "addr": { "description": "Guest memory address (integer or '0x...' hex string)" },
                    "len": { "type": "integer", "minimum": 1, "maximum": 65536, "description": "Bytes to read (default 64)" }
                }
            }
        },
        {
            "name": "tt_close",
            "description": "Close an open Time-Travel player session and release its Unicorn instance, keyframe cache, and micro-snapshot ring.",
            "inputSchema": {
                "type": "object",
                "required": ["ttId"],
                "properties": {
                    "ttId": { "type": "integer" }
                }
            }
        },
        {
            "name": "trace_taint",
            "description": "Offline byte-granular ARM64 taint tracking (forward) or causal backward slicing (backward) on trace.idx + trace.ext, crossing HLE memcpy/memmove/memset and immune to stack-frame / VM regfile address reuse.",
            "inputSchema": {
                "type": "object",
                "required": ["idxPath"],
                "properties": {
                    "idxPath": { "type": "string", "description": "Path to trace.idx file" },
                    "extPath": { "type": "string", "description": "Optional trace.ext path (auto-detected if sibling exists)" },
                    "mode": { "type": "string", "enum": ["forward", "backward"], "description": "Analysis direction (default backward)" },
                    "addr": { "description": "Seed/target memory address (integer or '0x...' hex string)" },
                    "len": { "type": "integer", "minimum": 1, "maximum": 4096, "description": "Memory byte length (default 8)" },
                    "reg": { "type": "string", "description": "Seed/target register name (e.g. 'x0', 'w8', 'v0', 'q1')" },
                    "atIdx": { "type": "integer", "minimum": 0, "description": "Anchor instruction index (start for forward, observation point for backward)" },
                    "startIdx": { "type": "integer", "minimum": 0, "description": "Alias of atIdx for forward mode" },
                    "fromIdx": { "type": "integer", "minimum": 0, "description": "Optional backward slice lower bound index (inclusive)" },
                    "stopAtPcs": { "type": "array", "items": {}, "description": "Optional PC list where backward slicing stops and promotes boundary state to origins" },
                    "stopMem": { "type": "array", "items": { "type": "object", "required": ["addr"], "properties": { "addr": {}, "len": { "type": "integer", "minimum": 1, "maximum": 65536 } } }, "description": "Optional memory ranges [{addr, len}] pinned as origins when read during backward slicing" },
                    "maxInsns": { "type": "integer", "minimum": 0, "description": "Optional max instructions to scan (0 = all)" },
                    "maxSteps": { "type": "integer", "minimum": 1, "maximum": 2000, "description": "Max propagation steps returned (default 200)" },
                    "trackMemIndex": { "type": "boolean", "description": "Track indexed load register dependencies such as S-Box lookups (default true)" },
                    "trackSp": { "type": "boolean", "description": "Track stack pointer SP arithmetic (default false)" }
                }
            }
        },
        {
            "name": "trace_query",
            "description": "Offline omniscient memory/value query over trace.idx + trace.ext (including HLE memcpy/memset/malloc/free events). Query either by written value+width or by address history.",
            "inputSchema": {
                "type": "object",
                "required": ["idxPath"],
                "properties": {
                    "idxPath": { "type": "string" },
                    "extPath": { "type": "string" },
                    "value": { "description": "Find all writes producing this value (integer or '0x...' hex)" },
                    "width": { "type": "integer", "minimum": 1, "maximum": 8, "description": "Value match byte width (1..8)" },
                    "align": { "type": "integer", "minimum": 1, "maximum": 8, "description": "Alias of width (1..8)" },
                    "addr": { "description": "Find read/write/HLE history touching [addr, addr+len)" },
                    "len": { "type": "integer", "minimum": 1, "description": "Byte length for addr query (default 1)" },
                    "minSeq": { "type": "integer", "minimum": 0, "description": "Optional lower seq bound" },
                    "maxSeq": { "type": "integer", "minimum": 0, "description": "Optional upper seq bound" },
                    "at": { "type": "integer", "minimum": 0, "description": "Upper seq bound (alias of maxSeq)" },
                    "writesOnly": { "type": "boolean", "description": "For addr query, return only writes & HLE mutations" },
                    "kind": { "type": "string", "enum": ["r", "w", "rw"], "description": "For addr query, filter by reads ('r'), writes ('w'), or both ('rw')" },
                    "includeHle": { "type": "boolean", "description": "For addr query, include HLE events (default true)" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "description": "Max hits returned (default 100)" }
                }
            }
        },
        {
            "name": "trace_diff",
            "description": "Differential comparison between two offline traces (a.idx vs b.idx), reporting common prefix length, first control-flow/data divergence, or (when targetAddr is set) per-byte buffer diff with automatic backward taint linkage.",
            "inputSchema": {
                "type": "object",
                "required": ["idxPathA", "idxPathB"],
                "properties": {
                    "idxPathA": { "type": "string" },
                    "idxPathB": { "type": "string" },
                    "extPathA": { "type": "string" },
                    "extPathB": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "description": "Max diff entries returned (default 64)" },
                    "targetAddr": { "description": "Optional buffer address for dual-run diff + automatic backward taint linkage" },
                    "len": { "type": "integer", "minimum": 1, "maximum": 4096, "description": "Buffer length when targetAddr is set (default 16)" },
                    "maxInsns": { "type": "integer", "minimum": 0, "description": "Optional max instructions for backward taint linkage (0 = all)" }
                }
            }
        },
        {
            "name": "trace_vm_analyze",
            "description": "Offline custom-VM & OLLVM reverse-engineering analyzer on trace.idx + trace.ext: auto-detects dispatch loops (BR/BLR), jump tables, bytecode PC registers, handler distribution (vm_opmap), per-handler consumed bytecode lengths, optional bitfield instruction-word decoding, and symbolic VM regfile diffs (auto-handling base-register relocation).",
            "inputSchema": {
                "type": "object",
                "required": ["idxPath"],
                "properties": {
                    "idxPath": { "type": "string", "description": "Path to trace.idx file" },
                    "extPath": { "type": "string", "description": "Optional trace.ext path (auto-detected if sibling exists)" },
                    "dispatcherPc": { "description": "Optional explicit dispatcher PC (integer or '0x...' hex); omitted = auto-detect" },
                    "bcReg": { "type": "string", "description": "Optional bytecode PC register (e.g. 'x23'); omitted = auto-detect" },
                    "bcDeref": { "type": "boolean", "description": "If true, treat [bcReg] memory as the bytecode PC pointer" },
                    "bcPtrAddr": { "description": "Optional fixed memory address holding the bytecode PC pointer" },
                    "baseReg": { "type": "string", "description": "Optional VM regfile base register (e.g. 'x25') to emit symbolic R[n] diffs and track base relocation" },
                    "regCount": { "type": "integer", "minimum": 1, "maximum": 256, "description": "Number of virtual registers (default 32)" },
                    "regSize": { "type": "integer", "enum": [4, 8], "description": "Virtual register byte width (4 or 8, default 8)" },
                    "layout": { "type": "string", "description": "Optional instruction-word bitfield spec '<op_lsb>:<op_width>[,<f0_lsb>[:<f0_width>],...]', e.g. '6:6,12:5,17:5,22:5,27:5'" },
                    "minHandlers": { "type": "integer", "minimum": 1, "maximum": 10000, "description": "Min unique handler targets for dispatcher detection (default 3)" },
                    "minDispatches": { "type": "integer", "minimum": 1, "maximum": 1000000, "description": "Min dispatch hits for dispatcher detection (default 4)" },
                    "minIdx": { "type": "integer", "minimum": 0, "description": "Optional lower instruction index bound (inclusive)" },
                    "maxIdx": { "type": "integer", "minimum": 0, "description": "Optional upper instruction index bound (inclusive)" },
                    "maxInsns": { "type": "integer", "minimum": 0, "description": "Max native instructions to scan (0 = all)" },
                    "maxSteps": { "type": "integer", "minimum": 1, "maximum": 2000, "description": "Max VM steps returned in report (default 200)" },
                    "baseAddr": { "description": "Optional module base address for +0x... offsets in summaryText" }
                }
            }
        },
        {
            "name": "trace_decompile",
            "description": "Dynamic taint slice -> single-path Bit-Vector SSA symbolic lifting -> algebraic/rotate/MBA deobfuscation -> self-verified compilable pseudo-C (and optional QF_BV / QF_UFBV SMT-LIB2 export). Zero path explosion, zero external solver dependency.",
            "inputSchema": {
                "type": "object",
                "required": ["idxPath"],
                "properties": {
                    "idxPath": { "type": "string", "description": "Path to trace.idx file" },
                    "extPath": { "type": "string", "description": "Optional trace.ext path (auto-detected if sibling exists)" },
                    "addr": { "description": "Target output memory address (integer or '0x...' hex string; mutually exclusive with reg)" },
                    "len": { "type": "integer", "minimum": 1, "maximum": 64, "description": "Output memory width in bytes (1..8 scalar return, 9..64 multi-output uint8_t *out buffer; default 4)" },
                    "reg": { "type": "string", "description": "Target output register (e.g. 'x0', 'w0'; mutually exclusive with addr)" },
                    "atIdx": { "type": "integer", "minimum": 0, "description": "Observation instruction index (default last instruction)" },
                    "fromIdx": { "type": "integer", "minimum": 0, "description": "Optional slice lower bound index (inclusive) to isolate a single loop round or phase" },
                    "stopAtPcs": { "type": "array", "items": {}, "description": "Optional PC list where slicing stops and promotes boundary state to symbolic inputs" },
                    "stopMem": { "type": "array", "items": { "type": "object", "required": ["addr"], "properties": { "addr": {}, "len": { "type": "integer", "minimum": 1, "maximum": 65536 } } }, "description": "Optional memory ranges [{addr, len}] pinned as symbolic inputs when read" },
                    "foldRodata": { "type": "boolean", "description": "Fold memory never written in the trace (e.g. .rodata / VM bytecode) into constants (default false)" },
                    "maxInsns": { "type": "integer", "minimum": 0, "description": "Max instructions to scan backward (0 = all)" },
                    "maxSteps": { "type": "integer", "minimum": 1, "maximum": 16384, "description": "Max taint slice steps (default 4096)" },
                    "functionName": { "type": "string", "description": "Generated C function name (default 'decompiled_slice')" },
                    "simplify": { "type": "boolean", "description": "Enable algebraic, rotate, and MBA deobfuscation passes (default true)" },
                    "emitSmt2": { "type": "boolean", "description": "Also emit standard QF_BV / QF_UFBV SMT-LIB2 for external Z3/Bitwuzla inversion (default false)" },
                    "trackMemIndex": { "type": "boolean", "description": "Track indexed table/S-Box lookups (default true)" },
                    "trackSp": { "type": "boolean", "description": "Track SP arithmetic (default false)" }
                }
            }
        },
        {
            "name": "trace_mem",
            "description": "Reconstruct a memory buffer [addr, addr+len) at a specific sequence number (or trace end) from offline trace.idx + trace.ext write & HLE history.",
            "inputSchema": {
                "type": "object",
                "required": ["idxPath", "addr"],
                "properties": {
                    "idxPath": { "type": "string", "description": "Path to trace.idx file" },
                    "extPath": { "type": "string", "description": "Optional trace.ext path (auto-detected if sibling exists)" },
                    "addr": { "description": "Start memory address (integer or '0x...' hex string)" },
                    "len": { "type": "integer", "minimum": 1, "maximum": 65536, "description": "Byte length to reconstruct (default 64, max 65536)" },
                    "atSeq": { "type": "integer", "minimum": 0, "description": "Optional upper sequence number (default end of trace)" },
                    "at": { "type": "integer", "minimum": 0, "description": "Alias of atSeq" }
                }
            }
        },
        {
            "name": "emu_asm",
            "description": "Assemble ARM64 instructions using built-in lightweight assembler `good64` (returns hex bytes & bad64 verification disassembly; set patch=true with emuId+addr to patch guest memory and flush cache).",
            "inputSchema": {
                "type": "object",
                "required": ["source"],
                "properties": {
                    "source": { "type": "string", "description": "ARM64 assembly source (supports ';' or newline separation, local labels, mov imm64 expansion, and .word/.quad directives)" },
                    "addr": { "description": "Base PC / target patch address (integer or '0x...' hex, default 0)" },
                    "pc": { "description": "Alias of addr" },
                    "patch": { "type": "boolean", "description": "If true, write assembled bytes into emuId at addr and flush instruction cache" },
                    "emuId": { "type": "integer", "description": "Target emulator ID (required when patch=true)" }
                }
            }
        }
    ]);
    if let (Some(arr), Some(more)) = (tools.as_array_mut(), extra.as_array()) {
        arr.extend(more.iter().cloned());
    }
    tools
}

/// Streamable HTTP MCP 服务端句柄（基于 `tokio` + `axum`，`POST /mcp`）
#[cfg(feature = "rpc")]
pub struct McpHttpHandle {
    local_addr: std::net::SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    worker_tx: async_channel::Sender<(String, tokio::sync::oneshot::Sender<Option<String>>)>,
    server_thread: Option<std::thread::JoinHandle<()>>,
    worker_thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "rpc")]
impl McpHttpHandle {
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    pub fn wait(mut self) {
        if let Some(h) = self.server_thread.take() {
            let _ = h.join();
        }
        self.worker_tx.close();
        if let Some(h) = self.worker_thread.take() {
            let _ = h.join();
        }
    }

    pub fn shutdown(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.server_thread.take() {
            let _ = h.join();
        }
        self.worker_tx.close();
        if let Some(h) = self.worker_thread.take() {
            let _ = h.join();
        }
    }
}

#[cfg(feature = "rpc")]
impl Drop for McpHttpHandle {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// 启动 Streamable HTTP MCP 服务端（`POST /mcp` JSON-RPC 2.0，支持多远程 Agent 并发接入）
#[cfg(feature = "rpc")]
pub fn start_mcp_http_server(
    listen_addr: &str,
    base_dir: &Path,
    init_script: Option<&Path>,
) -> Result<McpHttpHandle> {
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{header, HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::Router;
    use std::sync::Arc;

    let (worker_tx, worker_rx) =
        async_channel::bounded::<(String, tokio::sync::oneshot::Sender<Option<String>>)>(256);
    let (init_tx, init_rx) = std::sync::mpsc::sync_channel::<Result<()>>(1);
    let base_owned = base_dir.to_path_buf();
    let script_owned = init_script.map(Path::to_path_buf);

    let worker_thread = std::thread::Builder::new()
        .name("runidbg-mcp-worker".to_string())
        .spawn(move || {
            let mut server = match McpServer::new(&base_owned, script_owned.as_deref()) {
                Ok(s) => {
                    let _ = init_tx.send(Ok(()));
                    s
                }
                Err(err) => {
                    let _ = init_tx.send(Err(err));
                    return;
                }
            };
            while let Ok((line, reply)) = worker_rx.recv_blocking() {
                let resp = server.handle_message(&line);
                let _ = reply.send(resp);
            }
        })?;

    init_rx
        .recv()
        .map_err(|_| anyhow!("MCP Worker 初始化异常退出"))??;

    let listen_owned = listen_addr.to_string();
    let tx_state = Arc::new(worker_tx.clone());
    let (bound_tx, bound_rx) = std::sync::mpsc::sync_channel::<Result<std::net::SocketAddr>>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_thread = std::thread::Builder::new()
        .name("runidbg-mcp-http".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = bound_tx.send(Err(anyhow!("创建 Tokio 运行时失败: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(&listen_owned).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = bound_tx.send(Err(anyhow!("绑定 MCP HTTP 地址失败: {e}")));
                        return;
                    }
                };
                let local_addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = bound_tx.send(Err(anyhow!("获取本地地址失败: {e}")));
                        return;
                    }
                };
                let _ = bound_tx.send(Ok(local_addr));

                type McpTaskSender = async_channel::Sender<(
                    String,
                    tokio::sync::oneshot::Sender<Option<String>>,
                )>;

                async fn handle_mcp_post(
                    State(tx): State<Arc<McpTaskSender>>,
                    body: Bytes,
                ) -> Response {
                    let line = String::from_utf8_lossy(&body).into_owned();
                    let (rtx, rrx) = tokio::sync::oneshot::channel();
                    if tx.send((line, rtx)).await.is_err() {
                        return (StatusCode::SERVICE_UNAVAILABLE, "MCP worker closed")
                            .into_response();
                    }
                    match rrx.await {
                        Ok(Some(json_str)) => {
                            let mut resp = (StatusCode::OK, json_str).into_response();
                            resp.headers_mut().insert(
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/json"),
                            );
                            resp
                        }
                        Ok(None) => StatusCode::ACCEPTED.into_response(),
                        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "MCP worker dropped")
                            .into_response(),
                    }
                }

                let app = Router::new()
                    .route("/mcp", post(handle_mcp_post))
                    .with_state(tx_state);
                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
        })?;

    let local_addr = bound_rx
        .recv()
        .map_err(|_| anyhow!("MCP HTTP 线程启动失败"))??;

    Ok(McpHttpHandle {
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        worker_tx,
        server_thread: Some(server_thread),
        worker_thread: Some(worker_thread),
    })
}
