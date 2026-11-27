//! 单文件压缩 `.rtrace` Trace 归档端到端集成测试：
//! 1. `TraceArchive::pack` / `inspect` / `unpack` 完整往返（含尾部零填充裁剪、压缩率、CRC32、元信息、不压缩 level=0）
//! 2. `TraceReader::open("foo.rtrace", None)` 透明加载：无需解包直接驱动 `stats` / `reconstruct_mem_at` / `taint_backward` / `decompile_slice` (`verified=Some(true)`) / `diff_traces` / `diff_taint_bytes` / `scan_crypto`
//! 3. 安全与完整性防护：头 CRC32 篡改拒绝、数据位翻转拒绝、截断/尾部脏字节拒绝、超大解压声明 / zip-bomb 拦截、路径穿越 stem 拒绝、已有文件非 `--force` 拒绝覆盖、无 `.ext` 归档仍正确触发 `missing_ext_warning`
//! 4. CLI (`pack` / `unpack --info` / `unpack` + 直接对 `.rtrace` 运行 `stats` / `mem` / `decompile`) 与 QuickJS (`Trace.pack` / `Trace.inspectArchive` / `Trace.open` / `Trace.unpack`)

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc};
use runidbg_arm64_emu_tracer::good64;
use runidbg_arm64_emu_tracer::tracer::archive::{
    RTRACE_FLAG_DEFLATE, RTRACE_HEADER_SIZE, RTRACE_MAGIC, RTRACE_VERSION,
};
use runidbg_arm64_emu_tracer::tracer::{
    BinaryTracer, DecompileOptions, TaintOptions, TaintSeed, TraceArchive,
    TraceArchivePackOptions, TraceLevel, TraceReader,
};
use runidbg_arm64_emu_tracer::{AndroidEmulator, CpuBackend};

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "runidbg_rtrace_{tag}_{}_{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn record_sample_trace(
    tag: &str,
    level: TraceLevel,
    in_word: u32,
) -> (PathBuf, PathBuf, PathBuf, u64, u64, u32) {
    let dir = unique_dir(tag);
    let idx_path = dir.join("sample.idx");
    let ext_path = dir.join("sample.ext");

    let mut emu = AndroidEmulator::builder().build().expect("build emu");
    let code_base = 0x4000_0000u64;
    let in_buf = 0x4001_0000u64;
    let out_buf = 0x4001_0100u64;

    emu.cpu_mut()
        .mem_map(code_base, 0x20000, unicorn_engine::unicorn_const::Prot::ALL)
        .unwrap();
    let asm = r#"
        ldr w4, [x0]
        mov w5, #0x1337
        eor w6, w4, w5
        ror w6, w6, #7
        add w6, w6, #0x42
        str w6, [x1]
        ret
    "#;
    let code = good64::assemble(asm, code_base).unwrap();
    emu.cpu_mut().mem_write(code_base, &code).unwrap();
    emu.cpu_mut()
        .mem_write(in_buf, &in_word.to_le_bytes())
        .unwrap();

    let tracer = if level == TraceLevel::Full {
        BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 4096, 16384, level).unwrap()
    } else {
        BinaryTracer::new_mmap(&idx_path, 4096).unwrap()
    };
    emu.set_tracer(tracer).unwrap();
    emu.attach_tracer(code_base, code_base + 0x1000).unwrap();
    let _ = emu.call_address(code_base, &[in_buf, out_buf]).unwrap();
    emu.tracer().flush().unwrap();

    let mut out_raw = [0u8; 4];
    emu.cpu_mut().mem_read(out_buf, &mut out_raw).unwrap();
    (dir, idx_path, ext_path, in_buf, out_buf, u32::from_le_bytes(out_raw))
}

#[test]
fn test_rtrace_pack_inspect_transparent_read_and_unpack_roundtrip() {
    let (dir, idx_path, ext_path, _in_buf, out_buf, actual_out) =
        record_sample_trace("roundtrip", TraceLevel::Full, 0x1122_3344);
    let rtrace_path = dir.join("bundle.rtrace");

    // 模拟未裁剪的预分配 mmap 尾部全零填充（+32 KiB 零槽位）验证打包器自动裁剪 + Deflate 压缩
    {
        let mut f = OpenOptions::new().append(true).open(&idx_path).unwrap();
        f.write_all(&vec![0u8; 32 * 1024]).unwrap();
    }
    let raw_disk_total = fs::metadata(&idx_path).unwrap().len()
        + fs::metadata(&ext_path).unwrap().len();
    let info = TraceArchive::pack(
        &idx_path,
        Some(&ext_path),
        &rtrace_path,
        &TraceArchivePackOptions {
            base_addr: 0x4000_0000,
            note: Some("unit-test roundtrip".to_string()),
            compression_level: 6,
        },
    )
    .expect("pack .rtrace");

    assert_eq!(info.version, RTRACE_VERSION);
    assert!(info.has_ext);
    assert!(info.compressed);
    assert_eq!(info.base_addr, 0x4000_0000);
    assert!(info.idx_insns >= 7);
    assert!(info.ext_events > 0);
    assert_eq!(info.recorded_level.as_deref(), Some("full"));
    assert_eq!(info.note.as_deref(), Some("unit-test roundtrip"));
    assert!(
        info.archive_file_len < raw_disk_total / 10,
        "裁剪预分配零填充+Deflate 压缩后归档体积应大幅缩减: archive={} vs raw_disk={}",
        info.archive_file_len,
        raw_disk_total
    );

    // 1. O(1) inspect
    let inspected = TraceArchive::inspect(&rtrace_path).expect("inspect .rtrace");
    assert_eq!(inspected.idx_insns, info.idx_insns);
    assert_eq!(inspected.ext_events, info.ext_events);
    assert_eq!(inspected.idx_crc32, info.idx_crc32);
    assert_eq!(inspected.ext_crc32, info.ext_crc32);
    assert_eq!(inspected.base_addr, 0x4000_0000);
    assert!(inspected.format_summary().contains("unit-test roundtrip"));

    // 2. 删除原始 .idx/.ext 后，直接用 TraceReader::open("bundle.rtrace", None) 透明运行全部离线引擎！
    let orig_reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();
    let orig_len = orig_reader.len();
    let orig_ext_len = orig_reader.ext_len();
    drop(orig_reader);
    fs::remove_file(&idx_path).unwrap();
    fs::remove_file(&ext_path).unwrap();

    let arc_reader = TraceReader::open(&rtrace_path, None).expect("transparent open .rtrace");
    assert!(arc_reader.is_archive());
    assert_eq!(arc_reader.archive_base_addr(), Some(0x4000_0000));
    assert!(!arc_reader.missing_ext_warning());
    assert_eq!(arc_reader.len(), orig_len);
    assert_eq!(arc_reader.ext_len(), orig_ext_len);

    // 内存重建
    let mem = arc_reader.reconstruct_mem_at(out_buf, 4, u32::MAX);
    let rebuilt: Vec<u8> = mem.into_iter().map(|b| b.unwrap()).collect();
    assert_eq!(rebuilt.as_slice(), actual_out.to_le_bytes().as_slice());

    // 反向污点切片
    let taint = arc_reader.taint_backward(
        &TaintSeed::Mem { addr: out_buf, len: 4 },
        &TaintOptions::default(),
    );
    assert!(!taint.steps.is_empty());

    // 动态切片反编译（必须 verified == Some(true)！）
    let decomp = arc_reader.decompile_slice(
        &TaintSeed::Mem { addr: out_buf, len: 4 },
        &DecompileOptions {
            function_name: "from_rtrace".to_string(),
            ..Default::default()
        },
    );
    assert_eq!(decomp.verified, Some(true), "{}", decomp.format_summary());
    assert_eq!(decomp.expected_output, Some(u64::from(actual_out)));

    // 3. Unpack 还原并检验不允许静默覆写，以及 --force 允许覆写
    let unpack_dir = dir.join("unpacked");
    let unp = TraceArchive::unpack(&rtrace_path, &unpack_dir, Some("restored"), false).unwrap();
    assert!(unp.idx_path.is_file());
    assert!(unp.ext_path.as_ref().unwrap().is_file());
    let reopened = TraceReader::open(&unp.idx_path, unp.ext_path.as_deref()).unwrap();
    assert!(!reopened.is_archive());
    assert_eq!(reopened.len(), orig_len);
    assert_eq!(reopened.ext_len(), orig_ext_len);

    // 二次解包不带 overwrite 必须报错
    assert!(TraceArchive::unpack(&rtrace_path, &unpack_dir, Some("restored"), false).is_err());
    // 带 overwrite=true 成功
    assert!(TraceArchive::unpack(&rtrace_path, &unpack_dir, Some("restored"), true).is_ok());

    // 4. level=0 (无压缩原始存储) 往返
    let raw_rtrace = dir.join("uncompressed.rtrace");
    let raw_info = TraceArchive::pack(
        &unp.idx_path,
        unp.ext_path.as_deref(),
        &raw_rtrace,
        &TraceArchivePackOptions {
            compression_level: 0,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!raw_info.compressed);
    assert_eq!(raw_info.idx_comp_len, raw_info.idx_raw_len);
    let raw_reader = TraceReader::open(&raw_rtrace, None).unwrap();
    assert_eq!(raw_reader.len(), orig_len);
    assert_eq!(raw_reader.ext_len(), orig_ext_len);
}

#[test]
fn test_rtrace_security_integrity_and_zip_bomb_guards() {
    let (dir, idx_path, ext_path, _, _, _) =
        record_sample_trace("security", TraceLevel::Full, 0xABCD_1234);
    let rtrace_path = dir.join("good.rtrace");
    TraceArchive::pack(
        &idx_path,
        Some(&ext_path),
        &rtrace_path,
        &TraceArchivePackOptions::default(),
    )
    .unwrap();
    let good_bytes = fs::read(&rtrace_path).unwrap();

    // 1. 头部字段篡改 -> header_crc32 拦截
    let mut bad_hdr = good_bytes.clone();
    bad_hdr[8] ^= 0xFF;
    let p_hdr = dir.join("bad_hdr.rtrace");
    fs::write(&p_hdr, &bad_hdr).unwrap();
    assert!(TraceArchive::inspect(&p_hdr).is_err());
    assert!(TraceReader::open(&p_hdr, None).is_err());

    // 2. 载荷数据位翻转 -> data CRC32 / deflate 拦截
    let mut bad_data = good_bytes.clone();
    let last = bad_data.len() - 1;
    bad_data[last] ^= 0x55;
    let p_data = dir.join("bad_data.rtrace");
    fs::write(&p_data, &bad_data).unwrap();
    assert!(TraceReader::open(&p_data, None).is_err());

    // 3. 尾部追加脏字节 -> 精确文件长度校验拦截
    let mut trailing = good_bytes.clone();
    trailing.push(0x00);
    let p_trail = dir.join("trailing.rtrace");
    fs::write(&p_trail, &trailing).unwrap();
    assert!(TraceArchive::inspect(&p_trail).is_err());

    // 4. 构造伪造 zip-bomb：文件头声称 idx_raw_len=32B（1 条 TraceRecord），但实际 deflate 流展开为 64KB 零字节！
    let bomb_raw = vec![0u8; 64 * 1024];
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    enc.write_all(&bomb_raw).unwrap();
    let bomb_comp = enc.finish().unwrap();
    let mut bomb_hdr = [0u8; RTRACE_HEADER_SIZE];
    bomb_hdr[0..4].copy_from_slice(&RTRACE_MAGIC);
    bomb_hdr[4..6].copy_from_slice(&RTRACE_VERSION.to_le_bytes());
    bomb_hdr[6..8].copy_from_slice(&RTRACE_FLAG_DEFLATE.to_le_bytes());
    let one_rec = std::mem::size_of::<runidbg_arm64_emu_tracer::tracer::TraceRecord>() as u64;
    bomb_hdr[16..24].copy_from_slice(&one_rec.to_le_bytes()); // 声称仅 1 条记录 (32B)
    bomb_hdr[24..32].copy_from_slice(&(bomb_comp.len() as u64).to_le_bytes());
    let mut crc = Crc::new();
    crc.update(&bomb_hdr[0..60]);
    bomb_hdr[60..64].copy_from_slice(&crc.sum().to_le_bytes());
    let p_bomb = dir.join("bomb.rtrace");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&p_bomb)
            .unwrap();
        f.write_all(&bomb_hdr).unwrap();
        f.write_all(&bomb_comp).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
    }
    let err = TraceReader::open(&p_bomb, None)
        .err()
        .expect("zip-bomb 必须被流式解压上限拦截");
    let msg = err.to_string();
    assert!(
        msg.contains("zip-bomb") || msg.contains("上限"),
        "错误信息应明确提示解压上限拦截: {msg}"
    );

    // 5. 路径穿越 / 空白 / Windows 保留设备名 stem 拦截
    for bad_stem in [
        "../foo",
        "..\\foo",
        "a/..",
        "../../etc/passwd",
        "/etc/passwd",
        "sub/dir",
        "",
        "   ",
        "CON",
        "nul.txt",
        "com1",
    ] {
        assert!(
            TraceArchive::unpack(&rtrace_path, &dir, Some(bad_stem), true).is_err(),
            "非法 stem `{bad_stem}` 必须被拒绝"
        );
    }

    // 5b. 悬空符号链接防护（Unix）：overwrite=false 时必须拒绝写入悬空 symlink
    #[cfg(unix)]
    {
        let sym_dir = dir.join("sym_test");
        fs::create_dir_all(&sym_dir).unwrap();
        let outside = dir.join("outside_escape.idx");
        let dangling = sym_dir.join("escape.idx");
        std::os::unix::fs::symlink(&outside, &dangling).unwrap();
        assert!(
            TraceArchive::unpack(&rtrace_path, &sym_dir, Some("escape"), false).is_err(),
            "overwrite=false 时必须拦截悬空符号链接，防止写穿目录"
        );
        assert!(!outside.exists(), "不得沿悬空符号链接在外部创建文件");
    }

    // 5c. 篡改 meta_bytes 内容 -> header_crc32 必须拦截！
    let mut bad_meta = good_bytes.clone();
    // 紧随 64B header 之后就是 meta_bytes（如 "ext_events=..."）
    if bad_meta.len() > RTRACE_HEADER_SIZE {
        bad_meta[RTRACE_HEADER_SIZE] ^= 0x01;
        let p_meta = dir.join("bad_meta.rtrace");
        fs::write(&p_meta, &bad_meta).unwrap();
        assert!(
            TraceArchive::inspect(&p_meta).is_err(),
            "篡改 meta_bytes 必须触发 header_crc32 校验失败"
        );
    }

    // 5d. 压缩流帧尾夹带未消费脏字节 -> 必须被 decoder.total_in() != comp_len 拦截！
    {
        let real_rec = [0u8; 32];
        let mut crc_data = Crc::new();
        crc_data.update(&real_rec);
        let data_crc = crc_data.sum();
        let mut enc2 = DeflateEncoder::new(Vec::new(), Compression::default());
        enc2.write_all(&real_rec).unwrap();
        let mut smuggled = enc2.finish().unwrap();
        smuggled.extend_from_slice(b"SMUGGLED_TRAILING_BYTES");
        let mut sm_hdr = [0u8; RTRACE_HEADER_SIZE];
        sm_hdr[0..4].copy_from_slice(&RTRACE_MAGIC);
        sm_hdr[4..6].copy_from_slice(&RTRACE_VERSION.to_le_bytes());
        sm_hdr[6..8].copy_from_slice(&RTRACE_FLAG_DEFLATE.to_le_bytes());
        sm_hdr[16..24].copy_from_slice(&32u64.to_le_bytes());
        sm_hdr[24..32].copy_from_slice(&(smuggled.len() as u64).to_le_bytes());
        sm_hdr[32..36].copy_from_slice(&data_crc.to_le_bytes());
        let mut hc = Crc::new();
        hc.update(&sm_hdr[0..60]);
        sm_hdr[60..64].copy_from_slice(&hc.sum().to_le_bytes());
        let p_smug = dir.join("smuggled.rtrace");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&sm_hdr);
        bytes.extend_from_slice(&smuggled);
        fs::write(&p_smug, &bytes).unwrap();
        assert!(
            TraceReader::open(&p_smug, None).is_err(),
            "Deflate 帧尾夹带未消费脏字节必须被拒绝"
        );
    }

    // 5e. 空 0-insn Trace 打包 -> 检查 -> 透明打开 -> 解包 -> 重新打开全流程
    {
        let empty_idx = dir.join("empty.idx");
        let empty_arc = dir.join("empty.rtrace");
        fs::write(&empty_idx, []).unwrap();
        let einfo = TraceArchive::pack(
            &empty_idx,
            None,
            &empty_arc,
            &TraceArchivePackOptions::default(),
        )
        .unwrap();
        assert_eq!(einfo.idx_insns, 0);
        assert_eq!(einfo.idx_raw_len, 0);
        let er = TraceReader::open(&empty_arc, None).unwrap();
        assert!(er.is_empty());
        let eu = TraceArchive::unpack(&empty_arc, dir.join("empty_unp"), None, false).unwrap();
        let er2 = TraceReader::open(&eu.idx_path, None).unwrap();
        assert!(er2.is_empty());
    }

    // 6. Full 级别 .idx 缺失 .ext 打包时，打开 .rtrace 仍必须触发 missing_ext_warning
    let no_ext_arc = dir.join("missing_ext.rtrace");
    TraceArchive::pack(
        &idx_path,
        None,
        &no_ext_arc,
        &TraceArchivePackOptions::default(),
    )
    .unwrap();
    let no_ext_reader = TraceReader::open(&no_ext_arc, None).unwrap();
    assert!(no_ext_reader.missing_ext_warning());
}

#[test]
fn test_rtrace_cli_pack_unpack_and_transparent_offline_subcommands() {
    let (dir, idx_a, ext_a, _, out_buf, _) =
        record_sample_trace("cli_a", TraceLevel::Full, 0x1111_2222);
    let (_dir_b, idx_b, ext_b, _, _, _) =
        record_sample_trace("cli_b", TraceLevel::Full, 0x3333_4444);

    let arc_a = dir.join("run_a.rtrace");
    let arc_b = dir.join("run_b.rtrace");
    let cli_bin = env!("CARGO_BIN_EXE_runidbg-cli");

    // 1. CLI pack
    let p1 = Command::new(cli_bin)
        .args([
            "pack",
            idx_a.to_str().unwrap(),
            "--ext",
            ext_a.to_str().unwrap(),
            "--out",
            arc_a.to_str().unwrap(),
            "--base",
            "0x40000000",
            "--note",
            "cli-pack-test",
        ])
        .output()
        .unwrap();
    assert!(p1.status.success(), "{}", String::from_utf8_lossy(&p1.stderr));
    assert!(String::from_utf8_lossy(&p1.stdout).contains("cli-pack-test"));

    let p2 = Command::new(cli_bin)
        .args([
            "pack",
            idx_b.to_str().unwrap(),
            "--ext",
            ext_b.to_str().unwrap(),
            "--out",
            arc_b.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(p2.status.success(), "{}", String::from_utf8_lossy(&p2.stderr));

    // 2. CLI unpack --info
    let info_out = Command::new(cli_bin)
        .args(["unpack", arc_a.to_str().unwrap(), "--info"])
        .output()
        .unwrap();
    assert!(info_out.status.success());
    let info_s = String::from_utf8_lossy(&info_out.stdout);
    assert!(info_s.contains("0x0000000040000000") && info_s.contains("cli-pack-test"));

    // 3. 直接对 .rtrace 运行 stats（自动复用 --base）、dump（必须含 [MEM 扩展事件！）、search --val（必须命中内存写入！）、mem、decompile、diff --target-addr
    let st = Command::new(cli_bin)
        .args(["stats", arc_a.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    let st_s = String::from_utf8_lossy(&st.stdout);
    assert!(st_s.contains("[+0x0]"), "stats 应自动复用 .rtrace 中保存的 --base:\n{st_s}");

    let dmp = Command::new(cli_bin)
        .args(["dump", arc_a.to_str().unwrap(), "--limit", "20"])
        .output()
        .unwrap();
    assert!(dmp.status.success(), "{}", String::from_utf8_lossy(&dmp.stderr));
    let dmp_s = String::from_utf8_lossy(&dmp.stdout);
    assert!(
        dmp_s.contains("[MEM "),
        "CLI dump 直接读 .rtrace 必须输出内嵌 .ext 的 [MEM] 事件:\n{dmp_s}"
    );

    let find_val = Command::new(cli_bin)
        .args(["find", arc_a.to_str().unwrap(), "--val", "0x11112222"])
        .output()
        .unwrap();
    assert!(find_val.status.success(), "{}", String::from_utf8_lossy(&find_val.stderr));
    let fv_s = String::from_utf8_lossy(&find_val.stdout);
    assert!(
        fv_s.contains("命中内存读写值"),
        "CLI find --val 直接读 .rtrace 必须检索内嵌 .ext 的内存读写值:\n{fv_s}"
    );

    let mem_cmd = Command::new(cli_bin)
        .args([
            "mem",
            arc_a.to_str().unwrap(),
            "--addr",
            &format!("0x{out_buf:x}"),
            "--len",
            "4",
            "--hex",
        ])
        .output()
        .unwrap();
    assert!(mem_cmd.status.success(), "{}", String::from_utf8_lossy(&mem_cmd.stderr));
    assert_eq!(String::from_utf8_lossy(&mem_cmd.stdout).trim().len(), 8);

    // pack --no-ext 与异常输入拒绝
    let no_ext_cli = dir.join("cli_no_ext.rtrace");
    let p_noext = Command::new(cli_bin)
        .args([
            "pack",
            idx_a.to_str().unwrap(),
            "--no-ext",
            "--out",
            no_ext_cli.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(p_noext.status.success(), "{}", String::from_utf8_lossy(&p_noext.stderr));
    assert!(!TraceArchive::inspect(&no_ext_cli).unwrap().has_ext);
    assert!(
        !Command::new(cli_bin)
            .args(["pack", arc_a.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success(),
        "CLI pack 应拒绝重复打包 .rtrace"
    );

    let dec = Command::new(cli_bin)
        .args([
            "decompile",
            arc_a.to_str().unwrap(),
            "--addr",
            &format!("0x{out_buf:x}"),
            "--len",
            "4",
        ])
        .output()
        .unwrap();
    assert!(dec.status.success(), "{}", String::from_utf8_lossy(&dec.stderr));
    assert!(
        String::from_utf8_lossy(&dec.stdout).contains("verify=PASS (bit-exact)"),
        "{}",
        String::from_utf8_lossy(&dec.stdout)
    );

    let diff = Command::new(cli_bin)
        .args([
            "diff",
            arc_a.to_str().unwrap(),
            arc_b.to_str().unwrap(),
            "--target-addr",
            &format!("0x{out_buf:x}"),
            "--len",
            "4",
        ])
        .output()
        .unwrap();
    assert!(diff.status.success(), "{}", String::from_utf8_lossy(&diff.stderr));
    assert!(
        String::from_utf8_lossy(&diff.stdout).contains("差异字节=4"),
        "{}",
        String::from_utf8_lossy(&diff.stdout)
    );

    // 4. CLI unpack
    let unp_dir = dir.join("cli_unpacked");
    let unp = Command::new(cli_bin)
        .args([
            "unpack",
            arc_a.to_str().unwrap(),
            "--out-dir",
            unp_dir.to_str().unwrap(),
            "--stem",
            "extracted",
        ])
        .output()
        .unwrap();
    assert!(unp.status.success(), "{}", String::from_utf8_lossy(&unp.stderr));
    assert!(unp_dir.join("extracted.idx").is_file());
    assert!(unp_dir.join("extracted.ext").is_file());
}

#[cfg(feature = "js")]
#[test]
fn test_rtrace_js_pack_inspect_open_and_unpack() {
    use runidbg_arm64_emu_tracer::script::JsSession;
    use std::path::Path;

    let (dir, idx_path, _ext_path, _, out_buf, actual_out) =
        record_sample_trace("js_rtrace", TraceLevel::Full, 0x5566_7788);
    let rtrace_path = dir.join("js_bundle.rtrace");
    let unp_dir = dir.join("js_unpacked");

    let session = JsSession::new(&[], Path::new("."), true).unwrap();
    let js = format!(
        r#"
        (() => {{
            const packed = Trace.pack({idx:?}, {arc:?}, {{ baseAddr: 0x40000000n, note: "js-test", level: 6 }});
            if (!packed.hasExt || !packed.compressed || packed.note !== "js-test") throw new Error("bad pack info");
            const insp = Trace.inspectArchive({arc:?});
            if (insp.idxInsns !== packed.idxInsns || insp.baseAddrHex !== "0x0000000040000000") throw new Error("bad inspect");

            const tr = Trace.open({arc:?});
            if (!tr.isArchive || tr.archiveBaseAddrHex !== "0x0000000040000000") throw new Error("bad open archive metadata");
            const rep = tr.decompileSlice({{ addr: 0x{out_buf:x}n, len: 4, functionName: "js_rtrace_fn" }});
            tr.close();
            if (rep.verified !== true) throw new Error("rtrace decompile verified=" + rep.verified);
            if (rep.expectedOutputHex !== "0x{actual_out:x}") throw new Error("bad output: " + rep.expectedOutputHex);

            const unp = Trace.unpack({arc:?}, {unp_dir:?}, {{ stem: "from_js" }});
            if (!unp.idxPath.endsWith("from_js.idx") || !unp.extPath.endsWith("from_js.ext")) throw new Error("bad unpack paths");

            // 严格参数校验：漏传第 2 参数误把 opts 当 outPath 时必须抛 TypeError，绝不创建 "[object Object]" 文件！
            for (const fn of [
                () => Trace.pack({idx:?}, {{ level: 9 }}),
                () => Trace.unpack({arc:?}, {{ stem: "x" }}),
                () => Trace.pack(null),
                () => Trace.pack({idx:?}, {arc:?}, {{ level: 10 }}),
                () => Trace.pack({idx:?}, {arc:?}, {{ level: 1.5 }}),
                () => Trace.pack({idx:?}, {arc:?}, "bad_opts"),
                () => Trace.inspectArchive(123),
                () => Trace.unpack({arc:?}, {unp_dir:?}, {{ stem: "../escape" }}),
            ]) {{
                let threw = false;
                try {{ fn(); }} catch (_) {{ threw = true; }}
                if (!threw) throw new Error("expected JS validation error");
            }}
            // noExt: true 仅打包 .idx
            const noExtPath = {arc:?} + ".noext";
            const pNoExt = Trace.pack({idx:?}, noExtPath, {{ noExt: true }});
            if (pNoExt.hasExt) throw new Error("noExt: true should omit .ext");
            return "OK";
        }})()
        "#,
        idx = idx_path.to_str().unwrap(),
        arc = rtrace_path.to_str().unwrap(),
        unp_dir = unp_dir.to_str().unwrap()
    );
    let res = session.eval_json_string(&js).unwrap();
    assert_eq!(res, "\"OK\"");
}

#[cfg(feature = "mcp")]
#[test]
fn test_rtrace_mcp_dump_and_base_addr_inheritance() {
    use runidbg_arm64_emu_tracer::script::mcp::McpServer;
    use serde_json::json;
    use std::path::Path;

    let (dir, idx_path, ext_path, _, out_buf, _) =
        record_sample_trace("mcp_rtrace", TraceLevel::Full, 0x1234_5678);
    let arc_path = dir.join("mcp_bundle.rtrace");
    TraceArchive::pack(
        &idx_path,
        Some(&ext_path),
        &arc_path,
        &TraceArchivePackOptions {
            base_addr: 0x4000_0000,
            ..Default::default()
        },
    )
    .unwrap();

    let mut mcp = McpServer::new(Path::new("."), None).unwrap();
    // 1. trace_inspect(action="dump") 必须包含内嵌 .ext 的 [MEM] 行，且自动继承 base 0x40000000！
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "trace_inspect",
            "arguments": {
                "idxPath": arc_path.to_str().unwrap(),
                "action": "dump",
                "limit": 20
            }
        }
    });
    let resp: serde_json::Value =
        serde_json::from_str(&mcp.handle_message(&req.to_string()).unwrap()).unwrap();
    let body: serde_json::Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let joined = body["lines"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(joined.contains("[MEM "), "MCP trace_inspect dump 应包含内嵌 .ext 访存行:\n{joined}");
    assert!(joined.contains("[+0x0]"), "MCP trace_inspect 应继承 .rtrace 保存的 base:\n{joined}");

    // 2. trace_decompile 直接读 .rtrace
    let req2 = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "trace_decompile",
            "arguments": {
                "idxPath": arc_path.to_str().unwrap(),
                "addr": format!("0x{out_buf:x}"),
                "len": 4
            }
        }
    });
    let resp2: serde_json::Value =
        serde_json::from_str(&mcp.handle_message(&req2.to_string()).unwrap()).unwrap();
    let body2: serde_json::Value =
        serde_json::from_str(resp2["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body2["verified"], json!(true));
}

#[cfg(feature = "ui")]
#[test]
fn test_rtrace_web_ui_embedded_ext_and_saved_base() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let (dir, idx_path, ext_path, _, _, _) =
        record_sample_trace("ui_rtrace", TraceLevel::Full, 0xCAFE_BABE);
    let arc_path = dir.join("ui_bundle.rtrace");
    TraceArchive::pack(
        &idx_path,
        Some(&ext_path),
        &arc_path,
        &TraceArchivePackOptions {
            base_addr: 0x4000_0000,
            ..Default::default()
        },
    )
    .unwrap();

    let handle = runidbg_arm64_emu_tracer::ui::start_trace_ui_server(
        &arc_path,
        None,
        0,
        "127.0.0.1:0",
    )
    .unwrap();
    let addr = handle.local_addr();
    let http_get = |path: &str| -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        resp
    };

    let info_resp = http_get("/api/info");
    assert!(
        info_resp.contains("0x0000000040000000") || info_resp.contains("0x40000000"),
        "/api/info 应自动继承 .rtrace 保存的 base_addr:\n{info_resp}"
    );
    let dump_resp = http_get("/api/trace/dump?skip=0&limit=20");
    assert!(
        dump_resp.contains("[MEM "),
        "/api/trace/dump 对 .rtrace 必须返回非空 mems:\n{dump_resp}"
    );
    handle.shutdown();
}
