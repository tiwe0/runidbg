//! decompile v2 端到端集成测试：
//! 1. 可读小端内存加载/写回折叠（`LOAD16_LE`/`LOAD32_LE`/`LOAD64_LE`、`STORE16_LE`/`STORE32_LE`/`STORE64_LE`、奇长 15B 尾字节）
//! 2. 缓冲区级多输出联合反编译（15B / 16B / 20B 输出 -> `void fn(..., uint8_t *out)` + 跨输出共享 CSE + 多断言 SMT-LIB2）
//! 3. NEON 128-bit 通道级符号提升与审计回归（`LDR Q`/`STR Q`/`LDP Q`/`STP Q`/`LD1`/`LD1 lane`/`ST1`/`EOR`/`ADD`/`REV32`/`EXT`/`UZP1`/`ZIP1`/`TRN1`/`BSL`/`SLI`/`SRI`/`SSHR .16b` (`ASHR8` + `#8` 满位宽)/`MOVI msl`/`MOV x, v.d[1]`/`FMOV d[1]`/`INS`/未建模 NEON 安全降级 `Opaque`）
//! 4. ARMv8-CE 硬件 AES 原语（`AESE` / `AESMC` / `AESD` / `AESIMC`）对照 NIST FIPS-197 Appendix B 硬编码真值 + 真逆向解密还原明文 + `cc -O2 -Wall -Werror` 跨向量验证
//! 5. CLI（无特性门控）、QuickJS（`feature = "js"`）、MCP（`feature = "mcp"`）端到端与严格边界校验

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use runidbg_arm64_emu_tracer::good64;
use runidbg_arm64_emu_tracer::tracer::{
    BinaryTracer, DecompileOptions, TaintSeed, TraceLevel, TraceReader,
};
use runidbg_arm64_emu_tracer::{AndroidEmulator, CpuBackend};

fn unique_test_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "runidbg_decomp_v2_{tag}_{}_{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 在真实 Unicorn ARM64 引擎上执行机器码并录制 Full Trace
fn trace_arm64_words(
    tag: &str,
    code_bytes: &[u8],
    in0: &[u8],
    in1: &[u8],
    out_len: usize,
) -> (PathBuf, PathBuf, u64, u64, u64, Vec<u8>) {
    let dir = unique_test_dir(tag);
    let idx_path = dir.join("trace.idx");
    let ext_path = dir.join("trace.ext");

    let code_base = 0x4000_0000u64;
    let in0_buf = 0x4001_0000u64;
    let in1_buf = 0x4001_1000u64;
    let out_buf = 0x4001_2000u64;

    let mut emu = AndroidEmulator::builder().build().expect("build emu");
    emu.cpu_mut()
        .mem_map(code_base, 0x20000, unicorn_engine::unicorn_const::Prot::ALL)
        .unwrap();
    emu.cpu_mut().mem_write(code_base, code_bytes).unwrap();
    if !in0.is_empty() {
        emu.cpu_mut().mem_write(in0_buf, in0).unwrap();
    }
    if !in1.is_empty() {
        emu.cpu_mut().mem_write(in1_buf, in1).unwrap();
    }
    emu.cpu_mut()
        .mem_write(out_buf, &vec![0u8; out_len.max(64)])
        .unwrap();

    let tracer =
        BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 4096, 16384, TraceLevel::Full)
            .expect("create BinaryTracer");
    emu.set_tracer(tracer).unwrap();
    emu.attach_tracer(code_base, code_base + 0x1000).unwrap();
    let _ = emu
        .call_address(code_base, &[in0_buf, in1_buf, out_buf])
        .expect("call snippet");
    emu.tracer().flush().unwrap();

    let mut actual_out = vec![0u8; out_len];
    emu.cpu_mut().mem_read(out_buf, &mut actual_out).unwrap();
    (idx_path, ext_path, in0_buf, in1_buf, out_buf, actual_out)
}

fn compile_and_run_c(dir: &std::path::Path, name: &str, source: &str) {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }
    let c_file = dir.join(format!("{name}.c"));
    let bin_file = dir.join(name);
    fs::write(&c_file, source).unwrap();
    let compile = Command::new("cc")
        .args(["-O2", "-Wall", "-Werror"])
        .arg(&c_file)
        .arg("-o")
        .arg(&bin_file)
        .output()
        .expect("invoke cc");
    assert!(
        compile.status.success(),
        "C 编译 (-O2 -Wall -Werror) 失败!\nstderr: {}\nsource:\n{source}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new(&bin_file).output().expect("run compiled binary");
    assert!(
        run.status.success(),
        "编译后的 C 交叉验证失败!\nstderr: {}\nsource:\n{source}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn test_decompile_v2_load_le_and_multi_output_buffer_with_shared_cse() {
    // 构造 16B 输入：[a=0x1122334455667788, b=0x99aabbccddeeff00]
    // 构造 20B 多输出缓冲区：
    //   out[0..8]   = (a ^ b) + 0x1337
    //   out[8..16]  = ROR64((a ^ b), 13) + a   (共享公共子表达式 a ^ b!)
    //   out[16..20] = (uint32_t)((a ^ b) ^ 0xCAFEBABE)
    let a = 0x1122_3344_5566_7788u64;
    let b = 0x99AA_BBCC_DDEE_FF00u64;
    let mut in0 = Vec::new();
    in0.extend_from_slice(&a.to_le_bytes());
    in0.extend_from_slice(&b.to_le_bytes());

    let asm = r#"
        ldr x4, [x0]
        ldr x5, [x0, #8]
        eor x6, x4, x5
        mov x7, #0x1337
        add x8, x6, x7
        str x8, [x2]
        ror x9, x6, #13
        add x10, x9, x4
        str x10, [x2, #8]
        mov w11, #0xCAFEBABE
        eor w12, w6, w11
        str w12, [x2, #16]
        ret
    "#;
    let code = good64::assemble(asm, 0x4000_0000).unwrap();
    let (idx_path, ext_path, _in0_buf, _in1_buf, out_buf, actual_out) =
        trace_arm64_words("multi_out", &code, &in0, &[], 20);

    let reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();
    let report = reader.decompile_slice(
        &TaintSeed::Mem {
            addr: out_buf,
            len: 20,
        },
        &DecompileOptions {
            function_name: "joint_block".to_string(),
            emit_smt2: true,
            ..Default::default()
        },
    );

    assert_eq!(report.output_len, 20);
    assert_eq!(report.expected_output, None);
    assert_eq!(report.evaluated_output, None);
    assert_eq!(
        report.verified,
        Some(true),
        "20B 多输出联合反编译必须逐 bit 校验通过:\n{}",
        report.format_summary()
    );
    let actual_hex: String = actual_out.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        report.expected_output_bytes_hex.as_deref(),
        Some(actual_hex.as_str())
    );
    assert_eq!(
        report.evaluated_output_bytes_hex.as_deref(),
        Some(actual_hex.as_str())
    );
    assert!(
        report
            .c_code
            .contains("void joint_block(const uint8_t *in_0, uint8_t *out)"),
        "多输出签名应为 void fn(..., uint8_t *out):\n{}",
        report.c_code
    );
    assert!(
        report.c_code.contains("LOAD64_LE(in_0)") && report.c_code.contains("LOAD64_LE(in_0 + 8)"),
        "应折叠连续小端加载为 LOAD64_LE:\n{}",
        report.c_code
    );
    assert!(
        report.c_code.contains("STORE64_LE(out,")
            && report.c_code.contains("STORE64_LE(out + 8,")
            && report.c_code.contains("STORE32_LE(out + 16,"),
        "应生成清晰的 STORE64_LE / STORE32_LE 写回:\n{}",
        report.c_code
    );
    assert!(
        report.c_code.contains("uint64_t t0 ="),
        "跨 3 个输出块共享的 a ^ b 应触发联合 CSE 局部变量:\n{}",
        report.c_code
    );

    let smt = report.smt2.as_deref().expect("smt2");
    assert_eq!(
        smt.matches("(assert (= ").count(),
        3,
        "20B (8+8+4) 多输出 SMT-LIB2 应包含 3 条输出约束:\n{smt}"
    );

    // 真编译 + 全新输入交叉验证
    let harness = format!(
        r#"
{c_code}
#include <stdio.h>
#include <string.h>
int main(void) {{
    uint8_t in_a[16] = {{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    }};
    uint8_t out_buf[20] = {{0}};
    joint_block(in_a, out_buf);
    uint64_t a = 0xefcdab8967452301ULL;
    uint64_t b = 0x1032547698badcfeULL;
    uint64_t x = a ^ b;
    uint64_t e0 = x + 0x1337ULL;
    uint64_t e1 = ((x >> 13) | (x << 51)) + a;
    uint32_t e2 = (uint32_t)x ^ 0xCAFEBABEu;
    uint8_t exp[20];
    memcpy(exp, &e0, 8);
    memcpy(exp + 8, &e1, 8);
    memcpy(exp + 16, &e2, 4);
    if (memcmp(out_buf, exp, 20) != 0) {{
        fprintf(stderr, "multi-output mismatch\n");
        return 1;
    }}
    return 0;
}}
"#,
        c_code = report.c_code
    );
    compile_and_run_c(idx_path.parent().unwrap(), "verify_multi_out", &harness);
}

#[test]
fn test_decompile_v2_odd_len_15b_load16_load32_store16_tail() {
    // 奇长 15B (8+4+2+1) 输出测试：同时覆盖 LOAD64_LE / LOAD32_LE / LOAD16_LE / STORE64_LE / STORE32_LE / STORE16_LE / out[14]
    let asm = r#"
        ldr x4, [x0]
        ldr w5, [x0, #8]
        ldrh w6, [x0, #12]
        ldrb w7, [x0, #14]
        eor x4, x4, #0xff
        add w5, w5, #0x11
        eor w6, w6, #0x3
        add w7, w7, #0x07
        str x4, [x2]
        str w5, [x2, #8]
        strh w6, [x2, #12]
        strb w7, [x2, #14]
        ret
    "#;
    let code = good64::assemble(asm, 0x4000_0000).unwrap();
    let in0: [u8; 15] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x09,
    ];
    let (idx_path, ext_path, _, _, out_buf, actual_out) =
        trace_arm64_words("odd_15b", &code, &in0, &[], 15);
    let reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();
    let report = reader.decompile_slice(
        &TaintSeed::Mem {
            addr: out_buf,
            len: 15,
        },
        &DecompileOptions {
            function_name: "odd_15b_fn".to_string(),
            ..Default::default()
        },
    );
    assert_eq!(report.output_len, 15);
    assert_eq!(report.verified, Some(true), "{}", report.format_summary());
    assert!(report.c_code.contains("LOAD64_LE(in_0)"), "{}", report.c_code);
    assert!(report.c_code.contains("LOAD32_LE(in_0 + 8)"), "{}", report.c_code);
    assert!(report.c_code.contains("LOAD16_LE(in_0 + 12)"), "{}", report.c_code);
    assert!(report.c_code.contains("STORE64_LE(out,"), "{}", report.c_code);
    assert!(report.c_code.contains("STORE32_LE(out + 8,"), "{}", report.c_code);
    assert!(report.c_code.contains("STORE16_LE(out + 12,"), "{}", report.c_code);
    assert!(report.c_code.contains("out[14] ="), "{}", report.c_code);

    let exp_arr = actual_out
        .iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let harness = format!(
        r#"
{c_code}
#include <stdio.h>
#include <string.h>
int main(void) {{
    uint8_t in0[15] = {{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x09 }};
    uint8_t exp[15] = {{ {exp_arr} }};
    uint8_t got[15] = {{0}};
    odd_15b_fn(in0, got);
    if (memcmp(got, exp, 15) != 0) {{ fprintf(stderr, "15B mismatch\n"); return 1; }}
    return 0;
}}
"#,
        c_code = report.c_code
    );
    compile_and_run_c(idx_path.parent().unwrap(), "verify_odd_15b", &harness);
}

#[test]
fn test_decompile_v2_neon_128bit_lanes_and_shuffle() {
    // 测试 NEON 128-bit 通道级提升：
    //   ldr q0, [x0]            // 16B 输入 A
    //   ldr q1, [x1]            // 16B 输入 B
    //   eor v2.16b, v0.16b, v1.16b
    //   add v3.4s, v2.4s, v0.4s
    //   rev32 v4.16b, v3.16b
    //   ext v5.16b, v4.16b, v1.16b, #4
    //   str q5, [x2]
    //   ret
    let words: [u32; 8] = [
        0x3DC0_0000, // ldr q0, [x0]
        0x3DC0_0021, // ldr q1, [x1]
        0x6E21_1C02, // eor v2.16b, v0.16b, v1.16b
        0x4EA0_8443, // add v3.4s, v2.4s, v0.4s
        0x6E20_0864, // rev32 v4.16b, v3.16b
        0x6E01_2085, // ext v5.16b, v4.16b, v1.16b, #4
        0x3D80_0045, // str q5, [x2]
        0xD65F_03C0, // ret
    ];
    let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let in0: [u8; 16] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    ];
    let in1: [u8; 16] = [
        0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
        0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
    ];

    let (idx_path, ext_path, _in0_buf, _in1_buf, out_buf, actual_out) =
        trace_arm64_words("neon_lanes", &code, &in0, &in1, 16);

    let reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();
    let report = reader.decompile_slice(
        &TaintSeed::Mem {
            addr: out_buf,
            len: 16,
        },
        &DecompileOptions {
            function_name: "neon_mix_128".to_string(),
            emit_smt2: true,
            ..Default::default()
        },
    );

    assert_eq!(
        report.verified,
        Some(true),
        "NEON 128-bit 通道反编译必须逐 bit 校验通过:\n{}",
        report.format_summary()
    );
    assert!(
        !report.c_code.contains("opaque:"),
        "NEON 128-bit 流水线不应存在任何 opaque 占位:\n{}",
        report.c_code
    );
    let actual_hex: String = actual_out.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        report.evaluated_output_bytes_hex.as_deref(),
        Some(actual_hex.as_str())
    );

    // 真编译并在全新输入向量上与软件模拟结果逐字节交叉校验
    let harness = format!(
        r#"
{c_code}
#include <stdio.h>
#include <string.h>
static void ref_neon_mix(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {{
    uint8_t v2[16], v3[16], v4[16];
    for (int i = 0; i < 16; ++i) v2[i] = a[i] ^ b[i];
    for (int i = 0; i < 4; ++i) {{
        uint32_t wa, w2;
        memcpy(&wa, a + i * 4, 4);
        memcpy(&w2, v2 + i * 4, 4);
        uint32_t w3 = w2 + wa;
        memcpy(v3 + i * 4, &w3, 4);
        v4[i * 4 + 0] = v3[i * 4 + 3];
        v4[i * 4 + 1] = v3[i * 4 + 2];
        v4[i * 4 + 2] = v3[i * 4 + 1];
        v4[i * 4 + 3] = v3[i * 4 + 0];
    }}
    memcpy(out, v4 + 4, 12);
    memcpy(out + 12, b, 4);
}}
int main(void) {{
    uint8_t a[16] = {{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }};
    uint8_t b[16] = {{ 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 }};
    uint8_t got[16] = {{0}}, exp[16] = {{0}};
    neon_mix_128(a, b, got);
    ref_neon_mix(a, b, exp);
    if (memcmp(got, exp, 16) != 0) {{
        fprintf(stderr, "neon_mix_128 mismatch\n");
        return 1;
    }}
    return 0;
}}
"#,
        c_code = report.c_code
    );
    compile_and_run_c(idx_path.parent().unwrap(), "verify_neon_mix", &harness);
}

#[test]
fn test_decompile_v2_neon_audit_regressions_ashr8_msl_ld1_fmov_mov_alias_and_opaque() {
    // 审计回归测试：集中验证所有 P0/P1 NEON 语义边界，并用真编译 C 交叉验证！
    //   0: ld1  {v0.16b}, [x0]            // 4C407000
    //   1: ld1  {v1.16b}, [x1]            // 4C407021
    //   2: ld1  {v0.b}[10], [x1]          // 4D400820  (单通道 RMW，仅改 v0.b[10]，保留其余 15 字节！)
    //   3: sshr v2.16b, v0.16b, #3        // 4F0D0402  (8-bit 有符号右移 -> 必须发 ASHR8，不可发 ASHR32！)
    //   4: sshr v3.16b, v1.16b, #8        // 4F080423  (满位宽 #8 右移 -> 符号掩码 0x00/0xff，不可退化为恒等！)
    //   5: movi v4.4s, #0xca, msl #8      // 4F06C544  (MSL #8 -> 0x0000caff！)
    //   6: eor  v2.16b, v2.16b, v3.16b    // 6E231C42
    //   7: eor  v2.16b, v2.16b, v4.16b    // 6E241C42
    //   8: zip1 v5.4s, v2.4s, v1.4s       // 4E813845
    //   9: uzp1 v6.4s, v5.4s, v0.4s       // 4E8018A6
    //  10: trn1 v6.4s, v6.4s, v2.4s       // 4E8228C6
    //  11: bsl  v6.16b, v0.16b, v1.16b    // 6E611C06
    //  12: mov  x4, v6.d[1]               // 4E183CC4  (bad64 UMOV 别名，必须读高 64 位！)
    //  13: fmov x5, v6.d[1]               // 9EAE00C5  (FMOV 高 64 位 d[1]，必须与 x4 一致！)
    //  14: eor  x6, x4, x5                // CA050086  (两者相同，异或应化简或恒为 0！)
    //  15: add  x4, x4, x6                // 8B060084
    //  16: ins  v6.d[0], x4               // 4E081C86
    //  17: st1  {v6.16b}, [x2]            // 4C007046
    //  18: ret                            // D65F03C0
    let words: [u32; 19] = [
        0x4C40_7000, // ld1 {v0.16b}, [x0]
        0x4C40_7021, // ld1 {v1.16b}, [x1]
        0x4D40_0820, // ld1 {v0.b}[10], [x1]
        0x4F0D_0402, // sshr v2.16b, v0.16b, #3
        0x4F08_0423, // sshr v3.16b, v1.16b, #8
        0x4F06_C544, // movi v4.4s, #0xca, msl #8
        0x6E23_1C42, // eor v2.16b, v2.16b, v3.16b
        0x6E24_1C42, // eor v2.16b, v2.16b, v4.16b
        0x4E81_3845, // zip1 v5.4s, v2.4s, v1.4s
        0x4E80_18A6, // uzp1 v6.4s, v5.4s, v0.4s
        0x4E82_28C6, // trn1 v6.4s, v6.4s, v2.4s
        0x6E61_1C06, // bsl v6.16b, v0.16b, v1.16b
        0x4E18_3CC4, // mov x4, v6.d[1]
        0x9EAE_00C5, // fmov x5, v6.d[1]
        0xCA05_0086, // eor x6, x4, x5
        0x8B06_0084, // add x4, x4, x6
        0x4E08_1C86, // ins v6.d[0], x4
        0x4C00_7046, // st1 {v6.16b}, [x2]
        0xD65F_03C0, // ret
    ];
    // 先用 bad64 校验每条手写指令字反汇编准确无误
    for (i, &w) in words.iter().enumerate() {
        assert!(bad64::decode(w, 0x4000_0000 + (i as u64) * 4).is_ok(), "bad word #{i}: 0x{w:08x}");
    }
    let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    // 刻意包含最高位为 1 的负字节 (0x80, 0xf1, 0xa5, ...) 验证 ASHR8 与 SSHR #8 符号扩展！
    let in0: [u8; 16] = [
        0x80, 0x7f, 0xf1, 0x12, 0xa5, 0x34, 0x90, 0x56,
        0xc0, 0x01, 0xfe, 0x22, 0x88, 0x44, 0xd7, 0x09,
    ];
    let in1: [u8; 16] = [
        0x81, 0x10, 0xff, 0x40, 0x05, 0x99, 0x7e, 0x80,
        0xaa, 0x55, 0x84, 0x33, 0x70, 0xf0, 0x02, 0xc8,
    ];

    let (idx_path, ext_path, _, _, out_buf, actual_out) =
        trace_arm64_words("neon_audit_reg", &code, &in0, &in1, 16);

    let reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();
    let report = reader.decompile_slice(
        &TaintSeed::Mem {
            addr: out_buf,
            len: 16,
        },
        &DecompileOptions {
            function_name: "neon_audit_fn".to_string(),
            ..Default::default()
        },
    );
    assert_eq!(
        report.verified,
        Some(true),
        "NEON 审计回归组合必须逐 bit 通过:\n{}",
        report.format_summary()
    );
    assert!(
        report.c_code.contains("ASHR8("),
        "8-bit SSHR 必须使用 ASHR8 避免 C 零扩展成正数:\n{}",
        report.c_code
    );
    assert!(!report.c_code.contains("opaque:"), "{}", report.c_code);

    let exp_arr = actual_out
        .iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let harness = format!(
        r#"
{c_code}
#include <stdio.h>
#include <string.h>
int main(void) {{
    uint8_t a[16] = {{ 0x80, 0x7f, 0xf1, 0x12, 0xa5, 0x34, 0x90, 0x56, 0xc0, 0x01, 0xfe, 0x22, 0x88, 0x44, 0xd7, 0x09 }};
    uint8_t b[16] = {{ 0x81, 0x10, 0xff, 0x40, 0x05, 0x99, 0x7e, 0x80, 0xaa, 0x55, 0x84, 0x33, 0x70, 0xf0, 0x02, 0xc8 }};
    uint8_t exp[16] = {{ {exp_arr} }};
    uint8_t got[16] = {{0}};
    neon_audit_fn(a, b, got);
    if (memcmp(got, exp, 16) != 0) {{
        fprintf(stderr, "neon_audit_fn mismatch (ASHR8/MSL/LD1-lane/FMOV-d1)\n");
        return 1;
    }}
    return 0;
}}
"#,
        c_code = report.c_code
    );
    compile_and_run_c(idx_path.parent().unwrap(), "verify_neon_audit", &harness);

    // 验证未建模的向量指令 `mul v0.4s, v0.4s, v1.4s` 绝不误落入标量 lift_data_insn 给出假阳性 verified=true！
    let unmodeled_words: [u32; 5] = [
        0x3DC0_0000, // ldr q0, [x0]
        0x3DC0_0021, // ldr q1, [x1]
        0x4EA1_9C00, // mul v0.4s, v0.4s, v1.4s (未建模向量乘法)
        0x3D80_0040, // str q0, [x2]
        0xD65F_03C0, // ret
    ];
    let unmodeled_code: Vec<u8> = unmodeled_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let (u_idx, u_ext, _, _, u_out, _) =
        trace_arm64_words("neon_unmodeled_mul", &unmodeled_code, &in0, &in1, 16);
    let u_reader = TraceReader::open(&u_idx, Some(&u_ext)).unwrap();
    let u_rep = u_reader.decompile_slice(
        &TaintSeed::Mem { addr: u_out, len: 16 },
        &DecompileOptions {
            function_name: "uint64_t".to_string(), // 顺便验证 sanitize_c_ident 拦截 typedef 名！
            ..Default::default()
        },
    );
    assert_eq!(
        u_rep.verified, None,
        "未建模向量 mul 必须降级为 Opaque (verified=None)，绝不可误走标量乘法:\n{}",
        u_rep.format_summary()
    );
    assert!(u_rep.c_code.contains("opaque:"), "{}", u_rep.c_code);
    assert!(
        u_rep.c_code.contains("void decompiled_slice("),
        "typedef 保留名 uint64_t 应被安全规避:\n{}",
        u_rep.c_code
    );
    // 即使含 Opaque，生成的 C 也必须通过 -O2 -Wall -Werror（无未引用 CSE 临时变量 / 无 shift-count-overflow）
    let opq_harness = format!("{}\nint main(void) {{ return 0; }}\n", u_rep.c_code);
    compile_and_run_c(u_idx.parent().unwrap(), "verify_opaque_clean", &opq_harness);
}

#[test]
fn test_decompile_v2_armv8_hardware_aes_encrypt_and_decrypt_rounds() {
    // 严格对照 NIST FIPS-197 Appendix B 第 1 轮真值：
    //   plaintext = 3243f6a8885a308d313198a2e0370734
    //   rk0       = 2b7e151628aed2a6abf7158809cf4f3c
    //   rk1       = a0fafe1788542cb123a339392a6c7605
    //   AESMC(AESE(pt, rk0))           = 046681e5e0cb199a48f8d37a2806264c
    //   AESMC(AESE(pt, rk0)) ^ rk1     = a49c7ff2689f352b6b5bea43026a5049 (FIPS-197 Round 1 输出!)
    //
    //   in0[0..16]  = plaintext
    //   in1[0..16]  = rk0
    //   in1[16..32] = rk1
    let enc_words: [u32; 8] = [
        0x3DC0_0000, // ldr q0, [x0]          (plaintext)
        0xAD40_0821, // ldp q1, q2, [x1]      (q1 = rk0, q2 = rk1; 同时验证 LDP Q!)
        0x4E28_4820, // aese v0.16b, v1.16b   (SubBytes(ShiftRows(pt ^ rk0)))
        0x4E28_6800, // aesmc v0.16b, v0.16b  (MixColumns)
        0x6E22_1C00, // eor v0.16b, v0.16b, v2.16b (^ rk1)
        0x3D80_0040, // str q0, [x2]
        0xD65F_03C0, // ret
        0xD503_201F, // nop
    ];
    let enc_code: Vec<u8> = enc_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let pt: [u8; 16] = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    ];
    let rk0: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    let rk1: [u8; 16] = [
        0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1,
        0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05,
    ];
    let expected_nist_r1: [u8; 16] = [
        0xa4, 0x9c, 0x7f, 0xf2, 0x68, 0x9f, 0x35, 0x2b,
        0x6b, 0x5b, 0xea, 0x43, 0x02, 0x6a, 0x50, 0x49,
    ];
    let mut keys = Vec::with_capacity(32);
    keys.extend_from_slice(&rk0);
    keys.extend_from_slice(&rk1);

    let (idx_path, ext_path, _in0_buf, _in1_buf, out_buf, actual_ct) =
        trace_arm64_words("hw_aes_enc", &enc_code, &pt, &keys, 16);
    assert_eq!(
        actual_ct.as_slice(),
        expected_nist_r1.as_slice(),
        "Unicorn ARMv8-CE 加密轮输出必须精确匹配 NIST FIPS-197 Appendix B Round 1"
    );

    let reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();
    let report = reader.decompile_slice(
        &TaintSeed::Mem {
            addr: out_buf,
            len: 16,
        },
        &DecompileOptions {
            function_name: "hw_aes_round".to_string(),
            emit_smt2: true,
            ..Default::default()
        },
    );

    assert_eq!(
        report.verified,
        Some(true),
        "ARMv8-CE 硬件 AESE+AESMC+EOR 必须逐 bit 校验通过:\n{}",
        report.format_summary()
    );
    assert!(
        report.c_code.contains("AES_AESE_LO(") && report.c_code.contains("AES_MC_LO("),
        "应输出标准 AES_AESE / AES_MC 原语:\n{}",
        report.c_code
    );
    let smt = report.smt2.as_deref().expect("smt2");
    assert!(smt.contains("(set-logic QF_UFBV)"));
    assert!(smt.contains("(declare-fun aes_aese_lo"));
    assert!(smt.contains("(declare-fun aes_mc_lo"));

    // 同步验证真逆向解密轮：`ct ^ rk1 -> AESIMC -> AESD(0) -> ^ rk0 == pt`（精确还原明文！）
    let dec_words: [u32; 8] = [
        0x3DC0_0000, // ldr q0, [x0]            (ct = expected_nist_r1)
        0xAD40_0821, // ldp q1, q2, [x1]        (q1 = rk0, q2 = rk1)
        0x4F00_0403, // movi v3.16b, #0         (零密钥)
        0x6E22_1C00, // eor v0.16b, v0.16b, v2.16b  (ct ^ rk1)
        0x4E28_7800, // aesimc v0.16b, v0.16b   (InvMixColumns)
        0x4E28_5860, // aesd v0.16b, v3.16b     (InvSubBytes(InvShiftRows(state ^ 0)))
        0x6E21_1C00, // eor v0.16b, v0.16b, v1.16b  (^ rk0 == pt!)
        0x3D80_0040, // str q0, [x2]
    ];
    let mut dec_code: Vec<u8> = dec_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    dec_code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // ret

    let (d_idx, d_ext, _, _, d_out, d_actual) =
        trace_arm64_words("hw_aes_dec", &dec_code, &expected_nist_r1, &keys, 16);
    assert_eq!(
        d_actual.as_slice(),
        pt.as_slice(),
        "真逆向解密轮必须精确还原回 NIST FIPS-197 明文 pt！"
    );

    let d_reader = TraceReader::open(&d_idx, Some(&d_ext)).unwrap();
    let d_report = d_reader.decompile_slice(
        &TaintSeed::Mem {
            addr: d_out,
            len: 16,
        },
        &DecompileOptions {
            function_name: "hw_aes_dec_round".to_string(),
            ..Default::default()
        },
    );
    assert_eq!(
        d_report.verified,
        Some(true),
        "ARMv8-CE 硬件 AESIMC+AESD 逆向解密必须逐 bit 校验通过:\n{}",
        d_report.format_summary()
    );
    assert!(d_report.c_code.contains("AES_AESD_LO(") && d_report.c_code.contains("AES_IMC_LO("));

    // 将加密 C 与解密 C 一起真编译，既验证 NIST FIPS-197 向量，也用全新未见过的明文/密钥验证 `dec(enc(pt2, keys2), keys2) == pt2`！
    let combined_harness = format!(
        r#"
{enc_c}
{dec_c}
#include <stdio.h>
#include <string.h>
int main(void) {{
    // 1. NIST FIPS-197 Appendix B 硬编码向量
    uint8_t pt1[16] = {{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 }};
    uint8_t keys1[32] = {{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05
    }};
    uint8_t nist_r1[16] = {{ 0xa4, 0x9c, 0x7f, 0xf2, 0x68, 0x9f, 0x35, 0x2b, 0x6b, 0x5b, 0xea, 0x43, 0x02, 0x6a, 0x50, 0x49 }};
    uint8_t ct1[16] = {{0}}, rt1[16] = {{0}};
    hw_aes_round(pt1, keys1, ct1);
    if (memcmp(ct1, nist_r1, 16) != 0) {{ fprintf(stderr, "FIPS-197 R1 encrypt mismatch\n"); return 1; }}
    hw_aes_dec_round(ct1, keys1, rt1);
    if (memcmp(rt1, pt1, 16) != 0) {{ fprintf(stderr, "FIPS-197 R1 decrypt mismatch\n"); return 2; }}

    // 2. 全新未见输入：验证加解密互逆
    uint8_t pt2[16] = {{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }};
    uint8_t keys2[32] = {{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe
    }};
    uint8_t ct2[16] = {{0}}, rt2[16] = {{0}};
    hw_aes_round(pt2, keys2, ct2);
    hw_aes_dec_round(ct2, keys2, rt2);
    if (memcmp(rt2, pt2, 16) != 0) {{ fprintf(stderr, "Unseen vector AES roundtrip mismatch\n"); return 3; }}
    return 0;
}}
"#,
        enc_c = report.c_code,
        dec_c = d_report.c_code.replace("#include <stdint.h>\n\n", "").replace(
            "static inline uint64_t LOAD64_LE(const uint8_t *p) { return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56); }\n",
            ""
        ).replace(
            "static inline void STORE64_LE(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (i * 8)); }\n",
            ""
        ).replace(
            "static inline uint64_t aes_pack64(const uint8_t *p) { uint64_t r = 0; for (int i = 0; i < 8; ++i) r |= ((uint64_t)p[i] << (i * 8)); return r; }\n",
            ""
        ).replace(
            "static inline void aes_unpack128(uint64_t lo, uint64_t hi, uint8_t out[16]) { for (int i = 0; i < 8; ++i) { out[i] = (uint8_t)(lo >> (i * 8)); out[i + 8] = (uint8_t)(hi >> (i * 8)); } }\n",
            ""
        ).replace(
            "static inline uint8_t aes_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0u)); }\n",
            ""
        )
    );
    compile_and_run_c(idx_path.parent().unwrap(), "verify_hw_aes_roundtrip", &combined_harness);
}

#[test]
fn test_decompile_v2_cli_multi_output_16b_and_validation() {
    let asm = r#"
        ldr x4, [x0]
        ldr x5, [x0, #8]
        eor x6, x4, x5
        add x7, x4, x5
        str x6, [x2]
        str x7, [x2, #8]
        ret
    "#;
    let code = good64::assemble(asm, 0x4000_0000).unwrap();
    let in0: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    ];
    let (idx_path, ext_path, _, _, out_buf, _) =
        trace_arm64_words("cli_16b", &code, &in0, &[], 16);

    let cli = Command::new(env!("CARGO_BIN_EXE_runidbg-cli"))
        .args([
            "decompile",
            idx_path.to_str().unwrap(),
            "--ext",
            ext_path.to_str().unwrap(),
            "--addr",
            &format!("0x{out_buf:x}"),
            "--len",
            "16",
            "--fn",
            "cli_buf16",
        ])
        .output()
        .expect("run runidbg-cli decompile --len 16");
    assert!(
        cli.status.success(),
        "CLI decompile --len 16 失败: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_out = String::from_utf8_lossy(&cli.stdout);
    assert!(cli_out.contains("verify=PASS (bit-exact)"), "stdout:\n{cli_out}");
    assert!(
        cli_out.contains("void cli_buf16(const uint8_t *in_0, uint8_t *out)"),
        "stdout:\n{cli_out}"
    );

    // 边界拒绝测试：--len 0 与 --len 65
    for bad in ["0", "65"] {
        let bad_cli = Command::new(env!("CARGO_BIN_EXE_runidbg-cli"))
            .args([
                "decompile",
                idx_path.to_str().unwrap(),
                "--addr",
                &format!("0x{out_buf:x}"),
                "--len",
                bad,
            ])
            .output()
            .expect("run cli bad len");
        assert!(!bad_cli.status.success(), "CLI --len {bad} 必须报错拒绝");
    }
}

#[cfg(feature = "js")]
#[test]
fn test_decompile_v2_js_multi_output_16b_and_strict_len() {
    use runidbg_arm64_emu_tracer::script::JsSession;
    use std::path::Path;

    let asm = r#"
        ldr x4, [x0]
        ldr x5, [x0, #8]
        eor x6, x4, x5
        add x7, x4, x5
        str x6, [x2]
        str x7, [x2, #8]
        ret
    "#;
    let code = good64::assemble(asm, 0x4000_0000).unwrap();
    let in0: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    ];
    let (idx_path, ext_path, _, _, out_buf, actual_out) =
        trace_arm64_words("js_16b", &code, &in0, &[], 16);
    let expected_hex: String = actual_out.iter().map(|b| format!("{b:02x}")).collect();

    let session = JsSession::new(&[], Path::new("."), true).unwrap();
    let js = format!(
        r#"
        (() => {{
            const tr = Trace.open({idx:?}, {ext:?});
            const rep = tr.decompileSlice({{ addr: 0x{out_buf:x}n, len: 16, functionName: "js_buf16" }});
            if (rep.verified !== true) throw new Error("verified=" + rep.verified);
            if (rep.outputLen !== 16) throw new Error("outputLen=" + rep.outputLen);
            if (rep.expectedOutputHex !== undefined) throw new Error("multi-out should omit scalar expectedOutputHex");
            if (rep.expectedOutputBytesHex !== {expected_hex:?}) throw new Error("exp mismatch: " + rep.expectedOutputBytesHex);
            if (rep.evaluatedOutputBytesHex !== {expected_hex:?}) throw new Error("ev mismatch: " + rep.evaluatedOutputBytesHex);
            if (!rep.cCode.includes("STORE64_LE") || !rep.cCode.includes("LOAD64_LE")) throw new Error("missing LOAD/STORE");
            for (const bad of [0, -1, 65, 16.5, NaN, "16"]) {{
                let threw = false;
                try {{ tr.decompileSlice({{ addr: 0x{out_buf:x}n, len: bad }}); }} catch (_) {{ threw = true; }}
                if (!threw) throw new Error("JS decompileSlice should reject len=" + String(bad));
            }}
            tr.close();
            return "OK";
        }})()
        "#,
        idx = idx_path.to_str().unwrap(),
        ext = ext_path.to_str().unwrap()
    );
    let js_res = session.eval_json_string(&js).unwrap();
    assert_eq!(js_res, "\"OK\"");
}

#[cfg(feature = "mcp")]
#[test]
fn test_decompile_v2_mcp_multi_output_16b_and_strict_len() {
    use runidbg_arm64_emu_tracer::script::mcp::McpServer;
    use serde_json::json;
    use std::path::Path;

    let asm = r#"
        ldr x4, [x0]
        ldr x5, [x0, #8]
        eor x6, x4, x5
        add x7, x4, x5
        str x6, [x2]
        str x7, [x2, #8]
        ret
    "#;
    let code = good64::assemble(asm, 0x4000_0000).unwrap();
    let in0: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    ];
    let (idx_path, ext_path, _, _, out_buf, actual_out) =
        trace_arm64_words("mcp_16b", &code, &in0, &[], 16);
    let expected_hex: String = actual_out.iter().map(|b| format!("{b:02x}")).collect();

    let mut mcp = McpServer::new(Path::new("."), None).unwrap();
    let req = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "trace_decompile",
            "arguments": {
                "idxPath": idx_path.to_str().unwrap(),
                "extPath": ext_path.to_str().unwrap(),
                "addr": format!("0x{out_buf:x}"),
                "len": 16,
                "functionName": "mcp_buf16"
            }
        }
    });
    let resp_str = mcp.handle_message(&req.to_string()).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["verified"], json!(true));
    assert_eq!(body["outputLen"], json!(16));
    assert_eq!(body["expectedOutputHex"], json!(null));
    assert_eq!(body["expectedOutputBytesHex"], json!(expected_hex));
    assert_eq!(body["evaluatedOutputBytesHex"], json!(expected_hex));

    for bad_len in [0, 65] {
        let bad_req = json!({
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "trace_decompile",
                "arguments": {
                    "idxPath": idx_path.to_str().unwrap(),
                    "addr": format!("0x{out_buf:x}"),
                    "len": bad_len
                }
            }
        });
        let bad_resp_str = mcp.handle_message(&bad_req.to_string()).unwrap();
        let bad_resp: serde_json::Value = serde_json::from_str(&bad_resp_str).unwrap();
        assert!(
            bad_resp["result"]["isError"] == json!(true) || bad_resp.get("error").is_some(),
            "MCP trace_decompile 应拒绝 len={bad_len}: {bad_resp_str}"
        );
    }
}
