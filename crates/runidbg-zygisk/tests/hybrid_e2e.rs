//! Milestone 1 真机 ARM64 端到端集成测试（在 Apple Silicon / ARM64 Linux 上真实执行）
//!
//! 覆盖 4 大核心契约：
//! 1. 1:1 零拷贝 `uc_mem_map_ptr` + 真实 `libc`（`malloc`/`memcpy`/`gettimeofday`/`free`）原生逃逸
//!    + 自动 `dladdr` HLE + `.rtrace` 直出 + 离线 `TraceReader::open` & `decompile_slice` `verified == Some(true)`；
//! 2. Shadow Pristine Page 绕过 `.text` 自校验反篡改 + `max_hits` 耗尽后经 `good64` 重定位回退跳板零开销直通；
//! 3. 嵌套重入（Depth 2：模拟 -> 原生回调 -> 再次进入 Hook 模拟）+ 4 线程并发执行；
//! 4. 超过 8 个参数（栈传参 `a8`/`a9`）与 128-bit NEON `Q0`/`Q1` 跨逃逸桥位精确传递。

#![cfg(target_arch = "aarch64")]

use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, Mutex};

use runidbg_arm64_emu_tracer::good64::assemble;
use runidbg_arm64_emu_tracer::tracer::{DecompileOptions, TaintSeed, TraceLevel, TraceReader};
use runidbg_zygisk::config::HybridConfig;
use runidbg_zygisk::hybrid::{HybridRuntime, TraceOutputEvent};
use runidbg_zygisk::inline_hook::{flush_icache, macos_jit_write_protect};
use runidbg_zygisk::mem_map::os_page_size;

/// 串行化共享全局 `HybridRuntime::global()` 的集成测试锁
static TEST_SERIAL: Mutex<()> = Mutex::new(());

/// 分配独立的可执行代码页（模拟真实加载的 `.so` `.text` 段）并写入 `good64` 汇编机器码
struct JitCodePage {
    base: *mut u8,
    len: usize,
    is_jit: bool,
}

impl JitCodePage {
    fn from_asm(asm_src: &str) -> Self {
        let page = os_page_size().max(4096);
        let len = page * 2;
        #[cfg(target_os = "macos")]
        let (flags, is_jit) = (libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT, true);
        #[cfg(not(target_os = "macos"))]
        let (flags, is_jit) = (libc::MAP_PRIVATE | libc::MAP_ANON, false);

        // SAFETY: 匿名可执行映射用于装载测试机器码
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                flags,
                -1,
                0,
            )
        };
        assert!(ptr != libc::MAP_FAILED && !ptr.is_null(), "mmap code page failed");
        let base = ptr as *mut u8;
        let base_va = base as usize as u64;
        let code = assemble(asm_src, base_va).expect("good64::assemble failed");
        assert!(code.len() <= len);

        // SAFETY: 写入新分配的代码页并刷新指令缓存
        unsafe {
            if is_jit {
                macos_jit_write_protect(false);
            }
            ptr::write_bytes(base, 0, len);
            ptr::copy_nonoverlapping(code.as_ptr(), base, code.len());
            if is_jit {
                macos_jit_write_protect(true);
            }
            flush_icache(base, code.len());
        }

        Self { base, len, is_jit }
    }

    fn base_va(&self) -> u64 {
        self.base as usize as u64
    }

    fn end_va(&self) -> u64 {
        self.base_va() + self.len as u64
    }
}

impl Drop for JitCodePage {
    fn drop(&mut self) {
        // SAFETY: 释放由 mmap 分配的测试代码页
        unsafe {
            libc::munmap(self.base as *mut c_void, self.len);
        }
    }
}

#[test]
fn test_hybrid_e2e_escape_hle_and_decompile() {
    let _guard = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rt = HybridRuntime::global();
    rt.reset_for_tests().unwrap();

    // 汇编一段调用真实 libc::malloc / memcpy / gettimeofday / free 并完成确定性算术变换的 ARM64 函数：
    // uint64_t target(u64 a, u64 b, void* malloc_fn, void* memcpy_fn, void* free_fn, void* gtod_fn)
    // 返回：((a ^ 0x1234) + (b * 5)) ^ 0x99
    // 同时经由真实 malloc + memcpy 往返堆内存，并调用真实 gettimeofday 写入独立模拟栈局部 timeval！
    let code_page = JitCodePage::from_asm(
        r#"
        stp x29, x30, [sp, #-80]!
        mov x29, sp
        stp x19, x20, [sp, #16]
        stp x21, x22, [sp, #32]
        stp x23, x24, [sp, #48]

        mov x19, x0              // a
        mov x20, x1              // b
        mov x21, x3              // memcpy
        mov x22, x4              // free
        mov x23, x5              // gettimeofday

        // 1. 逃逸调用真实 libc::malloc(64)
        mov x0, #64
        blr x2
        mov x24, x0              // heap_ptr

        // 2. 在模拟栈局部槽 [sp, #64] 写入 (a ^ 0x1234) 与 (b * 5)
        mov x9, #0x1234
        eor x10, x19, x9
        add x11, x20, x20, lsl #2   // b * 5
        str x10, [sp, #64]
        str x11, [sp, #72]

        // 3. 逃逸调用真实 libc::memcpy(heap_ptr, sp + 64, 16)
        mov x0, x24
        add x1, sp, #64
        mov x2, #16
        blr x21

        // 4. 逃逸调用真实 libc::gettimeofday(sp + 64, NULL)（直接写入 1:1 模拟栈！）
        add x0, sp, #64
        mov x1, #0
        blr x23

        // 5. 从真实堆内存回读 memcpy 后的两个值并计算最终输出
        ldr x12, [x24, #0]
        ldr x13, [x24, #8]
        add x19, x12, x13
        mov x14, #0x99
        eor x19, x19, x14

        // 6. 逃逸调用真实 libc::free(heap_ptr)
        mov x0, x24
        blr x22

        mov x0, x19
        ldp x23, x24, [sp, #48]
        ldp x21, x22, [sp, #32]
        ldp x19, x20, [sp, #16]
        ldp x29, x30, [sp], #80
        ret
        "#,
    );

    let captured: Arc<Mutex<Vec<TraceOutputEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let cap_clone = Arc::clone(&captured);
    rt.set_config(HybridConfig {
        trace_level: TraceLevel::Full,
        max_insns: 100_000,
        max_hits: 4,
        ..Default::default()
    });
    rt.set_trace_sink(Some(Arc::new(move |ev| {
        cap_clone.lock().unwrap().push(ev);
    })));
    rt.register_emulated_module(
        "libdemo_test.so",
        code_page.base_va(),
        code_page.end_va(),
        vec![(code_page.base_va(), code_page.end_va())],
    );
    let hook_id = rt
        .install_hook(
            "demo_compute",
            code_page.base_va(),
            code_page.base_va(),
            Some(4),
            code_page.is_jit,
        )
        .expect("install_hook failed");

    type TargetFn = extern "C" fn(
        u64,
        u64,
        *const c_void,
        *const c_void,
        *const c_void,
        *const c_void,
    ) -> u64;

    // SAFETY: code_page 包含合法 AAPCS64 函数且已被 InlineHook 接管
    let f: TargetFn = unsafe { std::mem::transmute(code_page.base_va() as usize) };
    let a = 0x1000_2000u64;
    let b = 0x0000_0042u64;
    let expected = ((a ^ 0x1234).wrapping_add(b.wrapping_mul(5))) ^ 0x99;

    let actual = f(
        a,
        b,
        libc::malloc as *const c_void,
        libc::memcpy as *const c_void,
        libc::free as *const c_void,
        libc::gettimeofday as *const c_void,
    );
    assert_eq!(actual, expected, "混合模拟结果必须与原生语义完全一致");

    let events = captured.lock().unwrap();
    assert_eq!(events.len(), 1, "应产出 1 份 .rtrace");
    let ev = &events[0];
    assert_eq!(ev.escapes, 4, "应捕获 malloc/memcpy/gettimeofday/free 共 4 次逃逸");
    assert!(ev.info.idx_insns >= 25, "应录制完整指令流，实测 {}", ev.info.idx_insns);
    assert!(ev.info.has_ext && ev.info.ext_events > 0, "Full 级别应含扩展访存与 HLE 流");

    // 将内存直出的 .rtrace 落盘并用 runidbg 离线 TraceReader 完整校验（含 HLE + decompile 位精确自校验！）
    let tmp_path = std::env::temp_dir().join(format!(
        "runidbg_zygisk_e2e_{}.rtrace",
        std::process::id()
    ));
    std::fs::write(&tmp_path, &ev.rtrace_bytes).expect("write temp .rtrace");
    let reader = TraceReader::open(&tmp_path, None).expect("TraceReader::open(.rtrace) failed");
    let _ = std::fs::remove_file(&tmp_path);

    let hles = reader.hle_events();
    let hle_ops: Vec<&str> = hles.iter().map(|h| h.op).collect();
    assert!(
        hle_ops.contains(&"malloc"),
        "HLE 列表应包含 malloc，实际: {hle_ops:?}"
    );
    assert!(
        hle_ops.contains(&"memcpy") || hle_ops.contains(&"memmove"),
        "HLE 列表应包含 memcpy/memmove，实际: {hle_ops:?}"
    );
    assert!(
        hle_ops.contains(&"gettimeofday"),
        "HLE 列表应包含 gettimeofday，实际: {hle_ops:?}"
    );
    assert!(
        hle_ops.contains(&"free"),
        "HLE 列表应包含 free，实际: {hle_ops:?}"
    );

    // 对最终 RET 指令前的 X0 执行离线反向切片反编译，验证与离线分析工具链 100% 兼容且位精确！
    let last_seq = reader.len() - 1;
    let report = reader.decompile_slice(
        &TaintSeed::Reg { reg_id: 0 },
        &DecompileOptions {
            anchor_idx: Some(last_seq),
            ..Default::default()
        },
    );
    assert_eq!(
        report.verified,
        Some(true),
        "混合引擎产出的 .rtrace 经离线反编译自校验必须 PASS！report:\n{:?}",
        report
    );

    rt.uninstall_hook(hook_id).unwrap();
    rt.reset_for_tests().unwrap();
}

#[test]
fn test_hybrid_shadow_pristine_page_and_max_hits_fallback() {
    let _guard = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rt = HybridRuntime::global();
    rt.reset_for_tests().unwrap();

    // 目标函数主动读取自身入口首条指令字（模拟 .text CRC 防篡改自校验）并组合参数返回：
    // uint64_t self_check(uint64_t self_addr, uint64_t x) -> ((*(uint32_t*)self_addr) << 32) | (x + 42)
    let code_page = JitCodePage::from_asm(
        r#"
        stp x29, x30, [sp, #-16]!
        mov x29, sp
        ldr w9, [x0]
        add x10, x1, #42
        lsl x9, x9, #32
        orr x0, x9, x10
        ldp x29, x30, [sp], #16
        ret
        "#,
    );

    // 记录打 Inline Hook 之前原始的首条指令字（stp x29, x30, [sp, #-16]! = 0xA9BF7BFD）
    let orig_word0 = unsafe { ptr::read_unaligned(code_page.base as *const u32) };
    assert_eq!(orig_word0, 0xA9BF_7BFD);

    let trace_count = Arc::new(Mutex::new(0usize));
    let tc_clone = Arc::clone(&trace_count);
    rt.set_config(HybridConfig {
        trace_level: TraceLevel::RegDelta,
        max_hits: 2,
        ..Default::default()
    });
    rt.set_trace_sink(Some(Arc::new(move |_| {
        *tc_clone.lock().unwrap() += 1;
    })));
    rt.register_emulated_module(
        "libanti_tamper.so",
        code_page.base_va(),
        code_page.end_va(),
        vec![(code_page.base_va(), code_page.end_va())],
    );
    let hook_id = rt
        .install_hook(
            "self_check",
            code_page.base_va(),
            code_page.base_va(),
            Some(2),
            code_page.is_jit,
        )
        .expect("install_hook failed");

    // 确认宿主内存中入口确实已被写为 16B Inline Hook（ldr x16, #8 = 0x58000050）
    let patched_word0 = unsafe { ptr::read_unaligned(code_page.base as *const u32) };
    assert_eq!(patched_word0, 0x5800_0050);

    type CheckFn = extern "C" fn(u64, u64) -> u64;
    let f: CheckFn = unsafe { std::mem::transmute(code_page.base_va() as usize) };

    // 第 1、2 次调用走 Unicorn 模拟：必须看到 Shadow Pristine Page 里的原始字节 orig_word0！
    let r1 = f(code_page.base_va(), 100);
    assert_eq!(r1 >> 32, u64::from(orig_word0), "Unicorn 内读取自身 .text 必须命中 Shadow Pristine Page");
    assert_eq!(r1 & 0xFFFF_FFFF, 142);

    let r2 = f(code_page.base_va(), 200);
    assert_eq!(r2 >> 32, u64::from(orig_word0));
    assert_eq!(r2 & 0xFFFF_FFFF, 242);
    assert_eq!(*trace_count.lock().unwrap(), 2);

    // 第 3 次调用超过 max_hits=2：必须零开销尾跳转至 good64 重定位回退跳板（原生执行，不产出新 trace）！
    let r3 = f(code_page.base_va(), 300);
    assert_eq!(r3 & 0xFFFF_FFFF, 342, "回退跳板原生执行算术逻辑必须正确");
    assert_eq!(
        r3 >> 32,
        u64::from(patched_word0),
        "回退路径在真实 CPU 上执行，应读到已打补丁的实时内存字，证明确实跳过了 Unicorn"
    );
    assert_eq!(*trace_count.lock().unwrap(), 2, "超出 max_hits 不应再产生 Trace");

    rt.uninstall_hook(hook_id).unwrap();
    // 卸载后原字节恢复
    let restored_word0 = unsafe { ptr::read_unaligned(code_page.base as *const u32) };
    assert_eq!(restored_word0, orig_word0);
    rt.reset_for_tests().unwrap();
}

extern "C" fn native_reenter_callback(val: u64, self_fn_va: u64) -> u64 {
    if val == 0 {
        return 1;
    }
    type RecFn = extern "C" fn(u64, *const c_void, u64) -> u64;
    let f: RecFn = unsafe { std::mem::transmute(self_fn_va as usize) };
    // 再次进入同一个被 Hook 的函数（Depth 2 重入！）
    f(val - 1, native_reenter_callback as *const c_void, self_fn_va)
}

#[test]
fn test_hybrid_reentrancy_and_multithreading() {
    let _guard = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rt = HybridRuntime::global();
    rt.reset_for_tests().unwrap();

    // 递归函数：rec(n, cb, self_va) -> if n == 0 { 10 } else { n + cb(n, self_va) }
    // 其中 cb 是原生 Rust 函数，又会重入调用 rec(n - 1, cb, self_va) -> 验证 Depth 1..4 嵌套重入！
    let code_page = JitCodePage::from_asm(
        r#"
        stp x29, x30, [sp, #-32]!
        mov x29, sp
        stp x19, x20, [sp, #16]

        mov x19, x0          // n
        cbnz x19, recurse
        mov x0, #10
        b done
    recurse:
        mov x0, x19          // arg0 = n
        mov x20, x1          // cb
        mov x1, x2           // arg1 = self_va
        blr x20              // 逃逸调用原生回调 -> 原生回调重入本 Hook！
        add x0, x0, x19
    done:
        ldp x19, x20, [sp, #16]
        ldp x29, x30, [sp], #32
        ret
        "#,
    );

    let total_traces = Arc::new(Mutex::new(0usize));
    let tt_clone = Arc::clone(&total_traces);
    rt.set_config(HybridConfig {
        trace_level: TraceLevel::Fast,
        max_hits: 0, // 不限次
        max_reentry_depth: 8,
        ..Default::default()
    });
    rt.set_trace_sink(Some(Arc::new(move |_| {
        *tt_clone.lock().unwrap() += 1;
    })));
    rt.register_emulated_module(
        "libreentry.so",
        code_page.base_va(),
        code_page.end_va(),
        vec![(code_page.base_va(), code_page.end_va())],
    );
    let hook_id = rt
        .install_hook(
            "recursive_fn",
            code_page.base_va(),
            code_page.base_va(),
            Some(0),
            code_page.is_jit,
        )
        .expect("install_hook failed");

    type RecFn = extern "C" fn(u64, *const c_void, u64) -> u64;
    let fn_va = code_page.base_va();
    let f: RecFn = unsafe { std::mem::transmute(fn_va as usize) };

    // 1. 单线程 3 层重入验证：rec(3) = 3 + 2 + 1 + 10 = 16
    assert_eq!(f(3, native_reenter_callback as *const c_void, fn_va), 16);

    // 2. 4 线程并发 + 每线程内含嵌套重入验证
    let mut handles = Vec::new();
    for t in 0..4u64 {
        handles.push(std::thread::spawn(move || {
            let f_local: RecFn = unsafe { std::mem::transmute(fn_va as usize) };
            for iter in 0..5u64 {
                let n = (t + iter) % 4; // 0..3
                let expected = 10 + n * (n + 1) / 2;
                let got = f_local(n, native_reenter_callback as *const c_void, fn_va);
                assert_eq!(got, expected, "thread={t} iter={iter} n={n}");
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }

    assert!(*total_traces.lock().unwrap() >= 24);
    rt.uninstall_hook(hook_id).unwrap();
    rt.reset_for_tests().unwrap();
}

extern "C" fn native_ten_arg_helper(
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
    a9: u64,
) -> u64 {
    a0.wrapping_add(a1)
        .wrapping_add(a2)
        .wrapping_add(a3)
        .wrapping_add(a4)
        .wrapping_add(a5)
        .wrapping_add(a6)
        .wrapping_add(a7)
        .wrapping_add(a8.wrapping_mul(10))
        .wrapping_add(a9.wrapping_mul(100))
}

#[allow(improper_ctypes_definitions)]
extern "C" fn native_neon_xor_helper(
    a: std::arch::aarch64::uint64x2_t,
    b: std::arch::aarch64::uint64x2_t,
) -> std::arch::aarch64::uint64x2_t {
    // SAFETY: ARM64 硬件必支持 NEON veorq_u64
    unsafe { std::arch::aarch64::veorq_u64(a, b) }
}

#[test]
fn test_hybrid_stack_args_and_neon_escape() {
    let _guard = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rt = HybridRuntime::global();
    rt.reset_for_tests().unwrap();

    // 1) 测试超过 8 个参数（a8, a9 在入口栈上），同时再通过栈参数逃逸调用 10 参数原生函数！
    // uint64_t forward_10(a0..a7, a8, a9, helper_ptr) -> helper(a0..a7, a8, a9)
    // 注意：入口处 [orig_sp, #0]=a8, [orig_sp, #8]=a9, [orig_sp, #16]=helper_ptr
    // 将 FP/LR 保存在 [sp, #32..48]，空出 [sp, #0..32] 放置出参栈参数！
    let code_page = JitCodePage::from_asm(
        r#"
        sub sp, sp, #48
        stp x29, x30, [sp, #32]
        add x29, sp, #32

        // 入口栈参数在 [sp, #48 + 0/8/16]
        ldr x9,  [sp, #48]     // a8
        ldr x10, [sp, #56]     // a9
        ldr x11, [sp, #64]     // helper_ptr

        // 为逃逸调用原生 10 参数函数准备本帧栈参数 [sp, #0]=a8, [sp, #8]=a9
        str x9,  [sp, #0]
        str x10, [sp, #8]
        blr x11

        ldp x29, x30, [sp, #32]
        add sp, sp, #48
        ret
        "#,
    );

    rt.set_config(HybridConfig {
        trace_level: TraceLevel::RegDelta,
        max_hits: 4,
        ..Default::default()
    });
    rt.register_emulated_module(
        "libstack_args.so",
        code_page.base_va(),
        code_page.end_va(),
        vec![(code_page.base_va(), code_page.end_va())],
    );
    let hook_id = rt
        .install_hook(
            "forward_10",
            code_page.base_va(),
            code_page.base_va(),
            Some(4),
            code_page.is_jit,
        )
        .expect("install_hook failed");

    type TenArgPlusFn = extern "C" fn(
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        u64,
        *const c_void,
    ) -> u64;
    let f: TenArgPlusFn = unsafe { std::mem::transmute(code_page.base_va() as usize) };

    let got = f(
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        native_ten_arg_helper as *const c_void,
    );
    let expected = native_ten_arg_helper(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    assert_eq!(got, expected, "超过 8 个栈参数的入口传入与原生逃逸透传必须完全一致");
    rt.uninstall_hook(hook_id).unwrap();

    // 2) 测试 128-bit NEON Q0/Q1 入参 -> 逃逸原生 NEON 函数 -> Q0 返回值全链路位精确！
    // uint64x2_t neon_bridge(uint64x2_t a, uint64x2_t b, void* helper_ptr)
    let neon_page = JitCodePage::from_asm(
        r#"
        stp x29, x30, [sp, #-16]!
        mov x29, sp
        blr x0
        ldp x29, x30, [sp], #16
        ret
        "#,
    );
    rt.register_emulated_module(
        "libneon_test.so",
        neon_page.base_va(),
        neon_page.end_va(),
        vec![(neon_page.base_va(), neon_page.end_va())],
    );
    let neon_hook = rt
        .install_hook(
            "neon_bridge",
            neon_page.base_va(),
            neon_page.base_va(),
            Some(4),
            neon_page.is_jit,
        )
        .expect("install neon hook failed");

    #[allow(improper_ctypes_definitions)]
    type NeonBridgeFn = extern "C" fn(
        *const c_void,
        std::arch::aarch64::uint64x2_t,
        std::arch::aarch64::uint64x2_t,
    ) -> std::arch::aarch64::uint64x2_t;
    let nf: NeonBridgeFn = unsafe { std::mem::transmute(neon_page.base_va() as usize) };
    // SAFETY: ARM64 硬件构造 128-bit NEON 向量
    unsafe {
        let a_arr = [0x0123_4567_89AB_CDEFu64, 0xFEDC_BA98_7654_3210u64];
        let b_arr = [0x1111_2222_3333_4444u64, 0x5555_6666_7777_8888u64];
        let va = std::arch::aarch64::vld1q_u64(a_arr.as_ptr());
        let vb = std::arch::aarch64::vld1q_u64(b_arr.as_ptr());
        let out = nf(native_neon_xor_helper as *const c_void, va, vb);
        let mut out_arr = [0u64; 2];
        std::arch::aarch64::vst1q_u64(out_arr.as_mut_ptr(), out);
        assert_eq!(out_arr[0], a_arr[0] ^ b_arr[0], "NEON Q0 低 64 位位精确");
        assert_eq!(out_arr[1], a_arr[1] ^ b_arr[1], "NEON Q0 高 64 位位精确");
    }

    rt.uninstall_hook(neon_hook).unwrap();
    rt.reset_for_tests().unwrap();
}

#[test]
fn test_hybrid_svc_passthrough_tail_call_and_max_insns_continuation() {
    let _guard = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rt = HybridRuntime::global();
    rt.reset_for_tests().unwrap();

    // 1) SVC #0 透传测试：svc #0 后紧跟 `add x0, x0, #7; ret` —— 严禁跳过 svc+4 指令！
    let svc_page = JitCodePage::from_asm(
        r#"
        stp x29, x30, [sp, #-16]!
        mov x29, sp
        mov x8, #172          // __NR_getpid (Linux arm64)
        svc #0
        add x0, x0, #7        // 若错误跳转到 svc+8 则此指令会被跳过！
        ldp x29, x30, [sp], #16
        ret
        "#,
    );

    let saw_caller_pc = Arc::new(Mutex::new(0u64));
    let saw_clone = Arc::clone(&saw_caller_pc);
    rt.set_svc_handler(Some(Arc::new(move |args| {
        *saw_clone.lock().unwrap() = args.caller_pc;
        assert_eq!(args.nr, 172);
        Ok(runidbg_zygisk::hybrid::SvcResult {
            ret_x0: 4200,
            hle_event: None,
            memory_mutated: false,
            terminate_emulation: false,
        })
    })));
    rt.set_config(HybridConfig {
        trace_level: TraceLevel::RegDelta,
        max_insns: 1000,
        max_hits: 4,
        ..Default::default()
    });
    rt.register_emulated_module(
        "libsvc_test.so",
        svc_page.base_va(),
        svc_page.end_va(),
        vec![(svc_page.base_va(), svc_page.end_va())],
    );
    let svc_hook = rt
        .install_hook("svc_fn", svc_page.base_va(), svc_page.base_va(), Some(4), svc_page.is_jit)
        .expect("install svc hook");

    type SvcFn = extern "C" fn() -> u64;
    let f_svc: SvcFn = unsafe { std::mem::transmute(svc_page.base_va() as usize) };
    assert_eq!(f_svc(), 4207, "SVC #0 返回 4200 后必须执行紧随其后的 add x0, x0, #7");
    assert_eq!(
        *saw_caller_pc.lock().unwrap(),
        svc_page.base_va() + 12,
        "SvcArgs::caller_pc 应精确指向 svc #0 指令本身"
    );
    rt.uninstall_hook(svc_hook).unwrap();

    // 2) max_insns 录制截断但函数完整执行至 RET（严禁半途返回损坏寄存器！）
    // 循环累加 1..=50 -> 1275（约 160 条指令），设 max_insns = 20
    let loop_page = JitCodePage::from_asm(
        r#"
        stp x29, x30, [sp, #-16]!
        mov x29, sp
        mov x9, #0            // sum
        mov x10, #1           // i
    loop_head:
        cmp x10, #50
        b.gt loop_done
        add x9, x9, x10
        add x10, x10, #1
        b loop_head
    loop_done:
        mov x0, x9
        ldp x29, x30, [sp], #16
        ret
        "#,
    );
    let captured_insns = Arc::new(Mutex::new(0usize));
    let ci_clone = Arc::clone(&captured_insns);
    rt.set_config(HybridConfig {
        trace_level: TraceLevel::Fast,
        max_insns: 20,
        max_hits: 4,
        ..Default::default()
    });
    rt.set_trace_sink(Some(Arc::new(move |ev| {
        *ci_clone.lock().unwrap() = ev.info.idx_insns;
    })));
    rt.register_emulated_module(
        "libloop_test.so",
        loop_page.base_va(),
        loop_page.end_va(),
        vec![(loop_page.base_va(), loop_page.end_va())],
    );
    let loop_hook = rt
        .install_hook("sum50", loop_page.base_va(), loop_page.base_va(), Some(4), loop_page.is_jit)
        .expect("install loop hook");
    let f_loop: SvcFn = unsafe { std::mem::transmute(loop_page.base_va() as usize) };
    assert_eq!(f_loop(), 1275, "触达 max_insns=20 后仅停录，函数仍须完整算完并返回 1275");
    assert_eq!(*captured_insns.lock().unwrap(), 20, "录制指令数应精确截断在 max_insns=20");

    // 3) 地址重叠 Hook 必须被拒绝
    assert!(
        rt.install_hook("overlap", loop_page.base_va() + 8, loop_page.base_va(), Some(4), loop_page.is_jit)
            .is_err(),
        "重叠地址安装第二个 Hook 必须报错拒绝"
    );

    rt.uninstall_hook(loop_hook).unwrap();
    rt.reset_for_tests().unwrap();
}
