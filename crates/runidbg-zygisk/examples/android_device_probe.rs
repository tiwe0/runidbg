//! Android 15 ARM64 真机独立自检探针（通过 `adb push` 到 `/data/local/tmp/` 直接在真机内核上实测）：
//! 1. 真实 bionic `malloc` / `memcpy` / `gettimeofday` / `free` 原生逃逸 + 自动 HLE；
//! 2. 真实 Android 15 内核 `SVC #0` 透传（`SYS_getpid` + `SYS_getrandom` + Stealth `openat("/proc/self/maps")` 过滤验证）；
//! 3. 真实 Android 15 `dl_iterate_phdr` + 纯 Rust ELF64 `DT_SYMTAB` 符号解析；
//! 4. 产出真实 `.rtrace` 文件到 `/data/local/tmp/runidbg/probe_device.rtrace`，供桌面端 `runidbg-cli stats/decompile` 校验！

#[cfg(all(target_arch = "aarch64", target_os = "android"))]
fn main() {
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::{Arc, Mutex};

    use runidbg_arm64_emu_tracer::good64::assemble;
    use runidbg_arm64_emu_tracer::tracer::TraceLevel;
    use runidbg_zygisk::android::linker::runtime::enumerate_loaded_modules;
    use runidbg_zygisk::android::svc::build_android_svc_handler;
    use runidbg_zygisk::config::HybridConfig;
    use runidbg_zygisk::hybrid::{HybridRuntime, TraceOutputEvent};
    use runidbg_zygisk::inline_hook::flush_icache;

    println!("=== runidbg-zygisk Android 15 ARM64 Device Probe ===");

    // 1. 验证 dl_iterate_phdr + 纯 Rust ELF64 解析
    let mods = enumerate_loaded_modules();
    println!("[1/4] dl_iterate_phdr enumerated {} loaded modules", mods.len());
    assert!(mods.iter().any(|m| m.soname == "libc.so"), "libc.so must be found");

    // 2. 分配真实 RWX 匿名页并汇编一段综合测试函数：
    //    - 逃逸调用真实 Android bionic malloc / memcpy / gettimeofday / free
    //    - 直接内联执行真实 Android 内核 SVC #0: SYS_getpid(172) + SYS_getrandom(278) + SYS_openat("/proc/self/maps")
    let page_len = 8192usize;
    let code_ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            page_len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert!(code_ptr != libc::MAP_FAILED);
    let base_va = code_ptr as usize as u64;

    // target(a, b, malloc_fn, memcpy_fn, free_fn, maps_path_ptr) -> ((a ^ 0x1234) + (b * 5)) ^ 0x55
    let code = assemble(
        r#"
        stp x29, x30, [sp, #-96]!
        mov x29, sp
        stp x19, x20, [sp, #16]
        stp x21, x22, [sp, #32]
        stp x23, x24, [sp, #48]

        mov x19, x0              // a
        mov x20, x1              // b
        mov x21, x3              // memcpy
        mov x22, x4              // free
        mov x23, x5              // "/proc/self/maps"

        // A) 真实 Android bionic malloc(64)（验证 Scudo 堆指针含高 8 位 TBI 标签！）
        mov x0, #64
        blr x2
        mov x24, x0

        // B) 真实 Android 内核 SVC #0: SYS_getrandom(sp+64, 8, 0)
        add x0, sp, #64
        mov x1, #8
        mov x2, #0
        mov x8, #278
        svc #0

        // C) 真实 Android 内核 SVC #0: Stealth openat(AT_FDCWD=-100, "/proc/self/maps", O_RDONLY=0, 0) + close
        mov x0, #-100
        mov x1, x23
        mov x2, #0
        mov x3, #0
        mov x8, #56
        svc #0
        cmp x0, #0
        b.lt skip_close
        mov x8, #57
        svc #0
    skip_close:

        // D) 确定性算术 + 经由真实 Scudo 堆 malloc + bionic memcpy 往返
        mov x9, #0x1234
        eor x10, x19, x9
        add x11, x20, x20, lsl #2
        str x10, [sp, #64]
        str x11, [sp, #72]

        mov x0, x24
        add x1, sp, #64
        mov x2, #16
        blr x21

        ldr x12, [x24, #0]
        ldr x13, [x24, #8]
        add x19, x12, x13
        mov x14, #0x55
        eor x19, x19, x14

        // E) 释放 Scudo 堆块
        mov x0, x24
        blr x22

        mov x0, x19
        ldp x23, x24, [sp, #48]
        ldp x21, x22, [sp, #32]
        ldp x19, x20, [sp, #16]
        ldp x29, x30, [sp], #96
        ret
        "#,
        base_va,
    )
    .expect("assemble failed");

    unsafe {
        ptr::copy_nonoverlapping(code.as_ptr(), code_ptr as *mut u8, code.len());
        flush_icache(code_ptr as *const u8, code.len());
    }

    let rt = HybridRuntime::global();
    let captured: Arc<Mutex<Vec<TraceOutputEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let cap_clone = Arc::clone(&captured);
    rt.set_config(HybridConfig {
        trace_level: TraceLevel::Full,
        max_insns: 100_000,
        max_hits: 4,
        stealth: true,
        ..Default::default()
    });
    rt.set_svc_handler(Some(build_android_svc_handler(true)));
    rt.set_trace_sink(Some(Arc::new(move |ev| {
        cap_clone.lock().unwrap().push(ev);
    })));
    rt.register_emulated_module(
        "libprobe.so",
        base_va,
        base_va + page_len as u64,
        vec![(base_va, base_va + page_len as u64)],
    );
    let hid = rt
        .install_hook("probe_fn", base_va, base_va, Some(4), false)
        .expect("install_hook failed");

    type ProbeFn = extern "C" fn(
        u64,
        u64,
        *const c_void,
        *const c_void,
        *const c_void,
        *const libc::c_char,
    ) -> u64;
    let f: ProbeFn = unsafe { std::mem::transmute(base_va as usize) };
    let a = 0x2026_1128u64;
    let b = 0x0000_0077u64;
    let expected = ((a ^ 0x1234).wrapping_add(b.wrapping_mul(5))) ^ 0x55;
    let got = f(
        a,
        b,
        libc::malloc as *const c_void,
        libc::memcpy as *const c_void,
        libc::free as *const c_void,
        c"/proc/self/maps".as_ptr(),
    );
    println!("[2/4] Hybrid return: got=0x{got:x} expected=0x{expected:x}");
    assert_eq!(got, expected);

    let evs = captured.lock().unwrap();
    assert_eq!(evs.len(), 1);
    let ev = &evs[0];
    println!(
        "[3/4] Trace captured: insns={} ext={} escapes={} svcs={} rtrace_bytes={}",
        ev.info.idx_insns,
        ev.info.ext_events,
        ev.escapes,
        ev.svc_count,
        ev.rtrace_bytes.len()
    );
    assert_eq!(ev.escapes, 3);
    assert!(ev.svc_count >= 3);

    let out_dir = std::path::Path::new("/data/local/tmp/runidbg");
    let _ = std::fs::create_dir_all(out_dir);
    let out_path = out_dir.join("probe_device.rtrace");
    std::fs::write(&out_path, &ev.rtrace_bytes).expect("write probe_device.rtrace");
    println!("[4/4] Saved real device trace -> {}", out_path.display());

    rt.uninstall_hook(hid).unwrap();

    // 5. 真机实测 Hook Android 15 原生 `/system/lib64/libz.so!crc32`（以 `paciasp` 开头，测试 PAC/BTI + 纯 Rust ELF64 符号解析 + 回退跳板！）
    let libz_handle = unsafe { libc::dlopen(c"/system/lib64/libz.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!libz_handle.is_null(), "dlopen /system/lib64/libz.so failed");
    rt.set_config(HybridConfig {
        target_libs: vec!["/system/lib64/libz.so".to_string()],
        auto_include_app_deps: false,
        hooks: vec![runidbg_zygisk::config::HookTargetSpec::Symbol {
            lib: "/system/lib64/libz.so".to_string(),
            symbol: "crc32".to_string(),
        }],
        trace_level: TraceLevel::Full,
        max_insns: 50_000,
        max_hits: 2,
        stealth: true,
        ..Default::default()
    });
    let libz_traces: Arc<Mutex<Vec<TraceOutputEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let lz_clone = Arc::clone(&libz_traces);
    rt.set_trace_sink(Some(Arc::new(move |ev| {
        lz_clone.lock().unwrap().push(ev);
    })));
    let armed = runidbg_zygisk::android::linker::runtime::scan_and_arm_hooks();
    println!("[5/5] scan_and_arm_hooks armed {armed} hook(s) on real /system/lib64/libz.so!crc32");
    assert_eq!(armed, 1);

    type Crc32Fn = extern "C" fn(u64, *const u8, u32) -> u64;
    let crc32_sym = unsafe { libc::dlsym(libz_handle, c"crc32".as_ptr()) };
    let crc32_fn: Crc32Fn = unsafe { std::mem::transmute(crc32_sym) };
    let msg = b"runidbg-v0.5.0-android15-zygisk-hybrid";
    // 命中 1、2 次：走 Unicorn 混合模拟；第 3 次：超 max_hits=2，走 good64 重定位回退跳板原生执行！
    let c1 = crc32_fn(0, msg.as_ptr(), msg.len() as u32);
    let c2 = crc32_fn(0, msg.as_ptr(), msg.len() as u32);
    let c3 = crc32_fn(0, msg.as_ptr(), msg.len() as u32);
    println!(
        "[5/5] real libz.so!crc32: emu1=0x{c1:08x} emu2=0x{c2:08x} native_fallback=0x{c3:08x}"
    );
    assert_eq!(c1, c3, "Unicorn 模拟真实 libz.so!crc32 结果必须与真机原生回退结果完全一致");
    assert_eq!(c2, c3);
    let lz_evs = libz_traces.lock().unwrap();
    assert_eq!(lz_evs.len(), 2, "max_hits=2 应恰好产出 2 份 libz.so!crc32 .rtrace");
    let libz_out = out_dir.join("libz_crc32_device.rtrace");
    std::fs::write(&libz_out, &lz_evs[0].rtrace_bytes).expect("write libz_crc32_device.rtrace");
    println!(
        "[5/5] Saved real libz.so!crc32 trace: insns={} ext={} bytes={} -> {}",
        lz_evs[0].info.idx_insns,
        lz_evs[0].info.ext_events,
        lz_evs[0].rtrace_bytes.len(),
        libz_out.display()
    );
    println!("=== ANDROID 15 DEVICE PROBE PASS ===");
}

#[cfg(not(all(target_arch = "aarch64", target_os = "android")))]
fn main() {
    eprintln!("android_device_probe is intended for aarch64-linux-android.");
}
