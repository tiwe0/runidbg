//! Android NDK 兼容构建脚本：
//! 1. 生成 8 字节空归档 `libpthread.a`（Android Bionic 已内置 pthread 于 `libc.so`，NDK r23+ 无 `libpthread.a`）；
//! 2. 为 `cdylib` 注入精确的链接器版本脚本（仅导出 `zygisk_module_entry` 与 `zygisk_companion_entry`，
//!    彻底隐藏 `__clear_cache` 与 `runidbg_hook_dispatch` 避免符号抢占与反作弊特征泄露）；
//! 3. 显式启用 `-Wl,-Bsymbolic` 与 `-Wl,-z,max-page-size=16384`（确保 NDK r27 CI 产物同样满足 Android 15 16KB 页对齐要求）。

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
        let stub_dir = std::path::Path::new(&out_dir).join("android_stubs");
        std::fs::create_dir_all(&stub_dir).expect("create android_stubs dir");

        // 1. 空 libpthread.a 归档（8 字节标准 ar 魔数）
        std::fs::write(stub_dir.join("libpthread.a"), b"!<arch>\n")
            .expect("write stub libpthread.a");
        println!("cargo:rustc-link-search=native={}", stub_dir.display());

        // 2. 版本脚本：仅公开两个 Zygisk API v4 标准入口符号，隐藏其余内部符号
        let version_script = stub_dir.join("zygisk.map");
        std::fs::write(
            &version_script,
            "{\n  global:\n    zygisk_module_entry;\n    zygisk_companion_entry;\n  local:\n    *;\n};\n",
        )
        .expect("write zygisk.map");
        println!(
            "cargo:rustc-cdylib-link-arg=-Wl,--version-script={}",
            version_script.display()
        );
        println!("cargo:rustc-cdylib-link-arg=-Wl,-Bsymbolic");

        // 3. 显式 16KB PT_LOAD 对齐（兼容 Android 15 16KB 页设备，不依赖 NDK r28+ 默认行为）
        println!("cargo:rustc-cdylib-link-arg=-Wl,-z,max-page-size=16384");
    }
}
