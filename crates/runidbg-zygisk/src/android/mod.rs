//! Android 平台适配层（`SVC #0` 透传 + Stealth 隐身过滤 + Linker/ELF 依赖自动发现 + JNI 拦截 + Zygisk v4）

pub mod linker;
pub mod svc;
pub mod zygisk;

/// 统一 Android `logcat` / 桌面 `stderr` 日志输出（短消息走栈缓冲零堆分配）
pub fn log_info(msg: &str) {
    #[cfg(target_os = "android")]
    android_log_write(4, msg); // ANDROID_LOG_INFO = 4
    #[cfg(not(target_os = "android"))]
    eprintln!("[runidbg-zygisk][I] {msg}");
}

pub fn log_warn(msg: &str) {
    #[cfg(target_os = "android")]
    android_log_write(5, msg); // ANDROID_LOG_WARN = 5
    #[cfg(not(target_os = "android"))]
    eprintln!("[runidbg-zygisk][W] {msg}");
}

pub fn log_error(msg: &str) {
    #[cfg(target_os = "android")]
    android_log_write(6, msg); // ANDROID_LOG_ERROR = 6
    #[cfg(not(target_os = "android"))]
    eprintln!("[runidbg-zygisk][E] {msg}");
}

#[cfg(target_os = "android")]
#[link(name = "log")]
extern "C" {
    fn __android_log_write(
        prio: libc::c_int,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> libc::c_int;
}

#[cfg(target_os = "android")]
fn android_log_write(prio: libc::c_int, msg: &str) {
    let bytes = msg.as_bytes();
    if bytes.len() < 512 && !bytes.contains(&0) {
        let mut buf = [0u8; 512];
        buf[..bytes.len()].copy_from_slice(bytes);
        buf[bytes.len()] = 0;
        // SAFETY: 静态 NUL 结尾 tag 与 NUL 结尾栈缓冲
        unsafe {
            __android_log_write(
                prio,
                c"runidbg-zygisk".as_ptr(),
                buf.as_ptr() as *const libc::c_char,
            );
        }
        return;
    }
    let clean = msg.replace('\0', " ");
    if let Ok(cmsg) = std::ffi::CString::new(clean) {
        // SAFETY: 静态 NUL 结尾 tag 与有效 CString
        unsafe {
            __android_log_write(prio, c"runidbg-zygisk".as_ptr(), cmsg.as_ptr());
        }
    }
}
