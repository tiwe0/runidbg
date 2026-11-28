//! Zygisk API v4 C ABI 入口与 Root Companion 安全 IPC 守护服务
//!
//! 安全与稳定性设计：
//! 1. **严格 Zygisk API v4 ABI**：`AppSpecializeArgs` 精确 17 字段（136B），`register_module` 接收可变指针并校验返回值；
//!    `is_child_zygote != 0` 与 `system_server` 立即 `setOption(DLCLOSE_MODULE_LIBRARY)` 卸载；
//! 2. **防 `SIGPIPE` + 防未授权写 + 防符号链接提权**：
//!    - Linux/Android 使用 `send(..., MSG_NOSIGNAL)` 彻底杜绝断连 `SIGPIPE` 杀进程；
//!    - Companion 会话维护 `authorized: bool`，仅在 `CMD_GET_CONFIG` 命中 `package_name` 后才允许 `CMD_WRITE_RTRACE`；
//!    - 流式 64 KiB 分块落盘（零 64 MiB 守护进程堆峰值），校验输出目录非符号链接、`O_NOFOLLOW | O_CREAT | O_EXCL`
//!      + 唯一临时名 `.{name}.{pid}.{seq}.tmp` + fd 级 `fchmod`/`fchown`；
//! 3. **零 `OnceLock` 跨复入污染与全回调 `catch_unwind`**：每次 `zygisk_module_entry` 独立分配状态并经 `ModuleAbi.impl_` 传递，
//!    所有 `extern "C"` 回调统一包裹 `catch_unwind` 杜绝跨 FFI unwind 崩溃。

use std::ffi::{c_char, c_int, c_long, c_void};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::android::{log_error, log_info, log_warn};
use crate::config::HybridConfig;
use crate::hybrid::TraceOutputEvent;

/// Zygisk API 版本号（Magisk 26+ / ZygiskNext / ReZygisk 通用 v4 ABI）
pub const ZYGISK_API_VERSION: c_long = 4;
/// 配置文件默认路径（仅 Root Companion 可读，应用沙盒不可见）
pub const DEFAULT_CONFIG_PATH: &str = "/data/adb/runidbg/config.json";
/// 默认 `.rtrace` 输出目录（由 Root Companion 写入）
pub const DEFAULT_OUTPUT_DIR: &str = "/data/local/tmp/runidbg";
/// Companion IPC 协议命令码
pub const CMD_GET_CONFIG: u8 = 1;
pub const CMD_WRITE_RTRACE: u8 = 2;
/// 单份 `.rtrace` IPC 传输上限（64 MiB）
const MAX_IPC_RTRACE_BYTES: usize = 64 * 1024 * 1024;
/// `config.json` 最大允许体积（256 KiB）
const MAX_CONFIG_BYTES: usize = 256 * 1024;
/// 流式落盘分块大小（64 KiB）
const STREAM_CHUNK_BYTES: usize = 64 * 1024;
/// Android `shell` 用户 UID/GID（用于 `/data/local/tmp/runidbg` 使 `adb pull`/`adb shell rm` 均畅通）
#[cfg(target_os = "android")]
const ANDROID_SHELL_UID: libc::uid_t = 2000;

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(1);

/// `Api::setOption` 选项常量（对应 `zygisk.hpp` `enum Option`）
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZygiskOption {
    ForceDenylistUnmount = 0,
    DlcloseModuleLibrary = 1,
}

/// Zygisk API v4 `struct module_abi`
#[repr(C)]
pub struct ModuleAbi {
    pub api_version: c_long,
    pub impl_: *mut c_void,
    pub pre_app_specialize: Option<unsafe extern "C" fn(*mut c_void, *mut AppSpecializeArgs)>,
    pub post_app_specialize: Option<unsafe extern "C" fn(*mut c_void, *const AppSpecializeArgs)>,
    pub pre_server_specialize: Option<unsafe extern "C" fn(*mut c_void, *mut ServerSpecializeArgs)>,
    pub post_server_specialize:
        Option<unsafe extern "C" fn(*mut c_void, *const ServerSpecializeArgs)>,
}

/// Zygisk API v4 `struct api_table`（精确匹配 `zygisk.hpp` v4）
#[repr(C)]
pub struct ApiTable {
    pub impl_: *mut c_void,
    pub register_module: Option<unsafe extern "C" fn(*mut ApiTable, *mut ModuleAbi) -> bool>,
    pub hook_jni_native_methods:
        Option<unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, c_int)>,
    pub plt_hook_register: Option<
        unsafe extern "C" fn(libc::dev_t, libc::ino_t, *const c_char, *mut c_void, *mut *mut c_void),
    >,
    pub exempt_fd: Option<unsafe extern "C" fn(c_int) -> bool>,
    pub plt_hook_commit: Option<unsafe extern "C" fn() -> bool>,
    pub connect_companion: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pub set_option: Option<unsafe extern "C" fn(*mut c_void, c_int)>,
    pub get_module_dir: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pub get_flags: Option<unsafe extern "C" fn(*mut c_void) -> u32>,
}

/// Zygisk API v4 `struct AppSpecializeArgs`（精确 17 字段 = 136 字节，不含 v5 才引入的字段）
#[repr(C)]
pub struct AppSpecializeArgs {
    pub uid: *mut i32,
    pub gid: *mut i32,
    pub gids: *mut *mut c_void,
    pub runtime_flags: *mut i32,
    pub rlimits: *mut *mut c_void,
    pub mount_external: *mut i32,
    pub se_info: *mut *mut c_void,
    pub nice_name: *mut *mut c_void,
    pub instruction_set: *mut *mut c_void,
    pub app_data_dir: *mut *mut c_void,
    // Optional v1..v4 fields
    pub fds_to_ignore: *const *mut c_void,
    pub is_child_zygote: *const u8,
    pub is_top_app: *const u8,
    pub pkg_data_info_list: *const *mut c_void,
    pub whitelisted_data_info_list: *const *mut c_void,
    pub mount_data_dirs: *const u8,
    pub mount_storage_dirs: *const u8,
}

const _: () = assert!(std::mem::size_of::<AppSpecializeArgs>() == 17 * std::mem::size_of::<usize>());

/// Zygisk API v4 `struct ServerSpecializeArgs`
#[repr(C)]
pub struct ServerSpecializeArgs {
    pub uid: *mut i32,
    pub gid: *mut i32,
    pub gids: *mut *mut c_void,
    pub runtime_flags: *mut i32,
    pub permitted_capabilities: *mut i64,
    pub effective_capabilities: *mut i64,
}

// ============================================================================
// Companion IPC 帧协议（防 SIGPIPE、防路径穿越、流式 64 KiB 落盘）
// ============================================================================

fn read_exact_fd(fd: c_int, buf: &mut [u8]) -> io::Result<()> {
    let mut off = 0usize;
    while off < buf.len() {
        // SAFETY: 有效 fd 与切片范围
        let n = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr().add(off) as *mut c_void,
                buf.len() - off,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "companion socket closed",
            ));
        }
        off += n as usize;
    }
    Ok(())
}

fn write_all_fd(fd: c_int, buf: &[u8]) -> io::Result<()> {
    let mut off = 0usize;
    while off < buf.len() {
        // SAFETY: Linux/Android 使用 send(..., MSG_NOSIGNAL) 杜绝断连 SIGPIPE 杀死应用或 zygiskd
        #[cfg(any(target_os = "android", target_os = "linux"))]
        let n = unsafe {
            libc::send(
                fd,
                buf.as_ptr().add(off) as *const c_void,
                buf.len() - off,
                libc::MSG_NOSIGNAL,
            )
        };
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        let n = unsafe {
            libc::write(
                fd,
                buf.as_ptr().add(off) as *const c_void,
                buf.len() - off,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "companion socket write zero",
            ));
        }
        off += n as usize;
    }
    Ok(())
}

/// 清洗文件名：仅保留安全 ASCII 字符，消除 `..` 与首尾点/下划线，彻底杜绝路径穿越与空字节注入
pub fn sanitize_filename(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(128));
    for ch in raw.chars() {
        if out.len() >= 120 {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let mut collapsed = out;
    while collapsed.contains("..") {
        collapsed = collapsed.replace("..", "_");
    }
    while collapsed.contains("__") {
        collapsed = collapsed.replace("__", "_");
    }
    let cleaned = collapsed.trim_matches(|c| c == '.' || c == '_').to_string();
    if cleaned.is_empty() {
        "trace.rtrace".to_string()
    } else if cleaned.ends_with(".rtrace") {
        cleaned
    } else {
        format!("{cleaned}.rtrace")
    }
}

/// 构造防截断 Trace 文件名：先分别裁剪 `proc_name` 与 `hook_name`，保证 `_hit{}_tid{}.rtrace` 永不被截断
pub fn build_trace_filename(proc_name: &str, hook_name: &str, hit_index: u64, tid: u64) -> String {
    let clean_part = |s: &str, max_len: usize| -> String {
        let mut out = String::with_capacity(max_len);
        for ch in s.chars() {
            if out.len() >= max_len {
                break;
            }
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                out.push(ch);
            } else {
                out.push('_');
            }
        }
        out.trim_matches(|c| c == '.' || c == '_').to_string()
    };
    let p = clean_part(proc_name, 36);
    let h = clean_part(hook_name, 48);
    let p = if p.is_empty() { "app" } else { p.as_str() };
    let h = if h.is_empty() { "hook" } else { h.as_str() };
    sanitize_filename(&format!("{p}_{h}_hit{hit_index}_tid{tid}.rtrace"))
}

/// 校验 Companion 允许写入的输出目录（必须为绝对路径、无 `..`，且在允许根目录下）
fn resolve_safe_output_dir(configured: &str, default_dir: &Path) -> PathBuf {
    let trimmed = configured.trim();
    if trimmed.is_empty() {
        return default_dir.to_path_buf();
    }
    let cand = Path::new(trimmed);
    if !cand.is_absolute()
        || cand
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return default_dir.to_path_buf();
    }
    // 生产 Android 仅允许 /data/local/tmp/... 或 /data/adb/...；单测允许 default_dir 自身或其子目录
    let allowed = trimmed == "/data/local/tmp"
        || trimmed.starts_with("/data/local/tmp/")
        || trimmed.starts_with("/data/adb/runidbg")
        || cand.starts_with(default_dir);
    if allowed {
        cand.to_path_buf()
    } else {
        default_dir.to_path_buf()
    }
}

/// 客户端：向 Companion 请求指定 `process_name` 的配置 JSON（返回 `Ok(Some(json_str))` 表示命中目标进程）
pub fn ipc_client_fetch_config(fd: c_int, process_name: &str) -> io::Result<Option<String>> {
    let name_bytes = process_name.as_bytes();
    let name_len = (name_bytes.len().min(1024)) as u32;
    write_all_fd(fd, &[CMD_GET_CONFIG])?;
    write_all_fd(fd, &name_len.to_le_bytes())?;
    write_all_fd(fd, &name_bytes[..name_len as usize])?;

    let mut status = [0u8; 1];
    read_exact_fd(fd, &mut status)?;
    if status[0] == 0 {
        return Ok(None);
    }
    let mut len_buf = [0u8; 4];
    read_exact_fd(fd, &mut len_buf)?;
    let cfg_len = u32::from_le_bytes(len_buf) as usize;
    if cfg_len == 0 || cfg_len > MAX_CONFIG_BYTES {
        return Ok(None);
    }
    let mut cfg_bytes = vec![0u8; cfg_len];
    read_exact_fd(fd, &mut cfg_bytes)?;
    String::from_utf8(cfg_bytes)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// 客户端：通过常驻 Companion 套接字将 `.rtrace` 字节流交由 Root 侧落盘
pub fn ipc_client_write_rtrace(fd: c_int, filename: &str, data: &[u8]) -> io::Result<bool> {
    if data.is_empty() || data.len() > MAX_IPC_RTRACE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid rtrace payload length",
        ));
    }
    let clean_name = sanitize_filename(filename);
    let nb = clean_name.as_bytes();
    write_all_fd(fd, &[CMD_WRITE_RTRACE])?;
    write_all_fd(fd, &(nb.len() as u32).to_le_bytes())?;
    write_all_fd(fd, nb)?;
    write_all_fd(fd, &(data.len() as u32).to_le_bytes())?;
    write_all_fd(fd, data)?;

    let mut ack = [0u8; 1];
    read_exact_fd(fd, &mut ack)?;
    Ok(ack[0] == 1)
}

/// Root 侧 Companion 单个连接处理循环：
/// - 必须先通过 `CMD_GET_CONFIG` 匹配目标包名获得 `authorized = true` 才允许 `CMD_WRITE_RTRACE`；
/// - `CMD_WRITE_RTRACE` 以 64 KiB 分块流式落盘（零大堆分配）且全程防御符号链接提权。
pub fn run_companion_session(fd: c_int, config_path: &Path, default_output_dir: &Path) {
    let mut out_dir_buf = default_output_dir.to_path_buf();
    let mut authorized = false;

    loop {
        let mut cmd = [0u8; 1];
        if read_exact_fd(fd, &mut cmd).is_err() {
            break;
        }
        match cmd[0] {
            CMD_GET_CONFIG => {
                let mut nlen_buf = [0u8; 4];
                if read_exact_fd(fd, &mut nlen_buf).is_err() {
                    break;
                }
                let nlen = u32::from_le_bytes(nlen_buf) as usize;
                if nlen == 0 || nlen > 4096 {
                    let _ = write_all_fd(fd, &[0u8]);
                    break;
                }
                let mut nbuf = vec![0u8; nlen];
                if read_exact_fd(fd, &mut nbuf).is_err() {
                    break;
                }
                let proc_name = String::from_utf8_lossy(&nbuf);

                let matched_json = std::fs::read_to_string(config_path)
                    .ok()
                    .filter(|raw| raw.len() <= MAX_CONFIG_BYTES)
                    .and_then(|raw| {
                        let cfg = HybridConfig::from_json_str(&raw).ok()?;
                        // 安全防护：package_name 为空时不向任何进程注入
                        if cfg.package_name.is_empty() {
                            return None;
                        }
                        let matched = proc_name == cfg.package_name
                            || proc_name.starts_with(&format!("{}:", cfg.package_name));
                        if matched {
                            out_dir_buf =
                                resolve_safe_output_dir(&cfg.output_dir, default_output_dir);
                            Some(raw)
                        } else {
                            None
                        }
                    });

                match matched_json {
                    Some(raw) => {
                        authorized = true;
                        let bytes = raw.as_bytes();
                        if write_all_fd(fd, &[1u8]).is_err()
                            || write_all_fd(fd, &(bytes.len() as u32).to_le_bytes()).is_err()
                            || write_all_fd(fd, bytes).is_err()
                        {
                            break;
                        }
                    }
                    None => {
                        let _ = write_all_fd(fd, &[0u8]);
                        break;
                    }
                }
            }
            CMD_WRITE_RTRACE => {
                if !authorized {
                    let _ = write_all_fd(fd, &[0u8]);
                    break;
                }
                let mut fn_len_buf = [0u8; 4];
                if read_exact_fd(fd, &mut fn_len_buf).is_err() {
                    break;
                }
                let fn_len = u32::from_le_bytes(fn_len_buf) as usize;
                if fn_len == 0 || fn_len > 512 {
                    let _ = write_all_fd(fd, &[0u8]);
                    break;
                }
                let mut fn_buf = vec![0u8; fn_len];
                if read_exact_fd(fd, &mut fn_buf).is_err() {
                    break;
                }
                let mut data_len_buf = [0u8; 4];
                if read_exact_fd(fd, &mut data_len_buf).is_err() {
                    break;
                }
                let data_len = u32::from_le_bytes(data_len_buf) as usize;
                if data_len == 0 || data_len > MAX_IPC_RTRACE_BYTES {
                    let _ = write_all_fd(fd, &[0u8]);
                    break;
                }

                let raw_name = String::from_utf8_lossy(&fn_buf);
                let safe_name = sanitize_filename(&raw_name);
                let chown_shell = out_dir_buf.starts_with("/data/local/tmp");
                let ok = stream_fd_to_file_atomically(
                    fd,
                    data_len,
                    &out_dir_buf,
                    &safe_name,
                    0o755,
                    0o644,
                    chown_shell,
                );
                if write_all_fd(fd, &[u8::from(ok)]).is_err() {
                    break;
                }
                if !ok {
                    // 流式读取可能已失步，主动断开防协议错位
                    break;
                }
            }
            _ => break,
        }
    }
}

/// 校验目标目录存在且绝非符号链接（防御 Root 在 `/data/local/tmp` 下的符号链接提权）
fn ensure_real_directory(dir: &Path, dir_mode: u32, _chown_shell: bool) -> io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "output dir is a symlink or non-directory",
                ));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)?;
            let meta = std::fs::symlink_metadata(dir)?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "created output dir is not a real directory",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(dir_mode));
            }
            #[cfg(target_os = "android")]
            if _chown_shell {
                if let Ok(cdir) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) {
                    // SAFETY: 目录刚经非符号链接校验
                    unsafe {
                        libc::chown(cdir.as_ptr(), ANDROID_SHELL_UID, ANDROID_SHELL_UID);
                    }
                }
            }
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// 打开唯一、非符号链接、原子新建的临时文件（`O_CREAT | O_EXCL | O_NOFOLLOW`）
fn create_unique_tmp_file(
    dir: &Path,
    safe_filename: &str,
    file_mode: u32,
    _chown_shell: bool,
) -> io::Result<(std::fs::File, PathBuf)> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let pid = std::process::id();
    let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = dir.join(format!(".{safe_filename}.{pid}.{seq}.tmp"));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(file_mode).custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(&tmp_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: 对已打开的 fd 直接 fchmod/fchown，完全不受路径竞争与符号链接影响
        unsafe {
            libc::fchmod(file.as_raw_fd(), file_mode as libc::mode_t);
            #[cfg(target_os = "android")]
            if _chown_shell {
                libc::fchown(file.as_raw_fd(), ANDROID_SHELL_UID, ANDROID_SHELL_UID);
            }
        }
    }

    Ok((file, tmp_path))
}

/// 流式从 socket 读取 `total_len` 字节并原子落盘（固定 64 KiB 栈/堆缓冲，杜绝 64 MiB 堆峰值）
fn stream_fd_to_file_atomically(
    src_fd: c_int,
    total_len: usize,
    dir: &Path,
    safe_filename: &str,
    dir_mode: u32,
    file_mode: u32,
    chown_shell: bool,
) -> bool {
    if ensure_real_directory(dir, dir_mode, chown_shell).is_err() {
        return false;
    }
    let Ok((mut file, tmp_path)) =
        create_unique_tmp_file(dir, safe_filename, file_mode, chown_shell)
    else {
        return false;
    };

    let mut buf = vec![0u8; STREAM_CHUNK_BYTES];
    let mut rem = total_len;
    while rem > 0 {
        let want = rem.min(buf.len());
        if read_exact_fd(src_fd, &mut buf[..want]).is_err()
            || file.write_all(&buf[..want]).is_err()
        {
            drop(file);
            let _ = std::fs::remove_file(&tmp_path);
            return false;
        }
        rem -= want;
    }
    if file.flush().is_err() {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }
    drop(file);

    let final_path = dir.join(safe_filename);
    if std::fs::rename(&tmp_path, &final_path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }
    true
}

/// 内存切片直接原子落盘（用于 app 私有缓存降级路径，权限 `0700`/`0600`）
fn write_rtrace_atomically(
    dir: &Path,
    safe_filename: &str,
    payload: &[u8],
    dir_mode: u32,
    file_mode: u32,
) -> bool {
    if ensure_real_directory(dir, dir_mode, false).is_err() {
        return false;
    }
    let Ok((mut file, tmp_path)) = create_unique_tmp_file(dir, safe_filename, file_mode, false)
    else {
        return false;
    };
    if file.write_all(payload).is_err() || file.flush().is_err() {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }
    drop(file);
    let final_path = dir.join(safe_filename);
    if std::fs::rename(&tmp_path, &final_path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }
    true
}

// ============================================================================
// Android Zygisk 运行时状态（按实例经 `ModuleAbi.impl_` 传递，零 `OnceLock` 复用污染）
// ============================================================================

struct ZygiskModuleState {
    api: *mut ApiTable,
    env: *mut c_void,
    active: AtomicBool,
    process_name: Mutex<String>,
    fallback_cache_dir: Mutex<Option<String>>,
    companion_fd: Arc<Mutex<Option<c_int>>>,
    pending_config: Mutex<Option<HybridConfig>>,
}

// SAFETY: 内部状态均由 Atomic / Mutex 同步
unsafe impl Send for ZygiskModuleState {}
unsafe impl Sync for ZygiskModuleState {}

/// 通过 JNI vtable 安全读取 Java `jstring`（校验 `ExceptionCheck(228)`，失败时清理 `ExceptionClear(17)`）
unsafe fn jstring_to_rust(env: *mut c_void, jstr: *mut c_void) -> Option<String> {
    if env.is_null() || jstr.is_null() {
        return None;
    }
    let vtable = *(env as *const *const *const c_void);
    if vtable.is_null() {
        return None;
    }
    let exc_check_ptr = *vtable.add(228);
    let exc_clear_ptr = *vtable.add(17);
    let get_utf_ptr = *vtable.add(169);
    let rel_utf_ptr = *vtable.add(170);
    if get_utf_ptr.is_null() || rel_utf_ptr.is_null() {
        return None;
    }
    if !exc_check_ptr.is_null() {
        type ExcCheckFn = unsafe extern "C" fn(*mut c_void) -> u8;
        let exc_check: ExcCheckFn = std::mem::transmute(exc_check_ptr);
        if exc_check(env) != 0 {
            return None;
        }
    }

    type GetUtfFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut u8) -> *const c_char;
    type RelUtfFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char);
    let get_utf: GetUtfFn = std::mem::transmute(get_utf_ptr);
    let rel_utf: RelUtfFn = std::mem::transmute(rel_utf_ptr);
    let cptr = get_utf(env, jstr, std::ptr::null_mut());
    if cptr.is_null() {
        if !exc_clear_ptr.is_null() {
            type ExcClearFn = unsafe extern "C" fn(*mut c_void);
            let exc_clear: ExcClearFn = std::mem::transmute(exc_clear_ptr);
            exc_clear(env);
        }
        return None;
    }
    let s = std::ffi::CStr::from_ptr(cptr)
        .to_string_lossy()
        .into_owned();
    rel_utf(env, jstr, cptr);
    Some(s)
}

#[inline]
unsafe fn request_dlclose(api: *mut ApiTable) {
    if !api.is_null() {
        if let Some(set_opt) = (*api).set_option {
            set_opt((*api).impl_, ZygiskOption::DlcloseModuleLibrary as c_int);
        }
    }
}

unsafe extern "C" fn on_pre_app_specialize(
    impl_ptr: *mut c_void,
    args: *mut AppSpecializeArgs,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if impl_ptr.is_null() {
            return;
        }
        let state = &*(impl_ptr as *const ZygiskModuleState);
        if state.api.is_null() || args.is_null() {
            request_dlclose(state.api);
            return;
        }

        // 严禁在 app_zygote / webview_zygote 中保持驻留与共享 companion_fd，立即卸载！
        let is_child_zygote_ptr = std::ptr::addr_of!((*args).is_child_zygote).read();
        if !is_child_zygote_ptr.is_null() && *is_child_zygote_ptr != 0 {
            request_dlclose(state.api);
            return;
        }

        let nice_name_ptr = std::ptr::addr_of!((*args).nice_name).read();
        let proc_name = if !nice_name_ptr.is_null() {
            jstring_to_rust(state.env, *nice_name_ptr).unwrap_or_default()
        } else {
            String::new()
        };
        if proc_name.is_empty() {
            request_dlclose(state.api);
            return;
        }

        let app_data_ptr = std::ptr::addr_of!((*args).app_data_dir).read();
        let app_data_dir = if !app_data_ptr.is_null() {
            jstring_to_rust(state.env, *app_data_ptr)
        } else {
            None
        };

        let api = &*state.api;
        let cfd = match api.connect_companion {
            Some(f) => f(api.impl_),
            None => -1,
        };
        if cfd < 0 {
            request_dlclose(state.api);
            return;
        }

        let cfg_json = match ipc_client_fetch_config(cfd, &proc_name) {
            Ok(Some(json)) => json,
            _ => {
                libc::close(cfd);
                request_dlclose(state.api);
                return;
            }
        };

        let cfg = match HybridConfig::from_json_str(&cfg_json) {
            Ok(c) => c,
            Err(e) => {
                log_error(&format!("invalid config.json for `{proc_name}`: {e}"));
                libc::close(cfd);
                request_dlclose(state.api);
                return;
            }
        };

        let exempted = api.exempt_fd.is_some_and(|f| f(cfd));
        if exempted {
            if let Ok(mut g) = state.companion_fd.lock() {
                *g = Some(cfd);
            }
        } else {
            libc::close(cfd);
        }

        if let Ok(mut g) = state.process_name.lock() {
            *g = proc_name.clone();
        }
        if let Ok(mut g) = state.fallback_cache_dir.lock() {
            *g = app_data_dir.map(|d| format!("{d}/cache/runidbg"));
        }
        if let Ok(mut g) = state.pending_config.lock() {
            *g = Some(cfg);
        }
        state.active.store(true, Ordering::Release);
        log_info(&format!(
            "activated runidbg-zygisk for process `{proc_name}` (companion_exempt={exempted})"
        ));
    }));
}

unsafe extern "C" fn on_post_app_specialize(
    impl_ptr: *mut c_void,
    _args: *const AppSpecializeArgs,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if impl_ptr.is_null() {
            return;
        }
        let state = &*(impl_ptr as *const ZygiskModuleState);
        if !state.active.load(Ordering::Acquire) {
            return;
        }
        let cfg = state
            .pending_config
            .lock()
            .ok()
            .and_then(|mut g| g.take())
            .unwrap_or_default();

        let proc_name = state
            .process_name
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "app".to_string());
        let fallback_dir = state
            .fallback_cache_dir
            .lock()
            .ok()
            .and_then(|g| g.clone());
        let companion_fd_arc = Arc::clone(&state.companion_fd);

        // Android 12+ USAP (`nativeSpecializeAppProcess`) 与部分 Zygisk 实现在 preAppSpecialize
        // 阶段不支持 `exemptFd`（因无 `fds_to_ignore` 列表）。此时 `SpecializeCommon` 已结束，
        // 在 `postAppSpecialize` 中重新连接一次 Companion 即可免 `exemptFd` 长期持有安全通道。
        let need_reconnect = companion_fd_arc
            .lock()
            .map(|g| g.is_none())
            .unwrap_or(false);
        if need_reconnect && !state.api.is_null() {
            let api = &*state.api;
            if let Some(connect) = api.connect_companion {
                let cfd = connect(api.impl_);
                if cfd >= 0 {
                    match ipc_client_fetch_config(cfd, &proc_name) {
                        Ok(Some(_)) => {
                            if let Ok(mut g) = companion_fd_arc.lock() {
                                *g = Some(cfd);
                            }
                            log_info(&format!(
                                "reconnected companion in postAppSpecialize for `{proc_name}` (fd={cfd})"
                            ));
                        }
                        _ => {
                            libc::close(cfd);
                        }
                    }
                }
            }
        }

        let rt = crate::hybrid::HybridRuntime::global();
        rt.set_config(cfg.clone());
        rt.set_svc_handler(Some(crate::android::svc::build_android_svc_handler(
            cfg.stealth,
        )));

        rt.set_trace_sink(Some(Arc::new(move |ev: TraceOutputEvent| {
            let filename = build_trace_filename(&proc_name, &ev.hook_name, ev.hit_index, ev.tid);
            let mut written_via_ipc = false;
            if let Ok(mut fd_guard) = companion_fd_arc.lock() {
                if let Some(cfd) = *fd_guard {
                    match ipc_client_write_rtrace(cfd, &filename, &ev.rtrace_bytes) {
                        Ok(true) => {
                            written_via_ipc = true;
                            log_info(&format!(
                                "saved trace via companion: {filename} (insns={} ext={} escapes={} svcs={} bytes={})",
                                ev.info.idx_insns,
                                ev.info.ext_events,
                                ev.escapes,
                                ev.svc_count,
                                ev.rtrace_bytes.len()
                            ));
                        }
                        Ok(false) => {
                            log_warn(&format!(
                                "companion rejected trace {filename}; falling back to app cache"
                            ));
                            libc::close(cfd);
                            *fd_guard = None;
                        }
                        Err(err) => {
                            log_warn(&format!(
                                "companion IPC write failed ({err}); falling back to app cache"
                            ));
                            libc::close(cfd);
                            *fd_guard = None;
                        }
                    }
                }
            }
            if !written_via_ipc {
                if let Some(ref dir) = fallback_dir {
                    if write_rtrace_atomically(
                        Path::new(dir),
                        &filename,
                        &ev.rtrace_bytes,
                        0o700,
                        0o600,
                    ) {
                        log_info(&format!(
                            "saved trace to app cache fallback: {dir}/{filename} ({} B)",
                            ev.rtrace_bytes.len()
                        ));
                    } else {
                        log_warn(&format!("failed to save trace {filename} to fallback {dir}"));
                    }
                }
            }
        })));

        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let armed = crate::android::linker::runtime::scan_and_arm_hooks();
            crate::android::linker::runtime::install_dlopen_hooks();
            crate::android::linker::runtime::install_register_natives_hook(state.env);
            log_info(&format!(
                "postAppSpecialize ready: initially armed {armed} hook(s)"
            ));
        }
    }));
}

unsafe extern "C" fn on_pre_server_specialize(
    impl_ptr: *mut c_void,
    _args: *mut ServerSpecializeArgs,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if !impl_ptr.is_null() {
            let state = &*(impl_ptr as *const ZygiskModuleState);
            request_dlclose(state.api);
        }
    }));
}

unsafe extern "C" fn on_post_server_specialize(
    _impl_ptr: *mut c_void,
    _args: *const ServerSpecializeArgs,
) {
}

/// Zygisk API v4 模块主入口（导出至 `.dynsym`，由 Zygisk Loader 在 `dlopen` 后立即调用）
///
/// # Safety
/// 由 Zygisk 框架传入有效的 `ApiTable*` 与 `JNIEnv*`。
#[no_mangle]
pub unsafe extern "C" fn zygisk_module_entry(api: *mut ApiTable, env: *mut c_void) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if api.is_null() {
            return;
        }
        let Some(register) = (*api).register_module else {
            return;
        };

        let state_box = Box::new(ZygiskModuleState {
            api,
            env,
            active: AtomicBool::new(false),
            process_name: Mutex::new(String::new()),
            fallback_cache_dir: Mutex::new(None),
            companion_fd: Arc::new(Mutex::new(None)),
            pending_config: Mutex::new(None),
        });
        let state_ptr = Box::into_raw(state_box);

        let abi_box = Box::new(ModuleAbi {
            api_version: ZYGISK_API_VERSION,
            impl_: state_ptr as *mut c_void,
            pre_app_specialize: Some(on_pre_app_specialize),
            post_app_specialize: Some(on_post_app_specialize),
            pre_server_specialize: Some(on_pre_server_specialize),
            post_server_specialize: Some(on_post_server_specialize),
        });
        let abi_ptr = Box::into_raw(abi_box);

        if !register(api, abi_ptr) {
            // 注册失败时立即回收堆内存，避免泄漏
            let _ = Box::from_raw(abi_ptr);
            let _ = Box::from_raw(state_ptr);
        }
    }));
}

/// Zygisk API v4 Root Companion 守护入口（导出至 `.dynsym`，在 Root 特权进程中响应客户端连接）
///
/// 注意：按 Zygisk API v4 约定，本函数返回后由 Zygisk 框架自动关闭 `client_fd`（切勿重复 `close` 以免触发 `fdsan`）。
///
/// # Safety
/// 由 Zygisk 框架传入已连接的 Unix 域套接字 `client_fd`。
#[no_mangle]
pub unsafe extern "C" fn zygisk_companion_entry(client_fd: c_int) {
    if client_fd < 0 {
        return;
    }
    let _ = std::panic::catch_unwind(|| {
        run_companion_session(
            client_fd,
            Path::new(DEFAULT_CONFIG_PATH),
            Path::new(DEFAULT_OUTPUT_DIR),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_and_build_trace_filename() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "etc_passwd.rtrace");
        assert_eq!(sanitize_filename("..."), "trace.rtrace");
        let long_sym = "_ZN12VeryLongNamespace34VeryLongClassName56VeryLongMethodName78WithManyArgsEiiiiii";
        let built = build_trace_filename("com.example.super.long.package.name.test", long_sym, 3, 9876);
        assert!(built.ends_with("_hit3_tid9876.rtrace"), "got: {built}");
    }

    #[test]
    fn test_companion_rejects_unauthenticated_write() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "runidbg_companion_unauth_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg_path = tmp_dir.join("config.json");
        let out_dir = tmp_dir.join("out");
        std::fs::write(&cfg_path, r#"{"package_name": ""}"#).unwrap();

        let mut fds = [-1 as c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let (client_fd, server_fd) = (fds[0], fds[1]);
        let cfg_c = cfg_path.clone();
        let out_c = out_dir.clone();
        let server = std::thread::spawn(move || {
            run_companion_session(server_fd, &cfg_c, &out_c);
            unsafe {
                libc::close(server_fd);
            }
        });

        // 未先经过 CMD_GET_CONFIG 鉴权直接发送 CMD_WRITE_RTRACE 必须被拒绝
        let res = ipc_client_write_rtrace(client_fd, "evil.rtrace", b"RTRC_DATA");
        assert!(matches!(res, Ok(false) | Err(_)));
        unsafe {
            libc::close(client_fd);
        }
        server.join().unwrap();
        assert!(!out_dir.join("evil.rtrace").exists());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_companion_ipc_roundtrip_over_socketpair() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "runidbg_companion_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg_path = tmp_dir.join("config.json");
        let out_dir = tmp_dir.join("out");
        let cfg_text = format!(
            r#"{{
                "package_name": "com.android.settings",
                "target_libs": ["libdemo.so"],
                "output_dir": "{}"
            }}"#,
            out_dir.display()
        );
        std::fs::write(&cfg_path, &cfg_text).unwrap();

        let mut fds = [-1 as c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let client_fd = fds[0];
        let server_fd = fds[1];

        let cfg_clone = cfg_path.clone();
        let out_clone = out_dir.clone();
        let server = std::thread::spawn(move || {
            run_companion_session(server_fd, &cfg_clone, &out_clone);
            unsafe {
                libc::close(server_fd);
            }
        });

        let fetched = ipc_client_fetch_config(client_fd, "com.android.settings")
            .expect("fetch config")
            .expect("should match target package");
        assert!(fetched.contains("libdemo.so"));

        let payload = b"RTRC\x01\x00hello_rtrace_streaming_payload";
        let ok = ipc_client_write_rtrace(client_fd, "../evil/test_hit1.rtrace", payload)
            .expect("write rtrace");
        assert!(ok);
        unsafe {
            libc::close(client_fd);
        }
        server.join().expect("server thread");

        let saved = out_dir.join("evil_test_hit1.rtrace");
        assert_eq!(std::fs::read(&saved).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
