//! Android ARM64 `SVC #0` 原生系统调用透传与 Stealth 隐身过滤器
//!
//! 关键工程保证：
//! 1. **危险生命周期/控制流系统调用拦截**：拒绝将 `clone`/`clone3`/`rt_sigreturn`/`execve`/`execveat` 直接跑在宿主 Rust 栈上，
//!    `exit`/`exit_group` 先优雅结束模拟以刷出 `.rtrace`；
//! 2. **Unicorn 页表同步**：`mmap`/`munmap`/`mprotect`/`mremap`/`brk` 完成后设置 `memory_mutated = true` 并失效宿主 VMA 缓存，
//!    使 `hybrid.rs` 立即刷新 Unicorn 动态页映射，防止 QEMU TLB 残留陈旧 host 指针导致 SIGSEGV；
//! 3. **Android 15 硬件 MTE 兼容**：校验边界时使用去标签地址 `untag_tbi(ptr)`，解引用时保留原始指针上的 MTE 标签 `[59:56]`；
//! 4. **全路径 Stealth 隐身过滤**：支持 `openat(56)` 与 `openat2(437)`、相对路径 `dirfd` 解析、词法路径规范化（`//`/`./`/`../`）、
//!    工作线程 TID、`/proc/self/smaps` 有状态整块剔除、全原生 `svc #0` 读写（零 libc `errno` 污染 + 非 UTF-8 容错）、
//!    `MFD_NOEXEC_SEAL` 兼容与经 `/proc/self/fd/<mfd>` 重开为真正 `O_RDONLY` FD！

use std::sync::Arc;

use crate::hybrid::{SvcArgs, SvcHandler, SvcResult};
use crate::mem_map::parse_proc_maps_line;

/// Linux ARM64 关键系统调用号（asm-generic/unistd.h）
pub const SYS_OPENAT: u64 = 56;
pub const SYS_CLOSE: u64 = 57;
pub const SYS_LSEEK: u64 = 62;
pub const SYS_READ: u64 = 63;
pub const SYS_WRITE: u64 = 64;
pub const SYS_READLINKAT: u64 = 78;
pub const SYS_EXIT: u64 = 93;
pub const SYS_EXIT_GROUP: u64 = 94;
pub const SYS_CLOCK_GETTIME: u64 = 113;
pub const SYS_RT_SIGRETURN: u64 = 139;
pub const SYS_GETTIMEOFDAY: u64 = 169;
pub const SYS_GETCWD: u64 = 17;
pub const SYS_BRK: u64 = 214;
pub const SYS_MUNMAP: u64 = 215;
pub const SYS_MREMAP: u64 = 216;
pub const SYS_CLONE: u64 = 220;
pub const SYS_EXECVE: u64 = 221;
pub const SYS_MMAP: u64 = 222;
pub const SYS_MPROTECT: u64 = 226;
pub const SYS_GETRANDOM: u64 = 278;
pub const SYS_MEMFD_CREATE: u64 = 279;
pub const SYS_EXECVEAT: u64 = 281;
pub const SYS_CLONE3: u64 = 435;
pub const SYS_OPENAT2: u64 = 437;

/// 被 Stealth 过滤器识别的敏感 `/proc` 文件类别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveProcKind {
    Maps,
    Smaps,
    Status,
}

/// 敏感模块特征子串（大小写不敏感匹配；避开过短误杀串）
const STEALTH_MAPS_DENY_PATTERNS: &[&str] = &[
    "runidbg",
    "zygisk",
    "magisk",
    "lsposed",
    "lspd",
    "apatch",
    "kernelsu",
    "/data/adb/",
    "frida",
    "memfd:runidbg",
    "memfd:jit-cache",
];

/// 词法规范化 POSIX 绝对路径（折叠 `//`、`.`、`..`，不做 trim 以防成为检测 Oracle）
pub fn normalize_posix_path(raw: &str) -> String {
    if !raw.starts_with('/') {
        return raw.to_string();
    }
    let mut stack: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    if stack.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", stack.join("/"))
    }
}

/// 判断规范化后的路径是否指向自身进程的 `/proc/{self|thread-self|<pid>|<tid>}/{maps|smaps|status}`
pub fn classify_sensitive_proc_path(
    path: &str,
    self_pid: u32,
    self_tid: u32,
) -> Option<SensitiveProcKind> {
    if !path.starts_with('/') {
        return None;
    }
    let norm = normalize_posix_path(path);
    let rest = norm.strip_prefix("/proc/")?;
    let (who, tail) = rest.split_once('/')?;

    let is_self = who == "self"
        || who == "thread-self"
        || who
            .parse::<u32>()
            .ok()
            .is_some_and(|p| p == self_pid || p == self_tid);
    if !is_self {
        return None;
    }

    let leaf = match tail.strip_prefix("task/") {
        Some(after_task) => {
            let (tid_seg, l) = after_task.split_once('/')?;
            if tid_seg.is_empty() || !tid_seg.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            l
        }
        None => tail,
    };

    match leaf {
        "maps" => Some(SensitiveProcKind::Maps),
        "smaps" => Some(SensitiveProcKind::Smaps),
        "status" => Some(SensitiveProcKind::Status),
        _ => None,
    }
}

#[inline]
fn is_suspicious_maps_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    STEALTH_MAPS_DENY_PATTERNS
        .iter()
        .any(|pat| lower.contains(pat))
}

/// 过滤 `/proc/self/maps` 中的注入框架痕迹（纯 Rust，可跨平台单元测试）
pub fn filter_proc_maps_content(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for line in raw.lines() {
        if !is_suspicious_maps_line(line) {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// 有状态块级过滤 `/proc/self/smaps`：当某个 VMA 头部命中黑名单时，连同其后续所有属性行
/// （`Size:`/`Rss:`/`Pss:`/`VmFlags:` 等）整块剔除，直到下一个 VMA 头部为止！
pub fn filter_proc_smaps_content(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut skipping_block = false;
    for line in raw.lines() {
        if parse_proc_maps_line(line).is_some() {
            skipping_block = is_suspicious_maps_line(line);
        }
        if !skipping_block {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// 过滤 `/proc/self/status`，将非零 `TracerPid` 改写为 `0`（纯 Rust，可跨平台单元测试）
pub fn filter_proc_status_content(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for line in raw.lines() {
        if line.starts_with("TracerPid:") {
            out.push_str("TracerPid:\t0\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// 构造 Android ARM64 `SVC #0` 透传处理器并供 `HybridRuntime::set_svc_handler` 挂载
pub fn build_android_svc_handler(stealth: bool) -> SvcHandler {
    Arc::new(move |args: &SvcArgs| handle_svc_passthrough(args, stealth))
}

#[cfg(all(target_arch = "aarch64", any(target_os = "android", target_os = "linux")))]
#[inline(never)]
unsafe fn raw_linux_arm64_syscall(nr: u64, x: &[u64; 6]) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "svc #0",
        inout("x8") nr => _,
        inout("x0") x[0] => ret,
        inout("x1") x[1] => _,
        inout("x2") x[2] => _,
        inout("x3") x[3] => _,
        inout("x4") x[4] => _,
        inout("x5") x[5] => _,
        options(nostack),
    );
    ret
}

#[cfg(all(target_arch = "aarch64", any(target_os = "android", target_os = "linux")))]
fn handle_svc_passthrough(args: &SvcArgs, stealth: bool) -> Result<SvcResult, String> {
    use runidbg_arm64_emu_tracer::tracer::{ExtKind, HleOpEvent};

    use crate::mem_map::{invalidate_host_region_cache, query_host_region_uncached, untag_tbi};

    // 1. 严格拦截不可安全运行在宿主 Rust 栈上的控制流/生命周期系统调用
    match args.nr {
        SYS_CLONE | SYS_CLONE3 | SYS_RT_SIGRETURN | SYS_EXECVE | SYS_EXECVEAT => {
            return Ok(SvcResult {
                ret_x0: (-libc::ENOSYS as i64) as u64,
                hle_event: None,
                memory_mutated: false,
                terminate_emulation: false,
            });
        }
        SYS_EXIT | SYS_EXIT_GROUP => {
            // 不直接杀掉宿主线程/进程，先终止本次模拟让上层归还锁并刷出 .rtrace
            return Ok(SvcResult {
                ret_x0: args.x[0],
                hle_event: None,
                memory_mutated: false,
                terminate_emulation: true,
            });
        }
        _ => {}
    }

    // 2. Stealth 过滤：拦截 openat(56) 与 openat2(437) 对 /proc/{self|pid|tid}/maps|smaps|status 的只读访问
    if stealth && (args.nr == SYS_OPENAT || args.nr == SYS_OPENAT2) {
        let open_flags_opt: Option<i32> = if args.nr == SYS_OPENAT {
            Some(args.x[2] as i32)
        } else {
            // openat2(dirfd, pathname, struct open_how *how, size) — how->flags 位于 offset 0 (u64)
            let how_ptr = args.x[2];
            let how_sz = args.x[3];
            if how_ptr != 0 && how_sz >= 8 {
                safe_read_host_bytes(how_ptr, 8)
                    .map(|b| u64::from_le_bytes(b[0..8].try_into().unwrap()) as i32)
            } else {
                None
            }
        };

        if let Some(flags) = open_flags_opt {
            let acc = flags & libc::O_ACCMODE;
            let skip_special = (flags & (libc::O_PATH | libc::O_DIRECTORY)) != 0
                || (flags & (libc::O_CREAT | libc::O_EXCL)) == (libc::O_CREAT | libc::O_EXCL);
            if acc == libc::O_RDONLY && !skip_special {
                if let Some(raw_path) = safe_read_host_cstr(args.x[1], 4096) {
                    let abs_path = resolve_openat_abs_path(args.x[0] as i32, &raw_path);
                    if let Some(abs) = abs_path {
                        // SAFETY: getpid / SYS_gettid 无副作用
                        let pid = unsafe { libc::getpid() as u32 };
                        let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
                        if let Some(kind) = classify_sensitive_proc_path(&abs, pid, tid) {
                            if let Some(clean_fd) = create_filtered_proc_memfd(&abs, kind, flags) {
                                return Ok(SvcResult {
                                    ret_x0: clean_fd as u64,
                                    hle_event: None,
                                    memory_mutated: false,
                                    terminate_emulation: false,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. 直接经原生 ARM64 `svc #0` 转发至真实 Android 内核
    // SAFETY: 模拟代码显式发起的系统调用，参数指针均为当前进程 1:1 真实地址
    let ret = unsafe { raw_linux_arm64_syscall(args.nr, &args.x) };

    // 4. 内存映射变更类系统调用：失效宿主 VMA 缓存并通知 Unicorn 刷新动态页映射
    let is_vm_mut = matches!(
        args.nr,
        SYS_MMAP | SYS_MUNMAP | SYS_MPROTECT | SYS_MREMAP | SYS_BRK
    );
    let memory_mutated = is_vm_mut && (ret as i64) >= 0;
    if memory_mutated {
        invalidate_host_region_cache();
    }

    // 5. 熵源 / 时钟源系统调用自动注入 HleSource 事件（读取失败时宁缺毋滥，绝不伪造 0）
    let hle_event = match args.nr {
        SYS_GETRANDOM => {
            let n = ret as isize;
            let dst = args.x[0];
            if dst != 0 && n > 0 {
                let sample_len = (n as usize).min(8);
                safe_read_host_bytes(dst, sample_len).map(|b| {
                    let mut arr = [0u8; 8];
                    arr[..b.len()].copy_from_slice(&b);
                    HleOpEvent {
                        kind: ExtKind::HleSource,
                        subop_or_byte: 4, // getrandom
                        aux_subop: 0,
                        dst,
                        src: u64::from_le_bytes(arr),
                        len: n as u64,
                        caller_pc: args.caller_pc,
                    }
                })
            } else {
                None
            }
        }
        SYS_GETTIMEOFDAY => {
            let dst = args.x[0];
            if dst != 0 && (ret as i64) == 0 {
                safe_read_host_bytes(dst, 8).map(|b| HleOpEvent {
                    kind: ExtKind::HleSource,
                    subop_or_byte: 5, // gettimeofday
                    aux_subop: 0,
                    dst,
                    src: u64::from_le_bytes(b[0..8].try_into().unwrap()),
                    len: 16,
                    caller_pc: args.caller_pc,
                })
            } else {
                None
            }
        }
        SYS_CLOCK_GETTIME => {
            let dst = args.x[1];
            if dst != 0 && (ret as i64) == 0 {
                safe_read_host_bytes(dst, 8).map(|b| HleOpEvent {
                    kind: ExtKind::HleSource,
                    subop_or_byte: 6, // clock_gettime
                    aux_subop: 0,
                    dst,
                    src: u64::from_le_bytes(b[0..8].try_into().unwrap()),
                    len: 16,
                    caller_pc: args.caller_pc,
                })
            } else {
                None
            }
        }
        _ => None,
    };

    /// 跨相邻可读 VMA 安全读取 `len` 字节（保留原始 MTE 指针标签 `[59:56]` 解引用，防止 Android 15 MTE SIGSEGV）
    fn safe_read_host_bytes(ptr_va: u64, len: usize) -> Option<Vec<u8>> {
        if ptr_va == 0 || len == 0 {
            return None;
        }
        let mut out = Vec::with_capacity(len);
        let mut off = 0usize;
        while off < len {
            let cur_tagged = ptr_va.wrapping_add(off as u64);
            let canonical = untag_tbi(cur_tagged);
            let reg = query_host_region_uncached(canonical)?;
            if !reg.readable || reg.end <= canonical {
                return None;
            }
            let chunk = (reg.end.saturating_sub(canonical) as usize).min(len - off);
            // SAFETY: 已实时校验 [canonical, canonical + chunk) 可读；通过 cur_tagged 解引用保留 MTE 标签
            let slice = unsafe { std::slice::from_raw_parts(cur_tagged as *const u8, chunk) };
            out.extend_from_slice(slice);
            off += chunk;
        }
        Some(out)
    }

    /// 跨 VMA 安全读取以 `\0` 结尾的 C 字符串（必须显式遇到 NUL，否则返回 `None` 避免截断误判）
    fn safe_read_host_cstr(ptr_va: u64, max_len: usize) -> Option<String> {
        if ptr_va == 0 {
            return None;
        }
        let mut bytes = Vec::with_capacity(128);
        let mut off = 0usize;
        while off < max_len {
            let cur_tagged = ptr_va.wrapping_add(off as u64);
            let canonical = untag_tbi(cur_tagged);
            let reg = query_host_region_uncached(canonical)?;
            if !reg.readable || reg.end <= canonical {
                return None;
            }
            let chunk = (reg.end.saturating_sub(canonical) as usize).min(max_len - off);
            // SAFETY: 已实时校验可读并通过带标签指针读取
            let slice = unsafe { std::slice::from_raw_parts(cur_tagged as *const u8, chunk) };
            if let Some(nul) = slice.iter().position(|&b| b == 0) {
                bytes.extend_from_slice(&slice[..nul]);
                return String::from_utf8(bytes).ok();
            }
            bytes.extend_from_slice(slice);
            off += chunk;
        }
        None
    }

    /// 解析 `openat(dirfd, path)` 的绝对路径（纯 `svc #0`，不触碰 libc `errno`）
    fn resolve_openat_abs_path(dirfd: i32, raw_path: &str) -> Option<String> {
        if raw_path.starts_with('/') {
            return Some(raw_path.to_string());
        }
        let mut buf = [0u8; 4096];
        if dirfd == libc::AT_FDCWD {
            // SAFETY: raw SYS_getcwd(buf, len)
            let r = unsafe {
                raw_linux_arm64_syscall(
                    SYS_GETCWD,
                    &[buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0, 0],
                ) as i64
            };
            if r <= 0 {
                return None;
            }
            let nul = buf.iter().position(|&b| b == 0)?;
            let cwd = std::str::from_utf8(&buf[..nul]).ok()?;
            return Some(format!("{cwd}/{raw_path}"));
        }
        let fd_link = format!("/proc/self/fd/{dirfd}\0");
        // SAFETY: raw SYS_readlinkat(AT_FDCWD, "/proc/self/fd/<dirfd>", buf, len)
        let r = unsafe {
            raw_linux_arm64_syscall(
                SYS_READLINKAT,
                &[
                    libc::AT_FDCWD as i64 as u64,
                    fd_link.as_ptr() as u64,
                    buf.as_mut_ptr() as u64,
                    (buf.len() - 1) as u64,
                    0,
                    0,
                ],
            ) as i64
        };
        if r <= 0 {
            return None;
        }
        let dir = std::str::from_utf8(&buf[..r as usize]).ok()?;
        Some(format!("{dir}/{raw_path}"))
    }

    /// 全程纯 `svc #0` 读取目标 `/proc` 文件、过滤敏感内容、写入 `memfd` 并经 `/proc/self/fd/<mfd>` 重开为真正 `O_RDONLY` FD
    fn create_filtered_proc_memfd(
        abs_path: &str,
        kind: SensitiveProcKind,
        orig_flags: i32,
    ) -> Option<i32> {
        let mut cpath = Vec::with_capacity(abs_path.len() + 1);
        cpath.extend_from_slice(abs_path.as_bytes());
        cpath.push(0);

        // 1. 纯 svc #0 打开原 /proc 文件
        // SAFETY: raw SYS_openat(AT_FDCWD, cpath, O_RDONLY | O_CLOEXEC, 0)
        let src_fd = unsafe {
            raw_linux_arm64_syscall(
                SYS_OPENAT,
                &[
                    libc::AT_FDCWD as i64 as u64,
                    cpath.as_ptr() as u64,
                    (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                    0,
                    0,
                    0,
                ],
            ) as i64
        };
        if src_fd < 0 {
            return None;
        }

        let mut raw_bytes = Vec::with_capacity(64 * 1024);
        let mut chunk = [0u8; 8192];
        loop {
            // SAFETY: raw SYS_read
            let n = unsafe {
                raw_linux_arm64_syscall(
                    SYS_READ,
                    &[src_fd as u64, chunk.as_mut_ptr() as u64, chunk.len() as u64, 0, 0, 0],
                ) as i64
            };
            if n == -(libc::EINTR as i64) {
                continue;
            }
            if n < 0 {
                unsafe {
                    raw_linux_arm64_syscall(SYS_CLOSE, &[src_fd as u64, 0, 0, 0, 0, 0]);
                }
                return None;
            }
            if n == 0 {
                break;
            }
            raw_bytes.extend_from_slice(&chunk[..n as usize]);
        }
        // SAFETY: 关闭原 /proc fd
        unsafe {
            raw_linux_arm64_syscall(SYS_CLOSE, &[src_fd as u64, 0, 0, 0, 0, 0]);
        }

        // 2. 使用 lossy UTF-8 过滤，绝不因非 UTF-8 映射路径导致泄露未过滤 maps！
        let raw_text = String::from_utf8_lossy(&raw_bytes);
        let filtered = match kind {
            SensitiveProcKind::Maps => filter_proc_maps_content(&raw_text),
            SensitiveProcKind::Smaps => filter_proc_smaps_content(&raw_text),
            SensitiveProcKind::Status => filter_proc_status_content(&raw_text),
        };

        // 3. 创建 memfd（优先带 MFD_CLOEXEC | MFD_NOEXEC_SEAL 消除 Android 15 GKI 内核告警，不支持则回退）
        const MFD_CLOEXEC: u64 = 0x0001;
        const MFD_NOEXEC_SEAL: u64 = 0x0008;
        let name = c"maps";
        // SAFETY: raw SYS_memfd_create
        let mut mfd = unsafe {
            raw_linux_arm64_syscall(
                SYS_MEMFD_CREATE,
                &[name.as_ptr() as u64, MFD_CLOEXEC | MFD_NOEXEC_SEAL, 0, 0, 0, 0],
            ) as i64
        };
        if mfd == -(libc::EINVAL as i64) {
            mfd = unsafe {
                raw_linux_arm64_syscall(
                    SYS_MEMFD_CREATE,
                    &[name.as_ptr() as u64, MFD_CLOEXEC, 0, 0, 0, 0],
                ) as i64
            };
        }
        if mfd < 0 {
            return None;
        }

        // 4. 写入过滤后的内容（防 n <= 0 死循环）
        let bytes = filtered.as_bytes();
        let mut written = 0usize;
        while written < bytes.len() {
            // SAFETY: raw SYS_write
            let n = unsafe {
                raw_linux_arm64_syscall(
                    SYS_WRITE,
                    &[
                        mfd as u64,
                        bytes.as_ptr().add(written) as u64,
                        (bytes.len() - written) as u64,
                        0,
                        0,
                        0,
                    ],
                ) as i64
            };
            if n == -(libc::EINTR as i64) {
                continue;
            }
            if n <= 0 {
                unsafe {
                    raw_linux_arm64_syscall(SYS_CLOSE, &[mfd as u64, 0, 0, 0, 0, 0]);
                }
                return None;
            }
            written += n as usize;
        }

        // 5. 经 /proc/self/fd/<mfd> 重开为真正的 O_RDONLY FD（继承调用方 O_CLOEXEC | O_NONBLOCK，游标自动位于 0）
        let reopen_path = format!("/proc/self/fd/{mfd}\0");
        let ro_flags =
            libc::O_RDONLY | (orig_flags & (libc::O_CLOEXEC | libc::O_NONBLOCK));
        // SAFETY: raw SYS_openat
        let ro_fd = unsafe {
            raw_linux_arm64_syscall(
                SYS_OPENAT,
                &[
                    libc::AT_FDCWD as i64 as u64,
                    reopen_path.as_ptr() as u64,
                    ro_flags as u64,
                    0,
                    0,
                    0,
                ],
            ) as i64
        };
        if ro_fd >= 0 {
            unsafe {
                raw_linux_arm64_syscall(SYS_CLOSE, &[mfd as u64, 0, 0, 0, 0, 0]);
            }
            return Some(ro_fd as i32);
        }

        // 若 SELinux 禁止重开 /proc/self/fd/<mfd>，则回退到 lseek(mfd, 0) 直接返回
        let seek_rc = unsafe {
            raw_linux_arm64_syscall(SYS_LSEEK, &[mfd as u64, 0, libc::SEEK_SET as u64, 0, 0, 0])
                as i64
        };
        if seek_rc < 0 {
            unsafe {
                raw_linux_arm64_syscall(SYS_CLOSE, &[mfd as u64, 0, 0, 0, 0, 0]);
            }
            return None;
        }
        Some(mfd as i32)
    }

    Ok(SvcResult {
        ret_x0: ret,
        hle_event,
        memory_mutated,
        terminate_emulation: false,
    })
}

#[cfg(not(all(target_arch = "aarch64", any(target_os = "android", target_os = "linux"))))]
fn handle_svc_passthrough(_args: &SvcArgs, _stealth: bool) -> Result<SvcResult, String> {
    Ok(SvcResult {
        ret_x0: (-libc::ENOSYS as i64) as u64,
        hle_event: None,
        memory_mutated: false,
        terminate_emulation: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_sensitive_proc_path_and_normalization() {
        assert_eq!(
            classify_sensitive_proc_path("/proc/self/maps", 1234, 1235),
            Some(SensitiveProcKind::Maps)
        );
        // 词法规范化抵抗 ./ 与 // 与 .. 绕过
        assert_eq!(
            classify_sensitive_proc_path("/proc//self/./../self/maps", 1234, 1235),
            Some(SensitiveProcKind::Maps)
        );
        // 尾随空格绝不 trim（避免成为 Hook 检测 Oracle）
        assert_eq!(
            classify_sensitive_proc_path("/proc/self/maps ", 1234, 1235),
            None
        );
        // smaps 与 worker TID / task/<tid> 独立识别
        assert_eq!(
            classify_sensitive_proc_path("/proc/1235/smaps", 1234, 1235),
            Some(SensitiveProcKind::Smaps)
        );
        assert_eq!(
            classify_sensitive_proc_path("/proc/self/task/1235/maps", 1234, 1235),
            Some(SensitiveProcKind::Maps)
        );
        assert_eq!(
            classify_sensitive_proc_path("/proc/self/task/1235/status", 1234, 1235),
            Some(SensitiveProcKind::Status)
        );
        assert_eq!(
            classify_sensitive_proc_path("/proc/9999/maps", 1234, 1235),
            None
        );
    }

    #[test]
    fn test_filter_proc_maps_smaps_and_status() {
        let sample_smaps = "\
7a10000000-7a10040000 r-xp 00000000 fe:09 11 /data/app/com.demo/lib/arm64/libtarget.so
Size:                256 kB
Rss:                 128 kB
7a20000000-7a20100000 r-xp 00000000 fe:09 22 /data/adb/modules/runidbg_zygisk/zygisk/arm64-v8a.so
Size:               1024 kB
Rss:                 512 kB
VmFlags: rd ex mr mw me
7a40000000-7a40010000 r-xp 00000000 fe:09 33 /system/lib64/libc.so
Size:                 64 kB
";
        let clean_smaps = filter_proc_smaps_content(sample_smaps);
        assert!(clean_smaps.contains("libtarget.so"));
        assert!(clean_smaps.contains("256 kB"));
        assert!(clean_smaps.contains("libc.so"));
        assert!(!clean_smaps.contains("runidbg"));
        assert!(!clean_smaps.contains("1024 kB"), "被剔除 VMA 的后续 smaps 元数据行必须整块清除");
        assert!(!clean_smaps.contains("VmFlags: rd ex mr mw me"));

        let sample_status = "Name:\tcom.demo\nPid:\t1234\nTracerPid:\t5678\nUid:\t10200\n";
        let clean_status = filter_proc_status_content(sample_status);
        assert!(clean_status.contains("TracerPid:\t0\n"));
        assert!(!clean_status.contains("5678"));
    }
}
