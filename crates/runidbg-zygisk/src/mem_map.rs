//! 1:1 零拷贝内存路由、TBI 指针去标签与 Shadow Pristine Page（原始代码页镜像）管理
//!
//! 职责：
//! 1. 维护白名单模拟 `.so` 的虚拟地址范围（`emulated_modules`），判定任意 PC 属于“模拟执行域”还是“原生逃逸域”；
//! 2. 为被 Inline Hook 修改过的 4KB 代码页保存 Patch 前的原始 4096 字节镜像（`Arc<[u8; 4096]>`），
//!    防止 UAF 且在 Unicorn 映射该页时将 `uc_mem_map_ptr` 指向只读原始镜像而非真实已改写页；
//! 3. 缓存宿主进程 VMA 映射表（Linux/Android 缓存 `/proc/self/maps` 并在 miss 时刷新，macOS 调 `mach_vm_region_recurse`）；
//! 4. 严格权限隔离：
//!    - Unicorn 2.x 在无 MMU 态按原始 64-bit 地址查表（含 Android Scudo 高 8 位标签），因此 `uc_page` 保留原始页地址，
//!      而宿主权限查询与 `host_ptr` 使用去标签规范地址 `canonical_page`；
//!    - 取指严格校验 `region.readable && region.executable`（规避 Android XOM 宿主 SIGSEGV 与 `.rodata` 误授权）；
//!    - 读访存严格校验 `region.readable`（避免 `-w-p` 无限重故障）；
//!    - 含 Shadow Page 的代码页绝不授予实时 `canonical_page` 的 `Prot::EXEC`，也绝不将共享只读 Shadow Page 设为可写。

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Arc;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::sync::{OnceLock, RwLock};

use unicorn_engine::unicorn_const::Prot;

/// Unicorn 引擎固定的最小页对齐粒度（4 KiB）
pub const UC_PAGE_SIZE: u64 = 0x1000;
/// Unicorn 4 KiB 页对齐掩码
pub const UC_PAGE_MASK: u64 = !(UC_PAGE_SIZE - 1);
/// 保护性低地址阈值（低于 64 KiB 的访问一律视为非法空指针解引用，防止宿主 SIGSEGV）
const MIN_VALID_USER_ADDR: u64 = 0x1_0000;

/// 剥离 ARM64 TBI（Top Byte Ignore / Android Scudo 内存标签）的高 8 位，还原规范虚拟地址
#[inline]
pub const fn untag_tbi(addr: u64) -> u64 {
    addr & 0x00FF_FFFF_FFFF_FFFF
}

/// 向下对齐至 4 KiB Unicorn 页边界
#[inline]
pub const fn align_down_4k(addr: u64) -> u64 {
    addr & UC_PAGE_MASK
}

/// 查询宿主操作系统真实页大小（通常为 4096，Apple Silicon / Android 15 16KB 设备为 16384）
pub fn os_page_size() -> usize {
    // SAFETY: libc::sysconf(_SC_PAGESIZE) 为纯只读系统调用，线程安全
    let sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if sz <= 0 {
        4096
    } else {
        sz as usize
    }
}

/// 单个被纳入模拟域的模块及其可执行区间
#[derive(Debug, Clone)]
pub struct EmulatedModule {
    pub name: String,
    pub base: u64,
    pub end: u64,
    /// 该模块的可执行代码段区间 `[start, end)`（空列表表示整个 `[base, end)` 均允许取指）
    pub rx_ranges: Vec<(u64, u64)>,
}

impl EmulatedModule {
    #[inline]
    pub fn contains_code(&self, canonical_addr: u64) -> bool {
        if !self.rx_ranges.is_empty() {
            self.rx_ranges
                .iter()
                .any(|&(s, e)| canonical_addr >= s && canonical_addr < e)
        } else {
            canonical_addr >= self.base && canonical_addr < self.end
        }
    }

    #[inline]
    pub fn contains_any(&self, canonical_addr: u64) -> bool {
        canonical_addr >= self.base && canonical_addr < self.end
    }
}

/// `/proc/self/maps` 单行解析结果（跨平台纯 Rust，供 Android 与单元测试复用）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcMapEntry {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub path: String,
}

/// 解析 `/proc/self/maps` 中的单行记录
pub fn parse_proc_maps_line(line: &str) -> Option<ProcMapEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?;
    let (s_hex, e_hex) = range.split_once('-')?;
    let start = u64::from_str_radix(s_hex, 16).ok()?;
    let end = u64::from_str_radix(e_hex, 16).ok()?;
    let pb = perms.as_bytes();
    if pb.len() < 3 {
        return None;
    }
    // 跳过 offset, dev, inode 三个字段，剩余部分拼接为路径（可能含空格）
    let _offset = parts.next();
    let _dev = parts.next();
    let _inode = parts.next();
    let path = parts.collect::<Vec<_>>().join(" ");
    Some(ProcMapEntry {
        start,
        end,
        readable: pb[0] == b'r',
        writable: pb[1] == b'w',
        executable: pb[2] == b'x',
        path,
    })
}

/// 宿主进程地址空间区间权限信息
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRegionPerm {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Linux/Android `/proc/self/maps` VMA 排序缓存（miss 或显式失效时重建，避免每次缺页全量扫 1-5MB maps）
#[cfg(any(target_os = "linux", target_os = "android"))]
static VMA_CACHE: OnceLock<RwLock<Vec<HostRegionPerm>>> = OnceLock::new();

#[cfg(any(target_os = "linux", target_os = "android"))]
fn lookup_vma_slice(vmas: &[HostRegionPerm], canonical_addr: u64) -> Option<HostRegionPerm> {
    let idx = vmas.partition_point(|r| r.end <= canonical_addr);
    vmas.get(idx)
        .filter(|r| canonical_addr >= r.start && canonical_addr < r.end)
        .copied()
}

/// 刷新宿主 VMA 缓存（在 `dlopen`/`munmap`/Hook 卸载前显式调用以确保准确）
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn invalidate_host_region_cache() {
    if let Some(lock) = VMA_CACHE.get() {
        if let Ok(mut g) = lock.write() {
            g.clear();
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn invalidate_host_region_cache() {}

/// 强制绕过缓存直接查询宿主实时映射（用于 `uninstall` 校验等必须无陈旧缓存的场景）
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn query_host_region_uncached(canonical_addr: u64) -> Option<HostRegionPerm> {
    if canonical_addr < MIN_VALID_USER_ADDR {
        return None;
    }
    let content = read_proc_self_maps_raw().ok()?;
    for line in content.lines() {
        if let Some(entry) = parse_proc_maps_line(line) {
            if canonical_addr >= entry.start && canonical_addr < entry.end {
                return Some(HostRegionPerm {
                    start: entry.start,
                    end: entry.end,
                    readable: entry.readable,
                    writable: entry.writable,
                    executable: entry.executable,
                });
            }
            if entry.start > canonical_addr {
                break;
            }
        }
    }
    None
}

/// 查询宿主进程中指定规范地址所在内存映射的起止范围与权限（带 VMA 排序缓存）
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn query_host_region(canonical_addr: u64) -> Option<HostRegionPerm> {
    if canonical_addr < MIN_VALID_USER_ADDR {
        return None;
    }
    let cache = VMA_CACHE.get_or_init(|| RwLock::new(Vec::new()));
    if let Ok(guard) = cache.read() {
        if let Some(hit) = lookup_vma_slice(&guard, canonical_addr) {
            return Some(hit);
        }
    }
    // Cache miss：重新扫描 /proc/self/maps 并刷新缓存
    let content = read_proc_self_maps_raw().ok()?;
    let mut fresh = Vec::with_capacity(512);
    for line in content.lines() {
        if let Some(e) = parse_proc_maps_line(line) {
            fresh.push(HostRegionPerm {
                start: e.start,
                end: e.end,
                readable: e.readable,
                writable: e.writable,
                executable: e.executable,
            });
        }
    }
    fresh.sort_by_key(|r| r.start);
    let hit = lookup_vma_slice(&fresh, canonical_addr);
    if let Ok(mut guard) = cache.write() {
        *guard = fresh;
    }
    hit
}

/// 使用底层 `open`/`read` 直接读取 `/proc/self/maps`（规避 libc stdio 缓冲与重入）
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn read_proc_self_maps_raw() -> Result<String, i32> {
    // SAFETY: 静态 NUL 结尾路径常量 + 标准 POSIX open/read/close
    unsafe {
        let fd = libc::open(c"/proc/self/maps".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        }
        let mut out = Vec::with_capacity(64 * 1024);
        let mut buf = [0u8; 8192];
        loop {
            let n = libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len());
            if n < 0 {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                if err == libc::EINTR {
                    continue;
                }
                libc::close(fd);
                return Err(err);
            }
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        libc::close(fd);
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

/// macOS 宿主内存区权限查询（通过 `mach_vm_region_recurse` 穿透 submap 查询真实叶映射）
#[cfg(target_os = "macos")]
pub fn query_host_region(canonical_addr: u64) -> Option<HostRegionPerm> {
    if canonical_addr < MIN_VALID_USER_ADDR {
        return None;
    }

    #[repr(C, packed(4))]
    #[derive(Default)]
    struct VmRegionSubmapInfo64V0 {
        protection: i32,
        max_protection: i32,
        inheritance: u32,
        offset: u64,
        user_tag: u32,
        pages_resident: u32,
        pages_shared_now_private: u32,
        pages_swapped_out: u32,
        pages_dirtied: u32,
        ref_count: u32,
        shadow_depth: u16,
        external_pager: u8,
        share_mode: u8,
        is_submap: i32,
        behavior: i32,
        object_id: u32,
        user_wired_count: u16,
        flags: u16,
    }
    const VM_REGION_SUBMAP_INFO_V0_COUNT_64: u32 =
        (std::mem::size_of::<VmRegionSubmapInfo64V0>() / 4) as u32;
    const VM_PROT_READ: i32 = 1;
    const VM_PROT_WRITE: i32 = 2;
    const VM_PROT_EXECUTE: i32 = 4;

    extern "C" {
        fn mach_task_self() -> u32;
        fn mach_vm_region_recurse(
            target_task: u32,
            address: *mut u64,
            size: *mut u64,
            nesting_depth: *mut u32,
            info: *mut VmRegionSubmapInfo64V0,
            info_cnt: *mut u32,
        ) -> i32;
    }

    let mut addr = canonical_addr;
    let mut size: u64 = 0;
    let mut depth: u32 = 0;

    for _ in 0..8 {
        let mut info = VmRegionSubmapInfo64V0::default();
        let mut count = VM_REGION_SUBMAP_INFO_V0_COUNT_64;
        // SAFETY: 所有指针指向有效栈变量，结构体布局严格匹配 <mach/vm_region.h> (#pragma pack(4))
        let kr = unsafe {
            mach_vm_region_recurse(
                mach_task_self(),
                &mut addr,
                &mut size,
                &mut depth,
                &mut info,
                &mut count,
            )
        };
        if kr != 0 || size == 0 {
            return None;
        }
        let end = addr.saturating_add(size);
        if canonical_addr < addr || canonical_addr >= end {
            return None;
        }
        if info.is_submap != 0 {
            depth = depth.saturating_add(1);
            addr = canonical_addr;
            continue;
        }
        let prot = info.protection;
        return Some(HostRegionPerm {
            start: addr,
            end,
            readable: (prot & VM_PROT_READ) != 0,
            writable: (prot & VM_PROT_WRITE) != 0,
            executable: (prot & VM_PROT_EXECUTE) != 0,
        });
    }
    None
}

#[cfg(target_os = "macos")]
pub fn query_host_region_uncached(canonical_addr: u64) -> Option<HostRegionPerm> {
    query_host_region(canonical_addr)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
pub fn query_host_region(_canonical_addr: u64) -> Option<HostRegionPerm> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
pub fn query_host_region_uncached(_canonical_addr: u64) -> Option<HostRegionPerm> {
    None
}

/// 缺页路由决策结果
#[derive(Debug, Clone)]
pub enum PageMapDecision {
    /// 取指越出白名单模拟模块：必须停止 Unicorn 并逃逸至宿主原生执行
    ExternalEscape { target_pc: u64 },
    /// 允许 1:1 零拷贝映射（或映射只读 Shadow Pristine Page）到 Unicorn
    MapPtr {
        /// Unicorn 看到的 4KB 对齐规范虚拟地址（与 `TCR_EL1.TBI0|TBI1` 协同，始终去标签）
        uc_page: u64,
        /// 宿主进程内真实后备内存指针（实时内存页或 `Arc<[u8; 4096]>` Shadow Page）
        host_ptr: *mut c_void,
        /// 授予 Unicorn 的页权限（非模拟代码页绝不包含 `Prot::EXEC`）
        perms: Prot,
        /// 若使用 Shadow Page，附带 `Arc` 引用供 `EngineState` 持有直至 unmap，杜绝 UAF
        shadow_arc: Option<Arc<[u8; 4096]>>,
    },
}

/// 进程级共享内存路由器（管理模拟模块白名单与 Shadow Pristine Page 镜像）
#[derive(Debug, Default)]
pub struct MemoryRouter {
    emulated_modules: Vec<EmulatedModule>,
    /// `canonical_4k_page -> Arc<[u8; 4096]>`：在打 Inline Hook 前冻结的只读原始 4KB 页面镜像
    shadow_pages: HashMap<u64, Arc<[u8; 4096]>>,
    /// 每当模拟模块或 Shadow Page 变化时单调递增，用于通知线程本地 Unicorn 刷新过时映射
    epoch: u64,
}

// SAFETY: shadow_pages 仅存储只读 `Arc<[u8; 4096]>`，线程间共享安全
unsafe impl Send for MemoryRouter {}
unsafe impl Sync for MemoryRouter {}

impl MemoryRouter {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// 注册或更新一个纳入模拟执行域的模块（自动剥离地址上的 TBI 标签）
    pub fn register_emulated_module(
        &mut self,
        name: impl Into<String>,
        base: u64,
        end: u64,
        rx_ranges: Vec<(u64, u64)>,
    ) {
        let name = name.into();
        let base = untag_tbi(base);
        let end = untag_tbi(end);
        let rx_ranges: Vec<(u64, u64)> = rx_ranges
            .into_iter()
            .map(|(s, e)| (untag_tbi(s), untag_tbi(e)))
            .collect();

        if let Some(existing) = self
            .emulated_modules
            .iter_mut()
            .find(|m| m.base == base && m.end == end)
        {
            existing.name = name;
            existing.rx_ranges = rx_ranges;
        } else {
            self.emulated_modules.push(EmulatedModule {
                name,
                base,
                end,
                rx_ranges,
            });
        }
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// 清空全部注册模块（供测试隔离使用）
    pub fn clear_emulated_modules(&mut self) {
        self.emulated_modules.clear();
        self.epoch = self.epoch.wrapping_add(1);
    }

    pub fn emulated_modules(&self) -> &[EmulatedModule] {
        &self.emulated_modules
    }

    /// 判断指定地址（自动去 TBI 标签）是否位于模拟模块的可执行代码区间内
    #[inline]
    pub fn is_emulated_code_addr(&self, addr: u64) -> bool {
        let canonical = untag_tbi(addr);
        self.emulated_modules
            .iter()
            .any(|m| m.contains_code(canonical))
    }

    /// 根据地址反查所属模拟模块
    pub fn find_emulated_module(&self, addr: u64) -> Option<&EmulatedModule> {
        let canonical = untag_tbi(addr);
        self.emulated_modules
            .iter()
            .find(|m| m.contains_any(canonical))
    }

    /// 注册某个 4KB 页面在打 Inline Hook 之前的原始字节快照（若该页已有快照则保留最早的干净版本）
    pub fn register_shadow_page(&mut self, canonical_page: u64, pristine: Arc<[u8; 4096]>) {
        let page = align_down_4k(untag_tbi(canonical_page));
        self.shadow_pages.entry(page).or_insert(pristine);
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// 查询某 4KB 页是否存在 Shadow Pristine Page 镜像
    #[inline]
    pub fn shadow_page(&self, canonical_page: u64) -> Option<Arc<[u8; 4096]>> {
        let page = align_down_4k(untag_tbi(canonical_page));
        self.shadow_pages.get(&page).cloned()
    }

    /// 清除所有 Shadow Page（由于活跃 `EngineState` 持有 `Arc` 引用，清表不会引发 UAF）
    pub fn clear_shadow_pages(&mut self) {
        self.shadow_pages.clear();
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// 为 Unicorn 缺页或权限异常计算映射决策
    pub fn resolve_page(
        &self,
        fault_addr: u64,
        is_fetch: bool,
        is_write: bool,
    ) -> Result<PageMapDecision, String> {
        let canonical = untag_tbi(fault_addr);
        if canonical < MIN_VALID_USER_ADDR {
            return Err(format!("非法低地址访问: 0x{fault_addr:016x}"));
        }

        // Unicorn 2.x 在 MMU 关闭态下直接使用原始 64-bit 地址查表（含 Android Scudo 高 8 位 TBI 标签），
        // 因此 `uc_page` 保留原始页地址 `align_down_4k(fault_addr)`，而宿主机权限查询与 `host_ptr` 使用去标签规范地址！
        let uc_page = align_down_4k(fault_addr);
        let canonical_page = align_down_4k(canonical);

        // 1. 取指访问：先严格判定是否属于模拟白名单模块
        if is_fetch {
            if !self.is_emulated_code_addr(canonical) {
                return Ok(PageMapDecision::ExternalEscape {
                    target_pc: canonical,
                });
            }
            if let Some(shadow_arc) = self.shadow_page(canonical_page) {
                let host_ptr = shadow_arc.as_ptr() as *mut c_void;
                return Ok(PageMapDecision::MapPtr {
                    uc_page,
                    host_ptr,
                    perms: Prot::READ | Prot::EXEC,
                    shadow_arc: Some(shadow_arc),
                });
            }
            let region = query_host_region(canonical).ok_or_else(|| {
                format!("模拟模块取指页 0x{canonical_page:016x} 在宿主地址空间未映射")
            })?;
            // 严格校验同时可读且可执行：规避 Android XOM (--xp) 宿主 SIGSEGV 与 .rodata 误授权 EXEC
            if !region.readable || !region.executable {
                return Err(format!(
                    "模拟模块取指页 0x{canonical_page:016x} 权限不足 (r={} x={})",
                    region.readable, region.executable
                ));
            }
            let perms = if region.writable {
                Prot::ALL
            } else {
                Prot::READ | Prot::EXEC
            };
            return Ok(PageMapDecision::MapPtr {
                uc_page,
                host_ptr: canonical_page as *mut c_void,
                perms,
                shadow_arc: None,
            });
        }

        // 2. 数据读写访问：
        // 若该页存在 Shadow Pristine Page：
        // - 读访问：返回只读 Shadow Pristine Page（绕过 .text CRC 自校验 & literal pool 读取）；
        // - 写访问：禁止向共享只读 Shadow Page 添加写权限，亦禁止将实时已 Patch 页授予 EXEC。
        if let Some(shadow_arc) = self.shadow_page(canonical_page) {
            if is_write {
                return Err(format!(
                    "拒绝向已安装 Inline Hook 的代码页 0x{canonical_page:016x} 写入数据"
                ));
            }
            let perms = if self.is_emulated_code_addr(canonical) {
                Prot::READ | Prot::EXEC
            } else {
                Prot::READ
            };
            let host_ptr = shadow_arc.as_ptr() as *mut c_void;
            return Ok(PageMapDecision::MapPtr {
                uc_page,
                host_ptr,
                perms,
                shadow_arc: Some(shadow_arc),
            });
        }

        let region = query_host_region(canonical).ok_or_else(|| {
            format!("数据访存页 0x{canonical_page:016x} 在宿主地址空间未映射")
        })?;
        if is_write && !region.writable {
            return Err(format!(
                "试图写入宿主只读页 0x{canonical_page:016x} (fault=0x{fault_addr:016x})"
            ));
        }
        if !is_write && !region.readable {
            return Err(format!(
                "试图读取宿主不可读页 0x{canonical_page:016x} (fault=0x{fault_addr:016x})"
            ));
        }

        // 关键安全边界：非模拟模块的数据/代码页绝不授予 Prot::EXEC，
        // 保证后续向该页内任意函数的跳转仍会精确触发 MEM_FETCH_PROT 逃逸！
        let mut perms = Prot::NONE;
        if region.readable {
            perms |= Prot::READ;
        }
        if region.writable {
            perms |= Prot::WRITE;
        }
        if region.executable && region.readable && self.is_emulated_code_addr(canonical) {
            perms |= Prot::EXEC;
        }
        if perms == Prot::NONE {
            return Err(format!("页 0x{canonical_page:016x} 映射权限为空"));
        }

        Ok(PageMapDecision::MapPtr {
            uc_page,
            host_ptr: canonical_page as *mut c_void,
            perms,
            shadow_arc: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tbi_untag_and_align() {
        assert_eq!(untag_tbi(0xb400_0071_2345_6789), 0x0000_0071_2345_6789);
        assert_eq!(untag_tbi(0x0000_0071_2345_6789), 0x0000_0071_2345_6789);
        assert_eq!(align_down_4k(0x71_2345_6789), 0x71_2345_6000);
    }

    #[test]
    fn test_parse_proc_maps_line() {
        let line = "7a12340000-7a12360000 r-xp 00001000 fe:09 12345 /data/app/com.demo/lib/arm64/libtarget.so";
        let e = parse_proc_maps_line(line).expect("should parse");
        assert_eq!(e.start, 0x7a_1234_0000);
        assert_eq!(e.end, 0x7a_1236_0000);
        assert!(e.readable && !e.writable && e.executable);
        assert_eq!(e.path, "/data/app/com.demo/lib/arm64/libtarget.so");

        let anon = "7a20000000-7a20010000 rw-p 00000000 00:00 0";
        let e2 = parse_proc_maps_line(anon).expect("anon should parse");
        assert!(e2.readable && e2.writable && !e2.executable);
        assert!(e2.path.is_empty());
    }

    #[test]
    fn test_query_host_region_on_stack_and_heap() {
        let local_val: u64 = 0x1122_3344_5566_7788;
        let addr = (&local_val as *const u64) as u64;
        let region = query_host_region(addr).expect("stack page should be mapped");
        assert!(region.readable && region.writable);
        assert!(addr >= region.start && addr < region.end);

        let heap_box = Box::new(0xdead_beefu64);
        let haddr = (&*heap_box as *const u64) as u64;
        let hregion = query_host_region(haddr).expect("heap page should be mapped");
        assert!(hregion.readable && hregion.writable);
    }

    #[test]
    fn test_shadow_page_tbi_and_write_protection() {
        let mut router = MemoryRouter::new();
        let code_page = 0x7000_1000u64;
        router.register_emulated_module(
            "libtarget.so",
            0x7000_0000,
            0x7001_0000,
            vec![(0x7000_1000, 0x7000_4000)],
        );
        let mut raw = [0u8; 4096];
        raw[0..4].copy_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let pristine = Arc::new(raw);
        let expected_ptr = pristine.as_ptr() as usize;
        router.register_shadow_page(code_page, pristine);

        // 1. 带 TBI 标签取指应保留原始带标签页地址（匹配 Unicorn 无 MMU 查找）且后备指针命中 Shadow Page
        let dec = router
            .resolve_page(0xb400_0000_7000_1010, true, false)
            .expect("resolve shadow fetch");
        match dec {
            PageMapDecision::MapPtr {
                uc_page,
                host_ptr,
                perms,
                shadow_arc,
            } => {
                assert_eq!(uc_page, 0xb400_0000_7000_1000);
                assert_eq!(host_ptr as usize, expected_ptr);
                assert_eq!(perms, Prot::READ | Prot::EXEC);
                assert!(shadow_arc.is_some());
            }
            other => panic!("expected shadow MapPtr, got {other:?}"),
        }

        // 2. 尝试写入已安装 Hook 的 Shadow Page 必须被拒绝（防止破坏只读共享镜像）
        assert!(router.resolve_page(code_page + 0x20, false, true).is_err());

        // 3. 模拟模块外取指必须触发 ExternalEscape
        let esc = router
            .resolve_page(0x7100_2000, true, false)
            .expect("resolve external escape");
        assert!(matches!(
            esc,
            PageMapDecision::ExternalEscape {
                target_pc: 0x7100_2000
            }
        ));
    }
}
