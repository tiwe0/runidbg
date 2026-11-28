//! Android Linker 模块发现、纯 Rust 内存态 ELF64 符号/依赖解析、`libdl.so` GOT Hook 与 JNI `RegisterNatives` vtable Hook
//!
//! 针对 Android 15 ARM64 的关键设计：
//! 1. **纯 Rust 内存态 ELF64 符号解析（`DT_SYMTAB` + `DT_STRTAB` + `DT_GNU_HASH`/`DT_HASH`）**：
//!    彻底规避 Android linker namespace 隔离导致的 `dlopen(RTLD_NOLOAD)` 失败与 `dlsym(RTLD_DEFAULT)` 跨库误挂，
//!    原生支持 `base.apk!/lib/arm64-v8a/*.so` 与 Split APK；
//! 2. **`libdl.so` GOT/PLT 原子 8B 指针 Hook（`__loader_dlopen` / `__loader_android_dlopen_ext`）**：
//!    彻底避开 `libdl.so` 仅 8–12B 的短包装函数覆写风险与 SELinux `execmod`，且将真实 `caller_addr` 原样透传，100% 保持原 linker namespace；
//! 3. **`JNIEnv->RegisterNatives` 原子 8B vtable 槽位替换**：
//!    仅修改 `.data.rel.ro` 中的 `JNINativeInterface[215]` 指针槽，不触碰 `libart.so` 的 `.text`（零 PAC/BTI/SELinux 风险）；
//! 4. **单次 VMA 快照 + 严格边界校验 + 传递依赖闭包**：
//!    扫描前拍取单份实时 `/proc/self/maps` 快照并校验所有 `PT_DYNAMIC`/`DT_STRTAB`/`DT_SYMTAB` 读取边界，
//!    自动将目标库、被 Hook 库及同应用私有 `DT_NEEDED` 依赖纳入 `MemoryRouter`。

use std::collections::{HashMap, HashSet, VecDeque};

use crate::config::HybridConfig;

/// ELF64 常量
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_SONAME: i64 = 14;
#[cfg(any(target_os = "android", target_os = "linux"))]
const DT_PLTRELSZ: i64 = 2;
#[cfg(any(target_os = "android", target_os = "linux"))]
const DT_HASH: i64 = 4;
#[cfg(any(target_os = "android", target_os = "linux"))]
const DT_SYMTAB: i64 = 6;
#[cfg(any(target_os = "android", target_os = "linux"))]
const DT_SYMENT: i64 = 11;
#[cfg(any(target_os = "android", target_os = "linux"))]
const DT_JMPREL: i64 = 23;
#[cfg(any(target_os = "android", target_os = "linux"))]
const DT_GNU_HASH: i64 = 0x6FFF_FEF5u32 as i64;
#[cfg(any(target_os = "android", target_os = "linux"))]
const R_AARCH64_JUMP_SLOT: u32 = 1026;
#[cfg(any(target_os = "android", target_os = "linux"))]
const R_AARCH64_GLOB_DAT: u32 = 1025;

/// 单个已加载 ELF64 模块的解析结果
#[derive(Debug, Clone)]
pub struct LoadedModuleInfo {
    pub path: String,
    pub soname: String,
    pub base: u64,
    pub load_bias: u64,
    pub end: u64,
    pub load_ranges: Vec<(u64, u64)>,
    pub rx_ranges: Vec<(u64, u64)>,
    pub dt_needed: Vec<String>,
    /// 供纯 Rust 内存态符号/GOT 解析的动态表指针（仅在存活进程映像上非零）
    pub symtab_va: u64,
    pub strtab_va: u64,
    pub strsz: usize,
    pub syment: usize,
    pub gnu_hash_va: u64,
    pub sysv_hash_va: u64,
    pub jmprel_va: u64,
    pub pltrelsz: usize,
}

impl LoadedModuleInfo {
    /// 严格按路径边界匹配配置中的库名（防止 `foo.so` 误匹配 `libmyfoo.so`）
    pub fn matches_lib(&self, pattern: &str) -> bool {
        let p = pattern.trim();
        if p.is_empty() {
            return false;
        }
        if self.soname == p || self.path == p {
            return true;
        }
        let base_name = self.path.rsplit('/').next().unwrap_or(&self.path);
        base_name == p
    }
}

/// 纯 Rust 解析内存中的 ELF64 文件缓冲（用于离线单元测试）
pub fn parse_elf64_file_info(bytes: &[u8], load_base: u64, path: &str) -> Option<LoadedModuleInfo> {
    if bytes.len() < 64 || bytes[0..4] != ELF_MAGIC || bytes[4] != ELFCLASS64 {
        return None;
    }
    let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().ok()?) as usize;
    let e_phentsize = u16::from_le_bytes(bytes[54..56].try_into().ok()?) as usize;
    let e_phnum = u16::from_le_bytes(bytes[56..58].try_into().ok()?) as usize;
    let ph_total = e_phentsize.checked_mul(e_phnum)?;
    if e_phentsize < 56 || e_phoff.checked_add(ph_total)? > bytes.len() {
        return None;
    }

    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;
    let mut load_ranges = Vec::new();
    let mut rx_ranges = Vec::new();
    let mut dyn_off_size: Option<(usize, usize)> = None;
    let mut load_segs: Vec<(u64, u64, u64)> = Vec::new();

    for i in 0..e_phnum {
        let off = e_phoff + i * e_phentsize;
        let ph = &bytes[off..off + 56];
        let p_type = u32::from_le_bytes(ph[0..4].try_into().ok()?);
        let p_flags = u32::from_le_bytes(ph[4..8].try_into().ok()?);
        let p_offset = u64::from_le_bytes(ph[8..16].try_into().ok()?);
        let p_vaddr = u64::from_le_bytes(ph[16..24].try_into().ok()?);
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().ok()?);
        let p_memsz = u64::from_le_bytes(ph[40..48].try_into().ok()?);

        if p_type == PT_LOAD && p_memsz > 0 {
            let v_end = p_vaddr.saturating_add(p_memsz);
            min_vaddr = min_vaddr.min(p_vaddr);
            max_vaddr = max_vaddr.max(v_end);
            load_segs.push((p_vaddr, p_offset, p_filesz));
            let s = load_base.wrapping_add(p_vaddr) & !0xFFF;
            let e = load_base
                .wrapping_add(v_end)
                .saturating_add(0xFFF)
                & !0xFFF;
            load_ranges.push((s, e));
            if (p_flags & PF_X) != 0 {
                rx_ranges.push((s, e));
            }
        } else if p_type == PT_DYNAMIC && p_filesz > 0 {
            dyn_off_size = Some((p_offset as usize, p_filesz as usize));
        }
    }

    let mut dt_needed = Vec::new();
    let mut dt_soname: Option<String> = None;
    if let Some((doff, dsz)) = dyn_off_size {
        if doff.checked_add(dsz).is_some_and(|e| e <= bytes.len()) {
            let mut strtab_vaddr: Option<u64> = None;
            let mut strsz: usize = 0;
            let mut needed_offs = Vec::new();
            let mut soname_off: Option<usize> = None;
            let mut cur = doff;
            while cur.checked_add(16).is_some_and(|e| e <= doff + dsz) {
                let d_tag = i64::from_le_bytes(bytes[cur..cur + 8].try_into().ok()?);
                let d_val = u64::from_le_bytes(bytes[cur + 8..cur + 16].try_into().ok()?);
                cur += 16;
                if d_tag == DT_NULL {
                    break;
                } else if d_tag == DT_NEEDED {
                    needed_offs.push(d_val as usize);
                } else if d_tag == DT_SONAME {
                    soname_off = Some(d_val as usize);
                } else if d_tag == DT_STRTAB {
                    strtab_vaddr = Some(d_val);
                } else if d_tag == DT_STRSZ {
                    strsz = d_val as usize;
                }
            }
            if let Some(sva) = strtab_vaddr {
                if let Some(foff) = vaddr_to_file_off(&load_segs, sva) {
                    let end = foff.saturating_add(strsz).min(bytes.len());
                    if foff <= end {
                        let strtab = &bytes[foff..end];
                        if let Some(soff) = soname_off {
                            dt_soname = read_cstr_from_slice(strtab, soff);
                        }
                        for noff in needed_offs {
                            if let Some(s) = read_cstr_from_slice(strtab, noff) {
                                dt_needed.push(s);
                            }
                        }
                    }
                }
            }
        }
    }

    let base = if min_vaddr == u64::MAX {
        load_base
    } else {
        load_base.wrapping_add(min_vaddr) & !0xFFF
    };
    let end = if max_vaddr == 0 {
        base
    } else {
        load_base
            .wrapping_add(max_vaddr)
            .saturating_add(0xFFF)
            & !0xFFF
    };
    let soname = dt_soname
        .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path).to_string());

    Some(LoadedModuleInfo {
        path: path.to_string(),
        soname,
        base,
        load_bias: load_base,
        end,
        load_ranges,
        rx_ranges,
        dt_needed,
        symtab_va: 0,
        strtab_va: 0,
        strsz: 0,
        syment: 24,
        gnu_hash_va: 0,
        sysv_hash_va: 0,
        jmprel_va: 0,
        pltrelsz: 0,
    })
}

fn read_cstr_from_slice(buf: &[u8], off: usize) -> Option<String> {
    if off >= buf.len() {
        return None;
    }
    let nul = buf[off..].iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&buf[off..off + nul]).ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn vaddr_to_file_off(load_segs: &[(u64, u64, u64)], vaddr: u64) -> Option<usize> {
    for &(pv, po, pfsz) in load_segs {
        if vaddr >= pv && vaddr < pv.saturating_add(pfsz) {
            return po.checked_add(vaddr - pv).map(|v| v as usize);
        }
    }
    None
}

/// 根据配置与已加载模块列表，计算应当纳入 Unicorn 白名单的模块集合（支持 `DT_NEEDED` 传递闭包与多命名空间同名库）
pub fn resolve_emulated_dependency_closure<'a>(
    cfg: &HybridConfig,
    modules: &'a [LoadedModuleInfo],
    app_lib_dir: Option<&str>,
) -> Vec<&'a LoadedModuleInfo> {
    // 同一 soname 可能在多个 linker namespace 出现，保留 Vec<usize> 防覆盖
    let mut by_soname: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, m) in modules.iter().enumerate() {
        by_soname.entry(m.soname.as_str()).or_default().push(idx);
        if let Some(base_name) = m.path.rsplit('/').next() {
            if base_name != m.soname {
                by_soname.entry(base_name).or_default().push(idx);
            }
        }
    }

    let mut selected: HashSet<usize> = HashSet::new();
    let mut queue: VecDeque<usize> = VecDeque::new();

    for (idx, m) in modules.iter().enumerate() {
        if cfg.should_emulate_library(&m.path, app_lib_dir) && selected.insert(idx) {
            queue.push_back(idx);
        }
    }

    if cfg.auto_include_app_deps {
        while let Some(idx) = queue.pop_front() {
            for dep in &modules[idx].dt_needed {
                if let Some(candidates) = by_soname.get(dep.as_str()) {
                    for &dep_idx in candidates {
                        let dep_mod = &modules[dep_idx];
                        if !HybridConfig::is_system_library_path(&dep_mod.path)
                            && !cfg
                                .force_native_libs
                                .iter()
                                .any(|f| dep_mod.matches_lib(f))
                            && !dep_mod.path.contains("runidbg_zygisk")
                            && selected.insert(dep_idx)
                        {
                            queue.push_back(dep_idx);
                        }
                    }
                }
            }
        }
    }

    let mut out: Vec<&LoadedModuleInfo> = selected.into_iter().map(|i| &modules[i]).collect();
    out.sort_by_key(|m| m.base);
    out
}

/// 从已加载模块路径中自动推断应用私有 native 库根目录（同时兼容解压目录与 Split APK `*.apk!/lib/arm64-v8a/...`）
pub fn infer_app_lib_dir(modules: &[LoadedModuleInfo], cfg: &HybridConfig) -> Option<String> {
    for m in modules {
        if cfg.target_libs.iter().any(|t| m.matches_lib(t)) {
            // Android 15 extractNativeLibs="false" / App Bundle：
            // `/data/app/~~.../com.pkg-.../base.apk!/lib/arm64-v8a/libfoo.so`
            // 向上取到包含 APK 的包根目录 `/data/app/~~.../com.pkg-...`，使所有 split_*.apk 依赖均能自动命中！
            if let Some((apk_part, _)) = m.path.split_once(".apk!/") {
                if let Some((pkg_root, _)) = apk_part.rsplit_once('/') {
                    if !HybridConfig::is_system_library_path(pkg_root) && !pkg_root.is_empty() {
                        return Some(pkg_root.to_string());
                    }
                }
            }
            if let Some((dir, _)) = m.path.rsplit_once('/') {
                if !HybridConfig::is_system_library_path(dir) && !dir.is_empty() {
                    return Some(dir.to_string());
                }
            }
        }
    }
    None
}

// ============================================================================
// Android / Linux 运行时 `dl_iterate_phdr`、纯 Rust ELF64 符号/GOT Hook 与 JNI 拦截
// ============================================================================

#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod runtime {
    use std::cell::Cell;
    use std::collections::HashSet;
    use std::ffi::{c_void, CStr};
    use std::ptr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    use super::{
        infer_app_lib_dir, resolve_emulated_dependency_closure, LoadedModuleInfo, DT_GNU_HASH,
        DT_HASH, DT_JMPREL, DT_NEEDED, DT_NULL, DT_PLTRELSZ, DT_SONAME, DT_STRSZ, DT_STRTAB,
        DT_SYMENT, DT_SYMTAB, PF_X, PT_DYNAMIC, PT_LOAD, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT,
    };
    use crate::android::{log_info, log_warn};
    use crate::config::{HookTargetSpec, HybridConfig};
    use crate::hybrid::HybridRuntime;
    use crate::inline_hook::patch_relro_pointer;
    use crate::mem_map::{
        invalidate_host_region_cache, parse_proc_maps_line, read_proc_self_maps_raw, untag_tbi,
        HostRegionPerm,
    };

    static ARMED_PCS: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();
    static ORIG_LOADER_DLOPEN: AtomicU64 = AtomicU64::new(0);
    static ORIG_LOADER_ANDROID_DLOPEN_EXT: AtomicU64 = AtomicU64::new(0);
    static ORIG_REGISTER_NATIVES: AtomicU64 = AtomicU64::new(0);

    thread_local! {
        static IN_LINKER_HOOK: Cell<bool> = const { Cell::new(false) };
    }

    /// 拍取单份实时排序 VMA 快照，用于整次 `dl_iterate_phdr` 的 O(log N) 边界安全检查
    fn snapshot_live_vmas() -> Vec<HostRegionPerm> {
        let Ok(content) = read_proc_self_maps_raw() else {
            return Vec::new();
        };
        let mut vmas = Vec::with_capacity(512);
        for line in content.lines() {
            if let Some(e) = parse_proc_maps_line(line) {
                vmas.push(HostRegionPerm {
                    start: e.start,
                    end: e.end,
                    readable: e.readable,
                    writable: e.writable,
                    executable: e.executable,
                });
            }
        }
        vmas.sort_by_key(|r| r.start);
        vmas
    }

    fn vma_range_readable(vmas: &[HostRegionPerm], start: u64, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let Some(end) = start.checked_add(len as u64) else {
            return false;
        };
        let mut cursor = start;
        while cursor < end {
            let idx = vmas.partition_point(|r| r.end <= cursor);
            let Some(r) = vmas.get(idx) else {
                return false;
            };
            if cursor < r.start || cursor >= r.end || !r.readable || r.end <= cursor {
                return false;
            }
            cursor = r.end;
        }
        true
    }

    fn resolve_dyn_ptr(val: u64, load_bias: u64, load_ranges: &[(u64, u64)]) -> Option<u64> {
        if val == 0 {
            return None;
        }
        if load_ranges.iter().any(|&(s, e)| val >= s && val < e) {
            return Some(val);
        }
        let biased = load_bias.wrapping_add(val);
        if load_ranges.iter().any(|&(s, e)| biased >= s && biased < e) {
            return Some(biased);
        }
        None
    }

    /// 通过 `libc::dl_iterate_phdr` + 单份实时 VMA 快照枚举当前进程全部已加载 ELF64 共享库
    pub fn enumerate_loaded_modules() -> Vec<LoadedModuleInfo> {
        let vmas = snapshot_live_vmas();
        struct IterCtx<'a> {
            vmas: &'a [HostRegionPerm],
            list: Vec<LoadedModuleInfo>,
        }
        let mut ctx = IterCtx {
            vmas: &vmas,
            list: Vec::with_capacity(128),
        };

        unsafe extern "C" fn cb(
            info: *mut libc::dl_phdr_info,
            _size: libc::size_t,
            data: *mut c_void,
        ) -> libc::c_int {
            if info.is_null() || data.is_null() {
                return 0;
            }
            let info = &*info;
            let ctx = &mut *(data as *mut IterCtx<'_>);
            let path = if info.dlpi_name.is_null() {
                String::new()
            } else {
                CStr::from_ptr(info.dlpi_name)
                    .to_str()
                    .unwrap_or("")
                    .to_string()
            };
            if path.is_empty() || info.dlpi_phdr.is_null() || info.dlpi_phnum == 0 {
                return 0;
            }

            let load_bias = info.dlpi_addr as u64;
            let phdrs = std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);

            let mut min_va = u64::MAX;
            let mut max_va = 0u64;
            let mut load_ranges = Vec::new();
            let mut rx_ranges = Vec::new();
            let mut dyn_va: Option<(u64, usize)> = None;

            for ph in phdrs {
                if ph.p_type == PT_LOAD && ph.p_memsz > 0 {
                    let seg_start = load_bias.wrapping_add(ph.p_vaddr);
                    let seg_end = seg_start.saturating_add(ph.p_memsz);
                    min_va = min_va.min(seg_start);
                    max_va = max_va.max(seg_end);
                    let ps = seg_start & !0xFFF;
                    let pe = seg_end.saturating_add(0xFFF) & !0xFFF;
                    load_ranges.push((ps, pe));
                    if (ph.p_flags & PF_X) != 0 {
                        rx_ranges.push((ps, pe));
                    }
                } else if ph.p_type == PT_DYNAMIC && ph.p_memsz > 0 {
                    dyn_va = Some((load_bias.wrapping_add(ph.p_vaddr), ph.p_memsz as usize));
                }
            }

            let mut dt_needed = Vec::new();
            let mut dt_soname: Option<String> = None;
            let mut symtab_va = 0u64;
            let mut strtab_va = 0u64;
            let mut strsz = 0usize;
            let mut syment = 24usize;
            let mut gnu_hash_va = 0u64;
            let mut sysv_hash_va = 0u64;
            let mut jmprel_va = 0u64;
            let mut pltrelsz = 0usize;

            if let Some((dva, dsz)) = dyn_va {
                let mut needed_offs = Vec::new();
                let mut soname_off: Option<usize> = None;
                let max_entries = (dsz / 16).min(1024);
                for i in 0..max_entries {
                    let Some(ent_va) = dva.checked_add((i as u64) * 16) else {
                        break;
                    };
                    if !vma_range_readable(ctx.vmas, ent_va, 16) {
                        break;
                    }
                    let tag = ptr::read_unaligned(ent_va as *const i64);
                    let val = ptr::read_unaligned((ent_va + 8) as *const u64);
                    if tag == DT_NULL {
                        break;
                    } else if tag == DT_NEEDED {
                        needed_offs.push(val as usize);
                    } else if tag == DT_SONAME {
                        soname_off = Some(val as usize);
                    } else if tag == DT_STRTAB {
                        if let Some(p) = resolve_dyn_ptr(val, load_bias, &load_ranges) {
                            strtab_va = p;
                        }
                    } else if tag == DT_STRSZ {
                        strsz = (val as usize).min(4 * 1024 * 1024);
                    } else if tag == DT_SYMTAB {
                        if let Some(p) = resolve_dyn_ptr(val, load_bias, &load_ranges) {
                            symtab_va = p;
                        }
                    } else if tag == DT_SYMENT && val >= 24 {
                        syment = val as usize;
                    } else if tag == DT_GNU_HASH {
                        if let Some(p) = resolve_dyn_ptr(val, load_bias, &load_ranges) {
                            gnu_hash_va = p;
                        }
                    } else if tag == DT_HASH {
                        if let Some(p) = resolve_dyn_ptr(val, load_bias, &load_ranges) {
                            sysv_hash_va = p;
                        }
                    } else if tag == DT_JMPREL {
                        if let Some(p) = resolve_dyn_ptr(val, load_bias, &load_ranges) {
                            jmprel_va = p;
                        }
                    } else if tag == DT_PLTRELSZ {
                        pltrelsz = (val as usize).min(4 * 1024 * 1024);
                    }
                }

                if strtab_va != 0 && strsz > 0 && vma_range_readable(ctx.vmas, strtab_va, strsz) {
                    let slice = std::slice::from_raw_parts(strtab_va as *const u8, strsz);
                    if let Some(soff) = soname_off {
                        dt_soname = super::read_cstr_from_slice(slice, soff);
                    }
                    for noff in needed_offs {
                        if let Some(s) = super::read_cstr_from_slice(slice, noff) {
                            dt_needed.push(s);
                        }
                    }
                }
            }

            let base = if min_va == u64::MAX {
                load_bias
            } else {
                min_va & !0xFFF
            };
            let end = if max_va == 0 {
                base
            } else {
                max_va.saturating_add(0xFFF) & !0xFFF
            };
            let soname = dt_soname
                .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(&path).to_string());

            ctx.list.push(LoadedModuleInfo {
                path,
                soname,
                base,
                load_bias,
                end,
                load_ranges,
                rx_ranges,
                dt_needed,
                symtab_va,
                strtab_va,
                strsz,
                syment,
                gnu_hash_va,
                sysv_hash_va,
                jmprel_va,
                pltrelsz,
            });
            0
        }

        // SAFETY: dl_iterate_phdr 同步遍历并在栈变量 ctx 上写入
        unsafe {
            libc::dl_iterate_phdr(Some(cb), (&mut ctx as *mut IterCtx<'_>) as *mut c_void);
        }
        ctx.list
    }

    fn gnu_hash(name: &[u8]) -> u32 {
        let mut h: u32 = 5381;
        for &b in name {
            h = h.wrapping_mul(33).wrapping_add(u32::from(b));
        }
        h
    }

    fn sysv_hash(name: &[u8]) -> u32 {
        let mut h: u32 = 0;
        for &b in name {
            h = (h << 4).wrapping_add(u32::from(b));
            let g = h & 0xF000_0000;
            if g != 0 {
                h ^= g >> 24;
            }
            h &= !g;
        }
        h
    }

    /// 纯 Rust 内存态 ELF64 导出符号解析（零 `dlopen`/`dlsym`，无视 linker namespace 与 APK 封装）
    pub fn lookup_elf64_symbol_in_memory(
        m: &LoadedModuleInfo,
        symbol: &str,
        vmas: &[HostRegionPerm],
    ) -> Option<u64> {
        if m.symtab_va == 0 || m.strtab_va == 0 || m.strsz == 0 || m.syment < 24 {
            return None;
        }
        if !vma_range_readable(vmas, m.strtab_va, m.strsz) {
            return None;
        }
        // SAFETY: 已校验 strtab 整段可读
        let strtab = unsafe { std::slice::from_raw_parts(m.strtab_va as *const u8, m.strsz) };
        let sym_bytes = symbol.as_bytes();

        let check_sym = |sym_idx: u32| -> Option<u64> {
            let sym_va = m.symtab_va.checked_add((sym_idx as u64) * (m.syment as u64))?;
            if !vma_range_readable(vmas, sym_va, 24) {
                return None;
            }
            // Elf64_Sym: st_name(u32@0), st_info(u8@4), st_other(u8@5), st_shndx(u16@6), st_value(u64@8)
            // SAFETY: 已校验 24B 可读
            let (st_name, st_shndx, st_value) = unsafe {
                let n = ptr::read_unaligned(sym_va as *const u32) as usize;
                let sh = ptr::read_unaligned((sym_va + 6) as *const u16);
                let val = ptr::read_unaligned((sym_va + 8) as *const u64);
                (n, sh, val)
            };
            if st_shndx == 0 || st_value == 0 || st_name >= strtab.len() {
                return None;
            }
            let nul = strtab[st_name..].iter().position(|&b| b == 0)?;
            if &strtab[st_name..st_name + nul] == sym_bytes {
                Some(m.load_bias.wrapping_add(st_value))
            } else {
                None
            }
        };

        // 优先走 DT_GNU_HASH O(1) 查找
        if m.gnu_hash_va != 0 && vma_range_readable(vmas, m.gnu_hash_va, 16) {
            // SAFETY: 已校验 16B 头部可读
            let (nbuckets, symoffset, bloom_size, bloom_shift) = unsafe {
                let nb = ptr::read_unaligned(m.gnu_hash_va as *const u32);
                let so = ptr::read_unaligned((m.gnu_hash_va + 4) as *const u32);
                let bs = ptr::read_unaligned((m.gnu_hash_va + 8) as *const u32);
                let bsh = ptr::read_unaligned((m.gnu_hash_va + 12) as *const u32);
                (nb, so, bs, bsh)
            };
            if nbuckets > 0 && bloom_size > 0 && nbuckets < 1_000_000 && bloom_size < 1_000_000 {
                let h = gnu_hash(sym_bytes);
                let bloom_va = m.gnu_hash_va + 16;
                let bloom_idx = ((h / 64) % bloom_size) as u64;
                if vma_range_readable(vmas, bloom_va + bloom_idx * 8, 8) {
                    // SAFETY: 已校验可读
                    let word = unsafe { ptr::read_unaligned((bloom_va + bloom_idx * 8) as *const u64) };
                    let mask = (1u64 << (h % 64)) | (1u64 << ((h >> (bloom_shift & 63)) % 64));
                    if (word & mask) == mask {
                        let buckets_va = bloom_va + (bloom_size as u64) * 8;
                        let chains_va = buckets_va + (nbuckets as u64) * 4;
                        let b_idx = (h % nbuckets) as u64;
                        if vma_range_readable(vmas, buckets_va + b_idx * 4, 4) {
                            // SAFETY: 已校验可读
                            let mut sym_idx =
                                unsafe { ptr::read_unaligned((buckets_va + b_idx * 4) as *const u32) };
                            if sym_idx >= symoffset {
                                for _ in 0..4096 {
                                    let c_va = chains_va + ((sym_idx - symoffset) as u64) * 4;
                                    if !vma_range_readable(vmas, c_va, 4) {
                                        break;
                                    }
                                    // SAFETY: 已校验可读
                                    let chain = unsafe { ptr::read_unaligned(c_va as *const u32) };
                                    if (chain | 1) == (h | 1) {
                                        if let Some(addr) = check_sym(sym_idx) {
                                            return Some(addr);
                                        }
                                    }
                                    if (chain & 1) != 0 {
                                        break;
                                    }
                                    sym_idx = sym_idx.wrapping_add(1);
                                }
                            }
                        }
                    }
                }
                return None;
            }
        }

        // 回退走 DT_HASH (SysV)
        if m.sysv_hash_va != 0 && vma_range_readable(vmas, m.sysv_hash_va, 8) {
            // SAFETY: 已校验可读
            let (nbucket, nchain) = unsafe {
                let nb = ptr::read_unaligned(m.sysv_hash_va as *const u32);
                let nc = ptr::read_unaligned((m.sysv_hash_va + 4) as *const u32);
                (nb, nc)
            };
            if nbucket > 0 && nchain > 0 && nbucket < 1_000_000 && nchain < 1_000_000 {
                let h = sysv_hash(sym_bytes);
                let buckets_va = m.sysv_hash_va + 8;
                let chains_va = buckets_va + (nbucket as u64) * 4;
                let b_idx = (h % nbucket) as u64;
                if vma_range_readable(vmas, buckets_va + b_idx * 4, 4) {
                    // SAFETY: 已校验可读
                    let mut sym_idx =
                        unsafe { ptr::read_unaligned((buckets_va + b_idx * 4) as *const u32) };
                    for _ in 0..4096 {
                        if sym_idx == 0 || sym_idx >= nchain {
                            break;
                        }
                        if let Some(addr) = check_sym(sym_idx) {
                            return Some(addr);
                        }
                        let c_va = chains_va + (sym_idx as u64) * 4;
                        if !vma_range_readable(vmas, c_va, 4) {
                            break;
                        }
                        // SAFETY: 已校验可读
                        sym_idx = unsafe { ptr::read_unaligned(c_va as *const u32) };
                    }
                }
            }
        }

        None
    }

    /// 扫描当前已加载模块：更新 `MemoryRouter` 依赖白名单，并为匹配 `config.hooks` 的目标安装混合模拟 Hook
    pub fn scan_and_arm_hooks() -> usize {
        invalidate_host_region_cache();
        let rt = HybridRuntime::global();
        let cfg = rt.config();
        let vmas = snapshot_live_vmas();
        let modules = enumerate_loaded_modules();
        let app_dir = infer_app_lib_dir(&modules, &cfg);
        let emulated = resolve_emulated_dependency_closure(&cfg, &modules, app_dir.as_deref());

        for m in &emulated {
            rt.register_emulated_module(&m.soname, m.base, m.end, m.rx_ranges.clone());
        }

        let armed_lock = ARMED_PCS.get_or_init(|| Mutex::new(HashSet::new()));
        let mut newly_armed = 0usize;

        for spec in &cfg.hooks {
            let (lib_pat, hook_label, resolved_mod_and_pc): (&str, String, Option<(&LoadedModuleInfo, u64)>) =
                match spec {
                    HookTargetSpec::JniOnLoad { lib } => {
                        let found = modules.iter().find(|m| m.matches_lib(lib)).and_then(|m| {
                            lookup_elf64_symbol_in_memory(m, "JNI_OnLoad", &vmas).map(|pc| (m, pc))
                        });
                        (lib.as_str(), format!("{lib}!JNI_OnLoad"), found)
                    }
                    HookTargetSpec::Symbol { lib, symbol } => {
                        let found = modules.iter().find(|m| m.matches_lib(lib)).and_then(|m| {
                            lookup_elf64_symbol_in_memory(m, symbol, &vmas).map(|pc| (m, pc))
                        });
                        (lib.as_str(), format!("{lib}!{symbol}"), found)
                    }
                    HookTargetSpec::Offset { lib, offset } => {
                        let found = modules
                            .iter()
                            .find(|m| m.matches_lib(lib))
                            .map(|m| (m, m.base.wrapping_add(*offset)));
                        (lib.as_str(), format!("{lib}+0x{offset:x}"), found)
                    }
                };
            let _ = lib_pat;

            let Some((m, raw_pc)) = resolved_mod_and_pc else {
                continue;
            };
            let target_pc = untag_tbi(raw_pc);

            // 关键保障：凡被挂钩的模块必须已在 MemoryRouter 中注册，否则 Unicorn 会立即逃逸自递归！
            rt.register_emulated_module(&m.soname, m.base, m.end, m.rx_ranges.clone());

            // 原子去重（单次加锁占位，防止多线程 TOCTOU 重复安装）
            let claimed = armed_lock
                .lock()
                .map(|mut g| g.insert(target_pc))
                .unwrap_or(false);
            if !claimed {
                continue;
            }

            match rt.install_hook(&hook_label, target_pc, m.base, None, false) {
                Ok(hid) => {
                    newly_armed += 1;
                    log_info(&format!(
                        "armed hybrid hook #{hid}: {hook_label} @ 0x{target_pc:016x} (base=0x{:016x})",
                        m.base
                    ));
                }
                Err(e) => {
                    if let Ok(mut g) = armed_lock.lock() {
                        g.remove(&target_pc);
                    }
                    log_warn(&format!(
                        "failed to arm hook {hook_label} @ 0x{target_pc:016x}: {e}"
                    ));
                }
            }
        }

        newly_armed
    }

    /// 在 `libdl.so` 的 `.rela.plt` / GOT 槽位上以原子 8B 指针替换拦截 `__loader_dlopen` 与 `__loader_android_dlopen_ext`：
    /// - 绝不向 `libdl.so` 仅 8-12B 的 `.text` 包装函数打 Inline Hook；
    /// - 原样透传真实 `caller_addr`，100% 保持 Android 7–15 linker namespace；
    /// - 仅对 `.got`（RELRO）做 `RW -> atomic swap -> RO`，零 `PROT_EXEC`、零 SELinux `execmod`！
    pub fn install_dlopen_hooks() {
        let vmas = snapshot_live_vmas();
        let modules = enumerate_loaded_modules();
        let Some(libdl) = modules
            .iter()
            .find(|m| m.soname == "libdl.so" || m.path.ends_with("/libdl.so"))
        else {
            log_warn("libdl.so not found in dl_iterate_phdr; skip dlopen GOT hook");
            return;
        };

        if ORIG_LOADER_DLOPEN.load(Ordering::Acquire) == 0 {
            let repl = hooked_loader_dlopen as *const () as usize as u64;
            if let Some(slot) = find_plt_got_slot(libdl, "__loader_dlopen", &vmas) {
                // SAFETY: slot 是 libdl.so 内合法 8B 对齐的 R_AARCH64_JUMP_SLOT GOT 项
                match unsafe { install_got_slot_hook(slot, repl, &ORIG_LOADER_DLOPEN) } {
                    Ok(orig) => log_info(&format!(
                        "installed libdl.so GOT hook __loader_dlopen (slot=0x{slot:016x} orig=0x{orig:016x})"
                    )),
                    Err(e) => log_warn(&format!("install __loader_dlopen GOT hook failed: {e}")),
                }
            }
        }

        if ORIG_LOADER_ANDROID_DLOPEN_EXT.load(Ordering::Acquire) == 0 {
            let repl = hooked_loader_android_dlopen_ext as *const () as usize as u64;
            if let Some(slot) = find_plt_got_slot(libdl, "__loader_android_dlopen_ext", &vmas) {
                // SAFETY: slot 是 libdl.so 内合法 8B 对齐的 R_AARCH64_JUMP_SLOT GOT 项
                match unsafe { install_got_slot_hook(slot, repl, &ORIG_LOADER_ANDROID_DLOPEN_EXT) } {
                    Ok(orig) => log_info(&format!(
                        "installed libdl.so GOT hook __loader_android_dlopen_ext (slot=0x{slot:016x} orig=0x{orig:016x})"
                    )),
                    Err(e) => log_warn(&format!(
                        "install __loader_android_dlopen_ext GOT hook failed: {e}"
                    )),
                }
            }
        }
    }

    unsafe fn install_got_slot_hook(
        slot_va: u64,
        repl_va: u64,
        orig_store: &AtomicU64,
    ) -> Result<u64, String> {
        // 先读取原值并发布到 orig_store，确保并发线程在指针交换瞬间不会读到 0！
        let cur = ptr::read_volatile(slot_va as *const u64);
        if cur == 0 || cur == repl_va {
            return Err("GOT 槽位为空或已被替换".to_string());
        }
        orig_store.store(cur, Ordering::Release);
        match patch_relro_pointer(slot_va, repl_va) {
            Ok(old) => {
                orig_store.store(old, Ordering::Release);
                Ok(old)
            }
            Err(e) => {
                orig_store.store(0, Ordering::Release);
                Err(e)
            }
        }
    }

    /// 扫描 ELF64 的 `DT_JMPREL`（`Elf64_Rela` 数组）查找指定外部符号的 GOT 槽位虚拟地址
    fn find_plt_got_slot(
        m: &LoadedModuleInfo,
        target_sym: &str,
        vmas: &[HostRegionPerm],
    ) -> Option<u64> {
        if m.jmprel_va == 0
            || m.pltrelsz < 24
            || m.symtab_va == 0
            || m.strtab_va == 0
            || m.strsz == 0
            || m.syment < 24
        {
            return None;
        }
        if !vma_range_readable(vmas, m.strtab_va, m.strsz) {
            return None;
        }
        // SAFETY: 已校验 strtab 可读
        let strtab = unsafe { std::slice::from_raw_parts(m.strtab_va as *const u8, m.strsz) };
        let count = (m.pltrelsz / 24).min(4096);
        for i in 0..count {
            let rela_va = m.jmprel_va.checked_add((i as u64) * 24)?;
            if !vma_range_readable(vmas, rela_va, 24) {
                break;
            }
            // Elf64_Rela: r_offset(u64@0), r_info(u64@8) -> sym = r_info >> 32, type = r_info & 0xffffffff
            // SAFETY: 已校验 24B 可读
            let (r_offset, r_info) = unsafe {
                let off = ptr::read_unaligned(rela_va as *const u64);
                let info = ptr::read_unaligned((rela_va + 8) as *const u64);
                (off, info)
            };
            let r_type = (r_info & 0xFFFF_FFFF) as u32;
            if r_type != R_AARCH64_JUMP_SLOT && r_type != R_AARCH64_GLOB_DAT {
                continue;
            }
            let sym_idx = (r_info >> 32) as u64;
            let sym_va = m.symtab_va.checked_add(sym_idx * (m.syment as u64))?;
            if !vma_range_readable(vmas, sym_va, 24) {
                continue;
            }
            // SAFETY: 已校验 24B 可读
            let st_name = unsafe { ptr::read_unaligned(sym_va as *const u32) as usize };
            if let Some(name) = super::read_cstr_from_slice(strtab, st_name) {
                if name == target_sym {
                    return Some(m.load_bias.wrapping_add(r_offset));
                }
            }
        }
        None
    }

    fn maybe_rescan_after_dlopen(filename: *const libc::c_char, flags: libc::c_int) {
        if (flags & libc::RTLD_NOLOAD) != 0 || filename.is_null() {
            return;
        }
        // 线程局部重入防卫：防止 scan_and_arm_hooks 内部触发递归
        let already_in = IN_LINKER_HOOK.with(|c| {
            if c.get() {
                true
            } else {
                c.set(true);
                false
            }
        });
        if already_in {
            return;
        }
        // SAFETY: filename 由 dlopen 调用方传入有效 C 字符串
        let name_opt = unsafe { CStr::from_ptr(filename).to_str().ok() };
        if let Some(name) = name_opt {
            // 仅跳过明显的系统库加载；应用私有库或任意可能携带 DT_NEEDED 目标库的包装库均触发扫描
            if !HybridConfig::is_system_library_path(name)
                || HybridRuntime::global()
                    .config()
                    .target_libs
                    .iter()
                    .any(|t| name.contains(t.as_str()))
            {
                let _ = scan_and_arm_hooks();
            }
        }
        IN_LINKER_HOOK.with(|c| c.set(false));
    }

    unsafe extern "C" fn hooked_loader_dlopen(
        filename: *const libc::c_char,
        flags: libc::c_int,
        caller_addr: *const c_void,
    ) -> *mut c_void {
        let orig = ORIG_LOADER_DLOPEN.load(Ordering::Acquire);
        if orig == 0 {
            return ptr::null_mut();
        }
        type LoaderDlopenFn =
            unsafe extern "C" fn(*const libc::c_char, libc::c_int, *const c_void) -> *mut c_void;
        let orig_fn: LoaderDlopenFn = std::mem::transmute(orig as usize);
        let handle = orig_fn(filename, flags, caller_addr);
        if !handle.is_null() {
            maybe_rescan_after_dlopen(filename, flags);
        }
        handle
    }

    unsafe extern "C" fn hooked_loader_android_dlopen_ext(
        filename: *const libc::c_char,
        flags: libc::c_int,
        extinfo: *const c_void,
        caller_addr: *const c_void,
    ) -> *mut c_void {
        let orig = ORIG_LOADER_ANDROID_DLOPEN_EXT.load(Ordering::Acquire);
        if orig == 0 {
            return ptr::null_mut();
        }
        type LoaderAndroidDlopenExtFn = unsafe extern "C" fn(
            *const libc::c_char,
            libc::c_int,
            *const c_void,
            *const c_void,
        ) -> *mut c_void;
        let orig_fn: LoaderAndroidDlopenExtFn = std::mem::transmute(orig as usize);
        let handle = orig_fn(filename, flags, extinfo, caller_addr);
        if !handle.is_null() {
            maybe_rescan_after_dlopen(filename, flags);
        }
        handle
    }

    /// JNI `JNINativeMethod` 结构体（C ABI）
    #[repr(C)]
    pub struct JniNativeMethod {
        pub name: *const libc::c_char,
        pub signature: *const libc::c_char,
        pub fn_ptr: *mut c_void,
    }

    /// 原子替换 `JNINativeInterface[215]`（`RegisterNatives`）vtable 指针槽（不修改 `libart.so` `.text`！）
    ///
    /// # Safety
    /// `jni_env` 必须是当前线程有效的 `JNIEnv*`（如 `postAppSpecialize` 传入的 `env`）。
    pub unsafe fn install_register_natives_hook(jni_env: *mut c_void) {
        if jni_env.is_null() || ORIG_REGISTER_NATIVES.load(Ordering::Acquire) != 0 {
            return;
        }
        let vtable = *(jni_env as *const *const u64);
        if vtable.is_null() {
            return;
        }
        // JNI 规范固定索引：RegisterNatives == 215
        let slot_va = vtable.add(215) as usize as u64;
        let repl = hooked_register_natives as *const () as usize as u64;
        match install_got_slot_hook(slot_va, repl, &ORIG_REGISTER_NATIVES) {
            Ok(orig) => log_info(&format!(
                "installed JNIEnv->RegisterNatives vtable hook (slot=0x{slot_va:016x} orig=0x{orig:016x})"
            )),
            Err(e) => log_warn(&format!("install RegisterNatives vtable hook failed: {e}")),
        }
    }

    unsafe extern "C" fn hooked_register_natives(
        env: *mut c_void,
        clazz: *mut c_void,
        methods: *const JniNativeMethod,
        n_methods: i32,
    ) -> i32 {
        let orig = ORIG_REGISTER_NATIVES.load(Ordering::Acquire);
        if orig == 0 {
            return -1;
        }
        if !methods.is_null() && n_methods > 0 {
            let rt = HybridRuntime::global();
            let cfg = rt.config();
            let router = rt.router();
            let armed_lock = ARMED_PCS.get_or_init(|| Mutex::new(HashSet::new()));
            let slice = std::slice::from_raw_parts(methods, n_methods as usize);
            let mut refreshed_once = false;

            for m in slice {
                if m.name.is_null() || m.fn_ptr.is_null() {
                    continue;
                }
                let Ok(mname) = CStr::from_ptr(m.name).to_str() else {
                    continue;
                };
                let fn_va = untag_tbi(m.fn_ptr as usize as u64);

                let mut found_mod = router
                    .read()
                    .ok()
                    .and_then(|r| r.find_emulated_module(fn_va).map(|em| (em.name.clone(), em.base)));

                // 若该 .so 尚在 .init_array 期间注册（未及返回 dlopen），先即时刷新一次模块扫描！
                if found_mod.is_none() && !refreshed_once {
                    refreshed_once = true;
                    let _ = scan_and_arm_hooks();
                    found_mod = router.read().ok().and_then(|r| {
                        r.find_emulated_module(fn_va)
                            .map(|em| (em.name.clone(), em.base))
                    });
                }

                let Some((mod_name, base)) = found_mod else {
                    continue;
                };
                // 严格同时校验模块名与符号名，避免 `libtarget.so!*` 误挂其他依赖库方法
                let wanted = cfg.hooks.iter().any(|h| match h {
                    HookTargetSpec::Symbol { lib, symbol } => {
                        let lib_ok = lib == "*" || lib == &mod_name || mod_name.ends_with(lib);
                        let sym_ok = symbol == "*" || symbol == mname;
                        lib_ok && sym_ok
                    }
                    _ => false,
                });
                if wanted {
                    let claimed = armed_lock
                        .lock()
                        .map(|mut g| g.insert(fn_va))
                        .unwrap_or(false);
                    if claimed {
                        match rt.install_hook(format!("jni:{mname}"), fn_va, base, None, false) {
                            Ok(hid) => log_info(&format!(
                                "armed dynamic JNI hook #{hid}: {mod_name}!{mname} @ 0x{fn_va:016x}"
                            )),
                            Err(e) => {
                                if let Ok(mut g) = armed_lock.lock() {
                                    g.remove(&fn_va);
                                }
                                log_warn(&format!(
                                    "failed to arm dynamic JNI hook {mod_name}!{mname}: {e}"
                                ));
                            }
                        }
                    }
                }
            }
        }

        type RegNativesFn =
            unsafe extern "C" fn(*mut c_void, *mut c_void, *const JniNativeMethod, i32) -> i32;
        let orig_fn: RegNativesFn = std::mem::transmute(orig as usize);
        orig_fn(env, clazz, methods, n_methods)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_elf64(soname: Option<&str>, needed: &[&str]) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[4] = ELFCLASS64;
        buf[5] = 1;
        buf[6] = 1;
        buf[16..18].copy_from_slice(&3u16.to_le_bytes());
        buf[18..20].copy_from_slice(&183u16.to_le_bytes());
        buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        buf[56..58].copy_from_slice(&2u16.to_le_bytes());

        let ph0 = 64;
        buf[ph0..ph0 + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        buf[ph0 + 4..ph0 + 8].copy_from_slice(&(4u32 | PF_X).to_le_bytes());
        buf[ph0 + 32..ph0 + 40].copy_from_slice(&4096u64.to_le_bytes());
        buf[ph0 + 40..ph0 + 48].copy_from_slice(&4096u64.to_le_bytes());

        let strtab_off = 0x400usize;
        let mut cur_str = strtab_off + 1;
        let mut soname_off = None;
        if let Some(sn) = soname {
            let off = cur_str - strtab_off;
            buf[cur_str..cur_str + sn.len()].copy_from_slice(sn.as_bytes());
            buf[cur_str + sn.len()] = 0;
            cur_str += sn.len() + 1;
            soname_off = Some(off as u64);
        }
        let mut needed_offs = Vec::new();
        for s in needed {
            let off = cur_str - strtab_off;
            buf[cur_str..cur_str + s.len()].copy_from_slice(s.as_bytes());
            buf[cur_str + s.len()] = 0;
            cur_str += s.len() + 1;
            needed_offs.push(off as u64);
        }
        let strsz = (cur_str - strtab_off) as u64;

        let dyn_off = 0x200usize;
        let mut dcur = dyn_off;
        let mut push_dyn = |tag: i64, val: u64| {
            buf[dcur..dcur + 8].copy_from_slice(&tag.to_le_bytes());
            buf[dcur + 8..dcur + 16].copy_from_slice(&val.to_le_bytes());
            dcur += 16;
        };
        if let Some(soff) = soname_off {
            push_dyn(DT_SONAME, soff);
        }
        for noff in needed_offs {
            push_dyn(DT_NEEDED, noff);
        }
        push_dyn(DT_STRTAB, strtab_off as u64);
        push_dyn(DT_STRSZ, strsz);
        push_dyn(DT_NULL, 0);
        let dyn_sz = (dcur - dyn_off) as u64;

        let ph1 = 64 + 56;
        buf[ph1..ph1 + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        buf[ph1 + 8..ph1 + 16].copy_from_slice(&(dyn_off as u64).to_le_bytes());
        buf[ph1 + 16..ph1 + 24].copy_from_slice(&(dyn_off as u64).to_le_bytes());
        buf[ph1 + 32..ph1 + 40].copy_from_slice(&dyn_sz.to_le_bytes());
        buf[ph1 + 40..ph1 + 48].copy_from_slice(&dyn_sz.to_le_bytes());

        buf
    }

    #[test]
    fn test_parse_elf64_split_apk_and_dependency_closure() {
        let elf_a = build_minimal_elf64(Some("libtarget.so"), &["libcrypto_dep.so", "libc.so"]);
        let mod_a = parse_elf64_file_info(
            &elf_a,
            0x7000_0000,
            "/data/app/~~abc/com.demo-1/base.apk!/lib/arm64-v8a/libtarget.so",
        )
        .expect("parse elf A");
        assert_eq!(mod_a.soname, "libtarget.so");
        assert_eq!(mod_a.rx_ranges, vec![(0x7000_0000, 0x7000_1000)]);

        // 带版本号文件名但 DT_SONAME 为 libcrypto_dep.so 的 Split APK 依赖库
        let elf_b = build_minimal_elf64(Some("libcrypto_dep.so"), &["libsub_dep.so", "liblog.so"]);
        let mod_b = parse_elf64_file_info(
            &elf_b,
            0x7001_0000,
            "/data/app/~~abc/com.demo-1/split_config.arm64_v8a.apk!/lib/arm64-v8a/libcrypto_dep.so.1",
        )
        .expect("parse elf B");
        assert_eq!(mod_b.soname, "libcrypto_dep.so");

        let elf_c = build_minimal_elf64(None, &[]);
        let mod_c = parse_elf64_file_info(
            &elf_c,
            0x7002_0000,
            "/data/app/~~abc/com.demo-1/split_config.arm64_v8a.apk!/lib/arm64-v8a/libsub_dep.so",
        )
        .expect("parse elf C");

        let elf_libc = build_minimal_elf64(None, &[]);
        let mod_libc =
            parse_elf64_file_info(&elf_libc, 0x7100_0000, "/system/lib64/libc.so").unwrap();

        let modules = vec![mod_a, mod_b, mod_c, mod_libc];
        let cfg = HybridConfig {
            target_libs: vec!["libtarget.so".to_string()],
            auto_include_app_deps: true,
            ..Default::default()
        };
        let app_dir = infer_app_lib_dir(&modules, &cfg);
        assert_eq!(
            app_dir.as_deref(),
            Some("/data/app/~~abc/com.demo-1"),
            "Split APK 必须向上推断至应用根目录"
        );

        let closure = resolve_emulated_dependency_closure(&cfg, &modules, app_dir.as_deref());
        let names: Vec<&str> = closure.iter().map(|m| m.soname.as_str()).collect();
        assert_eq!(
            names,
            vec!["libtarget.so", "libcrypto_dep.so", "libsub_dep.so"]
        );
    }
}
