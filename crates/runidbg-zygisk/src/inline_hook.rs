//! 纯 Rust ARM64 Inline Hook 管理器（基于 `runidbg::good64`，零 C++ Dobby 依赖）
//!
//! 核心能力：
//! 1. **两阶段提交 (`prepare_install` -> `commit_install`)**：先校验页可读性、拒绝地址重叠、
//!    构造叠加还原后 100% 干净的 Shadow Pristine Page（支持同一 4KB 页内多 Hook）、构造跳板与回退，
//!    待上层将 Shadow Page 与 `HookEntry` 注册完毕后再写入实时 16B 跳转，彻底消除多线程竞态窗口；
//! 2. **ARMv8.5-A BTI 兼容**：识别函数入口 `bti` 着陆指令并在 `+4` 打补丁，且回退跳板尾跳采用
//!    近距 `B` 或 `ldr x16, #8; ret x16; .quad target`（`RET X16` 置 `BTYPE=0b00`，避免 `PROT_BTI` 页 `SIGILL`）；
//! 3. **安全卸载**：`uninstall` 先校验补丁起止地址均有效且字节仍匹配我们的 16B 跳转（防止 `dlclose` 后 VA 复用误写），
//!    写回原始字节成功后再从表中移除记录。

use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;
use std::sync::Arc;

use runidbg_arm64_emu_tracer::good64::{encode_abs_jump, relocate_instructions};

use crate::mem_map::{
    align_down_4k, os_page_size, query_host_region_uncached, untag_tbi, UC_PAGE_SIZE,
};
use crate::trampoline::common_trampoline_addr;

/// Per-hook Stub 固定大小（32 字节，8 字节对齐）
const HOOK_STUB_SIZE: usize = 32;

/// 检测指令字是否为显式 ARM64 BTI 着陆指令（`bti` / `bti c` / `bti j` / `bti jc`）
#[inline]
pub const fn is_bti_instruction(word: u32) -> bool {
    (word & 0xFFFF_FF3F) == 0xD503_241F
}

/// 检测指令字是否为隐式 BTI c 着陆指令 `paciasp` (`0xD503_233F`) 或 `pacibsp` (`0xD503_237F`)
/// （Android 15 `-mbranch-protection=standard` 下 Clang 会省略 `bti c` 直接以 `paciasp` 开头）
#[inline]
pub const fn is_pac_sp_instruction(word: u32) -> bool {
    word == 0xD503_233F || word == 0xD503_237F
}

/// 原子替换 RELRO / `.got` / JNI vtable 中的单个 8 字节函数指针（无需修改任何 `.text` 代码页，
/// 零 `PROT_EXEC`、零 SELinux `execmod`、天然免疫 PAC/BTI 与短函数体覆写风险）
///
/// # Safety
/// `slot_va` 必须是当前进程中 8 字节对齐的有效指针槽（如 `.got` 或 `JNINativeInterface[215]`）。
pub unsafe fn patch_relro_pointer(slot_va: u64, new_ptr: u64) -> Result<u64, String> {
    use std::sync::atomic::{AtomicU64, Ordering};

    let canonical = untag_tbi(slot_va);
    if (canonical & 7) != 0 {
        return Err(format!("RELRO 指针槽未按 8 字节对齐: 0x{canonical:016x}"));
    }
    ensure_range_readable(canonical, 8)?;
    let page = os_page_size() as u64;
    let page_va = canonical & !(page - 1);
    let was_writable = query_host_region_uncached(canonical)
        .map(|r| r.writable)
        .unwrap_or(false);

    if !was_writable
        && libc::mprotect(
            page_va as *mut c_void,
            page as usize,
            libc::PROT_READ | libc::PROT_WRITE,
        ) != 0
    {
        return Err(format!(
            "mprotect(RW) RELRO 槽 0x{page_va:016x} 失败: {}",
            std::io::Error::last_os_error()
        ));
    }

    let atom = &*(canonical as *const AtomicU64);
    let old = atom.swap(new_ptr, Ordering::AcqRel);

    if !was_writable {
        let _ = libc::mprotect(page_va as *mut c_void, page as usize, libc::PROT_READ);
    }
    Ok(old)
}

/// 编码 BTI-safe 的 16 字节绝对尾跳（使用 `ret x16` 而非 `br x16`，`PSTATE.BTYPE = 0b00`，
/// 可安全返回被 Hook 函数体中段而不触发 ARMv8.5-A `PROT_BTI` `SIGILL`）
pub fn encode_bti_safe_abs_jump(from_pc: u64, target_pc: u64) -> Vec<u8> {
    if (from_pc & 3) == 0 && (target_pc & 3) == 0 {
        let delta = (target_pc as i128) - (from_pc as i128);
        if (-0x0800_0000..=0x07FF_FFFC).contains(&delta) {
            let imm26 = ((delta >> 2) as u32) & 0x03FF_FFFF;
            return (0x1400_0000u32 | imm26).to_le_bytes().to_vec();
        }
    }
    let mut out = Vec::with_capacity(16);
    // ldr x16, #8: 0x5800_0050
    out.extend_from_slice(&0x5800_0050u32.to_le_bytes());
    // ret x16: 0xD65F_0200 (sets BTYPE=00 on ARMv8.5-A!)
    out.extend_from_slice(&0xD65F_0200u32.to_le_bytes());
    out.extend_from_slice(&target_pc.to_le_bytes());
    out
}

/// 编码 32 字节 Per-hook Stub
pub fn encode_hook_stub(hook_id: u64, common_trampoline: u64) -> [u8; HOOK_STUB_SIZE] {
    let mut stub = [0u8; HOOK_STUB_SIZE];
    // offset 0: bti jc
    stub[0..4].copy_from_slice(&0xD503_24DFu32.to_le_bytes());
    // offset 4: ldr x16, #12 -> offset 16 (hook_id)
    stub[4..8].copy_from_slice(&0x5800_0070u32.to_le_bytes());
    // offset 8: ldr x17, #16 -> offset 24 (common_trampoline)
    stub[8..12].copy_from_slice(&0x5800_0091u32.to_le_bytes());
    // offset 12: br x17
    stub[12..16].copy_from_slice(&0xD61F_0220u32.to_le_bytes());
    // offset 16..24: hook_id
    stub[16..24].copy_from_slice(&hook_id.to_le_bytes());
    // offset 24..32: common_trampoline
    stub[24..32].copy_from_slice(&common_trampoline.to_le_bytes());
    stub
}

/// 刷新 ARM64 指令缓存（macOS 使用 `sys_icache_invalidate`，Linux/Android 使用纯内联汇编 `dc cvau` + `ic ivau`）
pub fn flush_icache(addr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn sys_icache_invalidate(start: *mut c_void, len: usize);
        }
        // SAFETY: 仅刷新指令缓存，不修改内存内容
        unsafe {
            sys_icache_invalidate(addr as *mut c_void, len);
        }
    }

    #[cfg(all(target_arch = "aarch64", not(target_os = "macos")))]
    {
        // SAFETY: ARMv8-A EL0 标准缓存一致性序列
        unsafe {
            let ctr: u64;
            core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags));
            let dline = (4usize << ((ctr >> 16) & 0xF)).max(4);
            let iline = (4usize << (ctr & 0xF)).max(4);

            let start = addr as usize;
            let end = start.saturating_add(len);

            let mut p = start & !(dline - 1);
            while p < end {
                core::arch::asm!("dc cvau, {}", in(reg) p, options(nostack, preserves_flags));
                p = p.saturating_add(dline);
            }
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));

            let mut p = start & !(iline - 1);
            while p < end {
                core::arch::asm!("ic ivau, {}", in(reg) p, options(nostack, preserves_flags));
                p = p.saturating_add(iline);
            }
            core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "android"))]
core::arch::global_asm!(".hidden __clear_cache");

/// 为 Android NDK `-nodefaultlibs` 链接提供 Unicorn ARM64 TCG JIT 所需的 `__clear_cache` 符号
/// （直接使用上方的纯 ARMv8-A `dc cvau`/`ic ivau` 实现，确保 `.so` 零未解析符号）
///
/// # Safety
/// `start..end` 应为有效的指令代码地址范围（`end <= start` 时安全无操作）。
#[cfg(all(target_arch = "aarch64", target_os = "android"))]
#[no_mangle]
pub unsafe extern "C" fn __clear_cache(start: *mut c_void, end: *mut c_void) {
    let s = start as usize;
    let e = end as usize;
    if e > s {
        flush_icache(start as *const u8, e - s);
    }
}

/// 在 macOS Apple Silicon 上切换当前线程的 MAP_JIT 写保护状态
#[cfg(target_os = "macos")]
#[inline]
pub fn macos_jit_write_protect(enable_protect: bool) {
    extern "C" {
        fn pthread_jit_write_protect_np(enabled: libc::c_int);
    }
    // SAFETY: 标准 Darwin pthread API，用于向 MAP_JIT 页写入机器码
    unsafe {
        pthread_jit_write_protect_np(if enable_protect { 1 } else { 0 });
    }
}

#[cfg(not(target_os = "macos"))]
#[inline]
pub fn macos_jit_write_protect(_enable_protect: bool) {}

/// 可执行跳板内存池（按 OS 页按需 `mmap` 分配，析构时统一释放）
struct ExecutableArena {
    chunks: Vec<(*mut u8, usize)>,
    cur_base: *mut u8,
    cur_len: usize,
    cur_off: usize,
}

// SAFETY: ExecutableArena 仅在 Mutex 锁保护下被访问
unsafe impl Send for ExecutableArena {}

impl ExecutableArena {
    fn new() -> Self {
        Self {
            chunks: Vec::new(),
            cur_base: ptr::null_mut(),
            cur_len: 0,
            cur_off: 0,
        }
    }

    fn alloc_chunk(&mut self, min_size: usize) -> Result<(), String> {
        let page = os_page_size().max(4096);
        let len = min_size.max(page * 4).div_ceil(page) * page;

        #[cfg(target_os = "macos")]
        let flags = libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT;
        #[cfg(not(target_os = "macos"))]
        let flags = libc::MAP_PRIVATE | libc::MAP_ANON;

        // SAFETY: 匿名可执行映射
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
        if ptr == libc::MAP_FAILED || ptr.is_null() {
            return Err(format!(
                "分配可执行跳板页失败 ({len} B): {}",
                std::io::Error::last_os_error()
            ));
        }
        let base = ptr as *mut u8;
        self.chunks.push((base, len));
        self.cur_base = base;
        self.cur_len = len;
        self.cur_off = 0;
        Ok(())
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<u64, String> {
        let aligned = (self.cur_off + 15) & !15;
        if self.cur_base.is_null() || aligned + bytes.len() > self.cur_len {
            self.alloc_chunk(bytes.len() + 64)?;
        }
        let start_off = (self.cur_off + 15) & !15;
        // SAFETY: start_off + bytes.len() <= cur_len 且当前线程独占写入
        unsafe {
            let dst = self.cur_base.add(start_off);
            macos_jit_write_protect(false);
            ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
            macos_jit_write_protect(true);
            flush_icache(dst, bytes.len());
            self.cur_off = start_off + bytes.len();
            Ok(dst as usize as u64)
        }
    }

    fn reserve(&mut self, size: usize) -> Result<*mut u8, String> {
        let aligned = (self.cur_off + 15) & !15;
        if self.cur_base.is_null() || aligned + size > self.cur_len {
            self.alloc_chunk(size + 64)?;
        }
        let start_off = (self.cur_off + 15) & !15;
        // SAFETY: 边界已检查
        let dst = unsafe { self.cur_base.add(start_off) };
        self.cur_off = start_off + size;
        Ok(dst)
    }

    fn write_reserved(&self, dst: *mut u8, bytes: &[u8]) {
        // SAFETY: dst 来自 reserve 且长度不超过预留大小
        unsafe {
            macos_jit_write_protect(false);
            ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
            macos_jit_write_protect(true);
            flush_icache(dst, bytes.len());
        }
    }
}

impl Drop for ExecutableArena {
    fn drop(&mut self) {
        for &(ptr, len) in &self.chunks {
            // SAFETY: 释放由 mmap 分配的匿名页
            unsafe {
                libc::munmap(ptr as *mut c_void, len);
            }
        }
    }
}

/// 单个已安装 Inline Hook 的元数据与回滚备份
#[derive(Debug, Clone)]
struct InstalledHook {
    target_pc: u64,
    patch_offset: usize,
    /// 实际写入目标代码页的补丁长度（普通 16B，含 `paciasp`/`pacibsp` 替换为 `bti jc + 16B jump` 时为 20B）
    patch_len: usize,
    orig_patch_bytes: [u8; 20],
    jmp_patch_bytes: [u8; 20],
    target_is_jit: bool,
    stub_addr: u64,
    fallback_addr: u64,
}

impl InstalledHook {
    fn range(&self) -> (u64, u64) {
        (
            self.target_pc,
            self.target_pc + (self.patch_offset + self.patch_len) as u64,
        )
    }

    fn patch_va(&self) -> u64 {
        self.target_pc + self.patch_offset as u64
    }

    fn orig_slice(&self) -> &[u8] {
        &self.orig_patch_bytes[..self.patch_len]
    }

    fn jmp_slice(&self) -> &[u8] {
        &self.jmp_patch_bytes[..self.patch_len]
    }
}

/// 第一阶段（`prepare_install`）产出的待提交 Hook 描述符（尚未改写目标实时代码页）
#[derive(Debug)]
pub struct PreparedHook {
    pub hook_id: u64,
    pub target_pc: u64,
    pub stub_addr: u64,
    pub fallback_addr: u64,
    pub shadow_pages: Vec<(u64, Arc<[u8; 4096]>)>,
    record: InstalledHook,
}

/// 进程内 ARM64 Inline Hook 管理器
pub struct InlineHookManager {
    arena: ExecutableArena,
    hooks: HashMap<u64, InstalledHook>,
}

impl Default for InlineHookManager {
    fn default() -> Self {
        Self::new()
    }
}

impl InlineHookManager {
    pub fn new() -> Self {
        Self {
            arena: ExecutableArena::new(),
            hooks: HashMap::new(),
        }
    }

    /// 阶段 1：验证可读性与无重叠，构造干净 Shadow Pristine Page、回退跳板与 Per-hook Stub，
    /// **但暂不改写目标代码页**（供上层先注册 Shadow Page 与 `HookEntry`，消除并发竞态）。
    pub fn prepare_install(
        &mut self,
        hook_id: u64,
        target_pc: u64,
        target_is_jit: bool,
    ) -> Result<PreparedHook, String> {
        let canonical_pc = untag_tbi(target_pc);
        if (canonical_pc & 3) != 0 {
            return Err(format!("目标函数地址未按 4 字节对齐: 0x{canonical_pc:016x}"));
        }
        if self.hooks.contains_key(&hook_id) {
            return Err(format!("hook_id={hook_id} 已存在"));
        }

        // 先校验入口 4 字节可读再读取首条指令（避免非法地址 SIGSEGV）
        ensure_range_readable(canonical_pc, 4)?;
        // SAFETY: 已确认 [canonical_pc, canonical_pc + 4) 可读
        let word0 = unsafe { ptr::read_unaligned(canonical_pc as *const u32) };
        let has_bti = is_bti_instruction(word0);
        let has_pac = is_pac_sp_instruction(word0);
        // - 普通函数：patch_offset=0, patch_len=16, reloc_len=16
        // - 显式 bti*：保留 +0 的 bti，在 +4 写 16B 跳转（patch_offset=4, patch_len=16, reloc_len=20）
        // - 隐式 BTI `paciasp`/`pacibsp`：将 +0 写为 `bti jc` 并在 +4 写 16B 跳转（patch_offset=0, patch_len=20, reloc_len=20），
        //   既满足 ARMv8.5-A PROT_BTI 着陆要求，又不提前签名 X30，由 fallback/Unicorn 完整执行原始 paciasp！
        let patch_offset: usize = if has_bti { 4 } else { 0 };
        let patch_len: usize = if has_pac { 20 } else { 16 };
        let reloc_len: usize = patch_offset + patch_len;

        // 检查是否与任何已安装 Hook 存在地址区间重叠
        let new_start = canonical_pc;
        let new_end = canonical_pc + reloc_len as u64;
        for (&other_id, other) in &self.hooks {
            let (os, oe) = other.range();
            if new_start < oe && os < new_end {
                return Err(format!(
                    "目标地址区间 [0x{new_start:016x}, 0x{new_end:016x}) 与已有 hook_id={other_id} [0x{os:016x}, 0x{oe:016x}) 重叠"
                ));
            }
        }

        // 校验覆盖的所有 4KB 页均可完整读取（保证 Shadow Page 快照与原始指令拷贝绝不 SIGSEGV）
        let page0 = align_down_4k(canonical_pc);
        let page_last = align_down_4k(new_end - 1);
        ensure_range_readable(page0, UC_PAGE_SIZE as usize)?;
        if page_last != page0 {
            ensure_range_readable(page_last, UC_PAGE_SIZE as usize)?;
        }

        // 冻结干净的 Shadow Pristine Page：若同页已有其他 Hook，主动还原那些 Hook 的原始字节
        let mut shadow_pages = Vec::with_capacity(2);
        for page in [page0, page_last] {
            if shadow_pages.iter().any(|&(p, _)| p == page) {
                continue;
            }
            let mut snapshot = [0u8; 4096];
            // SAFETY: 已校验整页 4096B 可读
            unsafe {
                ptr::copy_nonoverlapping(page as *const u8, snapshot.as_mut_ptr(), 4096);
            }
            let page_end = page + UC_PAGE_SIZE;
            for existing in self.hooks.values() {
                let pva = existing.patch_va();
                let pend = pva + existing.patch_len as u64;
                if pva < page_end && pend > page {
                    let ov_start = pva.max(page);
                    let ov_end = pend.min(page_end);
                    let src_off = (ov_start - pva) as usize;
                    let dst_off = (ov_start - page) as usize;
                    let n = (ov_end - ov_start) as usize;
                    snapshot[dst_off..dst_off + n]
                        .copy_from_slice(&existing.orig_patch_bytes[src_off..src_off + n]);
                }
            }
            shadow_pages.push((page, Arc::new(snapshot)));
        }

        // 拷贝原始指令（用于回退重定位与卸载恢复）
        let mut orig_all = [0u8; 20];
        // SAFETY: [canonical_pc, canonical_pc + reloc_len) 位于已校验可读的 page0..page_last 内
        unsafe {
            ptr::copy_nonoverlapping(canonical_pc as *const u8, orig_all.as_mut_ptr(), reloc_len);
        }
        let mut orig_patch_bytes = [0u8; 20];
        orig_patch_bytes[..patch_len]
            .copy_from_slice(&orig_all[patch_offset..patch_offset + patch_len]);

        // 构造回退跳板（bti jc + good64 重定位指令 + BTI-safe 尾跳 `B` 或 `RET X16`）
        let fallback_ptr = self.arena.reserve(256)?;
        let fallback_addr = fallback_ptr as usize as u64;
        let mut fallback_code = Vec::with_capacity(128);
        fallback_code.extend_from_slice(&0xD503_24DFu32.to_le_bytes()); // bti jc
        let reloc_base = fallback_addr + 4;
        let relocated = relocate_instructions(&orig_all[..reloc_len], canonical_pc, reloc_base)
            .map_err(|e| format!("good64 重定位目标指令失败 (0x{canonical_pc:016x}): {e}"))?;
        fallback_code.extend_from_slice(&relocated);
        let tail_pc = fallback_addr + fallback_code.len() as u64;
        fallback_code.extend_from_slice(&encode_bti_safe_abs_jump(tail_pc, new_end));
        if fallback_code.len() > 256 {
            return Err(format!(
                "回退跳板超出 256B 预留空间: {}B",
                fallback_code.len()
            ));
        }
        self.arena.write_reserved(fallback_ptr, &fallback_code);

        // 构造 32B Per-hook Stub
        let common = common_trampoline_addr();
        if common == 0 {
            return Err("当前架构不支持 ARM64 通用 Hook 跳板".to_string());
        }
        let stub_bytes = encode_hook_stub(hook_id, common);
        let stub_addr = self.arena.emit(&stub_bytes)?;
        let jmp16 = encode_abs_jump(stub_addr);
        let mut jmp_patch_bytes = [0u8; 20];
        if has_pac {
            jmp_patch_bytes[0..4].copy_from_slice(&0xD503_24DFu32.to_le_bytes()); // bti jc
            jmp_patch_bytes[4..20].copy_from_slice(&jmp16);
        } else {
            jmp_patch_bytes[0..16].copy_from_slice(&jmp16);
        }

        let record = InstalledHook {
            target_pc: canonical_pc,
            patch_offset,
            patch_len,
            orig_patch_bytes,
            jmp_patch_bytes,
            target_is_jit,
            stub_addr,
            fallback_addr,
        };

        Ok(PreparedHook {
            hook_id,
            target_pc: canonical_pc,
            stub_addr,
            fallback_addr,
            shadow_pages,
            record,
        })
    }

    /// 阶段 2：将已准备好的补丁正式写入目标函数入口并记录至表
    pub fn commit_install(&mut self, prepared: PreparedHook) -> Result<(), String> {
        let patch_va = prepared.record.patch_va();
        patch_code_bytes(
            patch_va,
            prepared.record.jmp_slice(),
            prepared.record.target_is_jit,
        )?;
        self.hooks.insert(prepared.hook_id, prepared.record);
        Ok(())
    }

    /// 安装纯原生函数劫持（通过传入 `orig_slot` 在写入补丁前先发布原函数跳板地址，彻底消除并发竞态；
    /// 自动识别 `paciasp`/`pacibsp` 并检查函数前部无提前 `RET`/`B` 截断，拒绝破坏短包装 Stub）
    pub fn install_native_detour(
        &mut self,
        hook_id: u64,
        target_pc: u64,
        replacement_pc: u64,
        orig_slot: &std::sync::atomic::AtomicU64,
        target_is_jit: bool,
    ) -> Result<u64, String> {
        use std::sync::atomic::Ordering;

        let canonical_pc = untag_tbi(target_pc);
        let canonical_repl = untag_tbi(replacement_pc);
        if (canonical_pc & 3) != 0 || (canonical_repl & 3) != 0 {
            return Err("native detour 目标或替换地址未按 4 字节对齐".to_string());
        }
        if self.hooks.contains_key(&hook_id) {
            return Err(format!("hook_id={hook_id} 已存在"));
        }

        ensure_range_readable(canonical_pc, 4)?;
        // SAFETY: 已确认可读
        let word0 = unsafe { ptr::read_unaligned(canonical_pc as *const u32) };
        let has_bti = is_bti_instruction(word0);
        let has_pac = is_pac_sp_instruction(word0);
        let patch_offset: usize = if has_bti { 4 } else { 0 };
        let patch_len: usize = if has_pac { 20 } else { 16 };
        let reloc_len: usize = patch_offset + patch_len;
        let new_start = canonical_pc;
        let new_end = canonical_pc + reloc_len as u64;

        for (&other_id, other) in &self.hooks {
            let (os, oe) = other.range();
            if new_start < oe && os < new_end {
                return Err(format!(
                    "native detour 区间 [0x{new_start:016x}, 0x{new_end:016x}) 与 hook_id={other_id} 重叠"
                ));
            }
        }
        ensure_range_readable(canonical_pc, reloc_len)?;

        let mut orig_all = [0u8; 20];
        // SAFETY: 已校验整段可读
        unsafe {
            ptr::copy_nonoverlapping(canonical_pc as *const u8, orig_all.as_mut_ptr(), reloc_len);
        }
        // 短函数体防误伤检查：若前 reloc_len - 4 字节内已出现无条件终结指令（RET / B / BR），
        // 说明函数体短于补丁长度（如 8-12B 的 libdl.so Stub），严禁覆写相邻函数！
        for idx in 0..(reloc_len / 4).saturating_sub(1) {
            let w = u32::from_le_bytes(orig_all[idx * 4..idx * 4 + 4].try_into().unwrap());
            let is_uncond_term = w == 0xD65F_03C0 // ret
                || (w & 0xFC00_0000) == 0x1400_0000 // b imm26
                || (w & 0xFFFF_FC1F) == 0xD61F_0000; // br xn
            if is_uncond_term {
                return Err(format!(
                    "目标函数 0x{canonical_pc:016x} 在 +{}B 处即结束，短于 {reloc_len}B 补丁，拒绝覆写相邻函数",
                    idx * 4
                ));
            }
        }

        let mut orig_patch_bytes = [0u8; 20];
        orig_patch_bytes[..patch_len]
            .copy_from_slice(&orig_all[patch_offset..patch_offset + patch_len]);

        let fallback_ptr = self.arena.reserve(256)?;
        let fallback_addr = fallback_ptr as usize as u64;
        let mut fallback_code = Vec::with_capacity(128);
        fallback_code.extend_from_slice(&0xD503_24DFu32.to_le_bytes()); // bti jc
        let relocated = relocate_instructions(&orig_all[..reloc_len], canonical_pc, fallback_addr + 4)
            .map_err(|e| format!("good64 重定位 native detour 指令失败: {e}"))?;
        fallback_code.extend_from_slice(&relocated);
        let tail_pc = fallback_addr + fallback_code.len() as u64;
        fallback_code.extend_from_slice(&encode_bti_safe_abs_jump(tail_pc, new_end));
        if fallback_code.len() > 256 {
            return Err("native detour 原函数跳板超出 256B 预留空间".to_string());
        }
        self.arena.write_reserved(fallback_ptr, &fallback_code);

        let mut repl_stub = Vec::with_capacity(20);
        repl_stub.extend_from_slice(&0xD503_24DFu32.to_le_bytes()); // bti jc
        repl_stub.extend_from_slice(&encode_abs_jump(canonical_repl));
        let stub_addr = self.arena.emit(&repl_stub)?;
        let jmp16 = encode_abs_jump(stub_addr);
        let mut jmp_patch_bytes = [0u8; 20];
        if has_pac {
            jmp_patch_bytes[0..4].copy_from_slice(&0xD503_24DFu32.to_le_bytes());
            jmp_patch_bytes[4..20].copy_from_slice(&jmp16);
        } else {
            jmp_patch_bytes[0..16].copy_from_slice(&jmp16);
        }

        let record = InstalledHook {
            target_pc: canonical_pc,
            patch_offset,
            patch_len,
            orig_patch_bytes,
            jmp_patch_bytes,
            target_is_jit,
            stub_addr,
            fallback_addr,
        };
        // 先发布原函数跳板地址再写补丁，彻底消除多线程看到 orig == 0 的竞态；失败则回滚清零
        orig_slot.store(fallback_addr, Ordering::Release);
        if let Err(err) = patch_code_bytes(record.patch_va(), record.jmp_slice(), target_is_jit) {
            orig_slot.store(0, Ordering::Release);
            return Err(err);
        }
        self.hooks.insert(hook_id, record);
        Ok(fallback_addr)
    }

    /// 便捷封装：一次性完成准备与提交（单线程工具/测试用）
    pub fn install(
        &mut self,
        hook_id: u64,
        target_pc: u64,
        target_is_jit: bool,
    ) -> Result<PreparedHook, String> {
        let prep = self.prepare_install(hook_id, target_pc, target_is_jit)?;
        let shadow_pages = prep.shadow_pages.clone();
        let out_id = prep.hook_id;
        let out_pc = prep.target_pc;
        let out_stub = prep.stub_addr;
        let out_fb = prep.fallback_addr;
        let rec_clone = prep.record.clone();
        self.commit_install(prep)?;
        Ok(PreparedHook {
            hook_id: out_id,
            target_pc: out_pc,
            stub_addr: out_stub,
            fallback_addr: out_fb,
            shadow_pages,
            record: rec_clone,
        })
    }

    /// 卸载指定 Hook 并恢复原始指令：
    /// - 若目标 `.so` 已被 `dlclose`/复用 VA，先校验起止地址均有效且字节仍与我们写入的跳板一致；
    /// - 写回成功后再从 `self.hooks` 移除（失败时不丢失原始字节备份）。
    pub fn uninstall(&mut self, hook_id: u64) -> Result<(), String> {
        let Some(hook) = self.hooks.get(&hook_id).cloned() else {
            return Ok(());
        };
        let patch_va = hook.patch_va();
        let len = hook.patch_len;
        if ensure_range_readable(patch_va, len).is_err() {
            self.hooks.remove(&hook_id);
            return Ok(());
        }
        let mut cur = [0u8; 20];
        // SAFETY: 已校验 [patch_va, patch_va + len) 可读
        unsafe {
            ptr::copy_nonoverlapping(patch_va as *const u8, cur.as_mut_ptr(), len);
        }
        if &cur[..len] != hook.jmp_slice() {
            self.hooks.remove(&hook_id);
            return Ok(());
        }

        patch_code_bytes(patch_va, hook.orig_slice(), hook.target_is_jit)?;
        self.hooks.remove(&hook_id);
        Ok(())
    }

    /// 卸载全部已安装的 Hook
    pub fn uninstall_all(&mut self) -> Result<(), String> {
        let ids: Vec<u64> = self.hooks.keys().copied().collect();
        for id in ids {
            self.uninstall(id)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    pub fn get_addrs(&self, hook_id: u64) -> Option<(u64, u64)> {
        self.hooks
            .get(&hook_id)
            .map(|h| (h.stub_addr, h.fallback_addr))
    }
}

/// 校验 `[start, start + len)` 整段地址在宿主实时映射中均存在且可读
fn ensure_range_readable(start: u64, len: usize) -> Result<(), String> {
    if len == 0 {
        return Ok(());
    }
    let end = start
        .checked_add(len as u64)
        .ok_or_else(|| format!("地址区间溢出: 0x{start:016x} + {len}"))?;
    let mut cursor = start;
    while cursor < end {
        let reg = query_host_region_uncached(cursor)
            .ok_or_else(|| format!("地址 0x{cursor:016x} 未映射到宿主进程"))?;
        if !reg.readable {
            return Err(format!("地址 0x{cursor:016x} 所在页不可读"));
        }
        if reg.end <= cursor {
            return Err(format!("地址 0x{cursor:016x} VMA 边界异常"));
        }
        cursor = reg.end;
    }
    Ok(())
}

/// 安全写入目标代码页（按真实 OS 页大小 `mprotect`，保留原始可写属性并在失败时回滚）
fn patch_code_bytes(patch_va: u64, bytes: &[u8], target_is_jit: bool) -> Result<(), String> {
    if bytes.is_empty() {
        return Ok(());
    }
    if target_is_jit {
        // SAFETY: macOS MAP_JIT 页通过线程级写保护切换写入，无需 mprotect
        unsafe {
            macos_jit_write_protect(false);
            ptr::copy_nonoverlapping(bytes.as_ptr(), patch_va as *mut u8, bytes.len());
            macos_jit_write_protect(true);
            flush_icache(patch_va as *const u8, bytes.len());
        }
        return Ok(());
    }

    let page = os_page_size() as u64;
    let start_page = patch_va & !(page - 1);
    let end_page = (patch_va + bytes.len() as u64 - 1) & !(page - 1);
    let protect_len = (end_page - start_page + page) as usize;

    // 查询原页权限（若原本即为 RWX，则恢复时保留 PROT_WRITE；否则恢复 PROT_READ | PROT_EXEC）
    let was_writable = query_host_region_uncached(patch_va)
        .map(|r| r.writable)
        .unwrap_or(false);
    let restore_prot = if was_writable {
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
    } else {
        libc::PROT_READ | libc::PROT_EXEC
    };

    // 保存旧字节以便后续 mprotect 恢复失败时回滚
    let mut prev = vec![0u8; bytes.len()];
    // SAFETY: 调用方已验证可读
    unsafe {
        ptr::copy_nonoverlapping(patch_va as *const u8, prev.as_mut_ptr(), bytes.len());
    }

    // SAFETY: 临时增加 PROT_WRITE 写入后立即恢复权限并刷新指令缓存
    unsafe {
        if libc::mprotect(
            start_page as *mut c_void,
            protect_len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        ) != 0
        {
            return Err(format!(
                "mprotect(RWX) 0x{start_page:016x} ({protect_len} B) 失败: {}",
                std::io::Error::last_os_error()
            ));
        }
        ptr::copy_nonoverlapping(bytes.as_ptr(), patch_va as *mut u8, bytes.len());
        flush_icache(patch_va as *const u8, bytes.len());
        if restore_prot != (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC)
            && libc::mprotect(start_page as *mut c_void, protect_len, restore_prot) != 0
        {
            let err = std::io::Error::last_os_error();
            // 回滚旧字节，避免留下未记录的半成品补丁
            ptr::copy_nonoverlapping(prev.as_ptr(), patch_va as *mut u8, prev.len());
            flush_icache(patch_va as *const u8, prev.len());
            return Err(format!(
                "mprotect 恢复 0x{start_page:016x} 失败（已回滚）: {err}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_bti_instruction() {
        assert!(is_bti_instruction(0xD503_241F)); // bti
        assert!(is_bti_instruction(0xD503_245F)); // bti c
        assert!(is_bti_instruction(0xD503_249F)); // bti j
        assert!(is_bti_instruction(0xD503_24DF)); // bti jc
        assert!(!is_bti_instruction(0xD65F_03C0)); // ret
        assert!(!is_bti_instruction(0xA9BF_7BFD)); // stp x29, x30, [sp, #-16]!
    }

    #[test]
    fn test_encode_hook_stub_layout() {
        let stub = encode_hook_stub(0x1234_5678_9ABC_DEF0, 0x0000_7FFF_1122_3344);
        assert_eq!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 0xD503_24DF);
        assert_eq!(u32::from_le_bytes(stub[4..8].try_into().unwrap()), 0x5800_0070);
        assert_eq!(u32::from_le_bytes(stub[8..12].try_into().unwrap()), 0x5800_0091);
        assert_eq!(u32::from_le_bytes(stub[12..16].try_into().unwrap()), 0xD61F_0220);
        assert_eq!(
            u64::from_le_bytes(stub[16..24].try_into().unwrap()),
            0x1234_5678_9ABC_DEF0
        );
        assert_eq!(
            u64::from_le_bytes(stub[24..32].try_into().unwrap()),
            0x0000_7FFF_1122_3344
        );
    }

    #[test]
    fn test_encode_bti_safe_abs_jump() {
        // 近距使用 4B B 指令
        let near = encode_bti_safe_abs_jump(0x4000_0000, 0x4000_1000);
        assert_eq!(near.len(), 4);
        // 远距使用 ldr x16, #8; ret x16; .quad target（绝不用 br x16）
        let far = encode_bti_safe_abs_jump(0x1000_0000, 0x7000_0000_1234);
        assert_eq!(far.len(), 16);
        assert_eq!(u32::from_le_bytes(far[0..4].try_into().unwrap()), 0x5800_0050);
        assert_eq!(u32::from_le_bytes(far[4..8].try_into().unwrap()), 0xD65F_0200);
        assert_eq!(
            u64::from_le_bytes(far[8..16].try_into().unwrap()),
            0x7000_0000_1234
        );
    }
}
