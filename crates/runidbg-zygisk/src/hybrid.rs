//! 进程内混合执行核心引擎：1:1 零拷贝 Unicorn + 原生逃逸外层循环 + 线程本地重入池 + 自动 HLE Trace
//!
//! 关键工程不变量：
//! 1. **两阶段 Hook 提交**：安装前先注册 Shadow Page 与 `HookEntry` 再写补丁，卸载前先置 `disabled` 再还原字节，杜绝竞态；
//! 2. **独立 1:1 模拟栈 + `PROT_NONE` Guard Page + 独立 1:1 ShadowCallStack (`X18`)**：
//!    彻底隔离模拟栈与宿主 `SavedNativeContext`/Rust 栈，并隔离 Android 15 `-fsanitize=shadow-call-stack` 的 `X18`；
//! 3. **Unicorn 2.x `TCR_EL1.TBI0|TBI1` + 规范去标签页映射 + `Arc` Shadow Page 防 UAF**：
//!    原生兼容 Android 11+ Scudo 指针标签，并在每次 `EngineLease` 释放时清理非栈映射防止悬垂指针；
//! 4. **无损录制上限与安全回退**：`max_insns` 仅作为 Trace 录制上限（到达后停录并继续把函数跑完至 `RET`），
//!    若在产生副作用前发生错误/Panic 则无损尾跳回 `fallback_addr`；
//! 5. **精确 `SVC #0` PC 对齐**：Unicorn `add_intr_hook(intno == 2)` 触发时 `PC` 已前进至 `svc_pc + 4`，
//!    直接透传 `caller_pc = next_pc - 4` 并从 `next_pc` 恢复，绝不跳过 `svc #0` 后的 `ret`。

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::{c_void, CStr};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use runidbg_arm64_emu_tracer::tracer::{
    attach_code_hook, attach_mem_trace_hook, BinaryTracer, ExtKind, HleOpEvent,
    TraceArchiveInfo, TraceArchivePackOptions, TraceLevel,
};
use unicorn_engine::unicorn_const::{uc_error, Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{Arm64CpuModel, RegisterARM64, Unicorn};

use crate::config::HybridConfig;
use crate::inline_hook::InlineHookManager;
use crate::mem_map::{
    invalidate_host_region_cache, os_page_size, query_host_region, untag_tbi, MemoryRouter,
    PageMapDecision, UC_PAGE_SIZE,
};
use crate::trampoline::{runidbg_native_escape_call, NativeCallFrame, SavedNativeContext};

/// 模拟函数返回哨兵地址（非规范映射区的固定标记地址，函数 `RET` 至此即视为模拟完成）
pub const EMULATION_RETURN_SENTINEL: u64 = 0x0000_0000_DEAD_0000;
/// `CPACR_EL1` FPEN[21:20] = 0b11，启用 ARM64 FP/NEON/SIMD 指令
const CPACR_EL1_FPEN_ALL: u64 = 0x3 << 20;
/// 每个池化引擎的独立 1:1 模拟栈大小（256 KiB）
const EMU_STACK_SIZE: usize = 256 * 1024;
/// 每个池化引擎的独立 1:1 Android ShadowCallStack (`X18`) 缓冲大小（16 KiB）
const EMU_SCS_SIZE: usize = 16 * 1024;
/// 入口拷贝到模拟栈顶的最大栈参数窗口（256 字节）
const INCOMING_STACK_ARG_WINDOW: usize = 256;
/// `max_insns == 0` 时的默认内存态 Trace 缓冲容量
const DEFAULT_UNLIMITED_TRACE_CAPACITY: usize = 500_000;
/// 连续零进展逃逸上限（防止 `LR` 损坏导致无限逃逸死循环）
const MAX_ZERO_PROGRESS_ESCAPES: u32 = 64;
/// 符号缓存最大条目数
const MAX_SYMBOL_CACHE_ENTRIES: usize = 2048;

const GPR_REGS: [RegisterARM64; 31] = [
    RegisterARM64::X0,
    RegisterARM64::X1,
    RegisterARM64::X2,
    RegisterARM64::X3,
    RegisterARM64::X4,
    RegisterARM64::X5,
    RegisterARM64::X6,
    RegisterARM64::X7,
    RegisterARM64::X8,
    RegisterARM64::X9,
    RegisterARM64::X10,
    RegisterARM64::X11,
    RegisterARM64::X12,
    RegisterARM64::X13,
    RegisterARM64::X14,
    RegisterARM64::X15,
    RegisterARM64::X16,
    RegisterARM64::X17,
    RegisterARM64::X18,
    RegisterARM64::X19,
    RegisterARM64::X20,
    RegisterARM64::X21,
    RegisterARM64::X22,
    RegisterARM64::X23,
    RegisterARM64::X24,
    RegisterARM64::X25,
    RegisterARM64::X26,
    RegisterARM64::X27,
    RegisterARM64::X28,
    RegisterARM64::X29,
    RegisterARM64::X30,
];

const Q_REGS: [RegisterARM64; 32] = [
    RegisterARM64::Q0,
    RegisterARM64::Q1,
    RegisterARM64::Q2,
    RegisterARM64::Q3,
    RegisterARM64::Q4,
    RegisterARM64::Q5,
    RegisterARM64::Q6,
    RegisterARM64::Q7,
    RegisterARM64::Q8,
    RegisterARM64::Q9,
    RegisterARM64::Q10,
    RegisterARM64::Q11,
    RegisterARM64::Q12,
    RegisterARM64::Q13,
    RegisterARM64::Q14,
    RegisterARM64::Q15,
    RegisterARM64::Q16,
    RegisterARM64::Q17,
    RegisterARM64::Q18,
    RegisterARM64::Q19,
    RegisterARM64::Q20,
    RegisterARM64::Q21,
    RegisterARM64::Q22,
    RegisterARM64::Q23,
    RegisterARM64::Q24,
    RegisterARM64::Q25,
    RegisterARM64::Q26,
    RegisterARM64::Q27,
    RegisterARM64::Q28,
    RegisterARM64::Q29,
    RegisterARM64::Q30,
    RegisterARM64::Q31,
];

/// 单次模拟调用产出的 `.rtrace` 事件
#[derive(Debug, Clone)]
pub struct TraceOutputEvent {
    pub hook_id: u64,
    pub hook_name: String,
    pub hit_index: u64,
    pub target_pc: u64,
    pub module_base: u64,
    pub tid: u64,
    pub rtrace_bytes: Vec<u8>,
    pub info: TraceArchiveInfo,
    pub escapes: u64,
    pub svc_count: u64,
}

/// 可插拔 `.rtrace` 输出回调
pub type TraceSinkCallback = Arc<dyn Fn(TraceOutputEvent) + Send + Sync>;

/// `SVC #0` 系统调用透传上下文（由 Milestone 2 `android::svc` 实现具体处理器）
#[derive(Debug, Clone, Copy)]
pub struct SvcArgs {
    pub nr: u64,
    pub x: [u64; 6],
    pub caller_pc: u64,
}

/// `SVC #0` 系统调用透传结果
#[derive(Debug, Clone, Copy)]
pub struct SvcResult {
    pub ret_x0: u64,
    pub hle_event: Option<HleOpEvent>,
    /// 若系统调用改变了进程内存映射（`mmap`/`munmap`/`mprotect`/`mremap`/`brk`），
    /// 置 `true` 以通知混合引擎立即刷新 Unicorn 页映射，防止 QEMU TLB 残留陈旧指针。
    pub memory_mutated: bool,
    /// 若模拟代码显式调用 `exit`/`exit_group`，置 `true` 以优雅结束当前模拟并先刷出 `.rtrace`。
    pub terminate_emulation: bool,
}

/// 可插拔 `SVC #0` 透传处理器
pub type SvcHandler = Arc<dyn Fn(&SvcArgs) -> Result<SvcResult, String> + Send + Sync>;

/// 已注册 Hook 的运行时元数据
struct HookEntry {
    hook_id: u64,
    name: String,
    target_pc: u64,
    module_base: u64,
    fallback_addr: u64,
    max_hits: u64,
    hit_count: AtomicU64,
    /// 卸载阶段先置 `true`，令并发在途调用方直接尾跳转回退跳板，彻底消除卸载竞态
    disabled: AtomicBool,
}

/// Unicorn 回调记录的待处理逃逸请求（严禁在 C 回调栈内直接执行原生调用）
#[derive(Debug, Clone, Copy)]
enum EscapeRequest {
    ExternalCall { target_pc: u64 },
    /// Unicorn ARM64 `add_intr_hook(intno == 2)` 触发时 `PC` 已指向 `svc #0` 之后的下一条指令
    Svc { next_pc: u64 },
}

/// 单个 `Unicorn` 实例的已映射页信息（追踪真实后备指针与是否 Shadow Page）
#[derive(Debug, Clone, Copy)]
struct MappedPageMeta {
    host_ptr: *mut c_void,
    is_shadow: bool,
}

/// 单个 `Unicorn` 实例的附加状态
struct EngineState {
    router: Arc<RwLock<MemoryRouter>>,
    tracer: BinaryTracer,
    mapped_pages: HashMap<u64, MappedPageMeta>,
    /// 持有所有仍在 Unicorn 中映射的 Shadow Page `Arc`，直至对应页 unmap，彻底杜绝 UAF
    shadow_refs: HashMap<u64, Arc<[u8; 4096]>>,
    /// 永久映射的私有缓冲页集合（独立模拟栈与独立 ShadowCallStack），不随调用结束卸载
    pinned_pages: HashSet<u64>,
    router_epoch: u64,
    pending_escape: Option<EscapeRequest>,
    fatal_error: Option<String>,
}

/// 带底部 `PROT_NONE` Guard Page 的独立 1:1 模拟缓冲（用于模拟栈与 ShadowCallStack）
struct GuardedBuffer {
    alloc_base: *mut u8,
    alloc_len: usize,
    usable_base: *mut u8,
    usable_len: usize,
}

impl GuardedBuffer {
    fn new(usable_len: usize, with_bottom_guard: bool) -> Result<Self, String> {
        let page = os_page_size().max(4096);
        let aligned_usable = usable_len.div_ceil(page) * page;
        let guard_len = if with_bottom_guard { page } else { 0 };
        let alloc_len = aligned_usable + guard_len;

        // SAFETY: 匿名 RW 映射
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                alloc_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED || ptr.is_null() {
            return Err(format!(
                "分配 1:1 模拟缓冲失败 ({alloc_len} B): {}",
                std::io::Error::last_os_error()
            ));
        }
        let alloc_base = ptr as *mut u8;
        if guard_len > 0 {
            // SAFETY: 将最低一页设为 PROT_NONE，拦截栈溢出防止越界映射相邻宿主 VMA
            let rc = unsafe { libc::mprotect(alloc_base as *mut c_void, guard_len, libc::PROT_NONE) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::munmap(alloc_base as *mut c_void, alloc_len);
                }
                return Err(format!("设置模拟栈 Guard Page 失败: {err}"));
            }
        }
        // SAFETY: alloc_base + guard_len 位于已映射范围内
        let usable_base = unsafe { alloc_base.add(guard_len) };
        Ok(Self {
            alloc_base,
            alloc_len,
            usable_base,
            usable_len: aligned_usable,
        })
    }

    #[inline]
    fn base_addr(&self) -> u64 {
        self.usable_base as usize as u64
    }

    #[inline]
    fn top_addr(&self) -> u64 {
        self.base_addr() + self.usable_len as u64
    }

    #[inline]
    fn contains(&self, addr: u64) -> bool {
        addr >= self.base_addr() && addr < self.top_addr()
    }
}

impl Drop for GuardedBuffer {
    fn drop(&mut self) {
        // SAFETY: 释放由 mmap 分配的整块区域（含 Guard Page）
        unsafe {
            libc::munmap(self.alloc_base as *mut c_void, self.alloc_len);
        }
    }
}

/// 池化的单线程 Unicorn 实例（支持重入复用与零重建）
struct PooledEngine {
    uc: Unicorn<'static, EngineState>,
    stack: GuardedBuffer,
    scs: GuardedBuffer,
    trace_level: TraceLevel,
    trace_capacity: usize,
    symbol_cache: HashMap<u64, Option<String>>,
}

impl PooledEngine {
    fn create(
        router: Arc<RwLock<MemoryRouter>>,
        level: TraceLevel,
        capacity: usize,
    ) -> Result<Self, String> {
        let stack = GuardedBuffer::new(EMU_STACK_SIZE, true)?;
        let scs = GuardedBuffer::new(EMU_SCS_SIZE, false)?;
        let epoch = router.read().map(|r| r.epoch()).unwrap_or(0);
        let state = EngineState {
            router,
            tracer: BinaryTracer::new_in_memory_with_level(capacity, level),
            mapped_pages: HashMap::with_capacity(256),
            shadow_refs: HashMap::with_capacity(16),
            pinned_pages: HashSet::with_capacity(96),
            router_epoch: epoch,
            pending_escape: None,
            fatal_error: None,
        };

        let mut uc = Unicorn::new_with_data(Arch::ARM64, Mode::LITTLE_ENDIAN, state)
            .map_err(|e| format!("创建 Unicorn ARM64 实例失败: {e:?}"))?;

        // 1. 切换至 ARM64 MAX CPU 模型（启用 ARMv8.1+ LSE 原子指令如 ldaddal/casal/swpal、SHA3/SM3/SM4/DOTPROD）
        let _ = uc.ctl_set_cpu_model(Arm64CpuModel::MAX as i32);

        // 2. 启用 ARM64 FP/NEON/SIMD
        uc.reg_write(RegisterARM64::CPACR_EL1, CPACR_EL1_FPEN_ALL)
            .map_err(|e| format!("设置 CPACR_EL1 失败: {e:?}"))?;

        // 3. 1:1 映射独立模拟栈与独立 ShadowCallStack 缓冲
        for buf in [&stack, &scs] {
            // SAFETY: buf.usable_base 在 PooledEngine 生命周期内有效且按 OS 页对齐
            unsafe {
                uc.mem_map_ptr(
                    buf.base_addr(),
                    buf.usable_len as u64,
                    Prot::READ | Prot::WRITE,
                    buf.usable_base as *mut c_void,
                )
                .map_err(|e| format!("映射 1:1 私有模拟缓冲失败: {e:?}"))?;
            }
            let st = uc.get_data_mut();
            let mut p = buf.base_addr();
            while p < buf.top_addr() {
                st.mapped_pages.insert(
                    p,
                    MappedPageMeta {
                        host_ptr: p as *mut c_void,
                        is_shadow: false,
                    },
                );
                st.pinned_pages.insert(p);
                p += UC_PAGE_SIZE;
            }
        }

        // 4. 挂载缺页、中断与 BinaryTracer Hooks
        install_memory_hooks(&mut uc)?;
        install_intr_hook(&mut uc)?;
        attach_code_hook(&mut uc, 1, 0, |st| &mut st.tracer)
            .map_err(|e| format!("挂载 BinaryTracer code hook 失败: {e}"))?;
        if level == TraceLevel::Full {
            attach_mem_trace_hook(&mut uc, 1, 0, |st| &mut st.tracer)
                .map_err(|e| format!("挂载 BinaryTracer mem hook 失败: {e}"))?;
        }

        let mut symbol_cache: HashMap<u64, Option<String>> = HashMap::with_capacity(64);
        seed_libc_ifunc_symbols(&mut symbol_cache);

        Ok(Self {
            uc,
            stack,
            scs,
            trace_level: level,
            trace_capacity: capacity,
            symbol_cache,
        })
    }

    /// 卸载除永久私有缓冲（模拟栈 / SCS）外的全部动态页映射与 Shadow Page `Arc` 引用，
    /// 彻底杜绝跨调用悬垂指针（`munmap`/`dlclose` 后 VA 复用）与内存泄漏。
    fn unmap_ephemeral_pages(&mut self) {
        let to_unmap: Vec<u64> = {
            let st = self.uc.get_data();
            st.mapped_pages
                .keys()
                .copied()
                .filter(|p| !st.pinned_pages.contains(p))
                .collect()
        };
        for p in to_unmap {
            let _ = self.uc.mem_unmap(p, UC_PAGE_SIZE);
            let st = self.uc.get_data_mut();
            st.mapped_pages.remove(&p);
            st.shadow_refs.remove(&p);
        }
        let cur_epoch = self
            .uc
            .get_data()
            .router
            .read()
            .map(|r| r.epoch())
            .unwrap_or(self.uc.get_data().router_epoch);
        self.uc.get_data_mut().router_epoch = cur_epoch;
    }

    /// 若全局 `MemoryRouter` 版本变化（例如原生逃逸期间发生 `dlopen` 或安装新 Hook），
    /// 立即刷新非栈映射并清空符号缓存。
    fn sync_router_epoch(&mut self) {
        let cur_epoch = {
            let st = self.uc.get_data();
            st.router.read().map(|r| r.epoch()).unwrap_or(st.router_epoch)
        };
        if cur_epoch == self.uc.get_data().router_epoch {
            return;
        }
        self.unmap_ephemeral_pages();
        if self.symbol_cache.len() > 64 {
            self.symbol_cache.clear();
            seed_libc_ifunc_symbols(&mut self.symbol_cache);
        }
    }

    /// 使用 `dladdr` 精确查询宿主原生函数符号名（要求 `dli_saddr == canonical_pc`，防止非导出内部函数误判）
    fn resolve_native_symbol(&mut self, target_pc: u64) -> Option<String> {
        let canonical = untag_tbi(target_pc);
        if let Some(cached) = self.symbol_cache.get(&canonical) {
            return cached.clone();
        }
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        // SAFETY: dladdr 只读查询动态符号表
        let ok = unsafe { libc::dladdr(canonical as *const c_void, &mut info) };
        let sym = if ok != 0
            && !info.dli_sname.is_null()
            && info.dli_saddr == canonical as *mut c_void
        {
            // SAFETY: dladdr 返回有效 NUL 结尾 C 字符串
            unsafe { CStr::from_ptr(info.dli_sname) }
                .to_str()
                .ok()
                .map(str::to_string)
        } else {
            None
        };
        if self.symbol_cache.len() >= MAX_SYMBOL_CACHE_ENTRIES {
            self.symbol_cache.clear();
            seed_libc_ifunc_symbols(&mut self.symbol_cache);
        }
        self.symbol_cache.insert(canonical, sym.clone());
        sym
    }
}

/// 预装高频 libc 函数真实运行时地址（穿透 Android Bionic `STT_GNU_IFUNC` 隐藏实现如 `__memcpy_aarch64_simd` /
/// `__memcpy_chk` / `__memset_chk` 与熵源函数，并用 `or_insert` 防止别名覆盖 `memcpy`）
fn seed_libc_ifunc_symbols(cache: &mut HashMap<u64, Option<String>>) {
    let preseeded: [(*const c_void, &str); 10] = [
        (libc::malloc as *const c_void, "malloc"),
        (libc::calloc as *const c_void, "calloc"),
        (libc::realloc as *const c_void, "realloc"),
        (libc::free as *const c_void, "free"),
        (libc::memcpy as *const c_void, "memcpy"),
        (libc::memmove as *const c_void, "memmove"),
        (libc::memset as *const c_void, "memset"),
        (libc::gettimeofday as *const c_void, "gettimeofday"),
        (libc::clock_gettime as *const c_void, "clock_gettime"),
        (libc::time as *const c_void, "time"),
    ];
    for (ptr, name) in preseeded {
        let va = untag_tbi(ptr as usize as u64);
        if va != 0 {
            cache.entry(va).or_insert_with(|| Some(name.to_string()));
        }
    }
    // 动态查询 Android FORTIFY 与熵源符号（不引入硬链接符号依赖）
    let dyn_syms: [(&std::ffi::CStr, &str); 6] = [
        (c"__memcpy_chk", "memcpy"),
        (c"__memmove_chk", "memmove"),
        (c"__memset_chk", "memset"),
        (c"getrandom", "getrandom"),
        (c"arc4random", "arc4random"),
        (c"arc4random_buf", "arc4random_buf"),
    ];
    for (csym, name) in dyn_syms {
        // SAFETY: dlsym(RTLD_DEFAULT, ...) 仅只读查询当前进程已加载符号
        let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, csym.as_ptr()) };
        if !ptr.is_null() {
            let va = untag_tbi(ptr as usize as u64);
            cache.entry(va).or_insert_with(|| Some(name.to_string()));
        }
    }
}

/// 线程本地引擎池与当前重入深度
struct ThreadPoolState {
    engines: Vec<PooledEngine>,
    active_depth: usize,
}

thread_local! {
    static THREAD_ENGINE_POOL: RefCell<ThreadPoolState> = const {
        RefCell::new(ThreadPoolState {
            engines: Vec::new(),
            active_depth: 0,
        })
    };
}

/// RAII 借用守卫：归还前清理全部动态页映射，并使用 `try_with` 兼容线程析构阶段
struct EngineLease {
    engine: Option<PooledEngine>,
}

impl EngineLease {
    fn acquire(
        router: Arc<RwLock<MemoryRouter>>,
        level: TraceLevel,
        capacity: usize,
        max_depth: usize,
    ) -> Result<Option<Self>, String> {
        let popped = THREAD_ENGINE_POOL
            .try_with(|cell| {
                let mut st = cell.borrow_mut();
                if st.active_depth >= max_depth {
                    return None;
                }
                st.active_depth += 1;
                let found = st
                    .engines
                    .iter()
                    .rposition(|e| e.trace_level == level && e.trace_capacity == capacity)
                    .map(|idx| st.engines.swap_remove(idx));
                Some(found)
            })
            .ok()
            .flatten();

        let Some(maybe_engine) = popped else {
            return Ok(None);
        };

        let engine = match maybe_engine {
            Some(e) => e,
            None => match PooledEngine::create(router, level, capacity) {
                Ok(e) => e,
                Err(err) => {
                    let _ = THREAD_ENGINE_POOL.try_with(|cell| {
                        let mut st = cell.borrow_mut();
                        st.active_depth = st.active_depth.saturating_sub(1);
                    });
                    return Err(err);
                }
            },
        };

        Ok(Some(Self {
            engine: Some(engine),
        }))
    }

    fn as_mut(&mut self) -> &mut PooledEngine {
        self.engine.as_mut().expect("EngineLease already dropped")
    }
}

impl Drop for EngineLease {
    fn drop(&mut self) {
        if let Some(mut eng) = self.engine.take() {
            // 调用结束后立即卸载非栈页映射，消除跨调用的悬垂 host_ptr 风险
            eng.unmap_ephemeral_pages();
            let _ = THREAD_ENGINE_POOL.try_with(|cell| {
                let mut st = cell.borrow_mut();
                st.active_depth = st.active_depth.saturating_sub(1);
                if st.engines.len() < 8 {
                    st.engines.push(eng);
                }
            });
        } else {
            let _ = THREAD_ENGINE_POOL.try_with(|cell| {
                let mut st = cell.borrow_mut();
                st.active_depth = st.active_depth.saturating_sub(1);
            });
        }
    }
}

/// 为 `Unicorn` 挂载 1:1 零拷贝按需缺页与原生逃逸拦截 Hook
fn install_memory_hooks(uc: &mut Unicorn<'static, EngineState>) -> Result<(), String> {
    uc.add_mem_hook(
        HookType::MEM_UNMAPPED | HookType::MEM_PROT,
        1,
        0,
        |uc, mem_type, addr, _size, _value| {
            let is_fetch = matches!(
                mem_type,
                MemType::FETCH_UNMAPPED | MemType::FETCH_PROT
            );
            let is_write = matches!(
                mem_type,
                MemType::WRITE_UNMAPPED | MemType::WRITE_PROT
            );

            if is_fetch && untag_tbi(addr) == EMULATION_RETURN_SENTINEL {
                let _ = uc.emu_stop();
                return false;
            }

            let decision = {
                let st = uc.get_data();
                let Ok(router) = st.router.read() else {
                    return false;
                };
                router.resolve_page(addr, is_fetch, is_write)
            };

            match decision {
                Ok(PageMapDecision::ExternalEscape { target_pc }) => {
                    uc.get_data_mut().pending_escape =
                        Some(EscapeRequest::ExternalCall { target_pc });
                    let _ = uc.emu_stop();
                    false
                }
                Ok(PageMapDecision::MapPtr {
                    uc_page,
                    host_ptr,
                    perms,
                    shadow_arc,
                }) => {
                    let is_shadow = shadow_arc.is_some();
                    let existing = uc.get_data().mapped_pages.get(&uc_page).copied();

                    if let Some(meta) = existing {
                        // 绝对禁止将只读 Shadow Page 设为可写
                        if meta.is_shadow && (perms & Prot::WRITE) != Prot::NONE {
                            uc.get_data_mut().fatal_error = Some(format!(
                                "拒绝向只读 Shadow Page 0x{uc_page:016x} 授予写权限"
                            ));
                            let _ = uc.emu_stop();
                            return false;
                        }
                        // 若后备 host_ptr 未变，仅升级页权限
                        if meta.host_ptr == host_ptr && meta.is_shadow == is_shadow {
                            if uc.mem_protect(uc_page, UC_PAGE_SIZE, perms).is_ok() {
                                return true;
                            }
                            uc.get_data_mut().fatal_error = Some(format!(
                                "mem_protect 0x{uc_page:016x} ({perms:?}) 失败"
                            ));
                            let _ = uc.emu_stop();
                            return false;
                        }
                        // 后备指针变化（如实时页切换为 Shadow Page）：先彻底 unmap 再重新映射
                        let _ = uc.mem_unmap(uc_page, UC_PAGE_SIZE);
                        let st = uc.get_data_mut();
                        st.mapped_pages.remove(&uc_page);
                        st.shadow_refs.remove(&uc_page);
                    }

                    // 先持有 Arc 再调用 mem_map_ptr，保证整个映射期间后备缓冲绝不释放
                    if let Some(arc) = shadow_arc {
                        uc.get_data_mut().shadow_refs.insert(uc_page, arc);
                    }

                    // SAFETY: host_ptr 经 query_host_region 或 shadow_refs Arc 保证有效且 4KB 对齐
                    match unsafe { uc.mem_map_ptr(uc_page, UC_PAGE_SIZE, perms, host_ptr) } {
                        Ok(()) => {
                            uc.get_data_mut().mapped_pages.insert(
                                uc_page,
                                MappedPageMeta {
                                    host_ptr,
                                    is_shadow,
                                },
                            );
                            true
                        }
                        Err(uc_error::MAP) => {
                            if !is_shadow && uc.mem_protect(uc_page, UC_PAGE_SIZE, perms).is_ok() {
                                uc.get_data_mut().mapped_pages.insert(
                                    uc_page,
                                    MappedPageMeta {
                                        host_ptr,
                                        is_shadow: false,
                                    },
                                );
                                true
                            } else {
                                uc.get_data_mut().shadow_refs.remove(&uc_page);
                                uc.get_data_mut().fatal_error = Some(format!(
                                    "uc_mem_map_ptr 映射冲突 0x{uc_page:016x} ({perms:?})"
                                ));
                                let _ = uc.emu_stop();
                                false
                            }
                        }
                        Err(e) => {
                            uc.get_data_mut().shadow_refs.remove(&uc_page);
                            uc.get_data_mut().fatal_error = Some(format!(
                                "uc_mem_map_ptr 0x{uc_page:016x} -> {host_ptr:?} ({perms:?}) 失败: {e:?}"
                            ));
                            let _ = uc.emu_stop();
                            false
                        }
                    }
                }
                Err(msg) => {
                    uc.get_data_mut().fatal_error = Some(msg);
                    let _ = uc.emu_stop();
                    false
                }
            }
        },
    )
    .map_err(|e| format!("挂载 Unicorn 内存缺页 Hook 失败: {e:?}"))?;

    Ok(())
}

/// 为 `Unicorn` 挂载 `SVC #0` 中断拦截 Hook
///
/// 注意：Unicorn/QEMU ARM64 触发 `EXCP_SWI (intno == 2)` 时，`PC` **已经前进到 `svc_pc + 4`**。
fn install_intr_hook(uc: &mut Unicorn<'static, EngineState>) -> Result<(), String> {
    uc.add_intr_hook(|uc, intno| {
        if intno == 2 {
            let next_pc = uc.reg_read(RegisterARM64::PC).unwrap_or(0);
            uc.get_data_mut().pending_escape = Some(EscapeRequest::Svc { next_pc });
            let _ = uc.emu_stop();
        } else {
            let pc = uc.reg_read(RegisterARM64::PC).unwrap_or(0);
            uc.get_data_mut().fatal_error =
                Some(format!("未处理的 ARM64 异常中断 intno={intno} at PC=0x{pc:016x}"));
            let _ = uc.emu_stop();
        }
    })
    .map_err(|e| format!("挂载 Unicorn 中断 Hook 失败: {e:?}"))?;
    Ok(())
}

/// 模拟调用错误（区分“零副作用可无损回退原生”与“已产生副作用”）
struct EmulateError {
    message: String,
    can_fallback_natively: bool,
}

/// 全局混合执行运行时
pub struct HybridRuntime {
    config: RwLock<HybridConfig>,
    router: Arc<RwLock<MemoryRouter>>,
    hook_mgr: Mutex<InlineHookManager>,
    hooks: RwLock<HashMap<u64, Arc<HookEntry>>>,
    next_hook_id: AtomicU64,
    trace_sink: RwLock<Option<TraceSinkCallback>>,
    svc_handler: RwLock<Option<SvcHandler>>,
}

static GLOBAL_RUNTIME: OnceLock<HybridRuntime> = OnceLock::new();

impl HybridRuntime {
    pub fn global() -> &'static HybridRuntime {
        GLOBAL_RUNTIME.get_or_init(HybridRuntime::new)
    }

    fn new() -> Self {
        Self {
            config: RwLock::new(HybridConfig::default()),
            router: Arc::new(RwLock::new(MemoryRouter::new())),
            hook_mgr: Mutex::new(InlineHookManager::new()),
            hooks: RwLock::new(HashMap::new()),
            next_hook_id: AtomicU64::new(1),
            trace_sink: RwLock::new(None),
            svc_handler: RwLock::new(None),
        }
    }

    pub fn set_config(&self, cfg: HybridConfig) {
        if let Ok(mut guard) = self.config.write() {
            *guard = cfg;
        }
    }

    pub fn config(&self) -> HybridConfig {
        self.config
            .read()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    pub fn set_trace_sink(&self, sink: Option<TraceSinkCallback>) {
        if let Ok(mut guard) = self.trace_sink.write() {
            *guard = sink;
        }
    }

    pub fn set_svc_handler(&self, handler: Option<SvcHandler>) {
        if let Ok(mut guard) = self.svc_handler.write() {
            *guard = handler;
        }
    }

    pub fn router(&self) -> Arc<RwLock<MemoryRouter>> {
        Arc::clone(&self.router)
    }

    pub fn register_emulated_module(
        &self,
        name: impl Into<String>,
        base: u64,
        end: u64,
        rx_ranges: Vec<(u64, u64)>,
    ) {
        if let Ok(mut r) = self.router.write() {
            r.register_emulated_module(name, base, end, rx_ranges);
        }
        invalidate_host_region_cache();
    }

    /// 两阶段无竞态安装混合模拟 Inline Hook：
    /// 1. `prepare_install` 构造干净 Shadow Page 与跳板（暂不改写目标代码）；
    /// 2. 先注册 Shadow Page 与 `HookEntry`；
    /// 3. `commit_install` 写入实时 16B 跳转（失败则自动回滚 `HookEntry`）。
    pub fn install_hook(
        &self,
        name: impl Into<String>,
        target_pc: u64,
        module_base: u64,
        max_hits: Option<u64>,
        target_is_jit: bool,
    ) -> Result<u64, String> {
        let hook_id = self.next_hook_id.fetch_add(1, Ordering::Relaxed);
        let cfg_max_hits = self.config().max_hits as u64;
        let effective_max_hits = max_hits.unwrap_or(cfg_max_hits);

        let mut mgr = self
            .hook_mgr
            .lock()
            .map_err(|_| "InlineHookManager 锁中毒".to_string())?;

        // Phase 1: 准备跳板与干净 Shadow Page
        let prepared = mgr.prepare_install(hook_id, target_pc, target_is_jit)?;

        // Phase 2: 在写入实时代码补丁之前，先注册 Shadow Page 与 HookEntry
        if let Ok(mut router) = self.router.write() {
            for (page, pristine) in &prepared.shadow_pages {
                router.register_shadow_page(*page, Arc::clone(pristine));
            }
        }
        let entry = Arc::new(HookEntry {
            hook_id,
            name: name.into(),
            target_pc: prepared.target_pc,
            module_base,
            fallback_addr: prepared.fallback_addr,
            max_hits: effective_max_hits,
            hit_count: AtomicU64::new(0),
            disabled: AtomicBool::new(false),
        });
        if let Ok(mut map) = self.hooks.write() {
            map.insert(hook_id, entry);
        }

        // Phase 3: 写入实时 16B 跳转（若失败则回滚 hooks 表）
        if let Err(err) = mgr.commit_install(prepared) {
            if let Ok(mut map) = self.hooks.write() {
                map.remove(&hook_id);
            }
            return Err(err);
        }

        Ok(hook_id)
    }

    /// 无竞态卸载单个 Hook：先置 `disabled` 让在途调用尾跳回退 -> 恢复原始字节 -> 移除表项
    pub fn uninstall_hook(&self, hook_id: u64) -> Result<(), String> {
        if let Ok(map) = self.hooks.read() {
            if let Some(entry) = map.get(&hook_id) {
                entry.disabled.store(true, Ordering::Release);
            }
        }
        let res = {
            let mut mgr = self
                .hook_mgr
                .lock()
                .map_err(|_| "InlineHookManager 锁中毒".to_string())?;
            mgr.uninstall(hook_id)
        };
        if res.is_ok() {
            if let Ok(mut map) = self.hooks.write() {
                map.remove(&hook_id);
            }
        }
        res
    }

    /// 卸载全部 Hook 并清空路由状态（供测试隔离清理）
    pub fn reset_for_tests(&self) -> Result<(), String> {
        if let Ok(map) = self.hooks.read() {
            for entry in map.values() {
                entry.disabled.store(true, Ordering::Release);
            }
        }
        {
            let mut mgr = self
                .hook_mgr
                .lock()
                .map_err(|_| "InlineHookManager 锁中毒".to_string())?;
            mgr.uninstall_all()?;
        }
        if let Ok(mut map) = self.hooks.write() {
            map.clear();
        }
        if let Ok(mut r) = self.router.write() {
            r.clear_emulated_modules();
            r.clear_shadow_pages();
        }
        invalidate_host_region_cache();
        self.set_trace_sink(None);
        self.set_svc_handler(None);
        self.set_config(HybridConfig::default());
        Ok(())
    }

    /// 汇编跳板统一分发入口：返回 `0` 表示已完成模拟，返回非 `0` 表示零开销尾跳转至回退地址
    fn dispatch_hook(&self, ctx: &mut SavedNativeContext) -> u64 {
        let entry = {
            let Ok(map) = self.hooks.read() else {
                return 0;
            };
            map.get(&ctx.hook_id).cloned()
        };
        let Some(entry) = entry else {
            return 0;
        };

        if entry.disabled.load(Ordering::Acquire) {
            return entry.fallback_addr;
        }

        // 命中次数限制检查（0 表示不限次）
        let prev_hits = entry.hit_count.fetch_add(1, Ordering::Relaxed);
        if entry.max_hits > 0 && prev_hits >= entry.max_hits {
            return entry.fallback_addr;
        }
        let hit_index = prev_hits + 1;

        let cfg = self.config();
        let trace_level = cfg.trace_level;
        let trace_capacity = if cfg.max_insns == 0 {
            DEFAULT_UNLIMITED_TRACE_CAPACITY
        } else {
            cfg.max_insns.max(1024)
        };

        let lease = match EngineLease::acquire(
            Arc::clone(&self.router),
            trace_level,
            trace_capacity,
            cfg.max_reentry_depth.max(1),
        ) {
            Ok(Some(lease)) => lease,
            Ok(None) | Err(_) => {
                // 超过最大重入深度、TLS 析构期或 Unicorn 初始化失败：无损回退原生函数！
                return entry.fallback_addr;
            }
        };

        ctx.target_pc = entry.target_pc;
        match self.run_emulated_call(ctx, &entry, hit_index, &cfg, lease) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!(
                    "[runidbg-zygisk] emulate error hook={} hit={} fallback={}: {}",
                    entry.name, hit_index, err.can_fallback_natively, err.message
                );
                if err.can_fallback_natively {
                    entry.fallback_addr
                } else {
                    0
                }
            }
        }
    }

    fn run_emulated_call(
        &self,
        ctx: &mut SavedNativeContext,
        entry: &HookEntry,
        hit_index: u64,
        cfg: &HybridConfig,
        mut lease: EngineLease,
    ) -> Result<(), EmulateError> {
        let pooled = lease.as_mut();
        pooled.sync_router_epoch();

        // 1. 重置内存态 BinaryTracer（零重新分配，并启用入口 X0..X7/SP 快照以便离线 decompile 自动 PASS）
        {
            let tracer = &mut pooled.uc.get_data_mut().tracer;
            tracer.reset_in_memory();
            tracer.set_record_entry_regs(true);
            tracer.set_active(true);
        }
        pooled.uc.get_data_mut().pending_escape = None;
        pooled.uc.get_data_mut().fatal_error = None;

        // 2. 将入口栈参数窗口安全拷贝至独立 1:1 模拟栈顶（校验用去标签地址，拷贝保留 MTE 标签）
        let emu_sp = pooled.stack.top_addr() - (INCOMING_STACK_ARG_WINDOW as u64);
        let orig_sp_tagged = ctx.sp;
        let orig_sp = untag_tbi(orig_sp_tagged);
        let copy_len = query_host_region(orig_sp)
            .filter(|r| r.readable)
            .map(|r| (r.end.saturating_sub(orig_sp) as usize).min(INCOMING_STACK_ARG_WINDOW))
            .unwrap_or(0);
        // SAFETY: emu_sp 位于已分配的 256 KiB 模拟栈内；orig_sp..orig_sp+copy_len 经宿主映射校验可读
        unsafe {
            ptr::write_bytes(emu_sp as *mut u8, 0, INCOMING_STACK_ARG_WINDOW);
            if copy_len > 0 {
                ptr::copy_nonoverlapping(orig_sp_tagged as *const u8, emu_sp as *mut u8, copy_len);
            }
        }

        // 3. 将 SavedNativeContext 装填到 Unicorn 寄存器
        // 关键隔离：在 Android/Linux 上将 X18 指向独立 1:1 ShadowCallStack 缓冲，
        // 防止模拟函数内的 `str x30, [x18], #8` 覆盖当前线程真实的 SCS 返回栈！
        let emu_scs_base = pooled.scs.base_addr();
        for (i, &reg) in GPR_REGS.iter().enumerate() {
            let val = if i == 30 {
                EMULATION_RETURN_SENTINEL
            } else if i == 18 && cfg!(any(target_os = "android", target_os = "linux")) {
                emu_scs_base
            } else {
                ctx.x[i]
            };
            pooled.uc.reg_write(reg, val).map_err(|e| EmulateError {
                message: format!("写入寄存器 X{i} 失败: {e:?}"),
                can_fallback_natively: true,
            })?;
        }
        pooled
            .uc
            .reg_write(RegisterARM64::SP, emu_sp)
            .map_err(|e| EmulateError {
                message: format!("写入 SP 失败: {e:?}"),
                can_fallback_natively: true,
            })?;
        pooled
            .uc
            .reg_write(RegisterARM64::NZCV, ctx.nzcv)
            .map_err(|e| EmulateError {
                message: format!("写入 NZCV 失败: {e:?}"),
                can_fallback_natively: true,
            })?;
        let _ = pooled.uc.reg_write(RegisterARM64::TPIDR_EL0, ctx.tpidr_el0);
        if ctx.tpidrro_el0 != 0 {
            let _ = pooled
                .uc
                .reg_write(RegisterARM64::TPIDRRO_EL0, ctx.tpidrro_el0);
        }
        for (i, &qreg) in Q_REGS.iter().enumerate() {
            let mut raw = [0u8; 16];
            raw[0..8].copy_from_slice(&ctx.q[i][0].to_le_bytes());
            raw[8..16].copy_from_slice(&ctx.q[i][1].to_le_bytes());
            pooled
                .uc
                .reg_write_long(qreg, &raw)
                .map_err(|e| EmulateError {
                    message: format!("写入寄存器 Q{i} 失败: {e:?}"),
                    can_fallback_natively: true,
                })?;
        }

        // 4. 外层驱动循环：模拟执行 <-> 原生函数逃逸 / SVC 透传
        // `max_insns` 仅作为 Trace 录制上限：超出后关闭 Tracer 录制并继续把函数完整跑完至 RET，
        // 绝不在函数半途强行截断导致锁泄漏或调用方收到损坏寄存器！
        let trace_limit = cfg.max_insns as u64;
        let hard_runaway_limit: u64 = if trace_limit == 0 {
            50_000_000
        } else {
            trace_limit.saturating_mul(20).max(5_000_000)
        };
        let mut cur_pc = entry.target_pc;
        let mut escapes: u64 = 0;
        let mut svc_count: u64 = 0;
        let mut post_trace_insns: u64 = 0;
        let mut zero_progress_escapes: u32 = 0;
        let mut last_recorded_insns: u64 = 0;

        loop {
            let recorded = pooled.uc.get_data().tracer.stats.total_insns;
            let tracing_active = pooled.uc.get_data().tracer.is_active();

            let step_budget: usize = if tracing_active && trace_limit > 0 {
                if recorded >= trace_limit {
                    pooled.uc.get_data_mut().tracer.set_active(false);
                    (hard_runaway_limit.saturating_sub(post_trace_insns)).min(1_000_000) as usize
                } else {
                    (trace_limit - recorded).min(usize::MAX as u64) as usize
                }
            } else {
                let rem = hard_runaway_limit.saturating_sub(post_trace_insns);
                if rem == 0 {
                    return Err(EmulateError {
                        message: format!(
                            "触发防失控执行上限 ({hard_runaway_limit} 条指令) at PC=0x{cur_pc:016x}"
                        ),
                        can_fallback_natively: false,
                    });
                }
                rem.min(1_000_000) as usize
            };

            pooled.uc.get_data_mut().pending_escape = None;
            let emu_res = pooled
                .uc
                .emu_start(cur_pc, EMULATION_RETURN_SENTINEL, 0, step_budget);

            let pc_after = pooled.uc.reg_read(RegisterARM64::PC).unwrap_or(0);
            if untag_tbi(pc_after) == EMULATION_RETURN_SENTINEL {
                break;
            }

            if let Some(escape) = pooled.uc.get_data_mut().pending_escape.take() {
                let now_recorded = pooled.uc.get_data().tracer.stats.total_insns;
                if now_recorded == last_recorded_insns && tracing_active {
                    zero_progress_escapes += 1;
                    if zero_progress_escapes > MAX_ZERO_PROGRESS_ESCAPES {
                        return Err(EmulateError {
                            message: format!(
                                "检测到连续 {MAX_ZERO_PROGRESS_ESCAPES} 次零进展逃逸（疑似 LR/目标地址异常）at PC=0x{pc_after:016x}"
                            ),
                            can_fallback_natively: escapes == 0 && svc_count == 0 && now_recorded == 0,
                        });
                    }
                } else {
                    zero_progress_escapes = 0;
                    last_recorded_insns = now_recorded;
                }

                match escape {
                    EscapeRequest::ExternalCall { target_pc } => {
                        escapes += 1;
                        let lr = pooled.uc.reg_read(RegisterARM64::X30).unwrap_or(0);
                        execute_native_escape(pooled, target_pc, lr).map_err(|msg| EmulateError {
                            message: msg,
                            can_fallback_natively: false,
                        })?;
                        // 原生调用期间可能触发 dlopen / 新 Hook 安装，立即同步 Router 版本
                        pooled.sync_router_epoch();

                        if untag_tbi(lr) == EMULATION_RETURN_SENTINEL {
                            break;
                        }
                        cur_pc = lr;
                        continue;
                    }
                    EscapeRequest::Svc { next_pc } => {
                        svc_count += 1;
                        let nr = pooled.uc.reg_read(RegisterARM64::X8).unwrap_or(0);
                        let mut x = [0u64; 6];
                        for (i, slot) in x.iter_mut().enumerate() {
                            *slot = pooled.uc.reg_read(GPR_REGS[i]).unwrap_or(0);
                        }
                        let args = SvcArgs {
                            nr,
                            x,
                            caller_pc: next_pc.wrapping_sub(4),
                        };
                        let handler = self.svc_handler.read().ok().and_then(|g| g.clone());
                        if let Some(h) = handler {
                            let res = h(&args).map_err(|msg| EmulateError {
                                message: msg,
                                can_fallback_natively: false,
                            })?;
                            let _ = pooled.uc.reg_write(RegisterARM64::X0, res.ret_x0);
                            if let Some(hle) = res.hle_event {
                                pooled.uc.get_data_mut().tracer.record_hle_event(hle);
                            }
                            if res.memory_mutated {
                                pooled.unmap_ephemeral_pages();
                            }
                            if res.terminate_emulation {
                                break;
                            }
                        } else {
                            let _ = pooled
                                .uc
                                .reg_write(RegisterARM64::X0, (-libc::ENOSYS as i64) as u64);
                        }
                        // Unicorn ARM64 在 EXCP_SWI 回调时 PC 已指向 svc_pc + 4，直接从 next_pc 继续！
                        cur_pc = next_pc;
                        continue;
                    }
                }
            }

            if let Some(err) = pooled.uc.get_data_mut().fatal_error.take() {
                let no_side_effects = pooled.uc.get_data().tracer.stats.total_insns == 0
                    && escapes == 0
                    && svc_count == 0;
                return Err(EmulateError {
                    message: err,
                    can_fallback_natively: no_side_effects,
                });
            }

            if emu_res.is_ok() {
                // 到达单轮 budget：若是刚刚触达 trace_limit，则下一轮关闭 Tracer 并继续把函数跑完！
                if !tracing_active {
                    post_trace_insns = post_trace_insns.saturating_add(step_budget as u64);
                } else if trace_limit > 0 && pooled.uc.get_data().tracer.stats.total_insns >= trace_limit
                {
                    pooled.uc.get_data_mut().tracer.set_active(false);
                }
                cur_pc = pc_after;
                continue;
            }

            let no_side_effects = pooled.uc.get_data().tracer.stats.total_insns == 0
                && escapes == 0
                && svc_count == 0;
            return Err(EmulateError {
                message: format!(
                    "Unicorn 执行异常终止 at PC=0x{pc_after:016x}: {emu_res:?}"
                ),
                can_fallback_natively: no_side_effects,
            });
        }

        // 5. 将最终返回值回写到 SavedNativeContext（X0..X8, Q0..Q7, NZCV）
        for i in 0..9 {
            if let Ok(val) = pooled.uc.reg_read(GPR_REGS[i]) {
                ctx.x[i] = val;
            }
        }
        for i in 0..8 {
            if let Ok(bytes) = pooled.uc.reg_read_long(Q_REGS[i]) {
                let mut raw = [0u8; 16];
                let n = bytes.len().min(16);
                raw[..n].copy_from_slice(&bytes[..n]);
                ctx.q[i][0] = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                ctx.q[i][1] = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            }
        }
        if let Ok(nzcv) = pooled.uc.reg_read(RegisterARM64::NZCV) {
            ctx.nzcv = nzcv;
        }

        // 6. 直接从内存打包压缩为 `.rtrace` 并投递至输出回调
        let sink = self.trace_sink.read().ok().and_then(|g| g.clone());
        if let Some(sink) = sink {
            let note = format!(
                "hybrid hook={} hit={} pc=0x{:x} escapes={} svcs={}",
                entry.name, hit_index, entry.target_pc, escapes, svc_count
            );
            let opts = TraceArchivePackOptions {
                base_addr: entry.module_base,
                note: Some(note),
                compression_level: 6,
            };
            if let Ok((rtrace_bytes, info)) = pooled.uc.get_data().tracer.to_rtrace_bytes(&opts) {
                sink(TraceOutputEvent {
                    hook_id: entry.hook_id,
                    hook_name: entry.name.clone(),
                    hit_index,
                    target_pc: entry.target_pc,
                    module_base: entry.module_base,
                    tid: current_tid(),
                    rtrace_bytes,
                    info,
                    escapes,
                    svc_count,
                });
            }
        }

        Ok(())
    }
}

/// 在真实宿主 CPU 上执行单次外部原生函数调用，并自动通过 `dladdr` 注入 HLE Trace 事件
fn execute_native_escape(
    pooled: &mut PooledEngine,
    target_pc: u64,
    lr: u64,
) -> Result<(), String> {
    let mut frame = NativeCallFrame {
        target_pc: untag_tbi(target_pc),
        ..Default::default()
    };

    for i in 0..9 {
        frame.x[i] = pooled.uc.reg_read(GPR_REGS[i]).unwrap_or(0);
    }
    for i in 0..8 {
        if let Ok(bytes) = pooled.uc.reg_read_long(Q_REGS[i]) {
            let mut raw = [0u8; 16];
            let n = bytes.len().min(16);
            raw[..n].copy_from_slice(&bytes[..n]);
            frame.q[i][0] = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            frame.q[i][1] = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        }
    }

    // O(1) 快速路径：绝大多数情况下 uc_sp 位于 pooled.stack 内，无需扫描宿主 VMA 表（保留原始 MTE 标签拷贝）
    let uc_sp_tagged = pooled.uc.reg_read(RegisterARM64::SP).unwrap_or(0);
    let uc_sp = untag_tbi(uc_sp_tagged);
    let copy_len = if pooled.stack.contains(uc_sp) {
        (pooled.stack.top_addr().saturating_sub(uc_sp) as usize).min(256)
    } else {
        query_host_region(uc_sp)
            .filter(|r| r.readable)
            .map(|r| (r.end.saturating_sub(uc_sp) as usize).min(256))
            .unwrap_or(0)
    };
    if copy_len > 0 {
        // SAFETY: uc_sp..uc_sp+copy_len 经模拟栈边界或宿主 VMA 校验可读
        unsafe {
            ptr::copy_nonoverlapping(
                uc_sp_tagged as *const u8,
                frame.stack_args.as_mut_ptr(),
                copy_len,
            );
        }
    }
    frame.stack_arg_bytes = copy_len as u64;

    let arg0 = frame.x[0];
    let arg1 = frame.x[1];
    let arg2 = frame.x[2];

    // SAFETY: target_pc 指向宿主进程内有效函数入口，在独立外层循环栈上安全执行
    unsafe {
        runidbg_native_escape_call(&mut frame as *mut NativeCallFrame);
    }

    for i in 0..9 {
        let _ = pooled.uc.reg_write(GPR_REGS[i], frame.x[i]);
    }
    for i in 0..8 {
        let mut raw = [0u8; 16];
        raw[0..8].copy_from_slice(&frame.q[i][0].to_le_bytes());
        raw[8..16].copy_from_slice(&frame.q[i][1].to_le_bytes());
        let _ = pooled.uc.reg_write_long(Q_REGS[i], &raw);
    }
    let _ = pooled.uc.reg_write(RegisterARM64::NZCV, frame.nzcv);

    // 仅在精确符号匹配时记录 HLE 扩展事件
    if let Some(sym) = pooled.resolve_native_symbol(target_pc) {
        let caller_pc = if untag_tbi(lr) == EMULATION_RETURN_SENTINEL {
            pooled
                .uc
                .get_data()
                .tracer
                .records()
                .last()
                .map(|r| r.pc)
                .unwrap_or(target_pc)
        } else {
            lr.wrapping_sub(4)
        };
        let events = classify_native_hle(&sym, arg0, arg1, arg2, frame.x[0], caller_pc);
        for ev in events {
            pooled.uc.get_data_mut().tracer.record_hle_event(ev);
        }
    }

    Ok(())
}

/// 安全从宿主进程内存读取最多 8 字节并转为小端 `u64`（校验用去标签规范地址，解引用保留 MTE 标签 `[59:56]`）
fn safe_read_host_u64_prefix(ptr_va: u64, byte_len: usize) -> Option<u64> {
    if ptr_va == 0 || byte_len == 0 {
        return None;
    }
    let canonical = untag_tbi(ptr_va);
    let n = byte_len.min(8);
    let reg = query_host_region(canonical)?;
    if !reg.readable || reg.end.saturating_sub(canonical) < n as u64 {
        return None;
    }
    let mut buf = [0u8; 8];
    // SAFETY: 已确认 [canonical, canonical + n) 位于宿主可读映射内，使用带标签 ptr_va 解引用兼容硬件 MTE
    unsafe {
        ptr::copy_nonoverlapping(ptr_va as *const u8, buf.as_mut_ptr(), n);
    }
    Some(u64::from_le_bytes(buf))
}

/// 将 `dladdr` 精确解析出的宿主函数名归一化并映射为 `BinaryTracer` 的 `HleOpEvent`
pub fn classify_native_hle(
    raw_sym: &str,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    ret0: u64,
    caller_pc: u64,
) -> Vec<HleOpEvent> {
    let stripped = raw_sym.trim_start_matches('_');
    let base = stripped.split('$').next().unwrap_or(stripped);
    let mut out = Vec::new();

    match base {
        "malloc" => {
            if ret0 != 0 {
                out.push(HleOpEvent {
                    kind: ExtKind::HleMalloc,
                    subop_or_byte: 0,
                    aux_subop: 0,
                    dst: ret0,
                    src: 0,
                    len: arg0,
                    caller_pc,
                });
            }
        }
        "calloc" => {
            let total = arg0.saturating_mul(arg1);
            if ret0 != 0 {
                out.push(HleOpEvent {
                    kind: ExtKind::HleMalloc,
                    subop_or_byte: 1,
                    aux_subop: 0,
                    dst: ret0,
                    src: 0,
                    len: total,
                    caller_pc,
                });
                if total > 0 {
                    out.push(HleOpEvent {
                        kind: ExtKind::HleMemset,
                        subop_or_byte: 0,
                        aux_subop: 2, // calloc_zero
                        dst: ret0,
                        src: 0,
                        len: total,
                        caller_pc,
                    });
                }
            }
        }
        "realloc" => {
            if ret0 != 0 {
                out.push(HleOpEvent {
                    kind: ExtKind::HleMalloc,
                    subop_or_byte: 2,
                    aux_subop: 0,
                    dst: ret0,
                    src: arg0,
                    len: arg1,
                    caller_pc,
                });
                if arg0 != 0 && arg0 != ret0 && arg1 > 0 {
                    out.push(HleOpEvent {
                        kind: ExtKind::HleMemcpy,
                        subop_or_byte: 2, // realloc_copy
                        aux_subop: 0,
                        dst: ret0,
                        src: arg0,
                        len: arg1,
                        caller_pc,
                    });
                    out.push(HleOpEvent {
                        kind: ExtKind::HleFree,
                        subop_or_byte: 0,
                        aux_subop: 0,
                        dst: arg0,
                        src: 0,
                        len: 0,
                        caller_pc,
                    });
                }
            }
        }
        "free" => {
            if arg0 != 0 {
                out.push(HleOpEvent {
                    kind: ExtKind::HleFree,
                    subop_or_byte: 0,
                    aux_subop: 0,
                    dst: arg0,
                    src: 0,
                    len: 0,
                    caller_pc,
                });
            }
        }
        "memcpy" | "memcpy_chk" | "platform_memmove" | "memmove" | "memmove_chk" => {
            if arg0 != 0 && arg1 != 0 && arg2 > 0 {
                let subop = if base.contains("memmove") { 1 } else { 0 };
                out.push(HleOpEvent {
                    kind: ExtKind::HleMemcpy,
                    subop_or_byte: subop,
                    aux_subop: 0,
                    dst: arg0,
                    src: arg1,
                    len: arg2,
                    caller_pc,
                });
            }
        }
        "memset" | "memset_chk" | "platform_memset" => {
            if arg0 != 0 && arg2 > 0 {
                out.push(HleOpEvent {
                    kind: ExtKind::HleMemset,
                    subop_or_byte: (arg1 & 0xFF) as u8,
                    aux_subop: 0,
                    dst: arg0,
                    src: 0,
                    len: arg2,
                    caller_pc,
                });
            }
        }
        "bzero" | "platform_bzero" => {
            if arg0 != 0 && arg1 > 0 {
                out.push(HleOpEvent {
                    kind: ExtKind::HleMemset,
                    subop_or_byte: 0,
                    aux_subop: 1,
                    dst: arg0,
                    src: 0,
                    len: arg1,
                    caller_pc,
                });
            }
        }
        "rand" | "random" => {
            out.push(HleOpEvent {
                kind: ExtKind::HleSource,
                subop_or_byte: 0,
                aux_subop: 0,
                dst: 0,
                src: ret0,
                len: 0,
                caller_pc,
            });
        }
        "arc4random" => {
            out.push(HleOpEvent {
                kind: ExtKind::HleSource,
                subop_or_byte: 1,
                aux_subop: 0,
                dst: 0,
                src: ret0,
                len: 0,
                caller_pc,
            });
        }
        "arc4random_buf" => {
            if arg0 != 0 && arg1 > 0 {
                let first8 = safe_read_host_u64_prefix(arg0, arg1 as usize).unwrap_or(0);
                out.push(HleOpEvent {
                    kind: ExtKind::HleSource,
                    subop_or_byte: 4, // 按内存熵源（同 getrandom）记录前 8 字节，供离线重建与反编译
                    aux_subop: 0,
                    dst: arg0,
                    src: first8,
                    len: arg1,
                    caller_pc,
                });
            }
        }
        "lrand48" => {
            out.push(HleOpEvent {
                kind: ExtKind::HleSource,
                subop_or_byte: 2,
                aux_subop: 0,
                dst: 0,
                src: ret0,
                len: 0,
                caller_pc,
            });
        }
        "time" => {
            out.push(HleOpEvent {
                kind: ExtKind::HleSource,
                subop_or_byte: 3,
                aux_subop: 0,
                dst: arg0,
                src: ret0,
                len: if arg0 != 0 { 8 } else { 0 },
                caller_pc,
            });
        }
        "getrandom" => {
            let n = ret0 as isize;
            if arg0 != 0 && n > 0 {
                let len = n as u64;
                let first8 = safe_read_host_u64_prefix(arg0, len as usize).unwrap_or(0);
                out.push(HleOpEvent {
                    kind: ExtKind::HleSource,
                    subop_or_byte: 4,
                    aux_subop: 0,
                    dst: arg0,
                    src: first8,
                    len,
                    caller_pc,
                });
            }
        }
        "gettimeofday" => {
            // AAPCS64 返回 int (W0)，仅检查低 32 位是否为 0，且先校验指针可读性
            if arg0 != 0 && (ret0 as i32) == 0 {
                if let Some(tv_sec) = safe_read_host_u64_prefix(arg0, 8) {
                    out.push(HleOpEvent {
                        kind: ExtKind::HleSource,
                        subop_or_byte: 5,
                        aux_subop: 0,
                        dst: arg0,
                        src: tv_sec,
                        len: 16,
                        caller_pc,
                    });
                }
            }
        }
        "clock_gettime" if arg1 != 0 && (ret0 as i32) == 0 => {
            if let Some(tv_sec) = safe_read_host_u64_prefix(arg1, 8) {
                out.push(HleOpEvent {
                    kind: ExtKind::HleSource,
                    subop_or_byte: 6,
                    aux_subop: 0,
                    dst: arg1,
                    src: tv_sec,
                    len: 16,
                    caller_pc,
                });
            }
        }
        _ => {}
    }

    out
}

/// 获取当前线程 OS TID
fn current_tid() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut tid: u64 = 0;
        // SAFETY: pthread_threadid_np 写入当前线程 ID 到局部变量
        unsafe {
            libc::pthread_threadid_np(0, &mut tid);
        }
        tid
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: SYS_gettid 无副作用
        unsafe { libc::syscall(libc::SYS_gettid) as u64 }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    {
        0
    }
}

#[cfg(all(target_arch = "aarch64", any(target_os = "android", target_os = "linux")))]
core::arch::global_asm!(".hidden runidbg_hook_dispatch");

/// 供 ARM64 汇编跳板 `runidbg_hook_common_trampoline` 调用的 C ABI 分发符号
///
/// # Safety
/// `ctx` 必须是由 `runidbg_hook_common_trampoline` 在当前线程栈上构造的、16 字节对齐且有效可写的
/// `SavedNativeContext` 指针（允许为空，空指针时安全返回 0）。
#[no_mangle]
pub unsafe extern "C" fn runidbg_hook_dispatch(ctx: *mut SavedNativeContext) -> u64 {
    if ctx.is_null() {
        return 0;
    }
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: 汇编跳板在栈上构造了 16B 对齐的有效 SavedNativeContext
        let ctx_ref = unsafe { &mut *ctx };
        HybridRuntime::global().dispatch_hook(ctx_ref)
    }));
    match res {
        Ok(ret) => ret,
        Err(_) => {
            eprintln!("[runidbg-zygisk] panic caught in runidbg_hook_dispatch");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_native_hle_variants() {
        let mut buf = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let ptr = buf.as_mut_ptr() as u64;
        // getrandom 必须记录前 8 随机字节而非长度
        let evs = classify_native_hle("getrandom", ptr, 8, 0, 8, 0x1000);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, ExtKind::HleSource);
        assert_eq!(evs[0].subop_or_byte, 4);
        assert_eq!(evs[0].len, 8);
        assert_eq!(evs[0].src, u64::from_le_bytes(buf));

        // gettimeofday 返回非 0（失败）时不应产生脏记录
        assert!(classify_native_hle("gettimeofday", ptr, 0, 0, (-1i32 as u32) as u64, 0x1000).is_empty());
        // gettimeofday 返回 W0 == 0（高 32 位含脏数据）时仍应识别成功
        let tv = [1_700_000_000u64, 123456u64];
        let tv_evs = classify_native_hle(
            "gettimeofday",
            tv.as_ptr() as u64,
            0,
            0,
            0xDEAD_BEEF_0000_0000,
            0x2000,
        );
        assert_eq!(tv_evs.len(), 1);
        assert_eq!(tv_evs[0].subop_or_byte, 5);
        assert_eq!(tv_evs[0].src, 1_700_000_000);

        // realloc 搬迁时应产出 HleMalloc + HleMemcpy(realloc_copy) + HleFree
        let re = classify_native_hle("realloc", 0x5000, 128, 0, 0x6000, 0x3000);
        assert_eq!(re.len(), 3);
        assert_eq!(re[0].kind, ExtKind::HleMalloc);
        assert_eq!(re[1].kind, ExtKind::HleMemcpy);
        assert_eq!(re[2].kind, ExtKind::HleFree);
    }
}
