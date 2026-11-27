use std::fs::OpenOptions;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::ptr;

use memmap2::MmapMut;
use unicorn_engine::unicorn_const::{HookType, MemType};
use unicorn_engine::{RegisterARM64, UcHookId, Unicorn};

use crate::error::EmuResult;
use crate::tracer::record::{
    decode_trace_record, format_ext_record, ExtKind, ExtRecord, HleOpEvent, TraceFilter,
    TraceLevel, TraceRecord, TraceStats,
};

/// 追踪的 32 个核心 64 位寄存器列表：X0..X30 + SP
const TRACKED_REGS: [RegisterARM64; 32] = [
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
    RegisterARM64::SP,
];

/// 主索引流存储后端
enum TraceSink {
    Memory(Vec<TraceRecord>),
    Mmap {
        path: PathBuf,
        mmap: MmapMut,
        max_records: usize,
        written: usize,
    },
}

/// 扩展事件流存储后端
enum ExtSink {
    Disabled,
    Memory(Vec<ExtRecord>),
    Mmap {
        path: PathBuf,
        mmap: MmapMut,
        max_records: usize,
        written: usize,
    },
}

/// 高性能分层双流二进制 Trace 引擎
pub struct BinaryTracer {
    sink: TraceSink,
    ext_sink: ExtSink,
    level: TraceLevel,
    filter: TraceFilter,
    /// Tracer 当前是否已通过 `attach_tracer` 激活（未激活时 HLE/内存 Hook 严禁写入）
    active: bool,
    /// 上一条指令执行前的寄存器快照，用于 O(1) 计算增量变化
    prev_regs: [u64; 32],
    /// 是否已完成首次快照初始化
    initialized: bool,
    /// 最近一条已记录指令的 `seq_low32` 与 `pc`（供内存 R/W Hook 关联）
    last_seq_low32: u32,
    last_pc: u64,
    /// 防止 `finalize()` 与 `Drop` 重复输出截断告警
    truncation_warned: bool,
    pub stats: TraceStats,
}

impl BinaryTracer {
    /// 创建纯内存预分配模式的 Tracer（默认 `RegDelta` 级别）
    pub fn new_in_memory(capacity: usize) -> Self {
        Self::new_in_memory_with_level(capacity, TraceLevel::RegDelta)
    }

    /// 创建指定分层级别的纯内存预分配 Tracer（`Full`/`RegDelta` 自动预分配扩展流缓冲）
    pub fn new_in_memory_with_level(capacity: usize, level: TraceLevel) -> Self {
        let ext_sink = match level {
            TraceLevel::Fast => ExtSink::Disabled,
            TraceLevel::RegDelta | TraceLevel::Full => {
                ExtSink::Memory(Vec::with_capacity(capacity.saturating_mul(2)))
            }
        };
        Self {
            sink: TraceSink::Memory(Vec::with_capacity(capacity)),
            ext_sink,
            level,
            filter: TraceFilter::new(),
            active: false,
            prev_regs: [0u64; 32],
            initialized: false,
            last_seq_low32: 0,
            last_pc: 0,
            truncation_warned: false,
            stats: TraceStats::default(),
        }
    }

    /// 创建基于 `memmap2` 的单流零拷贝落盘 Tracer（`trace.idx`）
    pub fn new_mmap(path: impl AsRef<Path>, max_records: usize) -> EmuResult<Self> {
        let path_buf = path.as_ref().to_path_buf();
        let total_bytes = checked_mmap_bytes(max_records, size_of::<TraceRecord>())?;
        let mmap = create_mmap_file(&path_buf, total_bytes)?;
        Ok(Self {
            sink: TraceSink::Mmap {
                path: path_buf,
                mmap,
                max_records,
                written: 0,
            },
            ext_sink: ExtSink::Disabled,
            level: TraceLevel::RegDelta,
            filter: TraceFilter::new(),
            active: false,
            prev_regs: [0u64; 32],
            initialized: false,
            last_seq_low32: 0,
            last_pc: 0,
            truncation_warned: false,
            stats: TraceStats::default(),
        })
    }

    /// 创建双流零拷贝落盘 Tracer（`trace.idx` + `trace.ext`）
    pub fn new_dual_mmap(
        idx_path: impl AsRef<Path>,
        ext_path: impl AsRef<Path>,
        max_idx_records: usize,
        max_ext_records: usize,
        level: TraceLevel,
    ) -> EmuResult<Self> {
        let idx_buf = idx_path.as_ref().to_path_buf();
        let ext_buf = ext_path.as_ref().to_path_buf();
        let idx_bytes = checked_mmap_bytes(max_idx_records, size_of::<TraceRecord>())?;
        let ext_bytes = checked_mmap_bytes(max_ext_records, size_of::<ExtRecord>())?;
        let idx_mmap = create_mmap_file(&idx_buf, idx_bytes)?;
        let ext_mmap = create_mmap_file(&ext_buf, ext_bytes)?;

        Ok(Self {
            sink: TraceSink::Mmap {
                path: idx_buf,
                mmap: idx_mmap,
                max_records: max_idx_records,
                written: 0,
            },
            ext_sink: ExtSink::Mmap {
                path: ext_buf,
                mmap: ext_mmap,
                max_records: max_ext_records,
                written: 0,
            },
            level,
            filter: TraceFilter::new(),
            active: false,
            prev_regs: [0u64; 32],
            initialized: false,
            last_seq_low32: 0,
            last_pc: 0,
            truncation_warned: false,
            stats: TraceStats::default(),
        })
    }

    #[inline]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    #[inline]
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    #[inline]
    fn ext_remaining_capacity(&self) -> usize {
        match &self.ext_sink {
            ExtSink::Disabled => 0,
            ExtSink::Memory(buf) => buf.capacity().saturating_sub(buf.len()),
            ExtSink::Mmap {
                max_records,
                written,
                ..
            } => max_records.saturating_sub(*written),
        }
    }

    #[inline]
    pub const fn level(&self) -> TraceLevel {
        self.level
    }

    pub fn set_level(&mut self, level: TraceLevel) {
        self.level = level;
    }

    pub fn filter_mut(&mut self) -> &mut TraceFilter {
        &mut self.filter
    }

    #[inline(always)]
    pub fn should_trace(&self, pc: u64) -> bool {
        self.filter.matches(pc)
    }

    /// 热路径：极速记录（仅 PC + Opcode，无寄存器采样）
    #[inline(always)]
    pub fn record_fast(&mut self, pc: u64, opcode: u32) {
        let seq = self.stats.total_insns;
        self.stats.total_insns += 1;
        self.last_seq_low32 = seq as u32;
        self.last_pc = pc;

        let level_tag = if self.stats.recorded_insns == 0 {
            match self.level {
                TraceLevel::Fast => 1u8,
                TraceLevel::RegDelta => 2u8,
                TraceLevel::Full => 3u8,
            }
        } else {
            0u8
        };

        self.push_idx(TraceRecord {
            pc,
            opcode,
            reg_diff_mask: 0,
            primary_reg_id: 0xFF,
            _reserved: [0, level_tag, 0],
            primary_reg_val: 0,
            seq_low32: seq as u32,
        });
    }

    /// 热路径：增量寄存器记录（零堆分配、零字符串格式化）
    #[inline(always)]
    pub fn record_step(&mut self, pc: u64, opcode: u32, cur_regs: &[u64; 32]) {
        let seq = self.stats.total_insns;
        self.stats.total_insns += 1;
        let seq32 = seq as u32;
        self.last_seq_low32 = seq32;
        self.last_pc = pc;

        let mut diff_mask: u32 = 0;
        let mut primary_reg_id: u8 = 0xFF;
        let mut primary_reg_val: u64 = 0;
        let mut has_ext: u8 = 0;

        if self.initialized {
            for i in 0..32 {
                let cur = cur_regs[i];
                if cur != self.prev_regs[i] {
                    diff_mask |= 1u32 << i;
                    if primary_reg_id == 0xFF {
                        primary_reg_id = i as u8;
                        primary_reg_val = cur;
                    } else {
                        if !matches!(self.ext_sink, ExtSink::Disabled) {
                            has_ext = 1;
                        }
                        self.push_ext(ExtRecord {
                            seq_low32: seq32,
                            kind: ExtKind::RegDeltaExtra as u8,
                            size_or_reg: i as u8,
                            _pad: [0; 2],
                            addr: 0,
                            value: cur,
                            pc,
                        });
                    }
                    self.prev_regs[i] = cur;
                }
            }
        } else {
            self.prev_regs = *cur_regs;
            self.initialized = true;
        }

        // 记录首条指令的录制级别标记到 `_reserved[1]`（1=Fast, 2=RegDelta, 3=Full），用于离线检测缺失 `.ext`
        let level_tag = if self.stats.recorded_insns == 0 {
            match self.level {
                TraceLevel::Fast => 1u8,
                TraceLevel::RegDelta => 2u8,
                TraceLevel::Full => 3u8,
            }
        } else {
            0u8
        };

        self.push_idx(TraceRecord {
            pc,
            opcode,
            reg_diff_mask: diff_mask,
            primary_reg_id,
            _reserved: [has_ext, level_tag, 0],
            primary_reg_val,
            seq_low32: seq32,
        });
    }

    /// 热路径：记录内存读写事件到扩展流（零堆分配）
    #[inline(always)]
    pub fn record_mem_access(&mut self, is_write: bool, addr: u64, size: usize, value: u64) {
        let kind = if is_write {
            ExtKind::MemWrite
        } else {
            ExtKind::MemRead
        };
        self.push_ext(ExtRecord {
            seq_low32: self.last_seq_low32,
            kind: kind as u8,
            size_or_reg: size.min(255) as u8,
            _pad: [0; 2],
            addr,
            value,
            pc: self.last_pc,
        });
    }

    #[inline(always)]
    fn push_idx(&mut self, record: TraceRecord) {
        match &mut self.sink {
            TraceSink::Memory(buf) => {
                if buf.len() < buf.capacity() {
                    buf.push(record);
                    self.stats.recorded_insns += 1;
                } else {
                    self.stats.dropped_insns += 1;
                }
            }
            TraceSink::Mmap {
                mmap,
                max_records,
                written,
                ..
            } => {
                if *written < *max_records {
                    let offset = *written * size_of::<TraceRecord>();
                    // SAFETY: offset + size_of::<TraceRecord>() <= mmap.len()，unaligned 写入 packed 结构
                    unsafe {
                        let dst = mmap.as_mut_ptr().add(offset) as *mut TraceRecord;
                        ptr::write_unaligned(dst, record);
                    }
                    *written += 1;
                    self.stats.recorded_insns += 1;
                } else {
                    self.stats.dropped_insns += 1;
                }
            }
        }
    }

    #[inline(always)]
    fn push_ext(&mut self, record: ExtRecord) {
        match &mut self.ext_sink {
            ExtSink::Disabled => {}
            ExtSink::Memory(buf) => {
                if buf.len() < buf.capacity() {
                    buf.push(record);
                    self.stats.recorded_ext += 1;
                } else {
                    self.stats.dropped_ext += 1;
                }
            }
            ExtSink::Mmap {
                mmap,
                max_records,
                written,
                ..
            } => {
                if *written < *max_records {
                    let offset = *written * size_of::<ExtRecord>();
                    // SAFETY: offset + size_of::<ExtRecord>() <= mmap.len()
                    unsafe {
                        let dst = mmap.as_mut_ptr().add(offset) as *mut ExtRecord;
                        ptr::write_unaligned(dst, record);
                    }
                    *written += 1;
                    self.stats.recorded_ext += 1;
                } else {
                    self.stats.dropped_ext += 1;
                }
            }
        }
    }

    /// 记录 HLE 跳板内存/分配事件到 `trace.ext`（未激活、`Disabled` 或尚无已记录指令时零开销短路）
    #[inline]
    pub fn record_hle_event(&mut self, ev: HleOpEvent) {
        if !self.active
            || matches!(self.ext_sink, ExtSink::Disabled)
            || self.stats.recorded_insns == 0
        {
            return;
        }
        let seq = self.last_seq_low32;
        match ev.kind {
            ExtKind::HleMemcpy => {
                // 原子保证 HleMemcpy + HleMeta 成对落盘，避免仅写半条留下孤儿记录
                if self.ext_remaining_capacity() < 2 {
                    self.stats.dropped_ext += 2;
                    return;
                }
                self.push_ext(ExtRecord {
                    seq_low32: seq,
                    kind: ExtKind::HleMemcpy as u8,
                    size_or_reg: ev.subop_or_byte,
                    _pad: [0; 2],
                    addr: ev.dst,
                    value: ev.src,
                    pc: ev.caller_pc,
                });
                self.push_ext(ExtRecord {
                    seq_low32: seq,
                    kind: ExtKind::HleMeta as u8,
                    size_or_reg: ev.subop_or_byte,
                    _pad: [0; 2],
                    addr: ev.dst,
                    value: ev.len,
                    pc: ev.caller_pc,
                });
            }
            ExtKind::HleMemset => {
                self.push_ext(ExtRecord {
                    seq_low32: seq,
                    kind: ExtKind::HleMemset as u8,
                    size_or_reg: ev.subop_or_byte,
                    _pad: [ev.aux_subop, 0],
                    addr: ev.dst,
                    value: ev.len,
                    pc: ev.caller_pc,
                });
            }
            ExtKind::HleMalloc => {
                self.push_ext(ExtRecord {
                    seq_low32: seq,
                    kind: ExtKind::HleMalloc as u8,
                    size_or_reg: ev.subop_or_byte,
                    _pad: [0; 2],
                    addr: ev.dst,
                    value: ev.len,
                    pc: ev.caller_pc,
                });
            }
            ExtKind::HleFree => {
                self.push_ext(ExtRecord {
                    seq_low32: seq,
                    kind: ExtKind::HleFree as u8,
                    size_or_reg: 0,
                    _pad: [0; 2],
                    addr: ev.dst,
                    value: 0,
                    pc: ev.caller_pc,
                });
            }
            ExtKind::HleSource => {
                let need_meta = ev.dst != 0 && ev.len > 255;
                if need_meta && self.ext_remaining_capacity() < 2 {
                    self.stats.dropped_ext += 2;
                    return;
                }
                self.push_ext(ExtRecord {
                    seq_low32: seq,
                    kind: ExtKind::HleSource as u8,
                    size_or_reg: ev.subop_or_byte,
                    _pad: [ev.len.min(255) as u8, ev.aux_subop],
                    addr: ev.dst,
                    value: ev.src,
                    pc: ev.caller_pc,
                });
                if need_meta {
                    self.push_ext(ExtRecord {
                        seq_low32: seq,
                        kind: ExtKind::HleMeta as u8,
                        size_or_reg: 0,
                        _pad: [0; 2],
                        addr: ev.dst,
                        value: ev.len,
                        pc: ev.caller_pc,
                    });
                }
            }
            _ => {}
        }
    }

    /// 若使用 mmap 后端，主动刷新脏页到磁盘
    pub fn flush(&self) -> EmuResult<()> {
        if let TraceSink::Mmap { mmap, .. } = &self.sink {
            mmap.flush()?;
        }
        if let ExtSink::Mmap { mmap, .. } = &self.ext_sink {
            mmap.flush()?;
        }
        Ok(())
    }

    /// 刷盘、解除内存映射并将 `.idx` / `.ext` 文件精确截断至实际写入字节数（消除尾部零填充）
    pub fn finalize(&mut self) -> EmuResult<()> {
        if !self.truncation_warned && (self.stats.dropped_insns > 0 || self.stats.dropped_ext > 0) {
            self.truncation_warned = true;
            tracing::warn!(
                target: "runidbg::trace",
                recorded_insns = self.stats.recorded_insns,
                dropped_insns = self.stats.dropped_insns,
                recorded_ext = self.stats.recorded_ext,
                dropped_ext = self.stats.dropped_ext,
                "Trace 缓冲区容量耗尽并发生截断！请增大 trace.start({{ capacity }}) 后重抓"
            );
        }
        self.flush()?;
        if matches!(self.sink, TraceSink::Mmap { .. }) {
            let old = std::mem::replace(&mut self.sink, TraceSink::Memory(Vec::new()));
            if let TraceSink::Mmap {
                path,
                mmap,
                written,
                ..
            } = old
            {
                drop(mmap);
                let exact_len = (written * size_of::<TraceRecord>()) as u64;
                let file = OpenOptions::new().write(true).open(&path)?;
                file.set_len(exact_len)?;
            }
        }
        if matches!(self.ext_sink, ExtSink::Mmap { .. }) {
            let old = std::mem::replace(&mut self.ext_sink, ExtSink::Disabled);
            if let ExtSink::Mmap {
                path,
                mmap,
                written,
                ..
            } = old
            {
                drop(mmap);
                let exact_len = (written * size_of::<ExtRecord>()) as u64;
                let file = OpenOptions::new().write(true).open(&path)?;
                file.set_len(exact_len)?;
            }
        }
        Ok(())
    }

    /// 获取已记录的内存主索引切片（仅 Memory 后端有效）
    pub fn records(&self) -> &[TraceRecord] {
        match &self.sink {
            TraceSink::Memory(buf) => buf.as_slice(),
            TraceSink::Mmap { .. } => &[],
        }
    }

    /// 获取已记录的内存扩展事件切片（仅 Memory 后端有效）
    pub fn ext_records(&self) -> &[ExtRecord] {
        match &self.ext_sink {
            ExtSink::Memory(buf) => buf.as_slice(),
            _ => &[],
        }
    }

    pub fn decode_record(record: &TraceRecord) -> String {
        decode_trace_record(record)
    }

    pub fn format_ext_record(ext: &ExtRecord) -> String {
        format_ext_record(ext)
    }
}

impl Drop for BinaryTracer {
    fn drop(&mut self) {
        let _ = self.finalize();
    }
}

fn checked_mmap_bytes(max_records: usize, elem_size: usize) -> EmuResult<usize> {
    let total = max_records.checked_mul(elem_size).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Trace 容量过大导致字节数溢出: max_records={max_records}"),
        )
    })?;
    if total > isize::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Trace mmap 大小超出平台寻址上限: {total} bytes"),
        )
        .into());
    }
    Ok(total)
}

fn create_mmap_file(path: impl AsRef<Path>, total_bytes: usize) -> EmuResult<MmapMut> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    let map_len = total_bytes.max(32);
    file.set_len(map_len as u64)?;
    // SAFETY: 文件已创建并扩展到固定长度，且当前进程独占写入该映射区
    let mmap = unsafe { MmapMut::map_mut(&file)? };
    if mmap.len() < total_bytes {
        return Err(std::io::Error::other(format!(
            "mmap 实际长度 ({}) 小于请求大小 ({total_bytes})",
            mmap.len()
        ))
        .into());
    }
    Ok(mmap)
}

/// 将 BinaryTracer 挂载为 Unicorn 指令级 Code Hook
pub fn attach_code_hook<'a, D, F>(
    uc: &mut Unicorn<'a, D>,
    begin: u64,
    end: u64,
    mut get_tracer: F,
) -> EmuResult<UcHookId>
where
    F: FnMut(&mut D) -> &mut BinaryTracer + 'a,
{
    get_tracer(uc.get_data_mut()).set_active(true);
    let hook_id = uc.add_code_hook(begin, end, move |uc, addr, size| {
        let level = {
            let tracer = get_tracer(uc.get_data_mut());
            if !tracer.is_active() || !tracer.should_trace(addr) {
                return;
            }
            tracer.level()
        };

        let mut insn_bytes = [0u8; 4];
        let opcode = if size == 4 && uc.mem_read(addr, &mut insn_bytes).is_ok() {
            u32::from_le_bytes(insn_bytes)
        } else {
            0
        };

        if level == TraceLevel::Fast {
            let tracer = get_tracer(uc.get_data_mut());
            tracer.record_fast(addr, opcode);
            return;
        }

        let mut cur_regs = [0u64; 32];
        for (slot, &reg) in cur_regs.iter_mut().zip(TRACKED_REGS.iter()) {
            *slot = uc.reg_read(reg).unwrap_or(0);
        }

        let tracer = get_tracer(uc.get_data_mut());
        tracer.record_step(addr, opcode, &cur_regs);
    })?;

    Ok(hook_id)
}

/// 为 `TraceLevel::Full` 挂载内存读写 Hook，将访存事件实时写入扩展流 `trace.ext`
pub fn attach_mem_trace_hook<'a, D, F>(
    uc: &mut Unicorn<'a, D>,
    begin: u64,
    end: u64,
    mut get_tracer: F,
) -> EmuResult<UcHookId>
where
    F: FnMut(&mut D) -> &mut BinaryTracer + 'a,
{
    get_tracer(uc.get_data_mut()).set_active(true);
    let hook_id = uc.add_mem_hook(
        HookType::MEM_READ | HookType::MEM_WRITE,
        begin,
        end,
        move |uc, mem_type, addr, size, value| {
            let cur_pc = uc.reg_read(RegisterARM64::PC).unwrap_or(0);
            {
                let tracer = get_tracer(uc.get_data_mut());
                if !tracer.is_active()
                    || tracer.level() != TraceLevel::Full
                    || tracer.stats.recorded_insns == 0
                    || cur_pc != tracer.last_pc
                {
                    return true;
                }
            }
            let is_write = matches!(mem_type, MemType::WRITE);
            if !is_write && size > 8 {
                // Unicorn 偶发单次 16B 读回调时拆分为多条 8B 记录，避免丢失高 8 字节样本；读取失败则中止避免写入假 0
                let capped = size.min(64);
                let mut off = 0usize;
                while off < capped {
                    let chunk = (capped - off).min(8);
                    let mut buf = [0u8; 8];
                    if uc
                        .mem_read(addr.wrapping_add(off as u64), &mut buf[..chunk])
                        .is_err()
                    {
                        break;
                    }
                    let val = u64::from_le_bytes(buf);
                    let tracer = get_tracer(uc.get_data_mut());
                    tracer.record_mem_access(false, addr.wrapping_add(off as u64), chunk, val);
                    off += chunk;
                }
                return true;
            }
            let mask = match size {
                1 => 0xFFu64,
                2 => 0xFFFFu64,
                4 => 0xFFFF_FFFFu64,
                _ => u64::MAX,
            };
            let actual_val = if is_write {
                (value as u64) & mask
            } else {
                let mut buf = [0u8; 8];
                let n = size.min(8);
                if uc.mem_read(addr, &mut buf[..n]).is_ok() {
                    u64::from_le_bytes(buf) & mask
                } else {
                    0
                }
            };

            let tracer = get_tracer(uc.get_data_mut());
            tracer.record_mem_access(is_write, addr, size, actual_val);
            true
        },
    )?;

    Ok(hook_id)
}
