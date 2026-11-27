use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::ptr;

use memmap2::Mmap;

use crate::error::EmuResult;
use crate::tracer::archive::TraceArchive;
use crate::tracer::record::{format_ext_record, ExtKind, ExtRecord, HleTraceEvent, TraceRecord};

/// 按约定自动定位与 `trace.idx` 同目录伴生的 `.ext` 扩展流文件：
/// 若输入为 `.rtrace` 单文件归档则直接返回 `None`（优先使用归档内置 `.ext`）；
/// 否则优先匹配替换扩展名后的 `<stem>.ext`，若不存在则回退 `<idx_path>.ext`。
pub fn resolve_sibling_ext_path(idx_path: &Path) -> Option<PathBuf> {
    if idx_path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("rtrace"))
        || TraceArchive::is_rtrace_file(idx_path)
    {
        return None;
    }
    let replaced = idx_path.with_extension("ext");
    if replaced != idx_path && replaced.is_file() {
        return Some(replaced);
    }
    let mut appended = idx_path.as_os_str().to_os_string();
    appended.push(".ext");
    let appended_path = PathBuf::from(appended);
    if appended_path.is_file() {
        return Some(appended_path);
    }
    None
}

/// 内存写入字节流匹配命中项
#[derive(Debug, Clone)]
pub struct MemPatternHit {
    pub seq_low32: u32,
    pub pc: u64,
    pub addr: u64,
    pub matched_len: usize,
}

/// 离线全知查询命中项（供 `TraceReader::query_*` / JS `Trace.open().query(...)` 使用）
#[derive(Debug, Clone)]
pub struct TraceQueryHit {
    pub seq_low32: u32,
    pub pc: u64,
    pub addr: u64,
    pub size: u64,
    pub kind: &'static str,
    pub value: u64,
    pub src: u64,
}

/// 双跑 Trace 差分条目（供 `runidbg-cli diff a.idx b.idx` 与 JS/MCP 使用）
#[derive(Debug, Clone)]
pub struct TraceDiffEntry {
    pub idx: usize,
    pub kind: &'static str,
    pub pc_a: u64,
    pub pc_b: u64,
    pub detail: String,
}

/// 双跑 Trace 差分汇总结果
#[derive(Debug, Clone)]
pub struct TraceDiffSummary {
    pub total_a: usize,
    pub total_b: usize,
    pub common_prefix_insns: usize,
    pub first_control_divergence_idx: Option<usize>,
    pub first_data_divergence_idx: Option<usize>,
    pub diffs: Vec<TraceDiffEntry>,
}

/// 基于 `BL`/`BLR`/`RET` 构建的时间轴调用树节点
#[derive(Debug, Clone)]
pub struct CallTreeNode {
    pub target_pc: u64,
    pub caller_pc: u64,
    pub start_idx: usize,
    pub end_idx: usize,
    pub depth: usize,
}

impl CallTreeNode {
    pub const fn insn_count(&self) -> usize {
        self.end_idx.saturating_sub(self.start_idx) + 1
    }
}

/// 密码学常量/结构扫描归并后的算法调用窗口（附候选输入/输出缓冲地址）
#[derive(Debug, Clone)]
pub struct CryptoHitGroup {
    pub algorithm: &'static str,
    pub start_idx: usize,
    pub end_idx: usize,
    pub first_pc: u64,
    pub hit_count: usize,
    pub distinct_constants: Vec<u32>,
    /// 该算法窗口内推断的候选输入内存区间 `(addr, len)`（窗口内先读后写/只读缓冲）
    pub input_addrs: Vec<(u64, usize)>,
    /// 该算法窗口内推断的候选输出内存区间 `(addr, len)`（窗口内写入缓冲）
    pub output_addrs: Vec<(u64, usize)>,
}

/// 双跑差分 + 自动反向污点联动：单个差异字节段在 A/B 两侧的溯源对比
#[derive(Debug, Clone)]
pub struct DiffTaintByteSpan {
    pub offset: usize,
    pub addr: u64,
    pub len: usize,
    pub bytes_a: Vec<Option<u8>>,
    pub bytes_b: Vec<Option<u8>>,
    pub origins_a_regs: Vec<String>,
    pub origins_a_mem: Vec<(u64, usize)>,
    pub origins_a_hle: Vec<String>,
    pub origins_b_regs: Vec<String>,
    pub origins_b_mem: Vec<(u64, usize)>,
    pub origins_b_hle: Vec<String>,
}

/// 双跑差分 + 污点联动完整报告
#[derive(Debug, Clone)]
pub struct DiffTaintReport {
    pub target_addr: u64,
    pub len: usize,
    pub identical_bytes: usize,
    pub differing_bytes: usize,
    pub spans: Vec<DiffTaintByteSpan>,
}

impl DiffTaintReport {
    pub fn format_summary(&self) -> String {
        let mut out = format!(
            "# 双跑差分污点联动 | 目标: 0x{:016x}+{}B | 相同字节={} | 差异字节={} | 差异段={}\n",
            self.target_addr,
            self.len,
            self.identical_bytes,
            self.differing_bytes,
            self.spans.len()
        );
        for (i, sp) in self.spans.iter().enumerate() {
            let fmt_hex = |bs: &[Option<u8>]| -> String {
                bs.iter()
                    .map(|b| b.map(|v| format!("{v:02x}")).unwrap_or_else(|| "??".to_string()))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let fmt_mem = |ms: &[(u64, usize)]| -> String {
                ms.iter()
                    .take(6)
                    .map(|(a, l)| format!("0x{a:x}+{l}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push_str(&format!(
                "  [Span #{i}] +0x{:x} (0x{:016x}, {}B): A=[{}] vs B=[{}]\n",
                sp.offset,
                sp.addr,
                sp.len,
                fmt_hex(&sp.bytes_a),
                fmt_hex(&sp.bytes_b)
            ));
            if !sp.origins_a_regs.is_empty() || !sp.origins_b_regs.is_empty() {
                out.push_str(&format!(
                    "      Regs : A=[{}] | B=[{}]\n",
                    sp.origins_a_regs.join(", "),
                    sp.origins_b_regs.join(", ")
                ));
            }
            if !sp.origins_a_mem.is_empty() || !sp.origins_b_mem.is_empty() {
                out.push_str(&format!(
                    "      Mem  : A=[{}] | B=[{}]\n",
                    fmt_mem(&sp.origins_a_mem),
                    fmt_mem(&sp.origins_b_mem)
                ));
            }
            if !sp.origins_a_hle.is_empty() || !sp.origins_b_hle.is_empty() {
                out.push_str(&format!(
                    "      HLE  : A=[{}] | B=[{}]\n",
                    sp.origins_a_hle.join("; "),
                    sp.origins_b_hle.join("; ")
                ));
            }
        }
        out
    }
}

/// Trace 底层只读字节存储：普通 `.idx`/`.ext` 零拷贝 mmap，单文件 `.rtrace` 解压到自有内存缓冲
enum TraceBuffer {
    Mmap(Mmap),
    Owned(Vec<u8>),
}

impl std::ops::Deref for TraceBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        match self {
            Self::Mmap(m) => m,
            Self::Owned(v) => v,
        }
    }
}

/// 离线零拷贝 Trace 读取器（同时透明支持 `.idx`/`.ext` 与单文件压缩 `.rtrace` 归档）
pub struct TraceReader {
    idx_buf: TraceBuffer,
    idx_count: usize,
    ext_buf: Option<TraceBuffer>,
    ext_count: usize,
    ext_monotonic: bool,
    recorded_level_tag: u8,
    missing_ext: bool,
    from_archive: bool,
    archive_base_addr: Option<u64>,
}

fn map_file_or_empty(path: &Path) -> EmuResult<TraceBuffer> {
    let file = File::open(path)?;
    if file.metadata()?.len() == 0 {
        return Ok(TraceBuffer::Owned(Vec::new()));
    }
    // SAFETY: 离线只读映射
    Ok(TraceBuffer::Mmap(unsafe { Mmap::map(&file)? }))
}

impl TraceReader {
    /// 打开 `trace.idx`（及可选 `trace.ext`）或单文件压缩 `.rtrace` 归档（按 `RTRC` 魔数自动识别）
    pub fn open(idx_path: impl AsRef<Path>, ext_path: Option<&Path>) -> EmuResult<Self> {
        let idx_path = idx_path.as_ref();
        let (idx_buf, ext_buf, from_archive, archive_base_addr) =
            if TraceArchive::is_rtrace_file(idx_path) {
                let (idx_bytes, ext_bytes_opt, info) = TraceArchive::load_buffers(idx_path)?;
                // 若调用方显式指定了外部 ext_path，则允许其覆盖归档内置 .ext（并严格校验文件可读）
                let ext_buf = if let Some(ep) = ext_path {
                    Some(map_file_or_empty(ep)?)
                } else {
                    ext_bytes_opt.map(TraceBuffer::Owned)
                };
                let base_opt = (info.base_addr != 0).then_some(info.base_addr);
                (TraceBuffer::Owned(idx_bytes), ext_buf, true, base_opt)
            } else {
                let idx_buf = map_file_or_empty(idx_path)?;
                let ext_buf = match ext_path {
                    Some(ep) => Some(map_file_or_empty(ep)?),
                    None => None,
                };
                (idx_buf, ext_buf, false, None)
            };

        let total_idx_slots = idx_buf.len() / size_of::<TraceRecord>();

        let mut idx_count = 0usize;
        for i in 0..total_idx_slots {
            let rec = read_packed::<TraceRecord>(&idx_buf, i);
            let pc = rec.pc;
            let op = rec.opcode;
            if pc == 0 && op == 0 {
                break;
            }
            idx_count += 1;
        }

        let (ext_count, ext_monotonic) = if let Some(ref eb) = ext_buf {
            let total_ext_slots = eb.len() / size_of::<ExtRecord>();
            let mut count = 0usize;
            let mut monotonic = true;
            let mut prev_seq = 0u32;
            for i in 0..total_ext_slots {
                let rec = read_packed::<ExtRecord>(eb, i);
                if rec.kind == 0 {
                    break;
                }
                let seq = rec.seq_low32;
                if count > 0 && seq < prev_seq {
                    monotonic = false;
                }
                prev_seq = seq;
                count += 1;
            }
            (count, monotonic)
        } else {
            (0, true)
        };

        let recorded_level_tag = if idx_count > 0 {
            read_packed::<TraceRecord>(&idx_buf, 0)._reserved[1]
        } else {
            0
        };
        let has_any_ext_flag = ext_buf.is_none()
            && matches!(recorded_level_tag, 0 | 3)
            && (0..idx_count.min(4096))
                .any(|i| (read_packed::<TraceRecord>(&idx_buf, i)._reserved[0] & 1) != 0);
        let missing_ext = ext_buf.is_none() && (recorded_level_tag == 3 || has_any_ext_flag);

        Ok(Self {
            idx_buf,
            idx_count,
            ext_buf,
            ext_count,
            ext_monotonic,
            recorded_level_tag,
            missing_ext,
            from_archive,
            archive_base_addr,
        })
    }

    /// 是否已加载 `.ext` 扩展流（包括外部 `.ext` 文件或 `.rtrace` 归档内嵌 `.ext`）
    pub const fn has_ext(&self) -> bool {
        self.ext_buf.is_some()
    }

    /// 是否来自单文件 `.rtrace` 压缩归档
    pub const fn is_archive(&self) -> bool {
        self.from_archive
    }

    /// 若打开的是打包时记录了 `--base` 的 `.rtrace` 归档，返回其保存的模块基址
    pub const fn archive_base_addr(&self) -> Option<u64> {
        self.archive_base_addr
    }

    /// 若 `.idx` 录制于 `Full` 级别（或带扩展流标记）但未加载到伴生 `.ext` 文件，返回 `true`
    pub const fn missing_ext_warning(&self) -> bool {
        self.missing_ext
    }

    /// 返回 `.idx` 首条记录写入的录制级别名称（兼容旧版 `.idx` 时返回 `None`）
    pub const fn recorded_level_name(&self) -> Option<&'static str> {
        match self.recorded_level_tag {
            1 => Some("fast"),
            2 => Some("reg_delta"),
            3 => Some("full"),
            _ => None,
        }
    }

    pub const fn len(&self) -> usize {
        self.idx_count
    }

    pub const fn is_empty(&self) -> bool {
        self.idx_count == 0
    }

    pub const fn ext_len(&self) -> usize {
        self.ext_count
    }

    pub fn get(&self, index: usize) -> Option<TraceRecord> {
        if index < self.idx_count {
            Some(read_packed::<TraceRecord>(&self.idx_buf, index))
        } else {
            None
        }
    }

    pub fn get_ext(&self, index: usize) -> Option<ExtRecord> {
        let buf = self.ext_buf.as_ref()?;
        if index < self.ext_count {
            Some(read_packed::<ExtRecord>(buf, index))
        } else {
            None
        }
    }

    /// 按指令序号查找所有关联的扩展事件（单调序列自动走二分查找）
    pub fn ext_for_seq(&self, seq_low32: u32) -> Vec<ExtRecord> {
        let Some(mmap) = self.ext_buf.as_ref() else {
            return Vec::new();
        };
        if self.ext_count == 0 {
            return Vec::new();
        }
        if self.ext_monotonic {
            let mut lo = 0usize;
            let mut hi = self.ext_count;
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                let s = read_packed::<ExtRecord>(mmap, mid).seq_low32;
                if s < seq_low32 {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            let mut out = Vec::new();
            let mut i = lo;
            while i < self.ext_count {
                let rec = read_packed::<ExtRecord>(mmap, i);
                if rec.seq_low32 != seq_low32 {
                    break;
                }
                out.push(rec);
                i += 1;
            }
            return out;
        }
        let mut out = Vec::new();
        for i in 0..self.ext_count {
            let rec = read_packed::<ExtRecord>(mmap, i);
            if rec.seq_low32 == seq_low32 {
                out.push(rec);
            }
        }
        out
    }

    /// 获取指令 `idx` **执行后**产生的寄存器变更列表（修正 Unicorn pre-exec hook 1 条指令偏移）
    ///
    /// Unicorn 的 `hook_code` 在指令执行前触发，因此第 `idx+1` 条记录中的 `reg_delta`
    /// （以及 `ext` 中 `seq == rec[idx+1].seq_low32` 的 `RegDeltaExtra`）才是指令 `idx` 的执行结果。
    pub fn reg_deltas_for(&self, idx: usize) -> Vec<(u8, u64)> {
        let Some(cur) = self.get(idx) else {
            return Vec::new();
        };
        let Some(next) = self.get(idx + 1) else {
            return Vec::new();
        };
        if next.seq_low32 != cur.seq_low32.wrapping_add(1) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let pid = next.primary_reg_id;
        let pval = next.primary_reg_val;
        if pid != 0xFF {
            out.push((pid, pval));
        }
        if (next._reserved[0] & 1) != 0 {
            for ext in self.ext_for_seq(next.seq_low32) {
                if ext.kind == ExtKind::RegDeltaExtra as u8 {
                    out.push((ext.size_or_reg, ext.value));
                }
            }
        }
        out
    }

    /// 获取指令 `idx` 自身产生的内存读写事件（过滤掉 `RegDeltaExtra` 与 HLE 伴随记录）
    pub fn mem_events_for(&self, idx: usize) -> Vec<ExtRecord> {
        let Some(rec) = self.get(idx) else {
            return Vec::new();
        };
        self.ext_for_seq(rec.seq_low32)
            .into_iter()
            .filter(|e| e.kind == ExtKind::MemRead as u8 || e.kind == ExtKind::MemWrite as u8)
            .collect()
    }

    /// 解码一组连续 `ExtRecord` 中的全部 HLE 内存/分配事件（严格校验 `HleMemcpy + HleMeta` 的 `seq` 与 `addr` 配对）
    fn decode_hle_slice(recs: &[ExtRecord]) -> Vec<HleTraceEvent> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < recs.len() {
            let rec = recs[i];
            let seq = rec.seq_low32;
            let pc = rec.pc;
            let addr = rec.addr;
            let val = rec.value;
            let sr = rec.size_or_reg;
            match ExtKind::from_u8(rec.kind) {
                Some(ExtKind::HleMemcpy) => {
                    let op = match sr {
                        1 => "memmove",
                        2 => "realloc_copy",
                        _ => "memcpy",
                    };
                    let mut len = 0u64;
                    if i + 1 < recs.len() && is_matching_hle_meta(rec, recs[i + 1]) {
                        len = recs[i + 1].value;
                        i += 1;
                    }
                    out.push(HleTraceEvent {
                        seq_low32: seq,
                        op,
                        dst: addr,
                        src: val,
                        len,
                        pc,
                    });
                }
                Some(ExtKind::HleMemset) => {
                    let op = match rec._pad[0] {
                        1 => "bzero",
                        2 => "calloc_zero",
                        _ => "memset",
                    };
                    out.push(HleTraceEvent {
                        seq_low32: seq,
                        op,
                        dst: addr,
                        src: sr as u64,
                        len: val,
                        pc,
                    });
                }
                Some(ExtKind::HleMalloc) => {
                    let op = match sr {
                        1 => "calloc",
                        2 => "realloc",
                        3 => "posix_memalign",
                        _ => "malloc",
                    };
                    out.push(HleTraceEvent {
                        seq_low32: seq,
                        op,
                        dst: addr,
                        src: 0,
                        len: val,
                        pc,
                    });
                }
                Some(ExtKind::HleFree) => {
                    out.push(HleTraceEvent {
                        seq_low32: seq,
                        op: "free",
                        dst: addr,
                        src: 0,
                        len: 0,
                        pc,
                    });
                }
                Some(ExtKind::HleSource) => {
                    let op = match sr {
                        0 => "rand",
                        1 => "arc4random",
                        2 => "lrand48",
                        3 => "time",
                        4 => "getrandom",
                        5 => "gettimeofday",
                        6 => "clock_gettime",
                        _ => "hle_source",
                    };
                    let mut hlen = u64::from(rec._pad[0]);
                    if i + 1 < recs.len()
                        && recs[i + 1].kind == ExtKind::HleMeta as u8
                        && is_matching_hle_meta(rec, recs[i + 1])
                    {
                        hlen = recs[i + 1].value;
                        i += 1;
                    }
                    out.push(HleTraceEvent {
                        seq_low32: seq,
                        op,
                        dst: addr,
                        src: val,
                        len: hlen,
                        pc,
                    });
                }
                _ => {}
            }
            i += 1;
        }
        out
    }

    /// 枚举 `trace.ext` 中全部结构化 HLE 内存/分配事件（`memcpy`/`memmove`/`memset`/`malloc`/`free`）
    pub fn hle_events(&self) -> Vec<HleTraceEvent> {
        let Some(mmap) = self.ext_buf.as_ref() else {
            return Vec::new();
        };
        let mut raw = Vec::new();
        for i in 0..self.ext_count {
            let rec = read_packed::<ExtRecord>(mmap, i);
            if matches!(
                ExtKind::from_u8(rec.kind),
                Some(
                    ExtKind::HleMemcpy
                        | ExtKind::HleMemset
                        | ExtKind::HleMalloc
                        | ExtKind::HleFree
                        | ExtKind::HleMeta
                        | ExtKind::HleSource
                )
            ) {
                raw.push(rec);
            }
        }
        Self::decode_hle_slice(&raw)
    }

    /// 获取指令 `idx` 关联的全部 HLE 内存/分配事件
    pub fn hle_events_for(&self, idx: usize) -> Vec<HleTraceEvent> {
        let Some(rec) = self.get(idx) else {
            return Vec::new();
        };
        let exts = self.ext_for_seq(rec.seq_low32);
        Self::decode_hle_slice(&exts)
    }

    /// 获取指令 `idx` 关联的全部格式化扩展行（含 `[MEM R/W]` 与合并后的 `[HLE ...]`）
    pub fn mem_and_hle_lines_for(&self, idx: usize) -> Vec<String> {
        let mut lines: Vec<String> = self
            .mem_events_for(idx)
            .into_iter()
            .map(|e| format_ext_record(&e))
            .collect();
        for h in self.hle_events_for(idx) {
            lines.push(h.format_line());
        }
        lines
    }

    /// 搜索主索引寄存器值匹配的指令记录（原始未偏移接口，保留兼容性）
    pub fn search_value(&self, target: u64) -> Vec<(usize, TraceRecord)> {
        let mut hits = Vec::new();
        for i in 0..self.idx_count {
            let rec = read_packed::<TraceRecord>(&self.idx_buf, i);
            let reg_id = rec.primary_reg_id;
            let reg_val = rec.primary_reg_val;
            if reg_id != 0xFF && reg_val == target {
                hits.push((i, rec));
            }
        }
        hits
    }

    /// 搜索产生目标寄存器值的指令（覆盖 `primary_reg` 与 `RegDeltaExtra`，并归属到实际执行该写入的指令）
    pub fn search_value_attributed(&self, target: u64) -> Vec<(usize, TraceRecord, u8)> {
        let mut hits = Vec::new();
        let mut seq_to_idx: Option<HashMap<u32, usize>> = None;

        for i in 0..self.idx_count {
            let rec = read_packed::<TraceRecord>(&self.idx_buf, i);
            let reg_id = rec.primary_reg_id;
            let reg_val = rec.primary_reg_val;
            if reg_id != 0xFF && reg_val == target {
                let (attr_idx, attr_rec) = self.attribute_pre_exec(i, rec);
                hits.push((attr_idx, attr_rec, reg_id));
            }
        }

        if let Some(mmap) = self.ext_buf.as_ref() {
            for i in 0..self.ext_count {
                let ext = read_packed::<ExtRecord>(mmap, i);
                if ext.kind == ExtKind::RegDeltaExtra as u8 && ext.value == target {
                    let seq = ext.seq_low32;
                    let map = seq_to_idx.get_or_insert_with(|| self.build_seq_index_map());
                    if let Some(&raw_idx) = map.get(&seq) {
                        if let Some(raw_rec) = self.get(raw_idx) {
                            let (attr_idx, attr_rec) = self.attribute_pre_exec(raw_idx, raw_rec);
                            hits.push((attr_idx, attr_rec, ext.size_or_reg));
                        }
                    }
                }
            }
        }

        hits.sort_by_key(|(idx, _, reg)| (*idx, *reg));
        hits
    }

    /// 搜索扩展流中读写值匹配 `target` 的内存事件
    pub fn search_mem_value(&self, target: u64) -> Vec<ExtRecord> {
        let Some(mmap) = self.ext_buf.as_ref() else {
            return Vec::new();
        };
        let mut hits = Vec::new();
        for i in 0..self.ext_count {
            let rec = read_packed::<ExtRecord>(mmap, i);
            if rec.kind == ExtKind::MemRead as u8 || rec.kind == ExtKind::MemWrite as u8 {
                let val = rec.value;
                if val == target {
                    hits.push(rec);
                }
            }
        }
        hits
    }

    /// 返回第一个 `seq_low32 > at_seq`（或回绕纪元边界）的扩展流上界索引
    fn ext_end_index_for_seq(&self, at_seq: u32) -> usize {
        let Some(mmap) = self.ext_buf.as_ref() else {
            return 0;
        };
        if self.ext_count == 0 {
            return 0;
        }
        if self.ext_monotonic {
            let mut lo = 0usize;
            let mut hi = self.ext_count;
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                let s = read_packed::<ExtRecord>(mmap, mid).seq_low32;
                if s <= at_seq {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            return lo;
        }
        // 非单调（32 位 seq 回绕）：停在回绕发生前首次超过 at_seq 的位置，防止未来纪元混入
        let mut prev_seq = read_packed::<ExtRecord>(mmap, 0).seq_low32;
        for i in 0..self.ext_count {
            let seq = read_packed::<ExtRecord>(mmap, i).seq_low32;
            if i > 0 && seq < prev_seq {
                // 已发生 2^32 回绕，说明之前纪元全在 at_seq 之前或已结束
                return i;
            }
            if seq > at_seq {
                return i;
            }
            prev_seq = seq;
        }
        self.ext_count
    }

    /// 搜索扩展流中访问了目标内存地址的事件（同时覆盖 Guest 指令访存与 HLE 区间拷贝/填充/分配）
    pub fn search_mem_addr(&self, target_addr: u64) -> Vec<ExtRecord> {
        let Some(mmap) = self.ext_buf.as_ref() else {
            return Vec::new();
        };
        let mut hits = Vec::new();
        let mut i = 0usize;
        while i < self.ext_count {
            let rec = read_packed::<ExtRecord>(mmap, i);
            match ExtKind::from_u8(rec.kind) {
                Some(ExtKind::MemRead) | Some(ExtKind::MemWrite) => {
                    let sz = (rec.size_or_reg as u64).max(1);
                    if range_overlaps_u128(rec.addr, sz, target_addr, 1) {
                        hits.push(rec);
                    }
                }
                Some(ExtKind::HleMemcpy) => {
                    let dst = rec.addr;
                    let src = rec.value;
                    let len = if i + 1 < self.ext_count {
                        let next = read_packed::<ExtRecord>(mmap, i + 1);
                        if is_matching_hle_meta(rec, next) {
                            i += 1;
                            next.value
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    let in_dst = len > 0 && range_overlaps_u128(dst, len, target_addr, 1);
                    let in_src = len > 0 && range_overlaps_u128(src, len, target_addr, 1);
                    if in_dst || in_src || target_addr == dst || target_addr == src {
                        hits.push(rec);
                    }
                }
                Some(ExtKind::HleMemset) | Some(ExtKind::HleMalloc) => {
                    let dst = rec.addr;
                    let len = rec.value;
                    if target_addr == dst
                        || (len > 0 && range_overlaps_u128(dst, len, target_addr, 1))
                    {
                        hits.push(rec);
                    }
                }
                Some(ExtKind::HleFree) if rec.addr == target_addr => {
                    hits.push(rec);
                }
                _ => {}
            }
            i += 1;
        }
        hits
    }

    /// 回放 `.ext` 中的 `MemWrite` 与 HLE `memcpy`/`memset` 字节流，搜索连续内存写入拼出的目标字节序列
    pub fn search_mem_bytes(&self, pattern: &[u8]) -> Vec<MemPatternHit> {
        self.search_mem_bytes_bounded(pattern, None, None, 0)
    }

    /// 带 `min_seq` / `max_seq` / `limit` 提前终止的字节流匹配
    ///
    /// 采用 4KB 页块影子内存（`PagedShadowMem`）+ 256-bit 字节集合 O(1) 剪枝 +
    /// `HleMemset` 边界数学剪枝 + 页内连续切片 SIMD 锚点扫描（`WildcardMatcher`）。
    pub fn search_mem_bytes_bounded(
        &self,
        pattern: &[u8],
        min_seq: Option<u32>,
        max_seq: Option<u32>,
        limit: usize,
    ) -> Vec<MemPatternHit> {
        if pattern.is_empty() {
            return Vec::new();
        }
        let Some(mmap) = self.ext_buf.as_ref() else {
            return Vec::new();
        };
        let end_idx = max_seq
            .map(|hi| self.ext_end_index_for_seq(hi))
            .unwrap_or(self.ext_count);
        let pat_len = pattern.len();
        let matcher = crate::mem_match::WildcardMatcher::from_exact(pattern);
        let mut mem = crate::mem_match::PagedShadowMem::new();
        let mut hits = Vec::new();
        // 按 `seq_low32` 追踪同指令已命中地址集合，避免 `STP` 等同 seq 多写指令重复上报
        let mut dedup_seq: Option<u32> = None;
        let mut dedup_addrs: HashSet<u64> = HashSet::new();

        let check_range = |mem: &crate::mem_match::PagedShadowMem,
                           start_lo: u64,
                           start_hi: u64,
                           seq: u32,
                           pc: u64,
                           hits: &mut Vec<MemPatternHit>,
                           dedup_seq: &mut Option<u32>,
                           dedup_addrs: &mut HashSet<u64>|
         -> bool {
            if *dedup_seq != Some(seq) {
                if !dedup_addrs.is_empty() {
                    dedup_addrs.clear();
                }
                *dedup_seq = Some(seq);
            }
            let mut stopped = false;
            let _ = mem.scan_candidates(start_lo, start_hi, pattern, &matcher, |candidate| {
                if dedup_addrs.insert(candidate) {
                    hits.push(MemPatternHit {
                        seq_low32: seq,
                        pc,
                        addr: candidate,
                        matched_len: pat_len,
                    });
                    if limit > 0 && hits.len() >= limit {
                        stopped = true;
                        return std::ops::ControlFlow::Break(());
                    }
                }
                std::ops::ControlFlow::Continue(())
            });
            stopped
        };

        let check_window = |mem: &crate::mem_match::PagedShadowMem,
                            start_addr: u64,
                            write_len: usize,
                            seq: u32,
                            pc: u64,
                            hits: &mut Vec<MemPatternHit>,
                            dedup_seq: &mut Option<u32>,
                            dedup_addrs: &mut HashSet<u64>|
         -> bool {
            if let Some(lo) = min_seq {
                if seq < lo {
                    return false;
                }
            }
            let start_lo = start_addr.saturating_sub((pat_len - 1) as u64);
            let start_hi = start_addr.saturating_add((write_len.saturating_sub(1)) as u64);
            check_range(mem, start_lo, start_hi, seq, pc, hits, dedup_seq, dedup_addrs)
        };

        let mut i = 0usize;
        while i < end_idx {
            let rec = read_packed::<ExtRecord>(mmap, i);
            match ExtKind::from_u8(rec.kind) {
                Some(ExtKind::MemWrite) => {
                    let sz = (rec.size_or_reg as usize).clamp(1, 8);
                    let addr = rec.addr;
                    let bytes = rec.value.to_le_bytes();
                    let written = &bytes[..sz];
                    mem.write_bytes(addr, written);
                    // O(1) 字节集合剪枝：若本次写入的字节无一出现在 pattern 中，则覆盖区间内不可能匹配
                    if matcher.contains_any_byte(written)
                        && check_window(
                            &mem,
                            addr,
                            sz,
                            rec.seq_low32,
                            rec.pc,
                            &mut hits,
                            &mut dedup_seq,
                            &mut dedup_addrs,
                        )
                    {
                        break;
                    }
                }
                Some(ExtKind::HleMemcpy) => {
                    let dst = rec.addr;
                    let src = rec.value;
                    let mut len = 0usize;
                    if i + 1 < end_idx {
                        let next = read_packed::<ExtRecord>(mmap, i + 1);
                        if is_matching_hle_meta(rec, next) {
                            len = next.value.min(1 << 20) as usize;
                            i += 1;
                        }
                    }
                    if len > 0 {
                        mem.copy_range(dst, src, len);
                        if check_window(
                            &mem,
                            dst,
                            len,
                            rec.seq_low32,
                            rec.pc,
                            &mut hits,
                            &mut dedup_seq,
                            &mut dedup_addrs,
                        ) {
                            break;
                        }
                    }
                }
                Some(ExtKind::HleMemset) => {
                    let dst = rec.addr;
                    let fill = rec.size_or_reg;
                    let len = rec.value.min(1 << 20) as usize;
                    if len > 0 {
                        mem.fill_bytes(dst, fill, len);
                        if min_seq.is_none_or(|lo| rec.seq_low32 >= lo) {
                            if !matcher.contains_byte(fill) {
                                // fill 不在 pattern 中：任何覆盖 [dst, dst+len) 的窗口都不可能匹配
                            } else if matcher.all_same_exact() != Some(fill)
                                && len > pat_len.saturating_mul(2)
                                && dst.checked_add(len as u64).is_some()
                            {
                                // 大块 memset 数学剪枝：内部全为 fill 绝不可匹配，仅检查左右两个 pat_len-1 拼接边界
                                let mut stop = false;
                                if pat_len > 1 && dst > 0 {
                                    let left_lo = dst.saturating_sub((pat_len - 1) as u64);
                                    let left_hi = dst - 1;
                                    stop = check_range(
                                        &mem,
                                        left_lo,
                                        left_hi,
                                        rec.seq_low32,
                                        rec.pc,
                                        &mut hits,
                                        &mut dedup_seq,
                                        &mut dedup_addrs,
                                    );
                                }
                                if !stop && pat_len > 1 {
                                    let right_end = dst + len as u64 - 1;
                                    let right_lo = dst + len as u64 - (pat_len - 1) as u64;
                                    stop = check_range(
                                        &mem,
                                        right_lo,
                                        right_end,
                                        rec.seq_low32,
                                        rec.pc,
                                        &mut hits,
                                        &mut dedup_seq,
                                        &mut dedup_addrs,
                                    );
                                }
                                if stop {
                                    break;
                                }
                            } else if check_window(
                                &mem,
                                dst,
                                len,
                                rec.seq_low32,
                                rec.pc,
                                &mut hits,
                                &mut dedup_seq,
                                &mut dedup_addrs,
                            ) {
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
        hits
    }

    /// Omniscient 按值查询写入事件（支持按宽度 1..=8 小端匹配直接写或拼字节写，带 `min_seq`/`max_seq`/`limit` 提前终止）
    pub fn query_writes_by_value(
        &self,
        value: u64,
        width: u8,
        min_seq: Option<u32>,
        max_seq: Option<u32>,
        limit: usize,
    ) -> Vec<TraceQueryHit> {
        let w = width.clamp(1, 8) as usize;
        let masked_val = if w == 8 {
            value
        } else {
            value & ((1u64 << (w * 8)) - 1)
        };
        let pat = &masked_val.to_le_bytes()[..w];
        let hits = self.search_mem_bytes_bounded(pat, min_seq, max_seq, limit);
        hits.into_iter()
            .map(|h| TraceQueryHit {
                seq_low32: h.seq_low32,
                pc: h.pc,
                addr: h.addr,
                size: w as u64,
                kind: "write",
                value: masked_val,
                src: 0,
            })
            .collect()
    }

    /// Omniscient 地址历史查询：列出访问 `[addr, addr+len)` 的全部事件（支持 `at_seq` 截断上限与 `u64::MAX` 安全区间比较）
    pub fn query_addr_history(
        &self,
        addr: u64,
        len: u64,
        at_seq: Option<u32>,
        writes_only: bool,
        limit: usize,
    ) -> Vec<TraceQueryHit> {
        self.query_addr_history_in_range(addr, len, None, at_seq, writes_only, limit)
    }

    /// Omniscient 地址历史查询（支持 `min_seq`..=`max_seq` 闭区间过滤）
    pub fn query_addr_history_in_range(
        &self,
        addr: u64,
        len: u64,
        min_seq: Option<u32>,
        max_seq: Option<u32>,
        writes_only: bool,
        limit: usize,
    ) -> Vec<TraceQueryHit> {
        self.query_addr_history_filtered(
            addr,
            len,
            min_seq,
            max_seq,
            !writes_only,
            true,
            true,
            limit,
        )
    }

    /// Omniscient 地址历史精细查询（支持 `min_seq`..=`max_seq`、读/写独立过滤与 `--no-hle` 开关）
    #[allow(clippy::too_many_arguments)]
    pub fn query_addr_history_filtered(
        &self,
        addr: u64,
        len: u64,
        min_seq: Option<u32>,
        max_seq: Option<u32>,
        include_reads: bool,
        include_writes: bool,
        include_hle: bool,
        limit: usize,
    ) -> Vec<TraceQueryHit> {
        let Some(mmap) = self.ext_buf.as_ref() else {
            return Vec::new();
        };
        let q_len = len.max(1);
        let end_idx = max_seq
            .map(|hi| self.ext_end_index_for_seq(hi))
            .unwrap_or(self.ext_count);
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < end_idx {
            let rec = read_packed::<ExtRecord>(mmap, i);
            let seq = rec.seq_low32;
            let seq_ok = min_seq.is_none_or(|lo| seq >= lo);
            match ExtKind::from_u8(rec.kind) {
                Some(ExtKind::MemWrite) if seq_ok && include_writes => {
                    let sz = (rec.size_or_reg as u64).max(1);
                    if range_overlaps_u128(rec.addr, sz, addr, q_len) {
                        out.push(TraceQueryHit {
                            seq_low32: seq,
                            pc: rec.pc,
                            addr: rec.addr,
                            size: sz,
                            kind: "write",
                            value: rec.value,
                            src: 0,
                        });
                    }
                }
                Some(ExtKind::MemRead) if seq_ok && include_reads => {
                    let sz = (rec.size_or_reg as u64).max(1);
                    if range_overlaps_u128(rec.addr, sz, addr, q_len) {
                        out.push(TraceQueryHit {
                            seq_low32: seq,
                            pc: rec.pc,
                            addr: rec.addr,
                            size: sz,
                            kind: "read",
                            value: rec.value,
                            src: 0,
                        });
                    }
                }
                Some(ExtKind::HleMemcpy) => {
                    let dst = rec.addr;
                    let src = rec.value;
                    let mut hlen = 0u64;
                    if i + 1 < end_idx {
                        let next = read_packed::<ExtRecord>(mmap, i + 1);
                        if is_matching_hle_meta(rec, next) {
                            hlen = next.value;
                            i += 1;
                        }
                    }
                    if seq_ok && include_hle {
                        let dst_hit = include_writes
                            && hlen > 0
                            && range_overlaps_u128(dst, hlen, addr, q_len);
                        let src_hit = include_reads
                            && hlen > 0
                            && range_overlaps_u128(src, hlen, addr, q_len);
                        if dst_hit || src_hit {
                            let kind = match rec.size_or_reg {
                                1 => "hle_memmove",
                                2 => "hle_realloc_copy",
                                _ => "hle_memcpy",
                            };
                            out.push(TraceQueryHit {
                                seq_low32: seq,
                                pc: rec.pc,
                                addr: dst,
                                size: hlen,
                                kind,
                                value: hlen,
                                src,
                            });
                        }
                    }
                }
                Some(ExtKind::HleMemset) if seq_ok && include_hle && include_writes => {
                    let dst = rec.addr;
                    let hlen = rec.value;
                    if hlen > 0 && range_overlaps_u128(dst, hlen, addr, q_len) {
                        let kind = match rec._pad[0] {
                            1 => "hle_bzero",
                            2 => "hle_calloc_zero",
                            _ => "hle_memset",
                        };
                        out.push(TraceQueryHit {
                            seq_low32: seq,
                            pc: rec.pc,
                            addr: dst,
                            size: hlen,
                            kind,
                            value: rec.size_or_reg as u64,
                            src: 0,
                        });
                    }
                }
                Some(ExtKind::HleSource) if seq_ok && include_hle && include_writes => {
                    let dst = rec.addr;
                    let mut hlen = u64::from(rec._pad[0]);
                    if i + 1 < end_idx {
                        let next = read_packed::<ExtRecord>(mmap, i + 1);
                        if next.kind == ExtKind::HleMeta as u8 && is_matching_hle_meta(rec, next) {
                            hlen = next.value;
                            i += 1;
                        }
                    }
                    if dst != 0 && hlen > 0 && range_overlaps_u128(dst, hlen, addr, q_len) {
                        let kind = match rec.size_or_reg {
                            3 => "hle_time",
                            4 => "hle_getrandom",
                            5 => "hle_gettimeofday",
                            6 => "hle_clock_gettime",
                            _ => "hle_source",
                        };
                        out.push(TraceQueryHit {
                            seq_low32: seq,
                            pc: rec.pc,
                            addr: dst,
                            size: hlen,
                            kind,
                            value: rec.value,
                            src: 0,
                        });
                    }
                }
                _ => {}
            }
            if limit > 0 && out.len() >= limit {
                break;
            }
            i += 1;
        }
        out
    }

    /// 重建任意时刻 `at_seq` 时内存区间 `[addr, addr + len)` 的最近写入字节快照（逆向 O(len) 内存、无 1MiB 截断、全部槽位解出即早停）
    pub fn reconstruct_mem_at(&self, addr: u64, len: usize, at_seq: u32) -> Vec<Option<u8>> {
        let mut out = vec![None; len];
        let Some(mmap) = self.ext_buf.as_ref() else {
            return out;
        };
        if len == 0 {
            return out;
        }
        let end_idx = self.ext_end_index_for_seq(at_seq);
        if end_idx == 0 {
            return out;
        }
        // 每个目标字节槽位当前追寻的物理地址（None 表示已解出具体字节值或超出 u64 边界）
        let mut cur_addr: Vec<Option<u64>> = (0..len)
            .map(|off| addr.checked_add(off as u64))
            .collect();
        let mut remaining = cur_addr.iter().filter(|a| a.is_some()).count();

        let mut i = end_idx;
        while i > 0 && remaining > 0 {
            i -= 1;
            let rec = read_packed::<ExtRecord>(mmap, i);
            match ExtKind::from_u8(rec.kind) {
                Some(ExtKind::MemWrite) => {
                    let sz = (rec.size_or_reg as usize).clamp(1, 8) as u64;
                    let w_start = rec.addr as u128;
                    let w_end = w_start + sz as u128;
                    let bytes = rec.value.to_le_bytes();
                    for (slot, slot_addr) in cur_addr.iter_mut().enumerate() {
                        if let Some(a) = *slot_addr {
                            let a128 = a as u128;
                            if a128 >= w_start && a128 < w_end {
                                let off = (a128 - w_start) as usize;
                                out[slot] = Some(bytes[off]);
                                *slot_addr = None;
                                remaining -= 1;
                            }
                        }
                    }
                }
                Some(ExtKind::HleMemset) => {
                    let hlen = rec.value;
                    if hlen > 0 {
                        let d_start = rec.addr as u128;
                        let d_end = d_start + hlen as u128;
                        let fill = rec.size_or_reg;
                        for (slot, slot_addr) in cur_addr.iter_mut().enumerate() {
                            if let Some(a) = *slot_addr {
                                let a128 = a as u128;
                                if a128 >= d_start && a128 < d_end {
                                    out[slot] = Some(fill);
                                    *slot_addr = None;
                                    remaining -= 1;
                                }
                            }
                        }
                    }
                }
                Some(ExtKind::HleSource) => {
                    let dst = rec.addr;
                    let hlen = u64::from(rec._pad[0]);
                    if dst != 0 && hlen > 0 {
                        let d_start = dst as u128;
                        let d_end = d_start + hlen as u128;
                        let first8 = rec.value.to_le_bytes();
                        for (slot, slot_addr) in cur_addr.iter_mut().enumerate() {
                            if let Some(a) = *slot_addr {
                                let a128 = a as u128;
                                if a128 >= d_start && a128 < d_end {
                                    let off = (a128 - d_start) as usize;
                                    if off < 8 {
                                        out[slot] = Some(first8[off]);
                                    } else {
                                        // 8..hlen 的精确字节未内联于 HleSource，置为 None 防止穿透到更早的 memset 脏值
                                        out[slot] = None;
                                    }
                                    *slot_addr = None;
                                    remaining -= 1;
                                }
                            }
                        }
                    }
                }
                Some(ExtKind::HleMeta) => {
                    // 逆向扫描遇到 HleMeta 时与前一条 HleMemcpy 或 HleSource 精确配对
                    if i > 0 {
                        let prev = read_packed::<ExtRecord>(mmap, i - 1);
                        if prev.kind == ExtKind::HleMemcpy as u8
                            && is_matching_hle_meta(prev, rec)
                        {
                            i -= 1;
                            let hlen = rec.value;
                            if hlen > 0 {
                                let d_start = prev.addr as u128;
                                let d_end = d_start + hlen as u128;
                                let s_start = prev.value;
                                for slot_addr in cur_addr.iter_mut() {
                                    if let Some(a) = *slot_addr {
                                        let a128 = a as u128;
                                        if a128 >= d_start && a128 < d_end {
                                            let off = (a128 - d_start) as u64;
                                            *slot_addr = s_start.checked_add(off);
                                            if slot_addr.is_none() {
                                                remaining -= 1;
                                            }
                                        }
                                    }
                                }
                            }
                        } else if prev.kind == ExtKind::HleSource as u8
                            && is_matching_hle_meta(prev, rec)
                        {
                            i -= 1;
                            let dst = prev.addr;
                            let hlen = rec.value;
                            if dst != 0 && hlen > 0 {
                                let d_start = dst as u128;
                                let d_end = d_start + hlen as u128;
                                let first8 = prev.value.to_le_bytes();
                                for (slot, slot_addr) in cur_addr.iter_mut().enumerate() {
                                    if let Some(a) = *slot_addr {
                                        let a128 = a as u128;
                                        if a128 >= d_start && a128 < d_end {
                                            let off = (a128 - d_start) as usize;
                                            out[slot] = if off < 8 { Some(first8[off]) } else { None };
                                            *slot_addr = None;
                                            remaining -= 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// 双跑 Trace 差分对比（`runidbg-cli diff a.idx b.idx`）：
    /// 定位首次控制流分叉（PC/Opcode/长度）与同 PC 寄存器/内存写/HLE 事件差异
    pub fn diff_traces(a: &TraceReader, b: &TraceReader, max_diffs: usize) -> TraceDiffSummary {
        let min_len = a.len().min(b.len());
        let cap = if max_diffs == 0 { 100 } else { max_diffs };
        let mut diffs = Vec::new();
        let mut common_prefix_insns = 0usize;
        let mut prefix_broken = false;
        let mut first_control_divergence_idx = None;
        let mut first_data_divergence_idx = None;

        for idx in 0..min_len {
            let ra = read_packed::<TraceRecord>(&a.idx_buf, idx);
            let rb = read_packed::<TraceRecord>(&b.idx_buf, idx);
            let pc_a = ra.pc;
            let pc_b = rb.pc;
            let op_a = ra.opcode;
            let op_b = rb.opcode;

            if pc_a != pc_b || op_a != op_b {
                first_control_divergence_idx = Some(idx);
                if diffs.len() < cap {
                    let detail = if pc_a != pc_b {
                        format!("PC diverged: 0x{pc_a:016x} vs 0x{pc_b:016x}")
                    } else {
                        format!("opcode diverged @ 0x{pc_a:016x}: 0x{op_a:08x} vs 0x{op_b:08x}")
                    };
                    diffs.push(TraceDiffEntry {
                        idx,
                        kind: "control",
                        pc_a,
                        pc_b,
                        detail,
                    });
                }
                // 控制流一旦分叉，后续下标已失步，立即停止避免噪音洪泛
                break;
            }

            let mut step_diverged = false;

            // 1. 仅在双方均存在 idx + 1 记录时比对寄存器增量，避免不等长末尾误报
            if idx + 1 < min_len {
                let reg_a = a.reg_deltas_for(idx);
                let reg_b = b.reg_deltas_for(idx);
                if reg_a != reg_b {
                    step_diverged = true;
                    if first_data_divergence_idx.is_none() {
                        first_data_divergence_idx = Some(idx);
                    }
                    if diffs.len() < cap {
                        let fmt = |v: &[(u8, u64)]| -> String {
                            v.iter()
                                .map(|(r, val)| {
                                    if *r == 31 {
                                        format!("SP=0x{val:x}")
                                    } else {
                                        format!("X{r}=0x{val:x}")
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join(",")
                        };
                        diffs.push(TraceDiffEntry {
                            idx,
                            kind: "reg",
                            pc_a,
                            pc_b,
                            detail: format!("reg delta: [{}] vs [{}]", fmt(&reg_a), fmt(&reg_b)),
                        });
                    }
                }
            }

            // 2. 比对同 PC 内存写入事件差异
            let mw_a: Vec<(u64, u8, u64)> = a
                .mem_events_for(idx)
                .into_iter()
                .filter(|e| e.kind == ExtKind::MemWrite as u8)
                .map(|e| (e.addr, e.size_or_reg, e.value))
                .collect();
            let mw_b: Vec<(u64, u8, u64)> = b
                .mem_events_for(idx)
                .into_iter()
                .filter(|e| e.kind == ExtKind::MemWrite as u8)
                .map(|e| (e.addr, e.size_or_reg, e.value))
                .collect();
            if mw_a != mw_b {
                step_diverged = true;
                if first_data_divergence_idx.is_none() {
                    first_data_divergence_idx = Some(idx);
                }
                if diffs.len() < cap {
                    let fmt_mw = |v: &[(u64, u8, u64)]| -> String {
                        v.iter()
                            .map(|(ad, sz, val)| format!("0x{ad:x}({sz}B)=0x{val:x}"))
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    diffs.push(TraceDiffEntry {
                        idx,
                        kind: "mem",
                        pc_a,
                        pc_b,
                        detail: format!("mem write: [{}] vs [{}]", fmt_mw(&mw_a), fmt_mw(&mw_b)),
                    });
                }
            }

            // 3. 比对同 PC HLE 事件差异
            let hle_a: Vec<(&'static str, u64, u64, u64)> = a
                .hle_events_for(idx)
                .into_iter()
                .map(|e| (e.op, e.dst, e.src, e.len))
                .collect();
            let hle_b: Vec<(&'static str, u64, u64, u64)> = b
                .hle_events_for(idx)
                .into_iter()
                .map(|e| (e.op, e.dst, e.src, e.len))
                .collect();
            if hle_a != hle_b {
                step_diverged = true;
                if first_data_divergence_idx.is_none() {
                    first_data_divergence_idx = Some(idx);
                }
                if diffs.len() < cap {
                    diffs.push(TraceDiffEntry {
                        idx,
                        kind: "hle",
                        pc_a,
                        pc_b,
                        detail: format!("HLE events: {hle_a:?} vs {hle_b:?}"),
                    });
                }
            }

            if step_diverged {
                prefix_broken = true;
            } else if !prefix_broken {
                common_prefix_insns += 1;
            }
        }

        // 若前缀控制流未分叉但长度不同，补充一条 length 截断差异
        if first_control_divergence_idx.is_none() && a.len() != b.len() {
            let pc_a = a.get(min_len).map(|r| r.pc).unwrap_or(0);
            let pc_b = b.get(min_len).map(|r| r.pc).unwrap_or(0);
            if diffs.len() < cap {
                diffs.push(TraceDiffEntry {
                    idx: min_len,
                    kind: "length",
                    pc_a,
                    pc_b,
                    detail: format!(
                        "trace length diverged: A={} insns vs B={} insns",
                        a.len(),
                        b.len()
                    ),
                });
            }
        }

        TraceDiffSummary {
            total_a: a.len(),
            total_b: b.len(),
            common_prefix_insns,
            first_control_divergence_idx,
            first_data_divergence_idx,
            diffs,
        }
    }

    /// 双跑差分 + 自动反向污点联动：比较 A/B 两次 Trace 在 `[target_addr, target_addr + len)` 上的最终字节差异，
    /// 并对每个连续差异段在 A/B 两侧自动执行反向污点切片，直接定位导致每个协议字段不同的起源输入！
    pub fn diff_taint_bytes(
        a: &TraceReader,
        b: &TraceReader,
        target_addr: u64,
        len: usize,
        max_insns: usize,
    ) -> DiffTaintReport {
        use crate::tracer::taint::{TaintOptions, TaintSeed};

        let capped_len = len.min(4096);
        let bytes_a = a.reconstruct_mem_at(target_addr, capped_len, u32::MAX);
        let bytes_b = b.reconstruct_mem_at(target_addr, capped_len, u32::MAX);

        let mut identical = 0usize;
        let mut differing = 0usize;
        let mut spans: Vec<DiffTaintByteSpan> = Vec::new();
        const MAX_TAINT_SPANS: usize = 64;
        let mut i = 0usize;
        while i < capped_len {
            if bytes_a[i] == bytes_b[i] {
                if bytes_a[i].is_some() {
                    identical += 1;
                }
                i += 1;
                continue;
            }
            let start = i;
            while i < capped_len && bytes_a[i] != bytes_b[i] {
                differing += 1;
                i += 1;
            }
            if spans.len() >= MAX_TAINT_SPANS {
                continue;
            }
            let span_len = i - start;
            let span_addr = target_addr.wrapping_add(start as u64);
            let seed = TaintSeed::Mem {
                addr: span_addr,
                len: span_len,
            };
            let opts = TaintOptions {
                max_insns,
                max_steps: 256,
                ..Default::default()
            };
            let rep_a = a.taint_backward(&seed, &opts);
            let rep_b = b.taint_backward(&seed, &opts);
            spans.push(DiffTaintByteSpan {
                offset: start,
                addr: span_addr,
                len: span_len,
                bytes_a: bytes_a[start..i].to_vec(),
                bytes_b: bytes_b[start..i].to_vec(),
                origins_a_regs: rep_a.tainted_regs.into_iter().map(|(n, _)| n).collect(),
                origins_a_mem: rep_a
                    .tainted_mem_ranges
                    .into_iter()
                    .map(|(ad, l, _)| (ad, l))
                    .collect(),
                origins_a_hle: rep_a.origin_annotations,
                origins_b_regs: rep_b.tainted_regs.into_iter().map(|(n, _)| n).collect(),
                origins_b_mem: rep_b
                    .tainted_mem_ranges
                    .into_iter()
                    .map(|(ad, l, _)| (ad, l))
                    .collect(),
                origins_b_hle: rep_b.origin_annotations,
            });
        }

        DiffTaintReport {
            target_addr,
            len: capped_len,
            identical_bytes: identical,
            differing_bytes: differing,
            spans,
        }
    }

    /// 构建基于 `BL` / `BLR` / `RET` 的时间轴调用树（自动忽略未落入 Trace 过滤范围的外部调用）
    pub fn build_calltree(&self) -> Vec<CallTreeNode> {
        struct ActiveFrame {
            node_idx: usize,
            return_addr: u64,
        }

        let mut nodes: Vec<CallTreeNode> = Vec::new();
        let mut stack: Vec<ActiveFrame> = Vec::new();
        let total = self.idx_count;
        if total == 0 {
            return nodes;
        }

        // 根节点代表整个 Trace 入口函数
        let root_pc = read_packed::<TraceRecord>(&self.idx_buf, 0).pc;
        nodes.push(CallTreeNode {
            target_pc: root_pc,
            caller_pc: 0,
            start_idx: 0,
            end_idx: total - 1,
            depth: 0,
        });

        for idx in 0..total.saturating_sub(1) {
            let cur = read_packed::<TraceRecord>(&self.idx_buf, idx);
            let next = read_packed::<TraceRecord>(&self.idx_buf, idx + 1);
            let pc = cur.pc;
            let op = cur.opcode;
            let next_pc = next.pc;

            // 若当前 PC 已回到调用栈上某帧的 return_addr（例如经 .plt 调外部 HLE 返回，未经过模块内 RET）
            if let Some(pos) = stack.iter().rposition(|f| f.return_addr == pc) {
                while stack.len() > pos {
                    if let Some(frame) = stack.pop() {
                        nodes[frame.node_idx].end_idx = idx.saturating_sub(1);
                    }
                }
            }

            let is_bl = (op & 0xFC00_0000) == 0x9400_0000;
            let is_blr = (op & 0xFFFF_FC1F) == 0xD63F_0000;
            let is_ret = (op & 0xFFFF_FC1F) == 0xD65F_0000;

            if (is_bl || is_blr) && next_pc != pc.wrapping_add(4) {
                let depth = stack.len() + 1;
                let node_idx = nodes.len();
                nodes.push(CallTreeNode {
                    target_pc: next_pc,
                    caller_pc: pc,
                    start_idx: idx + 1,
                    end_idx: total - 1,
                    depth,
                });
                stack.push(ActiveFrame {
                    node_idx,
                    return_addr: pc.wrapping_add(4),
                });
            } else if is_ret {
                if let Some(pos) = stack.iter().rposition(|f| f.return_addr == next_pc) {
                    while stack.len() > pos {
                        if let Some(frame) = stack.pop() {
                            nodes[frame.node_idx].end_idx = idx;
                        }
                    }
                }
            }
        }

        nodes
    }

    /// 自动扫描 Trace 中出现的常见密码学算法常量（MD5/SHA1/SHA256/SM3/SM4/AES/ChaCha/CRC32/TEA/MurmurHash3）
    pub fn scan_crypto(&self) -> Vec<CryptoHitGroup> {
        const SIGNATURES: &[(&str, u32)] = &[
            // MD5 IV & round constants
            ("MD5", 0x6745_2301),
            ("MD5", 0xefcd_ab89),
            ("MD5", 0x98ba_dcfe),
            ("MD5", 0x1032_5476),
            ("MD5", 0xd76a_a478),
            ("MD5", 0xe8c7_b756),
            // SHA-1 unique H4 & round constants
            ("SHA-1", 0xc3d2_e1f0),
            ("SHA-1", 0x5a82_7999),
            ("SHA-1", 0x6ed9_eba1),
            ("SHA-1", 0x8f1b_bcdc),
            ("SHA-1", 0xca62_c1d6),
            // SHA-256 IV & K0
            ("SHA-256", 0x6a09_e667),
            ("SHA-256", 0xbb67_ae85),
            ("SHA-256", 0x3c6e_f372),
            ("SHA-256", 0xa54f_f53a),
            ("SHA-256", 0x428a_2f98),
            // SM3 IV & Tj
            ("SM3", 0x7380_166f),
            ("SM3", 0x4914_b2b9),
            ("SM3", 0x1724_42d7),
            ("SM3", 0xda8a_0600),
            ("SM3", 0x79cc_4519),
            ("SM3", 0x7a87_9d8a),
            // SM4 FK
            ("SM4", 0xa3b1_bac6),
            ("SM4", 0x56aa_3350),
            ("SM4", 0x677d_9197),
            ("SM4", 0xb270_22dc),
            // AES S-box / T-table / Rcon words
            ("AES", 0x637c_777b),
            ("AES", 0x7b77_7c63),
            ("AES", 0xc663_63a5),
            ("AES", 0xa563_63c6),
            ("AES", 0xf87c_7c84),
            ("AES", 0xee77_7799),
            ("AES", 0xf67b_7b8d),
            // Simon-128/256 z-sequence & key schedule constants
            ("Simon", 0xffff_fffc),
            ("Simon", 0x3369_f885),
            ("Simon", 0x192c_0ef5),
            ("Simon", 0x3dc9_4c3a),
            ("Simon", 0x046d_678b),
            // ChaCha20 / Salsa20 "expand 32-byte k"
            ("ChaCha20/Salsa20", 0x6170_7865),
            ("ChaCha20/Salsa20", 0x3320_646e),
            ("ChaCha20/Salsa20", 0x7962_2d32),
            ("ChaCha20/Salsa20", 0x6b20_6574),
            // CRC32
            ("CRC32", 0xedb8_8320),
            ("CRC32", 0x04c1_1db7),
            // TEA / XTEA / XXTEA
            ("TEA/XTEA", 0x9e37_79b9),
            ("TEA/XTEA", 0x61c8_8647),
            ("TEA/XTEA", 0xc6ef_3720),
            // MurmurHash3
            ("MurmurHash3", 0xcc9e_2d51),
            ("MurmurHash3", 0x1b87_3593),
            ("MurmurHash3", 0x85eb_ca6b),
        ];
        const SIGNATURES_64: &[(&str, u64)] = &[
            // 仅保留高熵 64-bit z 序列 / AES S-Box 常量（避免 -4i64 即 0xfffffffffffffffc 在普通代码中误报）
            ("Simon-128", 0x3369_f885_192c_0ef5),
            ("Simon-128", 0x3dc9_4c3a_046d_678b),
            ("AES", 0x76ab_d7fe_2b67_0130),
            ("AES", 0xc56f_6bf2_7b77_7c63),
        ];

        let mut const_map: HashMap<u32, Vec<&'static str>> = HashMap::new();
        for &(algo, val) in SIGNATURES {
            const_map.entry(val).or_default().push(algo);
        }
        let mut const_map64: HashMap<u64, Vec<&'static str>> = HashMap::new();
        for &(algo, val) in SIGNATURES_64 {
            const_map64.entry(val).or_default().push(algo);
        }

        // algo -> Vec<(idx, pc, constant)>
        let mut raw_hits: BTreeMap<&'static str, Vec<(usize, u64, u32)>> = BTreeMap::new();

        for i in 0..self.idx_count {
            let rec = read_packed::<TraceRecord>(&self.idx_buf, i);
            let op = rec.opcode;
            // 检测 ARMv8 硬件 AES 指令（AESE / AESD / AESMC / AESIMC）
            if matches!(
                op & 0xFFFF_FC00,
                0x4E28_4800 | 0x4E28_5800 | 0x4E28_6800 | 0x4E28_7800
            ) {
                let pc = rec.pc;
                raw_hits
                    .entry("AES (ARMv8-CE)")
                    .or_default()
                    .push((i, pc, op & 0xFFFF_FC00));
            }
            let reg_id = rec.primary_reg_id;
            if reg_id != 0xFF {
                let val = rec.primary_reg_val;
                if let Some(algos) = const_map64.get(&val) {
                    let (attr_idx, attr_rec) = self.attribute_pre_exec(i, rec);
                    let pc = attr_rec.pc;
                    for &algo in algos {
                        raw_hits
                            .entry(algo)
                            .or_default()
                            .push((attr_idx, pc, val as u32));
                    }
                }
                if val <= u32::MAX as u64 {
                    let v32 = val as u32;
                    if let Some(algos) = const_map.get(&v32) {
                        let (attr_idx, attr_rec) = self.attribute_pre_exec(i, rec);
                        let pc = attr_rec.pc;
                        for &algo in algos {
                            raw_hits.entry(algo).or_default().push((attr_idx, pc, v32));
                        }
                    }
                }
            }
        }

        let mut direct_groups: Vec<CryptoHitGroup> = Vec::new();
        if let Some(mmap) = self.ext_buf.as_ref() {
            const AES_SBOX_HEAD: [u8; 16] = [
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
                0xd7, 0xab, 0x76,
            ];
            let mut seq_to_idx: Option<HashMap<u32, usize>> = None;
            // 检测软件 AES S-Box 字节查表（任意对齐：按首 16 字节唯一值反推候选表基址 addr - off，命中 >= 6 个不同偏移）
            // 与 RC4 256B 状态写（延迟查 seq_to_idx 避免大 trace 无谓建表，且统计独立字节偏移数防止误报）
            let mut aes_sbox_hits: HashMap<u64, (u16, u32, u64)> = HashMap::new();
            let mut rc4_page_writes: HashMap<u64, ([u64; 4], u32, u32, u64, usize)> =
                HashMap::new();

            for i in 0..self.ext_count {
                let ext = read_packed::<ExtRecord>(mmap, i);
                let val = ext.value;
                if let Some(algos) = const_map64.get(&val) {
                    let seq = ext.seq_low32;
                    let map = seq_to_idx.get_or_insert_with(|| self.build_seq_index_map());
                    if let Some(&idx) = map.get(&seq) {
                        let (attr_idx, pc) = if ext.kind == ExtKind::RegDeltaExtra as u8 {
                            if let Some(raw_rec) = self.get(idx) {
                                let (ai, ar) = self.attribute_pre_exec(idx, raw_rec);
                                (ai, ar.pc)
                            } else {
                                (idx, ext.pc)
                            }
                        } else {
                            (idx, ext.pc)
                        };
                        for &algo in algos {
                            raw_hits
                                .entry(algo)
                                .or_default()
                                .push((attr_idx, pc, val as u32));
                        }
                    }
                }
                if ext.kind == ExtKind::MemRead as u8 && ext.size_or_reg == 1 {
                    let b = (val & 0xFF) as u8;
                    if let Some(off) = AES_SBOX_HEAD.iter().position(|&x| x == b) {
                        let base = ext.addr.wrapping_sub(off as u64);
                        let ent = aes_sbox_hits
                            .entry(base)
                            .or_insert((0u16, ext.seq_low32, ext.pc));
                        ent.0 |= 1u16 << off;
                    }
                } else if ext.kind == ExtKind::MemWrite as u8 && ext.size_or_reg == 1 {
                    let page = ext.addr & !0xFF;
                    let off = (ext.addr & 0xFF) as usize;
                    let ent = rc4_page_writes.entry(page).or_insert((
                        [0u64; 4],
                        ext.seq_low32,
                        ext.seq_low32,
                        ext.pc,
                        0,
                    ));
                    ent.0[off >> 6] |= 1u64 << (off & 63);
                    if ext.seq_low32 < ent.1 {
                        ent.1 = ext.seq_low32;
                    }
                    if ext.seq_low32 > ent.2 {
                        ent.2 = ext.seq_low32;
                    }
                    ent.4 += 1;
                }
                if val <= u32::MAX as u64 {
                    let v32 = val as u32;
                    if let Some(algos) = const_map.get(&v32) {
                        let seq = ext.seq_low32;
                        let map = seq_to_idx.get_or_insert_with(|| self.build_seq_index_map());
                        if let Some(&idx) = map.get(&seq) {
                            let (attr_idx, pc) = if ext.kind == ExtKind::RegDeltaExtra as u8 {
                                if let Some(raw_rec) = self.get(idx) {
                                    let (ai, ar) = self.attribute_pre_exec(idx, raw_rec);
                                    (ai, ar.pc)
                                } else {
                                    (idx, ext.pc)
                                }
                            } else {
                                (idx, ext.pc)
                            };
                            for &algo in algos {
                                raw_hits.entry(algo).or_default().push((attr_idx, pc, v32));
                            }
                        }
                    }
                }
            }
            for (_base, (mask, first_seq, first_pc)) in aes_sbox_hits {
                if mask.count_ones() >= 6 {
                    let map = seq_to_idx.get_or_insert_with(|| self.build_seq_index_map());
                    if let Some(&first_idx) = map.get(&first_seq) {
                        raw_hits
                            .entry("AES (S-Box)")
                            .or_default()
                            .push((first_idx, first_pc, 0x637c_777b));
                        raw_hits
                            .entry("AES (S-Box)")
                            .or_default()
                            .push((first_idx, first_pc, 0xf26b_6fc5));
                    }
                }
            }
            for (_page, (bits, first_seq, last_seq, first_pc, cnt)) in rc4_page_writes {
                let distinct_offs: u32 = bits.iter().map(|w| w.count_ones()).sum();
                if cnt >= 256 && distinct_offs >= 128 && last_seq.saturating_sub(first_seq) <= 40_000
                {
                    let map = seq_to_idx.get_or_insert_with(|| self.build_seq_index_map());
                    if let (Some(&start_i), Some(&end_i)) = (map.get(&first_seq), map.get(&last_seq))
                    {
                        let (lo, hi) = if start_i <= end_i {
                            (start_i, end_i)
                        } else {
                            (end_i, start_i)
                        };
                        let (in_addrs, out_addrs) = self.infer_window_io_buffers(lo, hi);
                        direct_groups.push(CryptoHitGroup {
                            algorithm: "RC4 (256B-State)",
                            start_idx: lo,
                            end_idx: hi,
                            first_pc,
                            hit_count: cnt,
                            distinct_constants: vec![distinct_offs, cnt as u32],
                            input_addrs: in_addrs,
                            output_addrs: out_addrs,
                        });
                    }
                }
            }
        }

        // 将同一算法在 2500 条指令窗口内的命中聚合成一次调用实例
        const WINDOW_GAP: usize = 2500;
        let mut groups = direct_groups;
        for (algo, mut events) in raw_hits {
            events.sort_by_key(|&(idx, _, _)| idx);
            let mut cur_start = 0usize;
            let mut cur_end = 0usize;
            let mut cur_pc = 0u64;
            let mut cur_hits = 0usize;
            let mut cur_consts: BTreeSet<u32> = BTreeSet::new();
            let min_consts = if matches!(algo, "CRC32" | "AES (ARMv8-CE)" | "Simon-128" | "TEA/XTEA")
            {
                1
            } else {
                2
            };

            for (idx, pc, c) in events {
                if cur_hits == 0 {
                    cur_start = idx;
                    cur_end = idx;
                    cur_pc = pc;
                    cur_hits = 1;
                    cur_consts.insert(c);
                } else if idx.saturating_sub(cur_end) <= WINDOW_GAP {
                    cur_end = idx;
                    cur_hits += 1;
                    cur_consts.insert(c);
                } else {
                    if cur_consts.len() >= min_consts {
                        let (in_addrs, out_addrs) =
                            self.infer_window_io_buffers(cur_start, cur_end);
                        groups.push(CryptoHitGroup {
                            algorithm: algo,
                            start_idx: cur_start,
                            end_idx: cur_end,
                            first_pc: cur_pc,
                            hit_count: cur_hits,
                            distinct_constants: cur_consts.iter().copied().collect(),
                            input_addrs: in_addrs,
                            output_addrs: out_addrs,
                        });
                    }
                    cur_start = idx;
                    cur_end = idx;
                    cur_pc = pc;
                    cur_hits = 1;
                    cur_consts.clear();
                    cur_consts.insert(c);
                }
            }
            if cur_hits > 0 && cur_consts.len() >= min_consts {
                let (in_addrs, out_addrs) = self.infer_window_io_buffers(cur_start, cur_end);
                groups.push(CryptoHitGroup {
                    algorithm: algo,
                    start_idx: cur_start,
                    end_idx: cur_end,
                    first_pc: cur_pc,
                    hit_count: cur_hits,
                    distinct_constants: cur_consts.iter().copied().collect(),
                    input_addrs: in_addrs,
                    output_addrs: out_addrs,
                });
            }
        }

        // 如果某窗口同时命中 SHA-1 与 MD5（因为共享前 4 个 IV），保留 SHA-1 并过滤掉重叠的 MD5 误报
        let sha1_ranges: Vec<(usize, usize)> = groups
            .iter()
            .filter(|g| g.algorithm == "SHA-1")
            .map(|g| (g.start_idx.saturating_sub(500), g.end_idx.saturating_add(500)))
            .collect();
        groups.retain(|g| {
            if g.algorithm != "MD5" {
                return true;
            }
            !sha1_ranges
                .iter()
                .any(|&(s, e)| g.start_idx >= s && g.end_idx <= e)
        });

        groups.sort_by_key(|g| g.start_idx);
        groups
    }

    /// 结合 `.ext` 推断某算法执行窗口 `[start_idx..=end_idx]` 内的 Top 候选输入（先读/只读）与输出（写入）内存缓冲区
    #[allow(clippy::type_complexity)]
    fn infer_window_io_buffers(
        &self,
        start_idx: usize,
        end_idx: usize,
    ) -> (Vec<(u64, usize)>, Vec<(u64, usize)>) {
        if self.ext_buf.is_none() || self.idx_count == 0 {
            return (Vec::new(), Vec::new());
        }
        let s_idx = start_idx.saturating_sub(128);
        let e_idx = end_idx.saturating_add(128).min(self.idx_count - 1);
        let Some(rec_s) = self.get(s_idx) else {
            return (Vec::new(), Vec::new());
        };
        let Some(rec_e) = self.get(e_idx) else {
            return (Vec::new(), Vec::new());
        };
        let min_seq = rec_s.seq_low32;
        let max_seq = rec_e.seq_low32;
        let Some(mmap) = self.ext_buf.as_ref() else {
            return (Vec::new(), Vec::new());
        };
        let ext_end = self.ext_end_index_for_seq(max_seq);
        let ext_start = if self.ext_monotonic && min_seq > 0 {
            self.ext_end_index_for_seq(min_seq.saturating_sub(1))
                .min(ext_end)
        } else {
            0
        };
        let mut read_bytes: BTreeSet<u64> = BTreeSet::new();
        let mut written_bytes: BTreeSet<u64> = BTreeSet::new();
        for i in ext_start..ext_end {
            let ext = read_packed::<ExtRecord>(mmap, i);
            let seq = ext.seq_low32;
            if seq < min_seq || seq > max_seq {
                continue;
            }
            let sz = (ext.size_or_reg as usize).clamp(1, 8);
            match ExtKind::from_u8(ext.kind) {
                Some(ExtKind::MemRead) => {
                    for off in 0..sz {
                        let a = ext.addr.wrapping_add(off as u64);
                        if !written_bytes.contains(&a) {
                            read_bytes.insert(a);
                        }
                    }
                }
                Some(ExtKind::MemWrite) => {
                    for off in 0..sz {
                        written_bytes.insert(ext.addr.wrapping_add(off as u64));
                    }
                }
                _ => {}
            }
        }
        let coalesce = |set: &BTreeSet<u64>| -> Vec<(u64, usize)> {
            let mut spans: Vec<(u64, usize)> = Vec::new();
            for &a in set {
                if let Some(last) = spans.last_mut() {
                    if a == last.0.wrapping_add(last.1 as u64) {
                        last.1 += 1;
                        continue;
                    }
                }
                spans.push((a, 1));
            }
            // 过滤掉单字节碎片，按长度降序保留 Top-4 候选缓冲
            spans.retain(|&(_, l)| l >= 4);
            spans.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            spans.truncate(4);
            spans
        };
        (coalesce(&read_bytes), coalesce(&written_bytes))
    }

    fn attribute_pre_exec(&self, raw_idx: usize, raw_rec: TraceRecord) -> (usize, TraceRecord) {
        if raw_idx > 0 {
            if let Some(prev) = self.get(raw_idx - 1) {
                if raw_rec.seq_low32 == prev.seq_low32.wrapping_add(1) {
                    return (raw_idx - 1, prev);
                }
            }
        }
        (raw_idx, raw_rec)
    }

    fn build_seq_index_map(&self) -> HashMap<u32, usize> {
        let mut map = HashMap::with_capacity(self.idx_count);
        for i in 0..self.idx_count {
            let seq = read_packed::<TraceRecord>(&self.idx_buf, i).seq_low32;
            map.insert(seq, i);
        }
        map
    }

    /// 导出 IDAPython 覆盖率染色脚本
    pub fn export_ida_python(&self, runtime_base: u64) -> String {
        let offsets = self.collect_relative_offsets(runtime_base);
        let mut script = String::from(
            "# Auto-generated by runidbg-arm64-emu-tracer runidbg-cli\n\
             import ida_nalt, idc\n\
             base = ida_nalt.get_imagebase()\n\
             offsets = [\n",
        );
        for off in &offsets {
            script.push_str(&format!("    0x{off:x},\n"));
        }
        script.push_str(
            "]\n\
             for off in offsets:\n\
                 idc.set_color(base + off, idc.CIC_ITEM, 0xCCFFCC)\n\
             print(f'[runidbg-arm64-emu-tracer] Highlighted {len(offsets)} instructions.')\n",
        );
        script
    }

    /// 导出 Binary Ninja 覆盖率高亮脚本
    pub fn export_binja_python(&self, runtime_base: u64) -> String {
        let offsets = self.collect_relative_offsets(runtime_base);
        let mut script = String::from(
            "# Auto-generated by runidbg-arm64-emu-tracer runidbg-cli\n\
             from binaryninja import HighlightStandardColor\n\
             base = bv.start\n\
             offsets = [\n",
        );
        for off in &offsets {
            script.push_str(&format!("    0x{off:x},\n"));
        }
        script.push_str(
            "]\n\
             for off in offsets:\n\
                 ea = base + off\n\
                 for f in bv.get_functions_containing(ea):\n\
                     f.set_user_instr_highlight(ea, HighlightStandardColor.GreenHighlightColor)\n\
             print(f'[runidbg-arm64-emu-tracer] Highlighted {len(offsets)} instructions.')\n",
        );
        script
    }

    fn collect_relative_offsets(&self, runtime_base: u64) -> BTreeSet<u64> {
        let mut offsets = BTreeSet::new();
        for i in 0..self.idx_count {
            let pc = read_packed::<TraceRecord>(&self.idx_buf, i).pc;
            if pc >= runtime_base {
                offsets.insert(pc - runtime_base);
            }
        }
        offsets
    }
}

#[inline]
fn is_matching_hle_meta(rec: ExtRecord, next: ExtRecord) -> bool {
    let rec_seq = rec.seq_low32;
    let next_seq = next.seq_low32;
    let rec_addr = rec.addr;
    let next_addr = next.addr;
    next.kind == ExtKind::HleMeta as u8 && next_seq == rec_seq && next_addr == rec_addr
}

#[inline]
fn range_overlaps_u128(a_start: u64, a_len: u64, b_start: u64, b_len: u64) -> bool {
    let a0 = a_start as u128;
    let a1 = a0 + a_len as u128;
    let b0 = b_start as u128;
    let b1 = b0 + b_len as u128;
    a0 < b1 && b0 < a1
}

#[inline]
fn read_packed<T: Copy>(buf: &[u8], index: usize) -> T {
    let offset = index
        .checked_mul(size_of::<T>())
        .expect("trace record index overflow");
    let end = offset
        .checked_add(size_of::<T>())
        .expect("trace record offset overflow");
    assert!(end <= buf.len(), "trace record read out of bounds");
    // SAFETY: 已在 release 与 debug 模式下显式校验 end <= buf.len()
    unsafe { ptr::read_unaligned(buf.as_ptr().add(offset) as *const T) }
}
