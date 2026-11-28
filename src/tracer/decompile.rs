//! 动态污点切片 → 单路径符号提升（Bit-Vector SSA）→ 代数/MBA 化简 → 自校验精简伪 C（及可选 SMT-LIB2）
//!
//! 架构特点（纯 Rust、零外部求解器依赖、零路径爆炸）：
//! 1. **反向精确切片**：复用 [`TraceReader::taint_backward`]，按 `(idx, seq, pc)` 切出从输入起源到目标输出
//!    的最小因果指令链（自动穿透栈帧复用、S-Box 查表变址与 HLE `memcpy`/`memset`）。
//! 2. **Concolic 单路径符号提升**：沿真实 Trace 单线推进，仅将污点输入提升为符号节点（`arg_xN` / `in_buf_N[off]`），
//!    非污点常量/密钥/表基址直接代入 `.idx`/`.ext` 录制的精确运行时值，并通过字节粒度内存模型自动消除栈溢出（spill）噪声。
//! 3. **不动点代数与 MBA 化简**：常数折叠、恒等/吸收/取消律、De Morgan、旋转（`ROTR32`/`ROTR64`）与字节序
//!    （`BSWAP32`/`BSWAP64`）识别，以及经典 OLLVM/MBA 混淆恒等式还原（如 `(a ^ b) + 2*(a & b) -> a + b`）。
//! 4. **自动数值自校验 + 精简 C / SMT-LIB2 导出**：用 Trace 录制的真实样本对化简后的 DAG 做求值自检
//!    （`verified == Some(true)` 表示与真实 `.so` 输出逐 bit 一致），并经 CSE 输出可直接编译的干净 C 函数
//!    及可选标准 `QF_BV` SMT-LIB2 脚本。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use bad64::{ArrSpec, Imm, Instruction, Operand, Reg, Shift};

use crate::tracer::reader::TraceReader;
use crate::tracer::record::{ExtKind, ExtRecord, HleTraceEvent};
use crate::tracer::taint::{
    format_reg_slot, is_hle_entropy_or_time_mem, is_hle_entropy_or_time_reg, parse_reg_slot,
    TaintOptions, TaintSeed, TaintStep,
};

// ============================================================================
// 1. 公共配置与输出报告类型
// ============================================================================

/// 动态污点切片反编译（伪 C / SMT-LIB2）选项
#[derive(Debug, Clone)]
pub struct DecompileOptions {
    /// 观测点指令下标（默认最后一条指令）
    pub anchor_idx: Option<usize>,
    /// 切片起点下界（含该指令；等价 CLI `--from-seq`），可将任意单轮循环/子阶段边界提升为符号输入
    pub from_idx: Option<usize>,
    /// 命中这些 PC 时停止反向回溯（把该边界处的寄存器/内存直接提升为符号输入参数）
    pub stop_at_pcs: Vec<u64>,
    /// 命中读取这些内存区间 `(addr, len)` 时直接钉死为符号输入参数，不再追寻更早写入
    pub stop_mem_ranges: Vec<(u64, usize)>,
    /// 将整个 Trace 中从未被写入过的只读内存（如 `.rodata` / VM 字节码）直接折叠为常量（默认 false）
    pub fold_rodata: bool,
    /// 最大反向扫描指令数（0 表示不限）
    pub max_insns: usize,
    /// 最大切片步数（默认 4096）
    pub max_steps: usize,
    /// 是否追踪访存变址（如 S-Box 查表 `LDRB Wd, [Xtable, Xidx]`，默认 true）
    pub track_mem_index: bool,
    /// 是否追踪 SP 本身（默认 false）
    pub track_sp: bool,
    /// 生成的 C 函数名称（默认 `"decompiled_slice"`）
    pub function_name: String,
    /// 是否执行代数/旋转/MBA/字节重装化简（默认 true）
    pub simplify: bool,
    /// 是否额外导出标准 `QF_BV` SMT-LIB2 文本（默认 false）
    pub emit_smt2: bool,
    /// 可选初始寄存器具体值（用于在 `idx == 0` 即读未改写参数寄存器时启用数值自校验）
    pub initial_regs: HashMap<u8, u64>,
}

impl Default for DecompileOptions {
    fn default() -> Self {
        Self {
            anchor_idx: None,
            from_idx: None,
            stop_at_pcs: Vec::new(),
            stop_mem_ranges: Vec::new(),
            fold_rodata: false,
            max_insns: 0,
            max_steps: 4096,
            track_mem_index: true,
            track_sp: false,
            function_name: "decompiled_slice".to_string(),
            simplify: true,
            emit_smt2: false,
            initial_regs: HashMap::new(),
        }
    }
}

/// 切片识别出的符号输入参数
#[derive(Debug, Clone)]
pub struct DecompiledInput {
    pub name: String,
    /// `"reg"` 或 `"mem"`
    pub kind: &'static str,
    pub addr: Option<u64>,
    pub width_bytes: usize,
    pub sample_hex: Option<String>,
}

/// 切片识别出的只读查找表（如 S-Box / 常量表）
#[derive(Debug, Clone)]
pub struct DecompiledTable {
    pub name: String,
    pub base_addr: u64,
    pub elem_bytes: u8,
    /// 本次 Trace 中观测到的 `(index -> value)` 查表样本
    pub observed_entries: BTreeMap<u64, u64>,
}

/// 动态污点切片反编译结果报告
#[derive(Debug, Clone)]
pub struct DecompileReport {
    pub seed_desc: String,
    pub anchor_idx: usize,
    pub stop_idx: usize,
    pub scanned_insns: usize,
    pub slice_insns: usize,
    pub raw_nodes: usize,
    pub simplified_nodes: usize,
    pub inputs: Vec<DecompiledInput>,
    pub tables: Vec<DecompiledTable>,
    pub origin_annotations: Vec<String>,
    /// 目标输出字节宽（标量 1/2/4/8B，多输出缓冲区模式为 `9..=64`B）
    pub output_len: usize,
    pub expected_output: Option<u64>,
    pub evaluated_output: Option<u64>,
    /// 多输出缓冲区模式下的完整十六进制期望字节串（按地址升序）
    pub expected_output_bytes_hex: Option<String>,
    /// 多输出缓冲区模式下的完整十六进制求值字节串（按地址升序）
    pub evaluated_output_bytes_hex: Option<String>,
    /// `Some(true)` = 化简后表达式在 Trace 真实输入上与真实输出逐 bit 一致
    pub verified: Option<bool>,
    pub c_code: String,
    pub smt2: Option<String>,
    pub taint_steps: Vec<TaintStep>,
}

impl DecompileReport {
    pub fn format_summary(&self) -> String {
        let mut out = String::new();
        let verify_str = match self.verified {
            Some(true) => "PASS (bit-exact)",
            Some(false) => "MISMATCH",
            None => "UNCHECKED (部分符号输入未在 Trace 中观测到具体初始值或含 Opaque 指令)",
        };
        out.push_str(&format!(
            "/* runidbg dynamic slice decompiler | seed={} | range=#{}..#{} | slice_insns={} | dag={} -> {} nodes | verify={} */\n",
            self.seed_desc,
            self.stop_idx,
            self.anchor_idx,
            self.slice_insns,
            self.raw_nodes,
            self.simplified_nodes,
            verify_str
        ));
        if !self.origin_annotations.is_empty() {
            out.push_str("/* External entropy/time origins:\n");
            for note in &self.origin_annotations {
                out.push_str(&format!(" *   {note}\n"));
            }
            out.push_str(" */\n");
        }
        out.push_str(&self.c_code);
        if let Some(ref smt) = self.smt2 {
            out.push_str("\n/* --- SMT-LIB2 (QF_BV) ---\n");
            out.push_str(smt);
            out.push_str("*/\n");
        }
        out
    }
}

// ============================================================================
// 2. Bit-Vector SSA 表达式 DAG（Arena + 哈希去重 + 代数/MBA 化简 + 求值器）
// ============================================================================

type NodeId = usize;

#[inline]
fn width_mask(width: u8) -> u64 {
    match width {
        0 => 0,
        64.. => u64::MAX,
        w => (1u64 << w) - 1,
    }
}

#[inline]
fn sign_extend_u64(val: u64, from_width: u8, to_width: u8) -> u64 {
    let m = width_mask(from_width);
    let v = val & m;
    if from_width == 0 || from_width >= 64 {
        return v & width_mask(to_width);
    }
    let shift = 64 - from_width;
    let signed = ((v << shift) as i64) >> shift;
    (signed as u64) & width_mask(to_width)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BvUnOp {
    Not,
    Neg,
    Bswap,
    Rbit,
    Clz,
    ZExt,
    SExt,
    Trunc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BvBinOp {
    Add,
    Sub,
    Mul,
    UMulh,
    SMulh,
    UDiv,
    SDiv,
    And,
    Or,
    Xor,
    Shl,
    Lshr,
    Ashr,
    Ror,
}

impl BvBinOp {
    fn is_commutative(self) -> bool {
        matches!(
            self,
            Self::Add | Self::Mul | Self::UMulh | Self::SMulh | Self::And | Self::Or | Self::Xor
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AesOpKind {
    Aese,
    Aesd,
    Aesmc,
    Aesimc,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BvNode {
    Const {
        val: u64,
        width: u8,
    },
    SymReg {
        reg_slot: u8,
        name: String,
        width: u8,
        sample: Option<u64>,
    },
    SymMemByte {
        addr: u64,
        sample: Option<u8>,
    },
    UnOp {
        op: BvUnOp,
        x: NodeId,
        width: u8,
    },
    BinOp {
        op: BvBinOp,
        a: NodeId,
        b: NodeId,
        width: u8,
    },
    Extract {
        x: NodeId,
        lsb: u8,
        width: u8,
    },
    TableLoad {
        table_id: usize,
        idx: NodeId,
        elem_bytes: u8,
        width: u8,
        sample_idx: Option<u64>,
        sample_out: u64,
    },
    /// ARMv8 硬件 AES 原语（128-bit 状态拆分为 lo/hi 两个 64-bit 输出节点）
    AesOp {
        kind: AesOpKind,
        state_lo: NodeId,
        state_hi: NodeId,
        key_lo: Option<NodeId>,
        key_hi: Option<NodeId>,
        hi_half: bool,
    },
    Opaque {
        asm: String,
        args: Vec<NodeId>,
        width: u8,
        sample: Option<u64>,
    },
}

impl BvNode {
    fn width(&self) -> u8 {
        match self {
            Self::Const { width, .. }
            | Self::SymReg { width, .. }
            | Self::UnOp { width, .. }
            | Self::BinOp { width, .. }
            | Self::Extract { width, .. }
            | Self::TableLoad { width, .. }
            | Self::Opaque { width, .. } => *width,
            Self::AesOp { .. } => 64,
            Self::SymMemByte { .. } => 8,
        }
    }
}

#[derive(Default)]
struct BvArena {
    nodes: Vec<BvNode>,
    intern: HashMap<BvNode, NodeId>,
    tables: Vec<DecompiledTable>,
    table_by_key: HashMap<(u64, u8), usize>,
}

impl BvArena {
    fn intern_node(&mut self, node: BvNode) -> NodeId {
        if let Some(&id) = self.intern.get(&node) {
            return id;
        }
        let id = self.nodes.len();
        self.intern.insert(node.clone(), id);
        self.nodes.push(node);
        id
    }

    fn get(&self, id: NodeId) -> &BvNode {
        &self.nodes[id]
    }

    fn width(&self, id: NodeId) -> u8 {
        self.nodes[id].width()
    }

    fn as_const(&self, id: NodeId) -> Option<u64> {
        match self.nodes[id] {
            BvNode::Const { val, .. } => Some(val),
            _ => None,
        }
    }

    fn c(&mut self, val: u64, width: u8) -> NodeId {
        let w = width.clamp(1, 64);
        self.intern_node(BvNode::Const {
            val: val & width_mask(w),
            width: w,
        })
    }

    fn sym_reg(&mut self, reg_slot: u8, width: u8, sample: Option<u64>) -> NodeId {
        let name = format!("arg_{}", format_reg_slot(reg_slot).to_ascii_lowercase());
        self.intern_node(BvNode::SymReg {
            reg_slot,
            name,
            width,
            sample: sample.map(|v| v & width_mask(width)),
        })
    }

    fn sym_mem_byte(&mut self, addr: u64, sample: Option<u8>) -> NodeId {
        // 若同一地址已存在 SymMemByte 且之前无 sample 而现在有 sample，则补齐 sample
        for (i, n) in self.nodes.iter_mut().enumerate() {
            if let BvNode::SymMemByte {
                addr: a,
                sample: s,
            } = n
            {
                if *a == addr {
                    if s.is_none() && sample.is_some() {
                        *s = sample;
                    }
                    return i;
                }
            }
        }
        self.intern_node(BvNode::SymMemByte { addr, sample })
    }

    fn get_or_create_table(
        &mut self,
        base_addr: u64,
        elem_bytes: u8,
        sample_idx: Option<u64>,
        sample_out: u64,
    ) -> usize {
        let key = (base_addr, elem_bytes);
        let id = if let Some(&existing) = self.table_by_key.get(&key) {
            existing
        } else {
            let new_id = self.tables.len();
            self.tables.push(DecompiledTable {
                name: format!("sbox_{new_id}"),
                base_addr,
                elem_bytes,
                observed_entries: BTreeMap::new(),
            });
            self.table_by_key.insert(key, new_id);
            new_id
        };
        if let Some(idx) = sample_idx {
            self.tables[id].observed_entries.insert(idx, sample_out);
        }
        id
    }

    fn table_load(
        &mut self,
        base_addr: u64,
        elem_bytes: u8,
        idx: NodeId,
        width: u8,
        sample_idx: Option<u64>,
        sample_out: u64,
    ) -> NodeId {
        let table_id = self.get_or_create_table(base_addr, elem_bytes, sample_idx, sample_out);
        self.intern_node(BvNode::TableLoad {
            table_id,
            idx,
            elem_bytes,
            width,
            sample_idx,
            sample_out: sample_out & width_mask(width),
        })
    }

    fn adapt_width(&mut self, x: NodeId, target_width: u8, signed: bool) -> NodeId {
        let cur = self.width(x);
        if cur == target_width {
            return x;
        }
        if target_width < cur {
            self.unop(BvUnOp::Trunc, x, target_width)
        } else if signed {
            self.unop(BvUnOp::SExt, x, target_width)
        } else {
            self.unop(BvUnOp::ZExt, x, target_width)
        }
    }

    fn extract(&mut self, x: NodeId, lsb: u8, width: u8) -> NodeId {
        let xw = self.width(x);
        if lsb == 0 && width == xw {
            return x;
        }
        if let Some(v) = self.as_const(x) {
            let shifted = if lsb >= 64 { 0 } else { v >> lsb };
            return self.c(shifted & width_mask(width), width);
        }
        if lsb == 0 && width < xw {
            return self.unop(BvUnOp::Trunc, x, width);
        }
        // Extract(ZExt(x), lsb, w) 当切片完全落在原始窄宽度内 -> 直接穿透 ZExt
        if let BvNode::UnOp {
            op: BvUnOp::ZExt,
            x: inner,
            ..
        } = self.get(x).clone()
        {
            let iw = self.width(inner);
            if u16::from(lsb) + u16::from(width) <= u16::from(iw) {
                return self.extract(inner, lsb, width);
            }
        }
        self.intern_node(BvNode::Extract { x, lsb, width })
    }

    fn unop(&mut self, op: BvUnOp, x: NodeId, width: u8) -> NodeId {
        if let Some(v) = self.as_const(x) {
            let xw = self.width(x);
            let res = eval_unop(op, v, xw, width);
            return self.c(res, width);
        }
        match (op, self.get(x).clone()) {
            (BvUnOp::Trunc, BvNode::BinOp { op: BvBinOp::Lshr, a: base, b: sh_id, .. }) => {
                if let Some(sh) = self.as_const(sh_id) {
                    let bw = self.width(base);
                    if sh <= 64 && (sh as u16) + u16::from(width) <= u16::from(bw) {
                        return self.extract(base, sh as u8, width);
                    }
                }
            }
            (BvUnOp::Not, BvNode::UnOp { op: BvUnOp::Not, x: inner, .. })
            | (BvUnOp::Neg, BvNode::UnOp { op: BvUnOp::Neg, x: inner, .. })
            | (BvUnOp::Bswap, BvNode::UnOp { op: BvUnOp::Bswap, x: inner, .. })
            | (BvUnOp::Rbit, BvNode::UnOp { op: BvUnOp::Rbit, x: inner, .. })
                if self.width(inner) == width =>
            {
                return inner;
            }
            (BvUnOp::Trunc, BvNode::UnOp { op: BvUnOp::ZExt | BvUnOp::SExt, x: inner, .. })
                if self.width(inner) == width =>
            {
                return inner;
            }
            (BvUnOp::Trunc, BvNode::UnOp { op: BvUnOp::ZExt | BvUnOp::SExt, x: inner, .. })
                if self.width(inner) > width =>
            {
                return self.unop(BvUnOp::Trunc, inner, width);
            }
            (BvUnOp::ZExt, BvNode::UnOp { op: BvUnOp::ZExt, x: inner, .. }) => {
                return self.unop(BvUnOp::ZExt, inner, width);
            }
            _ => {}
        }
        self.intern_node(BvNode::UnOp { op, x, width })
    }

    fn binop(&mut self, op: BvBinOp, mut a: NodeId, mut b: NodeId, width: u8) -> NodeId {
        a = self.adapt_width(a, width, false);
        b = self.adapt_width(b, width, false);
        if op.is_commutative() {
            // 规范化：常量放右侧；若都不是常量，较小 NodeId 放左侧，大幅提升公共子表达式与 MBA 规则命中率
            let swap = match (self.as_const(a), self.as_const(b)) {
                (Some(_), None) => true,
                (None, Some(_)) => false,
                _ => a > b,
            };
            if swap {
                std::mem::swap(&mut a, &mut b);
            }
        }
        if let (Some(va), Some(vb)) = (self.as_const(a), self.as_const(b)) {
            if let Some(res) = eval_binop(op, va, vb, width) {
                return self.c(res, width);
            }
        }
        let all_ones = width_mask(width);
        // 移位/旋转常量右操作数按 ARM64 语义规约为 mod width（防止 C shift-count-overflow UB）
        if matches!(
            op,
            BvBinOp::Shl | BvBinOp::Lshr | BvBinOp::Ashr | BvBinOp::Ror
        ) {
            if let Some(vb) = self.as_const(b) {
                let w = u64::from(width.max(1));
                let rem = vb % w;
                if rem != vb {
                    b = self.c(rem, width);
                }
            }
        }
        // 基础恒等/吸收律（构造期即化简，防止 DAG 膨胀）
        match (op, self.as_const(b)) {
            (BvBinOp::Add | BvBinOp::Sub | BvBinOp::Or | BvBinOp::Xor | BvBinOp::Shl | BvBinOp::Lshr | BvBinOp::Ashr | BvBinOp::Ror, Some(0)) => {
                return a;
            }
            (BvBinOp::And | BvBinOp::Mul | BvBinOp::UMulh | BvBinOp::SMulh, Some(0)) => {
                return self.c(0, width)
            }
            (BvBinOp::Mul | BvBinOp::UDiv | BvBinOp::SDiv, Some(1)) => return a,
            (BvBinOp::And, Some(v)) if v == all_ones => return a,
            (BvBinOp::And, Some(v)) => {
                // 消除对窄 ZExt 节点的冗余高位掩码（例如 `((uint64_t)(uint8_t)x) & 0xff` -> `(uint64_t)(uint8_t)x`）
                if let BvNode::UnOp {
                    op: BvUnOp::ZExt,
                    x: inner,
                    ..
                } = self.get(a)
                {
                    let imask = width_mask(self.width(*inner));
                    if (v & imask) == imask {
                        return a;
                    }
                }
            }
            (BvBinOp::Or, Some(v)) if v == all_ones => return self.c(all_ones, width),
            _ => {}
        }
        if a == b {
            match op {
                BvBinOp::Sub | BvBinOp::Xor => return self.c(0, width),
                BvBinOp::And | BvBinOp::Or => return a,
                _ => {}
            }
        }
        if op == BvBinOp::Sub && self.as_const(a) == Some(0) {
            return self.unop(BvUnOp::Neg, b, width);
        }
        if op == BvBinOp::Xor && self.as_const(b) == Some(all_ones) {
            return self.unop(BvUnOp::Not, a, width);
        }
        self.intern_node(BvNode::BinOp { op, a, b, width })
    }

    /// 尝试把小端字节序列合并回原始节点（完美消除栈 spill `str w0, [sp, #8]; ldr w1, [sp, #8]`）
    fn concat_le_bytes(&mut self, bytes: &[NodeId]) -> NodeId {
        debug_assert!(matches!(bytes.len(), 1 | 2 | 4 | 8));
        let total_w = (bytes.len() * 8) as u8;
        if bytes.len() == 1 {
            return bytes[0];
        }
        // 快路径 1：全部来自同一个底层节点的连续低位 Extract（栈 spill 零损耗还原！）
        if let Some(orig) = self.detect_contiguous_extract_source(bytes) {
            return self.adapt_width(orig, total_w, false);
        }
        // 快路径 2：全部是常量字节 -> 折叠为单个常量
        if bytes.iter().all(|&b| self.as_const(b).is_some()) {
            let mut acc = 0u64;
            for (i, &b) in bytes.iter().enumerate() {
                acc |= (self.as_const(b).unwrap() & 0xFF) << (i * 8);
            }
            return self.c(acc, total_w);
        }
        // 常规拼装：b[0] | (b[1] << 8) | ...
        let mut acc = self.adapt_width(bytes[0], total_w, false);
        for (i, &b) in bytes.iter().enumerate().skip(1) {
            let ext = self.adapt_width(b, total_w, false);
            let sh = self.c((i * 8) as u64, total_w);
            let shifted = self.binop(BvBinOp::Shl, ext, sh, total_w);
            acc = self.binop(BvBinOp::Or, acc, shifted, total_w);
        }
        acc
    }

    fn detect_contiguous_extract_source(&self, bytes: &[NodeId]) -> Option<NodeId> {
        let (base, base_lsb) = match self.get(bytes[0]) {
            BvNode::Extract { x, lsb, width: 8 } => (*x, *lsb),
            BvNode::UnOp {
                op: BvUnOp::Trunc,
                x,
                width: 8,
            } => (*x, 0),
            _ => return None,
        };
        if base_lsb != 0 || self.width(base) < (bytes.len() * 8) as u8 {
            return None;
        }
        for (i, &bid) in bytes.iter().enumerate().skip(1) {
            let expect_lsb = (i * 8) as u8;
            match self.get(bid) {
                BvNode::Extract {
                    x,
                    lsb,
                    width: 8,
                } if *x == base && *lsb == expect_lsb => {}
                _ => return None,
            }
        }
        Some(base)
    }

    /// 执行不动点代数 / 密码模式 / MBA 反混淆化简，返回化简后的新根节点
    fn simplify_root(&mut self, root: NodeId) -> NodeId {
        let mut cur = root;
        for _ in 0..8 {
            let mut memo = HashMap::new();
            let next = self.simplify_rec(cur, &mut memo);
            if next == cur {
                break;
            }
            cur = next;
        }
        cur
    }

    fn simplify_rec(&mut self, id: NodeId, memo: &mut HashMap<NodeId, NodeId>) -> NodeId {
        if let Some(&res) = memo.get(&id) {
            return res;
        }
        let node = self.get(id).clone();
        let out = match node {
            BvNode::Const { .. } | BvNode::SymReg { .. } | BvNode::SymMemByte { .. } => id,
            BvNode::Extract { x, lsb, width } => {
                let sx = self.simplify_rec(x, memo);
                self.extract(sx, lsb, width)
            }
            BvNode::TableLoad {
                table_id,
                idx,
                elem_bytes,
                width,
                sample_idx,
                sample_out,
            } => {
                let sidx = self.simplify_rec(idx, memo);
                self.intern_node(BvNode::TableLoad {
                    table_id,
                    idx: sidx,
                    elem_bytes,
                    width,
                    sample_idx,
                    sample_out,
                })
            }
            BvNode::AesOp {
                kind,
                state_lo,
                state_hi,
                key_lo,
                key_hi,
                hi_half,
            } => {
                let slo = self.simplify_rec(state_lo, memo);
                let shi = self.simplify_rec(state_hi, memo);
                let klo = key_lo.map(|k| self.simplify_rec(k, memo));
                let khi = key_hi.map(|k| self.simplify_rec(k, memo));
                // 若全部输入为编译期常量，直接常量折叠为精确 64-bit 结果
                if let (Some(vslo), Some(vshi)) = (self.as_const(slo), self.as_const(shi)) {
                    let key_consts = match (klo, khi) {
                        (Some(a), Some(b)) => match (self.as_const(a), self.as_const(b)) {
                            (Some(va), Some(vb)) => Some(Some((va, vb))),
                            _ => None,
                        },
                        (None, None) => Some(None),
                        _ => None,
                    };
                    if let Some(kc) = key_consts {
                        let (rlo, rhi) = eval_aes_op_128(kind, (vslo, vshi), kc);
                        let v = if hi_half { rhi } else { rlo };
                        let out = self.c(v, 64);
                        memo.insert(id, out);
                        return out;
                    }
                }
                self.intern_node(BvNode::AesOp {
                    kind,
                    state_lo: slo,
                    state_hi: shi,
                    key_lo: klo,
                    key_hi: khi,
                    hi_half,
                })
            }
            BvNode::Opaque {
                asm,
                args,
                width,
                sample,
            } => {
                let sargs = args.into_iter().map(|a| self.simplify_rec(a, memo)).collect();
                self.intern_node(BvNode::Opaque {
                    asm,
                    args: sargs,
                    width,
                    sample,
                })
            }
            BvNode::UnOp { op, x, width } => {
                let sx = self.simplify_rec(x, memo);
                // De Morgan 化简：~(~a & ~b) -> a | b；~(~a | ~b) -> a & b
                if op == BvUnOp::Not {
                    if let BvNode::BinOp {
                        op: bop @ (BvBinOp::And | BvBinOp::Or),
                        a,
                        b,
                        width: bw,
                    } = self.get(sx).clone()
                    {
                        if let (
                            BvNode::UnOp { op: BvUnOp::Not, x: na, .. },
                            BvNode::UnOp { op: BvUnOp::Not, x: nb, .. },
                        ) = (self.get(a).clone(), self.get(b).clone())
                        {
                            let dual = if bop == BvBinOp::And {
                                BvBinOp::Or
                            } else {
                                BvBinOp::And
                            };
                            let simplified = self.binop(dual, na, nb, bw);
                            memo.insert(id, simplified);
                            return simplified;
                        }
                    }
                }
                self.unop(op, sx, width)
            }
            BvNode::BinOp { op, a, b, width } => {
                let sa = self.simplify_rec(a, memo);
                let sb = self.simplify_rec(b, memo);
                let rebuilt = self.binop(op, sa, sb, width);
                self.simplify_binop_rules(rebuilt)
            }
        };
        memo.insert(id, out);
        out
    }

    /// 识别是否是 `2 * t`（覆盖 `t << 1`、`t * 2`、`t + t`）
    fn match_twice(&self, id: NodeId) -> Option<NodeId> {
        match self.get(id) {
            BvNode::BinOp { op: BvBinOp::Shl, a, b, .. } if self.as_const(*b) == Some(1) => {
                Some(*a)
            }
            BvNode::BinOp { op: BvBinOp::Mul, a, b, .. } if self.as_const(*b) == Some(2) => {
                Some(*a)
            }
            BvNode::BinOp { op: BvBinOp::Add, a, b, .. } if a == b => Some(*a),
            _ => None,
        }
    }

    fn simplify_binop_rules(&mut self, id: NodeId) -> NodeId {
        let BvNode::BinOp { op, a, b, width } = self.get(id).clone() else {
            return id;
        };
        let na = self.get(a).clone();
        let nb = self.get(b).clone();

        // 1. 结合律常数合并：((x op c1) op c2) -> x op (c1 op c2)
        if let Some(c2) = self.as_const(b) {
            if let BvNode::BinOp {
                op: inner_op,
                a: x,
                b: c1_id,
                ..
            } = na
            {
                if let Some(c1) = self.as_const(c1_id) {
                    match (op, inner_op) {
                        (BvBinOp::Add, BvBinOp::Add) => {
                            let c = self.c(c1.wrapping_add(c2), width);
                            return self.binop(BvBinOp::Add, x, c, width);
                        }
                        (BvBinOp::Add, BvBinOp::Sub) => {
                            let c = self.c(c2.wrapping_sub(c1), width);
                            return self.binop(BvBinOp::Add, x, c, width);
                        }
                        (BvBinOp::Sub, BvBinOp::Add) => {
                            let c = self.c(c1.wrapping_sub(c2), width);
                            return self.binop(BvBinOp::Add, x, c, width);
                        }
                        (BvBinOp::Sub, BvBinOp::Sub) => {
                            let c = self.c(c1.wrapping_add(c2), width);
                            return self.binop(BvBinOp::Sub, x, c, width);
                        }
                        (BvBinOp::Xor, BvBinOp::Xor) => {
                            let c = self.c(c1 ^ c2, width);
                            return self.binop(BvBinOp::Xor, x, c, width);
                        }
                        (BvBinOp::And, BvBinOp::And) => {
                            let c = self.c(c1 & c2, width);
                            return self.binop(BvBinOp::And, x, c, width);
                        }
                        (BvBinOp::Or, BvBinOp::Or) => {
                            let c = self.c(c1 | c2, width);
                            return self.binop(BvBinOp::Or, x, c, width);
                        }
                        (BvBinOp::Shl, BvBinOp::Shl)
                        | (BvBinOp::Lshr, BvBinOp::Lshr)
                            if c1.saturating_add(c2) < u64::from(width) =>
                        {
                            let c = self.c(c1 + c2, width);
                            return self.binop(op, x, c, width);
                        }
                        (BvBinOp::Ror, BvBinOp::Ror) => {
                            let w = u64::from(width.max(1));
                            let c = self.c(((c1 % w) + (c2 % w)) % w, width);
                            return self.binop(BvBinOp::Ror, x, c, width);
                        }
                        _ => {}
                    }
                }
            }
            // (~a) + 1 -> -a ; (-a) - 1 -> ~a
            if op == BvBinOp::Add && c2 == 1 {
                if let BvNode::UnOp { op: BvUnOp::Not, x, .. } = na {
                    return self.unop(BvUnOp::Neg, x, width);
                }
            }
            if op == BvBinOp::Sub && c2 == 1 {
                if let BvNode::UnOp { op: BvUnOp::Neg, x, .. } = na {
                    return self.unop(BvUnOp::Not, x, width);
                }
            }
        }

        // 2. XOR 自消去：(x ^ y) ^ y -> x ；a + (-b) -> a - b ；a - (-b) -> a + b
        if op == BvBinOp::Xor {
            if let BvNode::BinOp { op: BvBinOp::Xor, a: x, b: y, .. } = na {
                if y == b {
                    return x;
                }
                if x == b {
                    return y;
                }
            }
            if let BvNode::BinOp { op: BvBinOp::Xor, a: x, b: y, .. } = nb {
                if y == a {
                    return x;
                }
                if x == a {
                    return y;
                }
            }
        }
        if op == BvBinOp::Add {
            if let BvNode::UnOp { op: BvUnOp::Neg, x, .. } = nb {
                return self.binop(BvBinOp::Sub, a, x, width);
            }
            if let BvNode::UnOp { op: BvUnOp::Neg, x, .. } = na {
                return self.binop(BvBinOp::Sub, b, x, width);
            }
        }
        if op == BvBinOp::Sub {
            if let BvNode::UnOp { op: BvUnOp::Neg, x, .. } = nb {
                return self.binop(BvBinOp::Add, a, x, width);
            }
        }

        // 3. 循环移位识别（密码学核心模式）：(x >> k) | (x << (w - k)) 或 ^ -> ROTR(x, k)
        if matches!(op, BvBinOp::Or | BvBinOp::Xor) && matches!(width, 32 | 64) {
            if let Some((x, rot)) = self.match_rotate(&na, &nb, width)
                .or_else(|| self.match_rotate(&nb, &na, width))
            {
                let c = self.c(rot, width);
                return self.binop(BvBinOp::Ror, x, c, width);
            }
        }

        // 4. 经典 MBA (Mixed Boolean-Arithmetic) 反混淆恒等式（支持双向交换匹配）
        match op {
            BvBinOp::Add => {
                // MBA-1: (x ^ y) + 2*(x & y) -> x + y
                for (lhs, rhs) in [(a, b), (b, a)] {
                    if let (
                        BvNode::BinOp { op: BvBinOp::Xor, a: x1, b: y1, .. },
                        Some(twice_inner),
                    ) = (self.get(lhs).clone(), self.match_twice(rhs))
                    {
                        if let BvNode::BinOp { op: BvBinOp::And, a: x2, b: y2, .. } =
                            self.get(twice_inner).clone()
                        {
                            if (x1 == x2 && y1 == y2) || (x1 == y2 && y1 == x2) {
                                return self.binop(BvBinOp::Add, x1, y1, width);
                            }
                        }
                    }
                    // MBA-2: (x | y) + (x & y) -> x + y
                    if let (
                        BvNode::BinOp { op: BvBinOp::Or, a: x1, b: y1, .. },
                        BvNode::BinOp { op: BvBinOp::And, a: x2, b: y2, .. },
                    ) = (self.get(lhs).clone(), self.get(rhs).clone())
                    {
                        if (x1 == x2 && y1 == y2) || (x1 == y2 && y1 == x2) {
                            return self.binop(BvBinOp::Add, x1, y1, width);
                        }
                    }
                }
            }
            BvBinOp::Sub => {
                // MBA-3: 2*(x | y) - (x ^ y) -> x + y
                if let (
                    Some(twice_inner),
                    BvNode::BinOp { op: BvBinOp::Xor, a: x2, b: y2, .. },
                ) = (self.match_twice(a), nb.clone())
                {
                    if let BvNode::BinOp { op: BvBinOp::Or, a: x1, b: y1, .. } =
                        self.get(twice_inner).clone()
                    {
                        if (x1 == x2 && y1 == y2) || (x1 == y2 && y1 == x2) {
                            return self.binop(BvBinOp::Add, x1, y1, width);
                        }
                    }
                }
                // MBA-4: (x | y) - (x & y) -> x ^ y
                if let (
                    BvNode::BinOp { op: BvBinOp::Or, a: x1, b: y1, .. },
                    BvNode::BinOp { op: BvBinOp::And, a: x2, b: y2, .. },
                ) = (na.clone(), nb.clone())
                {
                    if (x1 == x2 && y1 == y2) || (x1 == y2 && y1 == x2) {
                        return self.binop(BvBinOp::Xor, x1, y1, width);
                    }
                }
                // MBA-5: (x + y) - 2*(x & y) -> x ^ y
                if let (
                    BvNode::BinOp { op: BvBinOp::Add, a: x1, b: y1, .. },
                    Some(twice_inner),
                ) = (na.clone(), self.match_twice(b))
                {
                    if let BvNode::BinOp { op: BvBinOp::And, a: x2, b: y2, .. } =
                        self.get(twice_inner).clone()
                    {
                        if (x1 == x2 && y1 == y2) || (x1 == y2 && y1 == x2) {
                            return self.binop(BvBinOp::Xor, x1, y1, width);
                        }
                    }
                }
                // MBA-6: (x ^ y) - 2*(~x & y) -> x - y
                if let (
                    BvNode::BinOp { op: BvBinOp::Xor, a: x1, b: y1, .. },
                    Some(twice_inner),
                ) = (na.clone(), self.match_twice(b))
                {
                    if let Some((not_arg, other)) = self.match_and_not(twice_inner) {
                        if not_arg == x1 && other == y1 {
                            return self.binop(BvBinOp::Sub, x1, y1, width);
                        }
                        if not_arg == y1 && other == x1 {
                            return self.binop(BvBinOp::Sub, y1, x1, width);
                        }
                    }
                }
                // MBA-7: (x & ~y) - (~x & y) -> x - y
                if let (Some((ny, x1)), Some((nx, y1))) =
                    (self.match_and_not(a), self.match_and_not(b))
                {
                    if nx == x1 && ny == y1 {
                        return self.binop(BvBinOp::Sub, x1, y1, width);
                    }
                }
                // MBA-8: (x | y) - y -> x & ~y
                if let BvNode::BinOp { op: BvBinOp::Or, a: x1, b: y1, .. } = na.clone() {
                    if y1 == b {
                        let nb_not = self.unop(BvUnOp::Not, y1, width);
                        return self.binop(BvBinOp::And, x1, nb_not, width);
                    }
                    if x1 == b {
                        let nb_not = self.unop(BvUnOp::Not, x1, width);
                        return self.binop(BvBinOp::And, y1, nb_not, width);
                    }
                }
            }
            BvBinOp::Or => {
                // 0. 字节重装恒等式（消除 VM/按字节拆装噪声）：
                //    (uint64_t)(uint8_t)x | ((uint64_t)(uint8_t)(x>>8) << 8) | ... -> x（反序 -> BSWAP(x)）
                if matches!(width, 16 | 32 | 64) {
                    if let Some(collapsed) = self.try_collapse_byte_reassembly(id, width) {
                        return collapsed;
                    }
                }
                // 分配吸收：(a & b) | (a & ~b) -> a
                if let (
                    BvNode::BinOp { op: BvBinOp::And, a: x1, b: y1, .. },
                    Some((not_part, keep_part)),
                ) = (na.clone(), self.match_and_not(b))
                {
                    if (keep_part == x1 && not_part == y1) || (keep_part == y1 && not_part == x1) {
                        return keep_part;
                    }
                }
                if let (
                    BvNode::BinOp { op: BvBinOp::And, a: x1, b: y1, .. },
                    Some((not_part, keep_part)),
                ) = (nb.clone(), self.match_and_not(a))
                {
                    if (keep_part == x1 && not_part == y1) || (keep_part == y1 && not_part == x1) {
                        return keep_part;
                    }
                }
            }
            _ => {}
        }

        id
    }

    /// 扁平化 `Or` 树并识别「把同一标量按字节拆开再左移拼回」的字节重装模式（顺序 -> `base`，逆序 -> `Bswap(base)`）
    fn try_collapse_byte_reassembly(&mut self, root_or: NodeId, width: u8) -> Option<NodeId> {
        let num_bytes = (width / 8) as usize;
        let mut terms = Vec::with_capacity(num_bytes);
        let mut stack = vec![root_or];
        while let Some(cur) = stack.pop() {
            if let BvNode::BinOp {
                op: BvBinOp::Or,
                a,
                b,
                width: w,
            } = self.get(cur)
            {
                if *w == width {
                    stack.push(*b);
                    stack.push(*a);
                    continue;
                }
            }
            terms.push(cur);
            if terms.len() > num_bytes {
                return None;
            }
        }
        if terms.len() != num_bytes {
            return None;
        }

        // 解析每一项提取出的 `(base, src_byte_lane, dst_byte_lane)`
        let mut base_id: Option<NodeId> = None;
        let mut lane_map: Vec<Option<usize>> = vec![None; num_bytes];
        for term in terms {
            let (base, src_lane, dst_lane) = self.match_byte_lane_term(term, width)?;
            if src_lane >= num_bytes || dst_lane >= num_bytes || lane_map[dst_lane].is_some() {
                return None;
            }
            match base_id {
                None => base_id = Some(base),
                Some(b) if b != base => return None,
                Some(_) => {}
            }
            lane_map[dst_lane] = Some(src_lane);
        }
        let base = base_id?;
        if self.width(base) < width {
            return None;
        }
        let is_identity = (0..num_bytes).all(|i| lane_map[i] == Some(i));
        if is_identity {
            return Some(self.adapt_width(base, width, false));
        }
        let is_reverse = (0..num_bytes).all(|i| lane_map[i] == Some(num_bytes - 1 - i));
        if is_reverse {
            let adapted = self.adapt_width(base, width, false);
            return Some(self.unop(BvUnOp::Bswap, adapted, width));
        }
        None
    }

    /// 匹配单个字节重装项，返回 `(base, src_byte_lane, dst_byte_lane)`
    fn match_byte_lane_term(&self, id: NodeId, width: u8) -> Option<(NodeId, usize, usize)> {
        // 情况 A：`base & (0xff << (8*k))`（原位掩码，k >= 1；k == 0 即 `& 0xff` 留给情况 B 以便解开 `(x >> 24) & 0xff` 这类 BSWAP）
        if let BvNode::BinOp {
            op: BvBinOp::And,
            a,
            b,
            ..
        } = self.get(id)
        {
            if let Some(mask) = self.as_const(*b) {
                for k in 1..(usize::from(width) / 8) {
                    if mask == (0xFFu64 << (k * 8)) {
                        return Some((*a, k, k));
                    }
                }
            }
        }
        // 情况 B：`Shl(inner, 8*dst_lane)` 或直接 `dst_lane = 0` 的 `inner`
        let (inner, dst_lane) = match self.get(id) {
            BvNode::BinOp {
                op: BvBinOp::Shl,
                a,
                b,
                ..
            } => {
                let sh = self.as_const(*b)?;
                if !sh.is_multiple_of(8) || sh >= u64::from(width) {
                    return None;
                }
                (*a, (sh / 8) as usize)
            }
            _ => (id, 0usize),
        };
        let (base, src_lane) = self.extract_byte_lane_source(inner)?;
        Some((base, src_lane, dst_lane))
    }

    fn extract_byte_lane_source(&self, id: NodeId) -> Option<(NodeId, usize)> {
        match self.get(id) {
            BvNode::UnOp {
                op: BvUnOp::ZExt,
                x,
                ..
            } => self.extract_byte_lane_source(*x),
            BvNode::Extract {
                x,
                lsb,
                width: 8,
            } if lsb.is_multiple_of(8) => Some((*x, (*lsb / 8) as usize)),
            BvNode::UnOp {
                op: BvUnOp::Trunc,
                x,
                width: 8,
            } => {
                if let BvNode::BinOp {
                    op: BvBinOp::Lshr,
                    a,
                    b,
                    ..
                } = self.get(*x)
                {
                    let sh = self.as_const(*b)?;
                    if sh.is_multiple_of(8) {
                        return Some((*a, (sh / 8) as usize));
                    }
                }
                Some((*x, 0))
            }
            BvNode::BinOp {
                op: BvBinOp::And,
                a,
                b,
                ..
            } if self.as_const(*b) == Some(0xFF) => {
                if let BvNode::BinOp {
                    op: BvBinOp::Lshr,
                    a: base,
                    b: sh_id,
                    ..
                } = self.get(*a)
                {
                    let sh = self.as_const(*sh_id)?;
                    if sh.is_multiple_of(8) {
                        return Some((*base, (sh / 8) as usize));
                    }
                }
                Some((*a, 0))
            }
            _ => None,
        }
    }

    fn match_rotate(&self, rshift: &BvNode, lshift: &BvNode, width: u8) -> Option<(NodeId, u64)> {
        if let (
            BvNode::BinOp { op: BvBinOp::Lshr, a: x1, b: k1, .. },
            BvNode::BinOp { op: BvBinOp::Shl, a: x2, b: k2, .. },
        ) = (rshift, lshift)
        {
            if x1 == x2 {
                if let (Some(rk), Some(lk)) = (self.as_const(*k1), self.as_const(*k2)) {
                    let w = u64::from(width);
                    if rk > 0 && lk > 0 && rk < w && lk < w && rk + lk == w {
                        return Some((*x1, rk));
                    }
                }
            }
        }
        None
    }

    /// 匹配 `(~not_arg) & other` 或 `other & (~not_arg)`，返回 `(not_arg, other)`
    fn match_and_not(&self, id: NodeId) -> Option<(NodeId, NodeId)> {
        let BvNode::BinOp { op: BvBinOp::And, a, b, .. } = self.get(id) else {
            return None;
        };
        if let BvNode::UnOp { op: BvUnOp::Not, x, .. } = self.get(*a) {
            return Some((*x, *b));
        }
        if let BvNode::UnOp { op: BvUnOp::Not, x, .. } = self.get(*b) {
            return Some((*x, *a));
        }
        None
    }

    /// 统计从一组 `roots` 可达的节点并集数
    fn count_reachable_many(&self, roots: &[NodeId]) -> usize {
        let mut vis = HashSet::new();
        for &r in roots {
            self.visit_reachable(r, &mut vis);
        }
        vis.len()
    }

    fn visit_reachable(&self, id: NodeId, vis: &mut HashSet<NodeId>) {
        if !vis.insert(id) {
            return;
        }
        match self.get(id) {
            BvNode::Const { .. } | BvNode::SymReg { .. } | BvNode::SymMemByte { .. } => {}
            BvNode::UnOp { x, .. } | BvNode::Extract { x, .. } => self.visit_reachable(*x, vis),
            BvNode::BinOp { a, b, .. } => {
                self.visit_reachable(*a, vis);
                self.visit_reachable(*b, vis);
            }
            BvNode::TableLoad { idx, .. } => self.visit_reachable(*idx, vis),
            BvNode::AesOp {
                state_lo,
                state_hi,
                key_lo,
                key_hi,
                ..
            } => {
                self.visit_reachable(*state_lo, vis);
                self.visit_reachable(*state_hi, vis);
                if let Some(k) = key_lo {
                    self.visit_reachable(*k, vis);
                }
                if let Some(k) = key_hi {
                    self.visit_reachable(*k, vis);
                }
            }
            BvNode::Opaque { args, .. } => {
                for &a in args {
                    self.visit_reachable(a, vis);
                }
            }
        }
    }

    /// 用 Trace 中录制的具体样本值对 DAG 求值（用于 `verified` 逐 bit 自校验）
    fn eval_sample(&self, root: NodeId) -> Option<u64> {
        let mut memo = HashMap::new();
        self.eval_sample_rec(root, &mut memo)
    }

    fn eval_sample_rec(&self, id: NodeId, memo: &mut HashMap<NodeId, Option<u64>>) -> Option<u64> {
        if let Some(&res) = memo.get(&id) {
            return res;
        }
        let res = match self.get(id) {
            BvNode::Const { val, .. } => Some(*val),
            BvNode::SymReg { sample, .. } => *sample,
            BvNode::SymMemByte { sample, .. } => sample.map(u64::from),
            BvNode::UnOp { op, x, width } => {
                let vx = self.eval_sample_rec(*x, memo)?;
                Some(eval_unop(*op, vx, self.width(*x), *width))
            }
            BvNode::BinOp { op, a, b, width } => {
                let va = self.eval_sample_rec(*a, memo)?;
                let vb = self.eval_sample_rec(*b, memo)?;
                eval_binop(*op, va, vb, *width)
            }
            BvNode::Extract { x, lsb, width } => {
                let vx = self.eval_sample_rec(*x, memo)?;
                let shifted = if *lsb >= 64 { 0 } else { vx >> *lsb };
                Some(shifted & width_mask(*width))
            }
            BvNode::TableLoad {
                table_id,
                idx,
                width,
                ..
            } => {
                let vidx = self.eval_sample_rec(*idx, memo)?;
                // 严禁回退到 sample_out 掩盖索引错误：必须在已观测表项中精确命中
                let v = self.tables[*table_id].observed_entries.get(&vidx).copied()?;
                Some(v & width_mask(*width))
            }
            BvNode::AesOp {
                kind,
                state_lo,
                state_hi,
                key_lo,
                key_hi,
                hi_half,
            } => {
                let vslo = self.eval_sample_rec(*state_lo, memo)?;
                let vshi = self.eval_sample_rec(*state_hi, memo)?;
                let kv = match (key_lo, key_hi) {
                    (Some(kl), Some(kh)) => {
                        Some((self.eval_sample_rec(*kl, memo)?, self.eval_sample_rec(*kh, memo)?))
                    }
                    _ => None,
                };
                let (rlo, rhi) = eval_aes_op_128(*kind, (vslo, vshi), kv);
                Some(if *hi_half { rhi } else { rlo })
            }
            // 含未建模 Opaque 指令时绝不可返回 Some(sample) 制造假阳性 verified == Some(true)
            BvNode::Opaque { .. } => None,
        };
        memo.insert(id, res);
        res
    }
}

fn eval_unop(op: BvUnOp, v: u64, from_w: u8, to_w: u8) -> u64 {
    let m = width_mask(to_w);
    match op {
        BvUnOp::Not => (!v) & m,
        BvUnOp::Neg => v.wrapping_neg() & m,
        BvUnOp::Bswap => match to_w {
            16 => u64::from((v as u16).swap_bytes()),
            32 => u64::from((v as u32).swap_bytes()),
            64 => v.swap_bytes(),
            _ => v & m,
        },
        BvUnOp::Rbit => match to_w {
            0 => 0,
            32 => u64::from((v as u32).reverse_bits()),
            64 => v.reverse_bits(),
            _ => (v.reverse_bits() >> (64 - to_w)) & m,
        },
        BvUnOp::Clz => match to_w {
            0 => 0,
            32 => u64::from((v as u32).leading_zeros()),
            64 => u64::from(v.leading_zeros()),
            _ => u64::from(((v & m) << (64 - to_w)).leading_zeros().min(u32::from(to_w))),
        },
        BvUnOp::ZExt | BvUnOp::Trunc => (v & width_mask(from_w)) & m,
        BvUnOp::SExt => sign_extend_u64(v, from_w, to_w),
    }
}

fn eval_binop(op: BvBinOp, a: u64, b: u64, width: u8) -> Option<u64> {
    let m = width_mask(width);
    let a = a & m;
    let b = b & m;
    let sh = (b as u32) % u32::from(width.max(1));
    let res = match op {
        BvBinOp::Add => a.wrapping_add(b) & m,
        BvBinOp::Sub => a.wrapping_sub(b) & m,
        BvBinOp::Mul => a.wrapping_mul(b) & m,
        BvBinOp::UMulh => ((u128::from(a) * u128::from(b)) >> 64) as u64 & m,
        BvBinOp::SMulh => {
            let sa = i128::from(a as i64);
            let sb = i128::from(b as i64);
            ((sa * sb) >> 64) as u64 & m
        }
        BvBinOp::UDiv => a.checked_div(b).unwrap_or(0) & m,
        BvBinOp::SDiv => {
            if width == 32 {
                let sa = a as u32 as i32;
                let sb = b as u32 as i32;
                if sb == 0 {
                    0
                } else {
                    (sa.wrapping_div(sb) as u32) as u64
                }
            } else {
                let sa = a as i64;
                let sb = b as i64;
                if sb == 0 {
                    0
                } else {
                    sa.wrapping_div(sb) as u64
                }
            }
        }
        BvBinOp::And => (a & b) & m,
        BvBinOp::Or => (a | b) & m,
        BvBinOp::Xor => (a ^ b) & m,
        BvBinOp::Shl => a.wrapping_shl(sh) & m,
        BvBinOp::Lshr => a.wrapping_shr(sh) & m,
        BvBinOp::Ashr => {
            if width == 32 {
                (((a as u32 as i32).wrapping_shr(sh)) as u32) as u64
            } else if width == 64 {
                ((a as i64).wrapping_shr(sh)) as u64
            } else {
                let s = sign_extend_u64(a, width, 64) as i64;
                (s.wrapping_shr(sh) as u64) & m
            }
        }
        BvBinOp::Ror => {
            if width == 32 {
                u64::from((a as u32).rotate_right(sh))
            } else if width == 64 {
                a.rotate_right(sh)
            } else if sh == 0 {
                a
            } else {
                ((a >> sh) | (a << (u32::from(width) - sh))) & m
            }
        }
    };
    Some(res)
}

// ── FIPS-197 AES-128 单轮原语求值（严格匹配 ARMv8-CE AESE/AESD/AESMC/AESIMC 语义） ──

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

#[inline]
fn aes_xtime(x: u8) -> u8 {
    (x << 1) ^ if (x & 0x80) != 0 { 0x1b } else { 0 }
}

#[inline]
fn aes_gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        a = aes_xtime(a);
        b >>= 1;
    }
    p
}

fn eval_aes_op_128(kind: AesOpKind, state: (u64, u64), key: Option<(u64, u64)>) -> (u64, u64) {
    let mut s = [0u8; 16];
    s[0..8].copy_from_slice(&state.0.to_le_bytes());
    s[8..16].copy_from_slice(&state.1.to_le_bytes());
    let mut out = [0u8; 16];
    match kind {
        AesOpKind::Aese => {
            if let Some((klo, khi)) = key {
                let mut k = [0u8; 16];
                k[0..8].copy_from_slice(&klo.to_le_bytes());
                k[8..16].copy_from_slice(&khi.to_le_bytes());
                for i in 0..16 {
                    s[i] ^= k[i];
                }
            }
            for c in 0..4 {
                for r in 0..4 {
                    out[c * 4 + r] = AES_SBOX[s[((c + r) % 4) * 4 + r] as usize];
                }
            }
        }
        AesOpKind::Aesd => {
            if let Some((klo, khi)) = key {
                let mut k = [0u8; 16];
                k[0..8].copy_from_slice(&klo.to_le_bytes());
                k[8..16].copy_from_slice(&khi.to_le_bytes());
                for i in 0..16 {
                    s[i] ^= k[i];
                }
            }
            for c in 0..4 {
                for r in 0..4 {
                    out[c * 4 + r] = AES_INV_SBOX[s[((c + 4 - r) % 4) * 4 + r] as usize];
                }
            }
        }
        AesOpKind::Aesmc => {
            for c in 0..4 {
                let b = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
                out[c * 4] = aes_gmul(b[0], 2) ^ aes_gmul(b[1], 3) ^ b[2] ^ b[3];
                out[c * 4 + 1] = b[0] ^ aes_gmul(b[1], 2) ^ aes_gmul(b[2], 3) ^ b[3];
                out[c * 4 + 2] = b[0] ^ b[1] ^ aes_gmul(b[2], 2) ^ aes_gmul(b[3], 3);
                out[c * 4 + 3] = aes_gmul(b[0], 3) ^ b[1] ^ b[2] ^ aes_gmul(b[3], 2);
            }
        }
        AesOpKind::Aesimc => {
            for c in 0..4 {
                let b = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
                out[c * 4] = aes_gmul(b[0], 0x0e)
                    ^ aes_gmul(b[1], 0x0b)
                    ^ aes_gmul(b[2], 0x0d)
                    ^ aes_gmul(b[3], 0x09);
                out[c * 4 + 1] = aes_gmul(b[0], 0x09)
                    ^ aes_gmul(b[1], 0x0e)
                    ^ aes_gmul(b[2], 0x0b)
                    ^ aes_gmul(b[3], 0x0d);
                out[c * 4 + 2] = aes_gmul(b[0], 0x0d)
                    ^ aes_gmul(b[1], 0x09)
                    ^ aes_gmul(b[2], 0x0e)
                    ^ aes_gmul(b[3], 0x0b);
                out[c * 4 + 3] = aes_gmul(b[0], 0x0b)
                    ^ aes_gmul(b[1], 0x0d)
                    ^ aes_gmul(b[2], 0x09)
                    ^ aes_gmul(b[3], 0x0e);
            }
        }
    }
    let lo = u64::from_le_bytes(out[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(out[8..16].try_into().unwrap());
    (lo, hi)
}

// ============================================================================
// 3. 单路径符号提升引擎（Trace + TaintSlice -> BvArena）
// ============================================================================

struct SliceLifter<'a> {
    reader: &'a TraceReader,
    arena: BvArena,
    /// 当前各寄存器槽位的符号表达式（0..32 为 GPR X0..SP，32..64 为向量寄存器 V0..V31 低 64 位）
    sym_regs: [Option<NodeId>; 64],
    /// 向量寄存器 V0..V31 的高 64 位符号表达式（用于 128-bit NEON / ARMv8-CE AES 精确提升）
    sym_vec_hi: [Option<NodeId>; 32],
    /// 当前各寄存器槽位的最新具体值（来自 `initial_regs` 与前向 `reg_deltas`）
    concrete_regs: [Option<u64>; 64],
    /// 字节粒度符号内存（`addr -> 8-bit NodeId`）
    sym_mem: HashMap<u64, NodeId>,
    /// 切片起始点处受污点的输入寄存器集合（从 `taint_backward` 溯源得出）
    origin_regs: HashSet<u8>,
    /// 切片起始点处受污点的输入内存地址集合
    origin_mem_addrs: HashSet<u64>,
    /// 整个 Trace 中曾被写入过的内存字节集合（用于 `--fold-rodata` 区分只读 `.rodata`/字节码 与可写缓冲）
    ever_written_mem: HashSet<u64>,
    /// 用户显式钉死为符号输入的内存区间（优先级高于 `fold_rodata`）
    stop_mem_ranges: Vec<(u64, usize)>,
    fold_rodata: bool,
    track_sp: bool,
    entropy_counter: usize,
}

impl<'a> SliceLifter<'a> {
    fn new(
        reader: &'a TraceReader,
        origin_regs: HashSet<u8>,
        origin_mem_addrs: HashSet<u64>,
        stop_mem_ranges: Vec<(u64, usize)>,
        fold_rodata: bool,
        initial_regs: &HashMap<u8, u64>,
        track_sp: bool,
    ) -> Self {
        let mut concrete_regs = [None; 64];
        for (&slot, &val) in initial_regs {
            if (slot as usize) < 64 {
                concrete_regs[slot as usize] = Some(val);
            }
        }
        Self {
            reader,
            arena: BvArena::default(),
            sym_regs: [None; 64],
            sym_vec_hi: [None; 32],
            concrete_regs,
            sym_mem: HashMap::new(),
            origin_regs,
            origin_mem_addrs,
            ever_written_mem: HashSet::new(),
            stop_mem_ranges,
            fold_rodata,
            track_sp,
            entropy_counter: 0,
        }
    }

    fn is_stop_mem(&self, addr: u64) -> bool {
        self.stop_mem_ranges
            .iter()
            .any(|&(s, l)| addr >= s && addr < s.saturating_add(l as u64))
    }

    fn alloc_entropy_sym(&mut self, op: &str, width: u8, sample: Option<u64>) -> NodeId {
        let idx = self.entropy_counter;
        self.entropy_counter += 1;
        let prefix = match op {
            "rand" | "random" | "lrand48" | "arc4random" | "getrandom" => "rand",
            "gettimeofday" | "clock_gettime" | "time" => "time",
            _ => "ext",
        };
        // 64..96 保留给向量高 64 位寄存器 arg_vN_hi，96..255 分配给外部熵源/时钟源 HLE 符号
        let pseudo_slot = (96 + (idx % 159)) as u8;
        self.arena.intern_node(BvNode::SymReg {
            reg_slot: pseudo_slot,
            name: format!("{prefix}_{idx}"),
            width,
            sample: sample.map(|v| v & width_mask(width)),
        })
    }

    fn update_concrete_from_step(&mut self, idx: usize) {
        for (reg_id, val) in self.reader.reg_deltas_for(idx) {
            if (reg_id as usize) < 64 {
                self.concrete_regs[reg_id as usize] = Some(val);
            }
        }
    }

    fn reg_expr(&mut self, reg: Reg, req_width: u8) -> NodeId {
        let name = reg.name();
        if matches!(name, "xzr" | "wzr") {
            return self.arena.c(0, req_width);
        }
        let Some(slot) = parse_reg_slot(name) else {
            return self.arena.c(0, req_width);
        };
        if slot == 31 && !self.track_sp {
            let v = self.concrete_regs[31].unwrap_or(0);
            return self.arena.c(v, req_width);
        }
        if let Some(sym) = self.sym_regs[slot as usize] {
            return self.arena.adapt_width(sym, req_width, false);
        }
        if self.origin_regs.contains(&slot) {
            let sample = self.concrete_regs[slot as usize];
            // 统一以 64 位架构全宽建立初始符号寄存器，防止先读 W0 后读 X0 丢失高 32 位
            let node64 = self.arena.sym_reg(slot, 64, sample);
            self.sym_regs[slot as usize] = Some(node64);
            return self.arena.adapt_width(node64, req_width, false);
        }
        // 非污点寄存器 -> 代入精确具体值；若尚未观测到则退化为 64 位符号寄存器参数避免静默变 0
        if let Some(v) = self.concrete_regs[slot as usize] {
            self.arena.c(v, req_width)
        } else {
            let node64 = self.arena.sym_reg(slot, 64, None);
            self.sym_regs[slot as usize] = Some(node64);
            self.arena.adapt_width(node64, req_width, false)
        }
    }

    fn apply_shift_or_extend(&mut self, val: NodeId, shift: Shift, width: u8) -> NodeId {
        match shift {
            Shift::LSL(amt) => {
                if amt == 0 {
                    val
                } else {
                    let c = self.arena.c(u64::from(amt), width);
                    self.arena.binop(BvBinOp::Shl, val, c, width)
                }
            }
            Shift::LSR(amt) => {
                if amt == 0 {
                    val
                } else {
                    let c = self.arena.c(u64::from(amt), width);
                    self.arena.binop(BvBinOp::Lshr, val, c, width)
                }
            }
            Shift::ASR(amt) => {
                if amt == 0 {
                    val
                } else {
                    let c = self.arena.c(u64::from(amt), width);
                    self.arena.binop(BvBinOp::Ashr, val, c, width)
                }
            }
            Shift::ROR(amt) => {
                if amt == 0 {
                    val
                } else {
                    let c = self.arena.c(u64::from(amt), width);
                    self.arena.binop(BvBinOp::Ror, val, c, width)
                }
            }
            Shift::UXTB(amt) => {
                let t = self.arena.adapt_width(val, 8, false);
                let e = self.arena.adapt_width(t, width, false);
                self.apply_shift_or_extend(e, Shift::LSL(amt), width)
            }
            Shift::UXTH(amt) => {
                let t = self.arena.adapt_width(val, 16, false);
                let e = self.arena.adapt_width(t, width, false);
                self.apply_shift_or_extend(e, Shift::LSL(amt), width)
            }
            Shift::UXTW(amt) => {
                let t = self.arena.adapt_width(val, 32, false);
                let e = self.arena.adapt_width(t, width, false);
                self.apply_shift_or_extend(e, Shift::LSL(amt), width)
            }
            Shift::UXTX(amt) => self.apply_shift_or_extend(val, Shift::LSL(amt), width),
            Shift::SXTB(amt) => {
                let t = self.arena.adapt_width(val, 8, false);
                let e = self.arena.adapt_width(t, width, true);
                self.apply_shift_or_extend(e, Shift::LSL(amt), width)
            }
            Shift::SXTH(amt) => {
                let t = self.arena.adapt_width(val, 16, false);
                let e = self.arena.adapt_width(t, width, true);
                self.apply_shift_or_extend(e, Shift::LSL(amt), width)
            }
            Shift::SXTW(amt) => {
                let t = self.arena.adapt_width(val, 32, false);
                let e = self.arena.adapt_width(t, width, true);
                self.apply_shift_or_extend(e, Shift::LSL(amt), width)
            }
            Shift::SXTX(amt) => self.apply_shift_or_extend(val, Shift::LSL(amt), width),
            Shift::MSL(amt) => {
                let c = self.arena.c(u64::from(amt), width);
                let sh = self.arena.binop(BvBinOp::Shl, val, c, width);
                let ones = self.arena.c(width_mask(amt as u8), width);
                self.arena.binop(BvBinOp::Or, sh, ones, width)
            }
        }
    }

    fn operand_expr(&mut self, op: &Operand, width: u8) -> Option<NodeId> {
        match op {
            Operand::Reg { reg, .. } => Some(self.reg_expr(*reg, width)),
            Operand::ShiftReg { reg, shift } => {
                let base_w = (reg.size() * 8).clamp(32, 64) as u8;
                let v = self.reg_expr(*reg, base_w);
                let v = self.arena.adapt_width(v, width, false);
                Some(self.apply_shift_or_extend(v, *shift, width))
            }
            Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift } => {
                let raw = imm_to_u64(*imm);
                let val = match shift {
                    Some(Shift::LSL(s)) => raw.wrapping_shl(*s),
                    _ => raw,
                };
                Some(self.arena.c(val, width))
            }
            Operand::Label(imm) => Some(self.arena.c(imm_to_u64(*imm), width)),
            _ => None,
        }
    }

    fn operand_imm_u64(op: &Operand) -> Option<u64> {
        match op {
            Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift } => {
                let raw = imm_to_u64(*imm);
                Some(match shift {
                    Some(Shift::LSL(s)) => raw.wrapping_shl(*s),
                    _ => raw,
                })
            }
            Operand::Label(imm) => Some(imm_to_u64(*imm)),
            _ => None,
        }
    }

    fn set_reg(&mut self, reg: Reg, expr: NodeId) {
        if matches!(reg.name(), "xzr" | "wzr") {
            return;
        }
        let Some(slot) = parse_reg_slot(reg.name()) else {
            return;
        };
        if slot == 31 && !self.track_sp {
            return;
        }
        let reg_w = (reg.size() * 8).clamp(32, 64) as u8;
        let adapted = self.arena.adapt_width(expr, reg_w, false);
        // 写 Wd 自动零扩展到 64 位，但保留 32 位自然宽度便于后续 32 位运算保持干净
        self.sym_regs[slot as usize] = Some(adapted);
        // ARM64 语义：写标量 FP/SIMD 寄存器 (Dn/Sn/Hn/Bn) 自动清零 Vn 高 64 位
        if let Some(v_idx) = vec_slot_index(reg) {
            if reg.size() <= 8 {
                self.sym_vec_hi[v_idx] = Some(self.arena.c(0, 64));
            }
        }
    }

    fn store_sym_bytes(&mut self, addr: u64, expr: NodeId, byte_len: usize) {
        for i in 0..byte_len {
            let b = self.arena.extract(expr, (i * 8) as u8, 8);
            self.sym_mem.insert(addr.wrapping_add(i as u64), b);
        }
    }

    fn load_sym_bytes(&mut self, addr: u64, byte_len: usize, sample_val: Option<u64>) -> NodeId {
        self.load_sym_bytes_ex(addr, byte_len, sample_val, true)
    }

    fn load_sym_bytes_ex(
        &mut self,
        addr: u64,
        byte_len: usize,
        sample_val: Option<u64>,
        honor_stop_mem: bool,
    ) -> NodeId {
        let mut bytes = Vec::with_capacity(byte_len);
        for i in 0..byte_len {
            let a = addr.wrapping_add(i as u64);
            let sb = sample_val.map(|v| ((v >> (i * 8)) & 0xFF) as u8);
            if honor_stop_mem && self.is_stop_mem(a) {
                // --stop-mem 钉死的内存边界优先于窗口内历史写入/HLE 填充，直接作为符号输入
                let node = self.arena.sym_mem_byte(a, sb);
                self.sym_mem.insert(a, node);
                bytes.push(node);
            } else if let Some(&existing) = self.sym_mem.get(&a) {
                bytes.push(existing);
            } else if self.fold_rodata
                && !self.ever_written_mem.contains(&a)
                && !self.is_stop_mem(a)
            {
                if let Some(bval) = sb {
                    // --fold-rodata：Trace 中从未被写入过的只读内存（.rodata / VM 字节码）直接折叠为常量！
                    bytes.push(self.arena.c(u64::from(bval), 8));
                } else {
                    let node = self.arena.sym_mem_byte(a, None);
                    self.sym_mem.insert(a, node);
                    bytes.push(node);
                }
            } else if self.origin_mem_addrs.contains(&a) {
                let node = self.arena.sym_mem_byte(a, sb);
                self.sym_mem.insert(a, node);
                bytes.push(node);
            } else if let Some(bval) = sb {
                bytes.push(self.arena.c(u64::from(bval), 8));
            } else {
                let node = self.arena.sym_mem_byte(a, None);
                self.sym_mem.insert(a, node);
                bytes.push(node);
            }
        }
        self.arena.concat_le_bytes(&bytes)
    }

    fn apply_hle_events(
        &mut self,
        events: &[HleTraceEvent],
        last_mem_write_bytes: &HashMap<u64, u8>,
    ) {
        for ev in events {
            match ev.op {
                "memcpy" | "memmove" | "realloc_copy" => {
                    let len = ev.len.min(64 * 1024);
                    let snapshot: Vec<(u64, Option<NodeId>)> = (0..len)
                        .map(|i| {
                            let s = ev.src.wrapping_add(i);
                            let sym = if self.is_stop_mem(s) {
                                Some(
                                    self.arena
                                        .sym_mem_byte(s, last_mem_write_bytes.get(&s).copied()),
                                )
                            } else {
                                self.sym_mem.get(&s).copied().or_else(|| {
                                    self.origin_mem_addrs.contains(&s).then(|| {
                                        self.arena
                                            .sym_mem_byte(s, last_mem_write_bytes.get(&s).copied())
                                    })
                                })
                            };
                            (ev.dst.wrapping_add(i), sym)
                        })
                        .collect();
                    for (d, sym) in snapshot {
                        if let Some(n) = sym {
                            self.sym_mem.insert(d, n);
                        } else {
                            self.sym_mem.remove(&d);
                        }
                    }
                }
                "memset" | "bzero" | "calloc_zero" => {
                    let len = ev.len.min(64 * 1024);
                    let fill = self.arena.c(ev.src & 0xFF, 8);
                    for i in 0..len {
                        self.sym_mem.insert(ev.dst.wrapping_add(i), fill);
                    }
                }
                _ => {}
            }
        }
    }

    /// 提升切片中的单条 ARM64 指令
    fn lift_insn(
        &mut self,
        idx: usize,
        insn: &Instruction,
        mem_events: &[ExtRecord],
        post_deltas: &[(u8, u64)],
    ) {
        let mnem = insn.op().to_string().to_ascii_lowercase();
        let ops = insn.operands();
        if ops.is_empty() {
            return;
        }

        // 1. 存储类指令（STR / STUR / STRB / STRH / STP / STNP / ST1）
        if matches!(
            mnem.as_str(),
            "str" | "stur" | "strb" | "sturb" | "strh" | "sturh" | "stlr" | "stlrb" | "stlrh"
        ) {
            let Some(Operand::Reg { reg: rt, .. }) = ops.first() else {
                return;
            };
            let mut writes: Vec<&ExtRecord> = mem_events
                .iter()
                .filter(|e| e.kind == ExtKind::MemWrite as u8)
                .collect();
            if writes.is_empty() {
                return;
            }
            writes.sort_by_key(|e| e.addr);
            self.clear_mem_writeback_base(ops.get(1));
            let total_w: usize = writes.iter().map(|e| e.size_or_reg as usize).sum();
            if rt.size() == 16 || total_w == 16 {
                let base_addr = writes[0].addr;
                let (lo, hi) = self.vec_read_pair(*rt);
                self.store_sym_bytes(base_addr, lo, 8);
                self.store_sym_bytes(base_addr.wrapping_add(8), hi, 8);
                return;
            }
            let sz = total_w.clamp(1, 8);
            let expr = self.reg_expr(*rt, (sz * 8) as u8);
            self.store_sym_bytes(writes[0].addr, expr, sz);
            return;
        }
        if matches!(mnem.as_str(), "stp" | "stnp") {
            let mut writes: Vec<&ExtRecord> = mem_events
                .iter()
                .filter(|e| e.kind == ExtKind::MemWrite as u8)
                .collect();
            writes.sort_by_key(|e| e.addr);
            self.clear_mem_writeback_base(ops.get(2));
            let is_q_pair = matches!(ops.first(), Some(Operand::Reg { reg, .. }) if reg.size() == 16);
            if is_q_pair {
                if let Some(first_w) = writes.first() {
                    let base = first_w.addr;
                    for slot_i in 0..2 {
                        if let Some(Operand::Reg { reg: rt, .. }) = ops.get(slot_i) {
                            let (lo, hi) = self.vec_read_pair(*rt);
                            let off = (slot_i as u64) * 16;
                            self.store_sym_bytes(base.wrapping_add(off), lo, 8);
                            self.store_sym_bytes(base.wrapping_add(off + 8), hi, 8);
                        }
                    }
                }
                return;
            }
            if let Some(first_w) = writes.first() {
                let base = first_w.addr;
                for slot_i in 0..2 {
                    if let Some(Operand::Reg { reg: rt, .. }) = ops.get(slot_i) {
                        let sz = rt.size().clamp(4, 8);
                        let expr = self.reg_expr(*rt, (sz * 8) as u8);
                        self.store_sym_bytes(base.wrapping_add((slot_i * sz) as u64), expr, sz);
                    }
                }
            }
            return;
        }
        if mnem == "st1" {
            let mut writes: Vec<&ExtRecord> = mem_events
                .iter()
                .filter(|e| e.kind == ExtKind::MemWrite as u8)
                .collect();
            writes.sort_by_key(|e| e.addr);
            self.clear_mem_writeback_base(ops.get(1));
            if let (Some(first_w), Some(Operand::MultiReg { regs, arrspec })) =
                (writes.first(), ops.first())
            {
                let (total_bytes, elem_bytes, lane_opt) = vec_arr_info_opt(*arrspec, 16);
                let mut cur_addr = first_w.addr;
                if let Some(lane) = lane_opt {
                    if elem_bytes > 0 && elem_bytes <= 8 {
                        for r in regs.iter().flatten() {
                            let need_total = if (lane + 1) * elem_bytes > 8 { 16 } else { 8 };
                            let lanes = self.vec_read_lanes(*r, need_total, elem_bytes);
                            if let Some(&lv) = lanes.get(lane) {
                                self.store_sym_bytes(cur_addr, lv, elem_bytes);
                            }
                            cur_addr = cur_addr.wrapping_add(elem_bytes as u64);
                        }
                    }
                } else {
                    for r in regs.iter().flatten() {
                        let lo = self.vec_read_lo(*r);
                        self.store_sym_bytes(cur_addr, lo, 8);
                        if total_bytes >= 16 {
                            let hi = self.vec_read_hi(*r);
                            self.store_sym_bytes(cur_addr.wrapping_add(8), hi, 8);
                        }
                        cur_addr = cur_addr.wrapping_add(total_bytes as u64);
                    }
                }
            }
            return;
        }

        // 2. 加载类指令（LDR / LDUR / LDRB / LDRH / LDRSB / LDRSH / LDRSW / LDP / LDNP / LD1）
        if matches!(
            mnem.as_str(),
            "ldr"
                | "ldur"
                | "ldrb"
                | "ldurb"
                | "ldrh"
                | "ldurh"
                | "ldrsb"
                | "ldursb"
                | "ldrsh"
                | "ldursh"
                | "ldrsw"
                | "ldursw"
                | "ldar"
                | "ldarb"
                | "ldarh"
        ) {
            let Some(Operand::Reg { reg: rt, .. }) = ops.first() else {
                return;
            };
            let mut reads: Vec<&ExtRecord> = mem_events
                .iter()
                .filter(|e| e.kind == ExtKind::MemRead as u8)
                .collect();
            if reads.is_empty() {
                return;
            }
            reads.sort_by_key(|e| e.addr);
            self.clear_mem_writeback_base(ops.get(1));
            let total_r: usize = reads.iter().map(|e| e.size_or_reg as usize).sum();
            if rt.size() == 16 || total_r == 16 {
                let base_addr = reads[0].addr;
                let (lo_s, hi_s) = sample_16b_from_reads(&reads, base_addr);
                let lo = self.load_sym_bytes(base_addr, 8, lo_s);
                let hi = self.load_sym_bytes(base_addr.wrapping_add(8), 8, hi_s);
                self.vec_write_pair(*rt, lo, hi);
                return;
            }
            let base_addr = reads[0].addr;
            let elem_bytes = total_r.clamp(1, 8);
            let sample_val = sample_bytes_from_reads(&reads, base_addr, elem_bytes);
            let reg_w = (rt.size() * 8).clamp(32, 64) as u8;
            let is_signed = matches!(
                mnem.as_str(),
                "ldrsb" | "ldursb" | "ldrsh" | "ldursh" | "ldrsw" | "ldursw"
            );

            // 检查是否是 S-Box / 常量查找表访问（索引寄存器受污点影响，且表地址非污点）
            if let Some(sv) = sample_val {
                if let Some(table_node) = self.try_lift_table_load(
                    ops.get(1),
                    base_addr,
                    elem_bytes as u8,
                    sv,
                    reg_w,
                    is_signed,
                ) {
                    self.set_reg(*rt, table_node);
                    return;
                }
            }

            let loaded = self.load_sym_bytes(base_addr, elem_bytes, sample_val);
            let final_expr = self.arena.adapt_width(loaded, reg_w, is_signed);
            self.set_reg(*rt, final_expr);
            return;
        }
        if matches!(mnem.as_str(), "ldp" | "ldnp" | "ldpsw") {
            let mut reads: Vec<&ExtRecord> = mem_events
                .iter()
                .filter(|e| e.kind == ExtKind::MemRead as u8)
                .collect();
            reads.sort_by_key(|e| e.addr);
            self.clear_mem_writeback_base(ops.get(2));
            let is_q_pair = matches!(ops.first(), Some(Operand::Reg { reg, .. }) if reg.size() == 16);
            if is_q_pair {
                if let Some(first_r) = reads.first() {
                    let base = first_r.addr;
                    for slot_i in 0..2 {
                        if let Some(Operand::Reg { reg: rt, .. }) = ops.get(slot_i) {
                            let off = (slot_i as u64) * 16;
                            let addr_q = base.wrapping_add(off);
                            let (lo_s, hi_s) = sample_16b_from_reads(&reads, addr_q);
                            let lo = self.load_sym_bytes(addr_q, 8, lo_s);
                            let hi = self.load_sym_bytes(addr_q.wrapping_add(8), 8, hi_s);
                            self.vec_write_pair(*rt, lo, hi);
                        }
                    }
                }
                return;
            }
            let is_signed = mnem == "ldpsw";
            if let Some(first_r) = reads.first() {
                let base = first_r.addr;
                for slot_i in 0..2 {
                    if let Some(Operand::Reg { reg: rt, .. }) = ops.get(slot_i) {
                        let elem_bytes = if is_signed {
                            4
                        } else {
                            rt.size().clamp(4, 8)
                        };
                        let addr_i = base.wrapping_add((slot_i * elem_bytes) as u64);
                        let sample_val = sample_bytes_from_reads(&reads, addr_i, elem_bytes);
                        let reg_w = (rt.size() * 8).clamp(32, 64) as u8;
                        let loaded = self.load_sym_bytes(addr_i, elem_bytes, sample_val);
                        let final_expr = self.arena.adapt_width(loaded, reg_w, is_signed);
                        self.set_reg(*rt, final_expr);
                    }
                }
            }
            return;
        }
        if mnem == "ld1" {
            let mut reads: Vec<&ExtRecord> = mem_events
                .iter()
                .filter(|e| e.kind == ExtKind::MemRead as u8)
                .collect();
            reads.sort_by_key(|e| e.addr);
            self.clear_mem_writeback_base(ops.get(1));
            if let (Some(first_r), Some(Operand::MultiReg { regs, arrspec })) =
                (reads.first(), ops.first())
            {
                let (total_bytes, elem_bytes, lane_opt) = vec_arr_info_opt(*arrspec, 16);
                let mut cur_addr = first_r.addr;
                if let Some(lane) = lane_opt {
                    if elem_bytes > 0 && elem_bytes <= 8 {
                        for r in regs.iter().flatten() {
                            let sample_val = sample_bytes_from_reads(&reads, cur_addr, elem_bytes);
                            let loaded = self.load_sym_bytes(cur_addr, elem_bytes, sample_val);
                            let mut lanes = self.vec_read_lanes(*r, 16, elem_bytes);
                            if lane < lanes.len() {
                                lanes[lane] = self
                                    .arena
                                    .adapt_width(loaded, (elem_bytes * 8) as u8, false);
                                self.vec_write_lanes(*r, &lanes, elem_bytes);
                            }
                            cur_addr = cur_addr.wrapping_add(elem_bytes as u64);
                        }
                    }
                } else {
                    for r in regs.iter().flatten() {
                        let (lo_s, hi_s) = sample_16b_from_reads(&reads, cur_addr);
                        let lo = self.load_sym_bytes(cur_addr, 8, lo_s);
                        let hi = if total_bytes >= 16 {
                            self.load_sym_bytes(cur_addr.wrapping_add(8), 8, hi_s)
                        } else {
                            self.arena.c(0, 64)
                        };
                        self.vec_write_pair(*r, lo, hi);
                        cur_addr = cur_addr.wrapping_add(total_bytes as u64);
                    }
                }
            }
            return;
        }

        // 未建模的多寄存器向量访存（LD1R/LD2..4/ST2..4）：不可静默 no-op 泄漏旧符号状态
        if let Some(Operand::MultiReg { regs, .. }) = ops.first() {
            self.clear_mem_writeback_base(ops.get(1));
            if mnem.starts_with("st") {
                for ev in mem_events {
                    if ev.kind == ExtKind::MemWrite as u8 {
                        let sz = (ev.size_or_reg as usize).clamp(1, 16);
                        for b in 0..sz {
                            self.sym_mem.remove(&ev.addr.wrapping_add(b as u64));
                        }
                    }
                }
            } else {
                let opq = self.arena.intern_node(BvNode::Opaque {
                    asm: format!("#{idx}: {insn}"),
                    args: Vec::new(),
                    width: 64,
                    sample: None,
                });
                for r in regs.iter().flatten() {
                    self.vec_write_pair(*r, opq, opq);
                }
            }
            return;
        }

        // 2.5 NEON / SIMD 向量与 ARMv8-CE AES 硬件指令（64-bit / 128-bit 通道精确提升）
        if self.try_lift_neon_insn(&mnem, ops) {
            return;
        }

        // 3. 通用数据处理指令（op[0] 为目的寄存器 Rd）
        let Some(Operand::Reg { reg: rd, .. }) = ops.first() else {
            return;
        };
        let dst_w = (rd.size() * 8).clamp(32, 64) as u8;
        let dst_slot = parse_reg_slot(rd.name());
        let post_val = dst_slot.and_then(|s| {
            post_deltas
                .iter()
                .find(|&&(id, _)| id == s)
                .map(|&(_, v)| v)
                .or(self.concrete_regs[s as usize])
        });

        // 凡涉及向量/浮点寄存器且未被 try_lift_neon_insn 建模的指令（如 mul/neg/rbit/clz/umull 向量版），
        // 绝不可落入标量 GPR lift_data_insn 造成按 64-bit 标量误提升或泄漏旧 sym_vec_hi！
        let touches_vec = ops
            .iter()
            .any(|o| matches!(o, Operand::Reg { reg, .. } if vec_slot_index(*reg).is_some()));
        let lifted = if touches_vec {
            None
        } else {
            self.lift_data_insn(&mnem, ops, *rd, dst_w, post_val)
        };

        let final_node = lifted.unwrap_or_else(|| {
            let mut args = Vec::new();
            for o in ops.iter().skip(1) {
                if let Some(e) = self.operand_expr(o, dst_w) {
                    args.push(e);
                }
            }
            self.arena.intern_node(BvNode::Opaque {
                asm: format!("#{idx}: {insn}"),
                args,
                width: dst_w,
                sample: post_val.map(|v| v & width_mask(dst_w)),
            })
        });
        self.set_reg(*rd, final_node);
        if let Some(v_idx) = vec_slot_index(*rd) {
            // 若是未建模的向量指令落入 Opaque，高 64 位同步标记为 Opaque 防止残留旧符号或误清零
            if matches!(self.arena.get(final_node), BvNode::Opaque { .. }) {
                self.sym_vec_hi[v_idx] = Some(final_node);
            }
        }
    }

    fn clear_mem_writeback_base(&mut self, mem_op: Option<&Operand>) {
        let base_reg = match mem_op {
            Some(Operand::MemPreIdx { reg, .. } | Operand::MemPostIdxImm { reg, .. }) => Some(*reg),
            Some(Operand::MemPostIdxReg(regs)) => Some(regs[0]),
            _ => None,
        };
        if let Some(r) = base_reg {
            if let Some(slot) = parse_reg_slot(r.name()) {
                if (slot as usize) < 64 {
                    self.sym_regs[slot as usize] = None;
                }
            }
        }
    }

    fn vec_read_lo(&mut self, reg: Reg) -> NodeId {
        let Some(v_idx) = vec_slot_index(reg) else {
            return self.arena.c(0, 64);
        };
        let slot = (32 + v_idx) as u8;
        if let Some(sym) = self.sym_regs[slot as usize] {
            return self.arena.adapt_width(sym, 64, false);
        }
        if self.origin_regs.contains(&slot) {
            let sample = self.concrete_regs[slot as usize];
            let n = self.arena.sym_reg(slot, 64, sample);
            self.sym_regs[slot as usize] = Some(n);
            return n;
        }
        if let Some(v) = self.concrete_regs[slot as usize] {
            self.arena.c(v, 64)
        } else {
            let n = self.arena.sym_reg(slot, 64, None);
            self.sym_regs[slot as usize] = Some(n);
            n
        }
    }

    fn vec_read_hi(&mut self, reg: Reg) -> NodeId {
        let Some(v_idx) = vec_slot_index(reg) else {
            return self.arena.c(0, 64);
        };
        if let Some(sym) = self.sym_vec_hi[v_idx] {
            return self.arena.adapt_width(sym, 64, false);
        }
        // 64..96 专用于向量高 64 位寄存器 arg_vN_hi（避免与 HLE 熵源 96..255 冲突）
        let pseudo_hi = (64 + v_idx) as u8;
        let n = self.arena.intern_node(BvNode::SymReg {
            reg_slot: pseudo_hi,
            name: format!("arg_v{v_idx}_hi"),
            width: 64,
            sample: None,
        });
        self.sym_vec_hi[v_idx] = Some(n);
        n
    }

    fn vec_read_pair(&mut self, reg: Reg) -> (NodeId, NodeId) {
        (self.vec_read_lo(reg), self.vec_read_hi(reg))
    }

    fn vec_write_pair(&mut self, reg: Reg, lo: NodeId, hi: NodeId) {
        let Some(v_idx) = vec_slot_index(reg) else {
            return;
        };
        let slot = 32 + v_idx;
        self.sym_regs[slot] = Some(self.arena.adapt_width(lo, 64, false));
        self.sym_vec_hi[v_idx] = Some(self.arena.adapt_width(hi, 64, false));
    }

    fn vec_read_lanes(&mut self, reg: Reg, total_bytes: usize, elem_bytes: usize) -> Vec<NodeId> {
        if elem_bytes == 0 || elem_bytes > 8 || total_bytes == 0 {
            return Vec::new();
        }
        let lo = self.vec_read_lo(reg);
        let hi = if total_bytes > 8 {
            Some(self.vec_read_hi(reg))
        } else {
            None
        };
        let elem_bits = (elem_bytes * 8) as u8;
        let count = total_bytes / elem_bytes;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let bit_off = i * elem_bytes * 8;
            let src = if bit_off < 64 {
                lo
            } else {
                hi.unwrap_or(lo)
            };
            let local_lsb = (bit_off % 64) as u8;
            let lane = if elem_bits == 64 {
                src
            } else {
                self.arena.extract(src, local_lsb, elem_bits)
            };
            out.push(lane);
        }
        out
    }

    fn vec_write_lanes(&mut self, reg: Reg, lanes: &[NodeId], elem_bytes: usize) {
        if elem_bytes == 0 || elem_bytes > 8 {
            return;
        }
        let elem_bits = (elem_bytes * 8) as u8;
        let lanes_per_half = 8 / elem_bytes;
        let build_half = |arena: &mut BvArena, slice: &[NodeId]| -> NodeId {
            if slice.is_empty() {
                return arena.c(0, 64);
            }
            if elem_bytes == 8 {
                return arena.adapt_width(slice[0], 64, false);
            }
            let mut acc = arena.adapt_width(slice[0], 64, false);
            for (i, &ln) in slice.iter().enumerate().skip(1) {
                let z = arena.adapt_width(ln, 64, false);
                let sh = arena.c((i * usize::from(elem_bits)) as u64, 64);
                let shifted = arena.binop(BvBinOp::Shl, z, sh, 64);
                acc = arena.binop(BvBinOp::Or, acc, shifted, 64);
            }
            acc
        };
        let lo_end = lanes.len().min(lanes_per_half);
        let lo = build_half(&mut self.arena, &lanes[..lo_end]);
        let hi = if lanes.len() > lanes_per_half {
            build_half(&mut self.arena, &lanes[lanes_per_half..lanes.len().min(lanes_per_half * 2)])
        } else {
            self.arena.c(0, 64)
        };
        self.vec_write_pair(reg, lo, hi);
    }

    /// 尝试以 64/128-bit NEON 通道或 ARMv8-CE AES 原语提升向量指令；命中返回 `true`
    fn try_lift_neon_insn(&mut self, mnem: &str, ops: &[Operand]) -> bool {
        let Some(Operand::Reg {
            reg: rd,
            arrspec: rd_arr,
        }) = ops.first()
        else {
            return false;
        };
        let dst_is_vec = vec_slot_index(*rd).is_some();
        let src_is_vec = ops
            .get(1)
            .is_some_and(|o| matches!(o, Operand::Reg { reg, .. } if vec_slot_index(*reg).is_some()));

        if !dst_is_vec && !src_is_vec {
            return false;
        }

        // 1. 标量 <-> 向量桥接指令（UMOV / SMOV / bad64 别名的 MOV Xd/Wd, Vn.<T>[lane] / FMOV / INS / DUP）
        let is_umov_alias = mnem == "mov"
            && !dst_is_vec
            && src_is_vec
            && matches!(ops.get(1), Some(Operand::Reg { arrspec: Some(a), .. }) if arr_lane(*a).is_some());
        if matches!(mnem, "umov" | "smov") || is_umov_alias {
            if let Some(Operand::Reg {
                reg: rn,
                arrspec: Some(arr),
            }) = ops.get(1)
            {
                let (_, elem_b, lane_opt) = vec_arr_info_opt(Some(*arr), 16);
                let lane = lane_opt.unwrap_or(0);
                if elem_b == 0 || elem_b > 8 {
                    return false;
                }
                let need_total = if (lane + 1) * elem_b > 8 { 16 } else { 8 };
                let lanes = self.vec_read_lanes(*rn, need_total, elem_b);
                if let Some(&ln) = lanes.get(lane) {
                    let dst_w = (rd.size() * 8).clamp(32, 64) as u8;
                    let expr = self.arena.adapt_width(ln, dst_w, mnem == "smov");
                    self.set_reg(*rd, expr);
                    return true;
                }
            }
            return false;
        }
        if mnem == "fmov" {
            if let Some(Operand::Reg {
                reg: rn,
                arrspec: src_arr,
            }) = ops.get(1)
            {
                // 高 64 位专用传输：`fmov x4, v28.d[1]` 与 `fmov v28.d[1], x4`
                if !dst_is_vec && src_is_vec && src_arr.and_then(arr_lane) == Some(1) {
                    let hi = self.vec_read_hi(*rn);
                    let dst_w = (rd.size() * 8).clamp(32, 64) as u8;
                    let expr = self.arena.adapt_width(hi, dst_w, false);
                    self.set_reg(*rd, expr);
                    return true;
                }
                if dst_is_vec && !src_is_vec && rd_arr.and_then(arr_lane) == Some(1) {
                    let lo = self.vec_read_lo(*rd);
                    let hi = self.reg_expr(*rn, 64);
                    self.vec_write_pair(*rd, lo, hi);
                    return true;
                }
                if dst_is_vec && !src_is_vec {
                    let exact_w = (rd.size().min(8) * 8).max(8) as u8;
                    let src = self.reg_expr(*rn, exact_w);
                    let lo = self.arena.adapt_width(src, 64, false);
                    let zero = self.arena.c(0, 64);
                    self.vec_write_pair(*rd, lo, zero);
                    return true;
                } else if !dst_is_vec && src_is_vec {
                    let lo = self.vec_read_lo(*rn);
                    let src_w = (rn.size().min(8) * 8).max(8) as u8;
                    let masked = self.arena.adapt_width(lo, src_w, false);
                    let dst_w = (rd.size() * 8).clamp(32, 64) as u8;
                    let expr = self.arena.adapt_width(masked, dst_w, false);
                    self.set_reg(*rd, expr);
                    return true;
                } else if dst_is_vec && src_is_vec {
                    let lo = self.vec_read_lo(*rn);
                    let exact_w = (rd.size().min(rn.size()).min(8) * 8).max(8) as u8;
                    let trunc = self.arena.adapt_width(lo, exact_w, false);
                    let zext = self.arena.adapt_width(trunc, 64, false);
                    let zero = self.arena.c(0, 64);
                    self.vec_write_pair(*rd, zext, zero);
                    return true;
                }
            }
            return false;
        }
        if mnem == "ins" || (mnem == "mov" && dst_is_vec && rd_arr.and_then(arr_lane).is_some()) {
            let (_, elem_b, lane_opt) = vec_arr_info_opt(*rd_arr, 16);
            if elem_b == 0 || elem_b > 8 {
                return false;
            }
            let dst_lane = lane_opt.unwrap_or(0);
            let mut lanes = self.vec_read_lanes(*rd, 16, elem_b);
            if dst_lane >= lanes.len() {
                return false;
            }
            let new_val = match ops.get(1) {
                Some(Operand::Reg {
                    reg: rn,
                    arrspec: Some(src_arr),
                }) if vec_slot_index(*rn).is_some() => {
                    let (_, s_eb, s_lane) = vec_arr_info_opt(Some(*src_arr), 16);
                    let sl_idx = s_lane.unwrap_or(0);
                    let need_total = if (sl_idx + 1) * s_eb > 8 { 16 } else { 8 };
                    let src_lanes = self.vec_read_lanes(*rn, need_total, s_eb);
                    let Some(&sl) = src_lanes.get(sl_idx) else {
                        return false;
                    };
                    self.arena.adapt_width(sl, (elem_b * 8) as u8, false)
                }
                Some(Operand::Reg { reg: rn, .. }) => self.reg_expr(*rn, (elem_b * 8) as u8),
                _ => return false,
            };
            lanes[dst_lane] = new_val;
            self.vec_write_lanes(*rd, &lanes, elem_b);
            return true;
        }
        if !dst_is_vec {
            return false;
        }

        // bad64 将标量 `DUP Bd/Hd/Sd/Dd, Vn.<T>[lane]` 反汇编为 `mov b1, v4.b[9]` / `mov s8, v14.s[3]`
        if mnem == "mov" && rd_arr.is_none() {
            if let Some(Operand::Reg {
                reg: rn,
                arrspec: Some(src_arr),
            }) = ops.get(1)
            {
                if vec_slot_index(*rn).is_some() && arr_lane(*src_arr).is_some() {
                    let (_, s_eb, s_lane) = vec_arr_info_opt(Some(*src_arr), 16);
                    let sl_idx = s_lane.unwrap_or(0);
                    if s_eb == 0 || s_eb > 8 {
                        return false;
                    }
                    let need_total = if (sl_idx + 1) * s_eb > 8 { 16 } else { 8 };
                    let src_lanes = self.vec_read_lanes(*rn, need_total, s_eb);
                    let Some(&sl) = src_lanes.get(sl_idx) else {
                        return false;
                    };
                    let lo = self.arena.adapt_width(sl, 64, false);
                    let zero = self.arena.c(0, 64);
                    self.vec_write_pair(*rd, lo, zero);
                    return true;
                }
            }
        }

        // 当无 arrspec 且为标量 B/H/S/D 寄存器时（如 `movi d11` / `add d0, d1, d2` / `shl d0, d1, #k`），
        // 元素宽度必须等于寄存器标量字节宽，而非退化成 1 字节！
        let (total_b, elem_b, _) = if rd_arr.is_none() && rd.size() <= 8 {
            let sz = rd.size().clamp(1, 8);
            (sz, sz, None)
        } else {
            vec_arr_info_opt(*rd_arr, rd.size().clamp(8, 16))
        };
        let is_128 = total_b >= 16;

        // 2. ARMv8-CE 硬件 AES 原语（AESE / AESD / AESMC / AESIMC）
        if matches!(mnem, "aese" | "aesd" | "aesmc" | "aesimc") {
            let Some(Operand::Reg { reg: rn, .. }) = ops.get(1) else {
                return false;
            };
            let (kind, s_lo, s_hi, k_lo, k_hi) = match mnem {
                "aese" => {
                    let (dlo, dhi) = self.vec_read_pair(*rd);
                    let (nlo, nhi) = self.vec_read_pair(*rn);
                    (AesOpKind::Aese, dlo, dhi, Some(nlo), Some(nhi))
                }
                "aesd" => {
                    let (dlo, dhi) = self.vec_read_pair(*rd);
                    let (nlo, nhi) = self.vec_read_pair(*rn);
                    (AesOpKind::Aesd, dlo, dhi, Some(nlo), Some(nhi))
                }
                "aesmc" => {
                    let (nlo, nhi) = self.vec_read_pair(*rn);
                    (AesOpKind::Aesmc, nlo, nhi, None, None)
                }
                _ => {
                    let (nlo, nhi) = self.vec_read_pair(*rn);
                    (AesOpKind::Aesimc, nlo, nhi, None, None)
                }
            };
            let out_lo = self.arena.intern_node(BvNode::AesOp {
                kind,
                state_lo: s_lo,
                state_hi: s_hi,
                key_lo: k_lo,
                key_hi: k_hi,
                hi_half: false,
            });
            let out_hi = self.arena.intern_node(BvNode::AesOp {
                kind,
                state_lo: s_lo,
                state_hi: s_hi,
                key_lo: k_lo,
                key_hi: k_hi,
                hi_half: true,
            });
            self.vec_write_pair(*rd, out_lo, out_hi);
            return true;
        }

        // 3. 向量常量 MOVI / MVNI（支持 LSL 与 MSL 移位）& 广播 DUP
        if matches!(mnem, "movi" | "mvni") {
            if elem_b == 0 || elem_b > 8 {
                return false;
            }
            let imm_u64 = match ops.get(1) {
                Some(Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift }) => {
                    let v = imm_to_u64(*imm);
                    match shift {
                        Some(Shift::LSL(s)) => v.wrapping_shl(*s),
                        Some(Shift::MSL(s)) => v.wrapping_shl(*s) | width_mask(*s as u8),
                        _ => v,
                    }
                }
                _ => return false,
            };
            let val = if mnem == "mvni" { !imm_u64 } else { imm_u64 };
            let lane_val = self.arena.c(val, (elem_b * 8) as u8);
            let count = total_b / elem_b;
            let lanes = vec![lane_val; count];
            self.vec_write_lanes(*rd, &lanes, elem_b);
            return true;
        }
        if mnem == "dup" {
            if elem_b == 0 || elem_b > 8 {
                return false;
            }
            let count = total_b / elem_b;
            let elem_val = match ops.get(1) {
                Some(Operand::Reg {
                    reg: rn,
                    arrspec: Some(src_arr),
                }) if vec_slot_index(*rn).is_some() => {
                    let (_, s_eb, s_lane) = vec_arr_info_opt(Some(*src_arr), 16);
                    let sl_idx = s_lane.unwrap_or(0);
                    let need_total = if (sl_idx + 1) * s_eb > 8 { 16 } else { 8 };
                    let src_lanes = self.vec_read_lanes(*rn, need_total, s_eb);
                    let Some(&sl) = src_lanes.get(sl_idx) else {
                        return false;
                    };
                    self.arena.adapt_width(sl, (elem_b * 8) as u8, false)
                }
                Some(Operand::Reg { reg: rn, .. }) => self.reg_expr(*rn, (elem_b * 8) as u8),
                _ => return false,
            };
            let lanes = vec![elem_val; count];
            self.vec_write_lanes(*rd, &lanes, elem_b);
            return true;
        }

        // 4. 64/128-bit 按位逻辑指令（64-bit 模式不读取高 64 位，避免无端引入 arg_vN_hi）
        if mnem == "mov" {
            if let Some(Operand::Reg { reg: rn, .. }) = ops.get(1) {
                if vec_slot_index(*rn).is_some() {
                    let nlo = self.vec_read_lo(*rn);
                    let out_hi = if is_128 {
                        self.vec_read_hi(*rn)
                    } else {
                        self.arena.c(0, 64)
                    };
                    self.vec_write_pair(*rd, nlo, out_hi);
                    return true;
                }
            }
            return false;
        }
        if matches!(mnem, "not" | "mvn") {
            let Some(Operand::Reg { reg: rn, .. }) = ops.get(1) else {
                return false;
            };
            let nlo = self.vec_read_lo(*rn);
            let out_lo = self.arena.unop(BvUnOp::Not, nlo, 64);
            let out_hi = if is_128 {
                let nhi = self.vec_read_hi(*rn);
                self.arena.unop(BvUnOp::Not, nhi, 64)
            } else {
                self.arena.c(0, 64)
            };
            self.vec_write_pair(*rd, out_lo, out_hi);
            return true;
        }
        if matches!(mnem, "eor" | "orr" | "and" | "bic" | "orn") {
            let (Some(Operand::Reg { reg: rn, .. }), Some(Operand::Reg { reg: rm, .. })) =
                (ops.get(1), ops.get(2))
            else {
                return false;
            };
            let nlo = self.vec_read_lo(*rn);
            let mlo = self.vec_read_lo(*rm);
            let apply_bit = |arena: &mut BvArena, a: NodeId, b: NodeId| -> NodeId {
                match mnem {
                    "eor" => arena.binop(BvBinOp::Xor, a, b, 64),
                    "orr" => arena.binop(BvBinOp::Or, a, b, 64),
                    "and" => arena.binop(BvBinOp::And, a, b, 64),
                    "bic" => {
                        let nb = arena.unop(BvUnOp::Not, b, 64);
                        arena.binop(BvBinOp::And, a, nb, 64)
                    }
                    _ => {
                        let nb = arena.unop(BvUnOp::Not, b, 64);
                        arena.binop(BvBinOp::Or, a, nb, 64)
                    }
                }
            };
            let out_lo = apply_bit(&mut self.arena, nlo, mlo);
            let out_hi = if is_128 {
                let nhi = self.vec_read_hi(*rn);
                let mhi = self.vec_read_hi(*rm);
                apply_bit(&mut self.arena, nhi, mhi)
            } else {
                self.arena.c(0, 64)
            };
            self.vec_write_pair(*rd, out_lo, out_hi);
            return true;
        }
        if mnem == "eor3" {
            let (
                Some(Operand::Reg { reg: rn, .. }),
                Some(Operand::Reg { reg: rm, .. }),
                Some(Operand::Reg { reg: ra, .. }),
            ) = (ops.get(1), ops.get(2), ops.get(3))
            else {
                return false;
            };
            let (nlo, nhi) = self.vec_read_pair(*rn);
            let (mlo, mhi) = self.vec_read_pair(*rm);
            let (alo, ahi) = self.vec_read_pair(*ra);
            let tlo = self.arena.binop(BvBinOp::Xor, nlo, mlo, 64);
            let out_lo = self.arena.binop(BvBinOp::Xor, tlo, alo, 64);
            let thi = self.arena.binop(BvBinOp::Xor, nhi, mhi, 64);
            let out_hi = self.arena.binop(BvBinOp::Xor, thi, ahi, 64);
            self.vec_write_pair(*rd, out_lo, out_hi);
            return true;
        }
        if matches!(mnem, "bsl" | "bit" | "bif") {
            let (Some(Operand::Reg { reg: rn, .. }), Some(Operand::Reg { reg: rm, .. })) =
                (ops.get(1), ops.get(2))
            else {
                return false;
            };
            let dlo = self.vec_read_lo(*rd);
            let nlo = self.vec_read_lo(*rn);
            let mlo = self.vec_read_lo(*rm);
            let mux = |arena: &mut BvArena, sel: NodeId, t_val: NodeId, f_val: NodeId| -> NodeId {
                // (sel & t_val) | (~sel & f_val)
                let a = arena.binop(BvBinOp::And, sel, t_val, 64);
                let nsel = arena.unop(BvUnOp::Not, sel, 64);
                let b = arena.binop(BvBinOp::And, nsel, f_val, 64);
                arena.binop(BvBinOp::Or, a, b, 64)
            };
            let out_lo = match mnem {
                "bsl" => mux(&mut self.arena, dlo, nlo, mlo),
                "bit" => mux(&mut self.arena, mlo, nlo, dlo),
                _ => mux(&mut self.arena, mlo, dlo, nlo),
            };
            let out_hi = if is_128 {
                let dhi = self.vec_read_hi(*rd);
                let nhi = self.vec_read_hi(*rn);
                let mhi = self.vec_read_hi(*rm);
                match mnem {
                    "bsl" => mux(&mut self.arena, dhi, nhi, mhi),
                    "bit" => mux(&mut self.arena, mhi, nhi, dhi),
                    _ => mux(&mut self.arena, mhi, dhi, nhi),
                }
            } else {
                self.arena.c(0, 64)
            };
            self.vec_write_pair(*rd, out_lo, out_hi);
            return true;
        }

        // 5. 通道级整型运算（ADD / SUB / SHL / USHR / SSHR / SLI / SRI）
        if matches!(mnem, "add" | "sub") {
            if elem_b == 0 || elem_b > 8 {
                return false;
            }
            let (Some(Operand::Reg { reg: rn, .. }), Some(Operand::Reg { reg: rm, .. })) =
                (ops.get(1), ops.get(2))
            else {
                return false;
            };
            let a_lanes = self.vec_read_lanes(*rn, total_b, elem_b);
            let b_lanes = self.vec_read_lanes(*rm, total_b, elem_b);
            let op = if mnem == "add" { BvBinOp::Add } else { BvBinOp::Sub };
            let bits = (elem_b * 8) as u8;
            let out: Vec<NodeId> = a_lanes
                .into_iter()
                .zip(b_lanes)
                .map(|(a, b)| self.arena.binop(op, a, b, bits))
                .collect();
            self.vec_write_lanes(*rd, &out, elem_b);
            return true;
        }
        if matches!(mnem, "shl" | "ushr" | "sshr" | "sli" | "sri") {
            if elem_b == 0 || elem_b > 8 {
                return false;
            }
            let (Some(Operand::Reg { reg: rn, .. }), Some(sh_op)) = (ops.get(1), ops.get(2)) else {
                return false;
            };
            let sh_amt = match sh_op {
                Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. } => imm_to_u64(*imm),
                _ => return false,
            };
            let bits = (elem_b * 8) as u8;
            let src_lanes = self.vec_read_lanes(*rn, total_b, elem_b);
            let dst_lanes = if matches!(mnem, "sli" | "sri") {
                Some(self.vec_read_lanes(*rd, total_b, elem_b))
            } else {
                None
            };
            let mut out = Vec::with_capacity(src_lanes.len());
            for (i, s) in src_lanes.into_iter().enumerate() {
                let res = if sh_amt >= u64::from(bits) {
                    // ARMv8-A 合法右移范围 1..=elem_bits（如 `sshr .4s, #32` 提取符号掩码，`ushr #bits` -> 0）
                    match mnem {
                        "shl" | "ushr" => self.arena.c(0, bits),
                        "sshr" => {
                            let max_sh = self.arena.c(u64::from(bits - 1), bits);
                            self.arena.binop(BvBinOp::Ashr, s, max_sh, bits)
                        }
                        _ => dst_lanes.as_ref().unwrap()[i],
                    }
                } else if sh_amt == 0 {
                    s
                } else {
                    let sh_node = self.arena.c(sh_amt, bits);
                    match mnem {
                        "shl" => self.arena.binop(BvBinOp::Shl, s, sh_node, bits),
                        "ushr" => self.arena.binop(BvBinOp::Lshr, s, sh_node, bits),
                        "sshr" => self.arena.binop(BvBinOp::Ashr, s, sh_node, bits),
                        "sli" => {
                            let d = dst_lanes.as_ref().unwrap()[i];
                            let mask = self.arena.c(width_mask(sh_amt as u8), bits);
                            let keep = self.arena.binop(BvBinOp::And, d, mask, bits);
                            let shifted = self.arena.binop(BvBinOp::Shl, s, sh_node, bits);
                            self.arena.binop(BvBinOp::Or, keep, shifted, bits)
                        }
                        _ => {
                            let d = dst_lanes.as_ref().unwrap()[i];
                            let top_mask = !width_mask(bits - (sh_amt as u8)) & width_mask(bits);
                            let top_mask_c = self.arena.c(top_mask, bits);
                            let keep = self.arena.binop(BvBinOp::And, d, top_mask_c, bits);
                            let shifted = self.arena.binop(BvBinOp::Lshr, s, sh_node, bits);
                            self.arena.binop(BvBinOp::Or, keep, shifted, bits)
                        }
                    }
                };
                out.push(res);
            }
            self.vec_write_lanes(*rd, &out, elem_b);
            return true;
        }

        // 6. 字节/通道重排（EXT / REV64 / REV32 / REV16 / UZP1 / UZP2 / ZIP1 / ZIP2 / TRN1 / TRN2）
        if mnem == "ext" {
            let (
                Some(Operand::Reg { reg: rn, .. }),
                Some(Operand::Reg { reg: rm, .. }),
                Some(Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. }),
            ) = (ops.get(1), ops.get(2), ops.get(3))
            else {
                return false;
            };
            let idx = (imm_to_u64(*imm) as usize) % total_b;
            let a = self.vec_read_lanes(*rn, total_b, 1);
            let b = self.vec_read_lanes(*rm, total_b, 1);
            let mut out = Vec::with_capacity(total_b);
            out.extend_from_slice(&a[idx..]);
            out.extend_from_slice(&b[..idx]);
            self.vec_write_lanes(*rd, &out, 1);
            return true;
        }
        if matches!(mnem, "rev64" | "rev32" | "rev16") {
            let Some(Operand::Reg { reg: rn, .. }) = ops.get(1) else {
                return false;
            };
            let container_b = match mnem {
                "rev64" => 8usize,
                "rev32" => 4usize,
                _ => 2usize,
            };
            if elem_b >= container_b {
                return false;
            }
            let mut lanes = self.vec_read_lanes(*rn, total_b, elem_b);
            let group = container_b / elem_b;
            for chunk in lanes.chunks_mut(group) {
                chunk.reverse();
            }
            self.vec_write_lanes(*rd, &lanes, elem_b);
            return true;
        }
        if matches!(mnem, "uzp1" | "uzp2" | "zip1" | "zip2" | "trn1" | "trn2") {
            let (Some(Operand::Reg { reg: rn, .. }), Some(Operand::Reg { reg: rm, .. })) =
                (ops.get(1), ops.get(2))
            else {
                return false;
            };
            let a = self.vec_read_lanes(*rn, total_b, elem_b);
            let b = self.vec_read_lanes(*rm, total_b, elem_b);
            let n = a.len();
            let half = n / 2;
            let mut out = Vec::with_capacity(n);
            match mnem {
                "uzp1" => {
                    for i in (0..n).step_by(2) { out.push(a[i]); }
                    for i in (0..n).step_by(2) { out.push(b[i]); }
                }
                "uzp2" => {
                    for i in (1..n).step_by(2) { out.push(a[i]); }
                    for i in (1..n).step_by(2) { out.push(b[i]); }
                }
                "zip1" => {
                    for i in 0..half {
                        out.push(a[i]);
                        out.push(b[i]);
                    }
                }
                "zip2" => {
                    for i in half..n {
                        out.push(a[i]);
                        out.push(b[i]);
                    }
                }
                "trn1" => {
                    for i in (0..n).step_by(2) {
                        out.push(a[i]);
                        out.push(b[i]);
                    }
                }
                _ => {
                    for i in (1..n).step_by(2) {
                        out.push(a[i]);
                        out.push(b[i]);
                    }
                }
            }
            self.vec_write_lanes(*rd, &out, elem_b);
            return true;
        }

        false
    }

    fn lift_data_insn(
        &mut self,
        mnem: &str,
        ops: &[Operand],
        rd: Reg,
        dst_w: u8,
        post_val: Option<u64>,
    ) -> Option<NodeId> {
        match mnem {
            "mov" | "movz" | "adr" | "adrp" => {
                if let Some(op1) = ops.get(1) {
                    self.operand_expr(op1, dst_w)
                } else {
                    None
                }
            }
            "movn" | "mvn" => {
                let src = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                Some(self.arena.unop(BvUnOp::Not, src, dst_w))
            }
            "movk" => {
                let cur = self.reg_expr(rd, dst_w);
                let (imm16, shift_bits) = match ops.get(1) {
                    Some(Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift }) => {
                        let sh = match shift {
                            Some(Shift::LSL(s)) => *s as u8,
                            _ => 0,
                        };
                        (imm_to_u64(*imm) & 0xFFFF, sh)
                    }
                    _ => return None,
                };
                if shift_bits >= dst_w {
                    return None;
                }
                let clear_mask = !(0xFFFFu64.wrapping_shl(u32::from(shift_bits))) & width_mask(dst_w);
                let m = self.arena.c(clear_mask, dst_w);
                let cleared = self.arena.binop(BvBinOp::And, cur, m, dst_w);
                let ins = self.arena.c(imm16.wrapping_shl(u32::from(shift_bits)), dst_w);
                Some(self.arena.binop(BvBinOp::Or, cleared, ins, dst_w))
            }
            "neg" | "negs" => {
                let src = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                Some(self.arena.unop(BvUnOp::Neg, src, dst_w))
            }
            "add" | "adds" => self.lift_bin(ops, BvBinOp::Add, dst_w),
            "sub" | "subs" => self.lift_bin(ops, BvBinOp::Sub, dst_w),
            "mul" => self.lift_bin(ops, BvBinOp::Mul, dst_w),
            "mneg" => {
                let prod = self.lift_bin(ops, BvBinOp::Mul, dst_w)?;
                Some(self.arena.unop(BvUnOp::Neg, prod, dst_w))
            }
            "madd" | "msub" => {
                let rn = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let rm = ops.get(2).and_then(|o| self.operand_expr(o, dst_w))?;
                let ra = ops.get(3).and_then(|o| self.operand_expr(o, dst_w))?;
                let prod = self.arena.binop(BvBinOp::Mul, rn, rm, dst_w);
                let op = if mnem == "madd" {
                    BvBinOp::Add
                } else {
                    BvBinOp::Sub
                };
                Some(self.arena.binop(op, ra, prod, dst_w))
            }
            "smull" | "umull" | "smaddl" | "umaddl" | "smsubl" | "umsubl" => {
                let signed = mnem.starts_with('s');
                let rn = ops.get(1).and_then(|o| self.operand_expr(o, 32))?;
                let rm = ops.get(2).and_then(|o| self.operand_expr(o, 32))?;
                let rn64 = self.arena.adapt_width(rn, 64, signed);
                let rm64 = self.arena.adapt_width(rm, 64, signed);
                let prod = self.arena.binop(BvBinOp::Mul, rn64, rm64, 64);
                if mnem.ends_with("addl") {
                    let ra = ops.get(3).and_then(|o| self.operand_expr(o, 64))?;
                    Some(self.arena.binop(BvBinOp::Add, ra, prod, 64))
                } else if mnem.ends_with("subl") {
                    let ra = ops.get(3).and_then(|o| self.operand_expr(o, 64))?;
                    Some(self.arena.binop(BvBinOp::Sub, ra, prod, 64))
                } else {
                    Some(prod)
                }
            }
            "umulh" => self.lift_bin(ops, BvBinOp::UMulh, 64),
            "smulh" => self.lift_bin(ops, BvBinOp::SMulh, 64),
            "udiv" => self.lift_bin(ops, BvBinOp::UDiv, dst_w),
            "sdiv" => self.lift_bin(ops, BvBinOp::SDiv, dst_w),
            "and" | "ands" => self.lift_bin(ops, BvBinOp::And, dst_w),
            "orr" => self.lift_bin(ops, BvBinOp::Or, dst_w),
            "eor" => self.lift_bin(ops, BvBinOp::Xor, dst_w),
            "bic" | "bics" => {
                let a = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let b = ops.get(2).and_then(|o| self.operand_expr(o, dst_w))?;
                let nb = self.arena.unop(BvUnOp::Not, b, dst_w);
                Some(self.arena.binop(BvBinOp::And, a, nb, dst_w))
            }
            "orn" => {
                let a = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let b = ops.get(2).and_then(|o| self.operand_expr(o, dst_w))?;
                let nb = self.arena.unop(BvUnOp::Not, b, dst_w);
                Some(self.arena.binop(BvBinOp::Or, a, nb, dst_w))
            }
            "eon" => {
                let a = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let b = ops.get(2).and_then(|o| self.operand_expr(o, dst_w))?;
                let nb = self.arena.unop(BvUnOp::Not, b, dst_w);
                Some(self.arena.binop(BvBinOp::Xor, a, nb, dst_w))
            }
            "lsl" | "lslv" => self.lift_bin(ops, BvBinOp::Shl, dst_w),
            "lsr" | "lsrv" => self.lift_bin(ops, BvBinOp::Lshr, dst_w),
            "asr" | "asrv" => self.lift_bin(ops, BvBinOp::Ashr, dst_w),
            "ror" | "rorv" => self.lift_bin(ops, BvBinOp::Ror, dst_w),
            "extr" => {
                let rn = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let rm = ops.get(2).and_then(|o| self.operand_expr(o, dst_w))?;
                let lsb = ops.get(3).and_then(Self::operand_imm_u64)?;
                if lsb >= u64::from(dst_w) {
                    return None;
                }
                if rn == rm {
                    let c = self.arena.c(lsb, dst_w);
                    Some(self.arena.binop(BvBinOp::Ror, rn, c, dst_w))
                } else if lsb == 0 {
                    Some(rm)
                } else {
                    let c_lsb = self.arena.c(lsb, dst_w);
                    let lo = self.arena.binop(BvBinOp::Lshr, rm, c_lsb, dst_w);
                    let c_hi = self.arena.c(u64::from(dst_w) - lsb, dst_w);
                    let hi = self.arena.binop(BvBinOp::Shl, rn, c_hi, dst_w);
                    Some(self.arena.binop(BvBinOp::Or, lo, hi, dst_w))
                }
            }
            "sxtb" | "sxth" | "sxtw" | "uxtb" | "uxth" => {
                let (src_w, signed) = match mnem {
                    "sxtb" => (8u8, true),
                    "sxth" => (16u8, true),
                    "sxtw" => (32u8, true),
                    "uxtb" => (8u8, false),
                    "uxth" => (16u8, false),
                    _ => unreachable!(),
                };
                let src = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let trunc = self.arena.adapt_width(src, src_w, false);
                Some(self.arena.adapt_width(trunc, dst_w, signed))
            }
            "ubfx" | "sbfx" => {
                let rn = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let lsb = ops.get(2).and_then(Self::operand_imm_u64)? as u8;
                let w = ops.get(3).and_then(Self::operand_imm_u64)? as u8;
                if w == 0 || u16::from(lsb) + u16::from(w) > u16::from(dst_w) {
                    return None;
                }
                let c_lsb = self.arena.c(u64::from(lsb), dst_w);
                let sh = self.arena.binop(BvBinOp::Lshr, rn, c_lsb, dst_w);
                if mnem == "ubfx" {
                    let mask = self.arena.c(width_mask(w), dst_w);
                    Some(self.arena.binop(BvBinOp::And, sh, mask, dst_w))
                } else {
                    let shl_amt = dst_w - (lsb + w);
                    let c_up = self.arena.c(u64::from(shl_amt), dst_w);
                    let up = self.arena.binop(BvBinOp::Shl, rn, c_up, dst_w);
                    let dn_amt = dst_w - w;
                    let c_dn = self.arena.c(u64::from(dn_amt), dst_w);
                    Some(self.arena.binop(BvBinOp::Ashr, up, c_dn, dst_w))
                }
            }
            "bfi" => {
                let dst = self.reg_expr(rd, dst_w);
                let src = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let lsb = ops.get(2).and_then(Self::operand_imm_u64)? as u8;
                let w = ops.get(3).and_then(Self::operand_imm_u64)? as u8;
                if w == 0 || u16::from(lsb) + u16::from(w) > u16::from(dst_w) {
                    return None;
                }
                let wmask = width_mask(w);
                let field_mask = wmask.wrapping_shl(u32::from(lsb)) & width_mask(dst_w);
                let c_clear = self.arena.c((!field_mask) & width_mask(dst_w), dst_w);
                let cleared = self.arena.binop(BvBinOp::And, dst, c_clear, dst_w);
                let c_wmask = self.arena.c(wmask, dst_w);
                let masked_src = self.arena.binop(BvBinOp::And, src, c_wmask, dst_w);
                let c_lsb = self.arena.c(u64::from(lsb), dst_w);
                let shifted_src = self.arena.binop(BvBinOp::Shl, masked_src, c_lsb, dst_w);
                Some(self.arena.binop(BvBinOp::Or, cleared, shifted_src, dst_w))
            }
            "bfxil" => {
                let dst = self.reg_expr(rd, dst_w);
                let src = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let lsb = ops.get(2).and_then(Self::operand_imm_u64)? as u8;
                let w = ops.get(3).and_then(Self::operand_imm_u64)? as u8;
                if w == 0 || u16::from(lsb) + u16::from(w) > u16::from(dst_w) {
                    return None;
                }
                let wmask = width_mask(w);
                let c_clear = self.arena.c((!wmask) & width_mask(dst_w), dst_w);
                let cleared = self.arena.binop(BvBinOp::And, dst, c_clear, dst_w);
                let c_lsb = self.arena.c(u64::from(lsb), dst_w);
                let shifted = self.arena.binop(BvBinOp::Lshr, src, c_lsb, dst_w);
                let c_wmask = self.arena.c(wmask, dst_w);
                let extracted = self.arena.binop(BvBinOp::And, shifted, c_wmask, dst_w);
                Some(self.arena.binop(BvBinOp::Or, cleared, extracted, dst_w))
            }
            "ubfiz" | "sbfiz" => {
                let rn = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let lsb = ops.get(2).and_then(Self::operand_imm_u64)? as u8;
                let w = ops.get(3).and_then(Self::operand_imm_u64)? as u8;
                if w == 0 || u16::from(lsb) + u16::from(w) > u16::from(dst_w) {
                    return None;
                }
                if mnem == "ubfiz" {
                    let mask = self.arena.c(width_mask(w), dst_w);
                    let masked = self.arena.binop(BvBinOp::And, rn, mask, dst_w);
                    let c_lsb = self.arena.c(u64::from(lsb), dst_w);
                    Some(self.arena.binop(BvBinOp::Shl, masked, c_lsb, dst_w))
                } else {
                    let up_amt = dst_w - w;
                    let c_up = self.arena.c(u64::from(up_amt), dst_w);
                    let up = self.arena.binop(BvBinOp::Shl, rn, c_up, dst_w);
                    let dn_amt = dst_w - (lsb + w);
                    let c_dn = self.arena.c(u64::from(dn_amt), dst_w);
                    let dn = self.arena.binop(BvBinOp::Ashr, up, c_dn, dst_w);
                    let c_clear = self.arena.c((!width_mask(lsb)) & width_mask(dst_w), dst_w);
                    Some(self.arena.binop(BvBinOp::And, dn, c_clear, dst_w))
                }
            }
            "ubfm" | "sbfm" => {
                let rn = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let immr = ops.get(2).and_then(Self::operand_imm_u64)? as u8;
                let imms = ops.get(3).and_then(Self::operand_imm_u64)? as u8;
                if immr >= dst_w || imms >= dst_w {
                    return None;
                }
                if imms >= immr {
                    // 等价 ubfx / sbfx(lsb=immr, width=imms-immr+1)
                    let lsb = immr;
                    let w = imms - immr + 1;
                    if mnem == "ubfm" {
                        let c_lsb = self.arena.c(u64::from(lsb), dst_w);
                        let sh = self.arena.binop(BvBinOp::Lshr, rn, c_lsb, dst_w);
                        let mask = self.arena.c(width_mask(w), dst_w);
                        Some(self.arena.binop(BvBinOp::And, sh, mask, dst_w))
                    } else {
                        let c_up = self.arena.c(u64::from(dst_w - (lsb + w)), dst_w);
                        let up = self.arena.binop(BvBinOp::Shl, rn, c_up, dst_w);
                        let c_dn = self.arena.c(u64::from(dst_w - w), dst_w);
                        Some(self.arena.binop(BvBinOp::Ashr, up, c_dn, dst_w))
                    }
                } else {
                    // 等价 ubfiz / sbfiz(lsb=dst_w-immr, width=imms+1)
                    let lsb = dst_w - immr;
                    let w = imms + 1;
                    if u16::from(lsb) + u16::from(w) > u16::from(dst_w) {
                        return None;
                    }
                    if mnem == "ubfm" {
                        let mask = self.arena.c(width_mask(w), dst_w);
                        let masked = self.arena.binop(BvBinOp::And, rn, mask, dst_w);
                        let c_lsb = self.arena.c(u64::from(lsb), dst_w);
                        Some(self.arena.binop(BvBinOp::Shl, masked, c_lsb, dst_w))
                    } else {
                        let c_up = self.arena.c(u64::from(dst_w - w), dst_w);
                        let up = self.arena.binop(BvBinOp::Shl, rn, c_up, dst_w);
                        let c_dn = self.arena.c(u64::from(dst_w - (lsb + w)), dst_w);
                        let dn = self.arena.binop(BvBinOp::Ashr, up, c_dn, dst_w);
                        let c_clear = self.arena.c((!width_mask(lsb)) & width_mask(dst_w), dst_w);
                        Some(self.arena.binop(BvBinOp::And, dn, c_clear, dst_w))
                    }
                }
            }
            "bfc" => {
                let dst = self.reg_expr(rd, dst_w);
                let lsb = ops.get(1).and_then(Self::operand_imm_u64)? as u8;
                let w = ops.get(2).and_then(Self::operand_imm_u64)? as u8;
                if w == 0 || u16::from(lsb) + u16::from(w) > u16::from(dst_w) {
                    return None;
                }
                let field_mask = width_mask(w).wrapping_shl(u32::from(lsb)) & width_mask(dst_w);
                let c_clear = self.arena.c((!field_mask) & width_mask(dst_w), dst_w);
                Some(self.arena.binop(BvBinOp::And, dst, c_clear, dst_w))
            }
            "rev" => {
                let src = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                Some(self.arena.unop(BvUnOp::Bswap, src, dst_w))
            }
            "rev16" => {
                let src = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let (m_lo, m_hi) = if dst_w == 32 {
                    (0x00FF_00FFu64, 0xFF00_FF00u64)
                } else {
                    (0x00FF_00FF_00FF_00FFu64, 0xFF00_FF00_FF00_FF00u64)
                };
                let c_lo = self.arena.c(m_lo, dst_w);
                let c_hi = self.arena.c(m_hi, dst_w);
                let c8 = self.arena.c(8, dst_w);
                let lo = self.arena.binop(BvBinOp::And, src, c_lo, dst_w);
                let hi = self.arena.binop(BvBinOp::And, src, c_hi, dst_w);
                let lo_sh = self.arena.binop(BvBinOp::Shl, lo, c8, dst_w);
                let hi_sh = self.arena.binop(BvBinOp::Lshr, hi, c8, dst_w);
                Some(self.arena.binop(BvBinOp::Or, lo_sh, hi_sh, dst_w))
            }
            "rev32" => {
                let src = ops.get(1).and_then(|o| self.operand_expr(o, 64))?;
                let lo = self.arena.extract(src, 0, 32);
                let hi = self.arena.extract(src, 32, 32);
                let blo = self.arena.unop(BvUnOp::Bswap, lo, 32);
                let bhi = self.arena.unop(BvUnOp::Bswap, hi, 32);
                let blo64 = self.arena.adapt_width(blo, 64, false);
                let bhi64 = self.arena.adapt_width(bhi, 64, false);
                let c32 = self.arena.c(32, 64);
                let bhi_sh = self.arena.binop(BvBinOp::Shl, bhi64, c32, 64);
                Some(self.arena.binop(BvBinOp::Or, blo64, bhi_sh, 64))
            }
            "rbit" => {
                let src = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                Some(self.arena.unop(BvUnOp::Rbit, src, dst_w))
            }
            "clz" => {
                let src = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                Some(self.arena.unop(BvUnOp::Clz, src, dst_w))
            }
            "cset" | "csetm" => post_val.map(|v| self.arena.c(v, dst_w)),
            "csel" | "csinc" | "csinv" | "csneg" | "cinc" | "cinv" | "cneg" => {
                // 单路径 Concolic 精选：对比指令执行后的具体结果决定沿本条 Trace 究竟命中哪一分支！
                let n_expr = ops.get(1).and_then(|o| self.operand_expr(o, dst_w))?;
                let m_raw = match mnem {
                    "cinc" | "cinv" | "cneg" => n_expr,
                    _ => ops.get(2).and_then(|o| self.operand_expr(o, dst_w))?,
                };
                let alt_expr = match mnem {
                    "csel" => m_raw,
                    "csinc" | "cinc" => {
                        let one = self.arena.c(1, dst_w);
                        self.arena.binop(BvBinOp::Add, m_raw, one, dst_w)
                    }
                    "csinv" | "cinv" => self.arena.unop(BvUnOp::Not, m_raw, dst_w),
                    "csneg" | "cneg" => self.arena.unop(BvUnOp::Neg, m_raw, dst_w),
                    _ => unreachable!(),
                };
                if n_expr == alt_expr {
                    return Some(n_expr);
                }
                let pv = post_val?;
                let pv_m = pv & width_mask(dst_w);
                let vn = self.arena.eval_sample(n_expr);
                let va = self.arena.eval_sample(alt_expr);
                if vn == Some(pv_m) && va != Some(pv_m) {
                    Some(n_expr)
                } else if va == Some(pv_m) && vn != Some(pv_m) {
                    Some(alt_expr)
                } else {
                    // 两个分支样本值相同或无法求值时绝不盲猜，降级为 Opaque
                    None
                }
            }
            _ => None,
        }
    }

    fn lift_bin(&mut self, ops: &[Operand], op: BvBinOp, width: u8) -> Option<NodeId> {
        let a = ops.get(1).and_then(|o| self.operand_expr(o, width))?;
        let b = ops.get(2).and_then(|o| self.operand_expr(o, width))?;
        Some(self.arena.binop(op, a, b, width))
    }

    /// 识别 S-Box / 常量表查找：`ldrb w5, [xtable, xidx{, lsl #s}]`（当 `xidx` 为符号表达式而 `xtable` 为非污点地址时）
    fn try_lift_table_load(
        &mut self,
        mem_op: Option<&Operand>,
        eff_addr: u64,
        elem_bytes: u8,
        sample_out: u64,
        reg_w: u8,
        is_signed: bool,
    ) -> Option<NodeId> {
        let Operand::MemExt { regs, shift, .. } = mem_op? else {
            return None;
        };
        let base_slot = parse_reg_slot(regs[0].name())?;
        let idx_slot = parse_reg_slot(regs[1].name())?;
        let idx_is_sym = self.sym_regs[idx_slot as usize].is_some()
            || self.origin_regs.contains(&idx_slot);
        let base_is_sym = self.sym_regs[base_slot as usize].is_some()
            || self.origin_regs.contains(&base_slot);
        if !idx_is_sym || base_is_sym {
            return None;
        }
        // 若被访问的表字节本身曾被当前切片写入（动态缓冲区而非只读表），不误判为只读 S-Box
        if (0..u64::from(elem_bytes)).any(|off| self.sym_mem.contains_key(&eff_addr.wrapping_add(off)))
        {
            return None;
        }

        let idx_reg_w = (regs[1].size() * 8).clamp(32, 64) as u8;
        let raw_idx = self.reg_expr(regs[1], idx_reg_w);
        let idx_expr = match shift {
            Some(Shift::UXTW(_)) => self.arena.adapt_width(raw_idx, 32, false),
            Some(Shift::SXTW(_)) => self.arena.adapt_width(raw_idx, 64, true),
            _ => raw_idx,
        };
        let scale_shift = match shift {
            Some(Shift::LSL(s) | Shift::UXTW(s) | Shift::SXTW(s) | Shift::SXTX(s)) => *s,
            _ => 0,
        };
        // C 数组下标 `sbox_N[idx]` 按 `sizeof(elem)` 步进，仅当移位步长严格等于元素字节宽度时提升为 TableLoad
        if (1u64.checked_shl(scale_shift)) != Some(u64::from(elem_bytes)) {
            return None;
        }
        // 有符号扩展可能产生负索引（C 无符号下标 UB），仅接受非负索引
        if matches!(shift, Some(Shift::SXTW(_))) {
            let raw_c = self.concrete_regs[idx_slot as usize].map(|v| sign_extend_u64(v, 32, 64));
            if raw_c.is_some_and(|v| (v as i64) < 0) {
                return None;
            }
        }
        let sample_idx = self.arena.eval_sample(idx_expr).or_else(|| {
            self.concrete_regs[idx_slot as usize].map(|v| match shift {
                Some(Shift::SXTW(_)) => sign_extend_u64(v, 32, 64),
                _ => v & width_mask(idx_reg_w),
            })
        });
        let base_addr = self.concrete_regs[base_slot as usize].or_else(|| {
            sample_idx.map(|iv| eff_addr.wrapping_sub(iv.wrapping_shl(scale_shift)))
        })?;
        // 校验基址 + 索引 * scale == eff_addr
        if let Some(iv) = sample_idx {
            if base_addr.wrapping_add(iv.wrapping_shl(scale_shift)) != eff_addr {
                return None;
            }
        }
        let load_w = (elem_bytes * 8).clamp(8, 64);
        let tnode = self.arena.table_load(
            base_addr,
            elem_bytes,
            idx_expr,
            load_w,
            sample_idx,
            sample_out,
        );
        Some(self.arena.adapt_width(tnode, reg_w, is_signed))
    }
}

fn imm_to_u64(imm: Imm) -> u64 {
    match imm {
        Imm::Signed(v) => v as u64,
        Imm::Unsigned(v) => v,
    }
}

fn vec_slot_index(reg: Reg) -> Option<usize> {
    let slot = parse_reg_slot(reg.name())?;
    if (32..64).contains(&slot) {
        Some((slot - 32) as usize)
    } else {
        None
    }
}

fn arr_lane(arr: ArrSpec) -> Option<usize> {
    let opt = match arr {
        ArrSpec::Full(l)
        | ArrSpec::TwoDoubles(l)
        | ArrSpec::FourSingles(l)
        | ArrSpec::EightHalves(l)
        | ArrSpec::SixteenBytes(l)
        | ArrSpec::OneDouble(l)
        | ArrSpec::TwoSingles(l)
        | ArrSpec::FourHalves(l)
        | ArrSpec::EightBytes(l)
        | ArrSpec::OneSingle(l)
        | ArrSpec::TwoHalves(l)
        | ArrSpec::FourBytes(l)
        | ArrSpec::OneHalf(l)
        | ArrSpec::OneByte(l) => l,
    };
    opt.map(|v| v as usize)
}

/// 解析向量排列规格，返回 `(total_bytes, elem_bytes, lane_opt)`
fn vec_arr_info_opt(arr: Option<ArrSpec>, default_total: usize) -> (usize, usize, Option<usize>) {
    match arr {
        Some(ArrSpec::SixteenBytes(l)) => (16, 1, l.map(|v| v as usize)),
        Some(ArrSpec::EightHalves(l)) => (16, 2, l.map(|v| v as usize)),
        Some(ArrSpec::FourSingles(l)) => (16, 4, l.map(|v| v as usize)),
        Some(ArrSpec::TwoDoubles(l)) => (16, 8, l.map(|v| v as usize)),
        Some(ArrSpec::EightBytes(l)) => (8, 1, l.map(|v| v as usize)),
        Some(ArrSpec::FourHalves(l)) => (8, 2, l.map(|v| v as usize)),
        Some(ArrSpec::TwoSingles(l)) => (8, 4, l.map(|v| v as usize)),
        Some(ArrSpec::OneDouble(l)) => (8, 8, l.map(|v| v as usize)),
        Some(ArrSpec::FourBytes(l)) => (4, 1, l.map(|v| v as usize)),
        Some(ArrSpec::TwoHalves(l)) => (4, 2, l.map(|v| v as usize)),
        Some(ArrSpec::OneSingle(l)) => (4, 4, l.map(|v| v as usize)),
        Some(ArrSpec::OneHalf(l)) => (2, 2, l.map(|v| v as usize)),
        Some(ArrSpec::OneByte(l)) => (1, 1, l.map(|v| v as usize)),
        Some(ArrSpec::Full(l)) => (16, 16, l.map(|v| v as usize)),
        None => (default_total.clamp(8, 16), 1, None),
    }
}

/// 从单条指令的 `MemRead` 事件切片中重组 `[base_addr, base_addr + byte_len)`（`1..=8` 字节，兼容跨页拆分读）
fn sample_bytes_from_reads(reads: &[&ExtRecord], base_addr: u64, byte_len: usize) -> Option<u64> {
    let n = byte_len.clamp(1, 8);
    let mut bytes = [None::<u8>; 8];
    for ev in reads {
        let sz = (ev.size_or_reg as usize).clamp(1, 8);
        for b in 0..sz {
            let a = ev.addr.wrapping_add(b as u64);
            let off = a.wrapping_sub(base_addr);
            if (off as usize) < n {
                bytes[off as usize] = Some(((ev.value >> (b * 8)) & 0xFF) as u8);
            }
        }
    }
    if !bytes[..n].iter().all(Option::is_some) {
        return None;
    }
    let mut acc = 0u64;
    for (i, b) in bytes[..n].iter().enumerate() {
        acc |= u64::from(b.unwrap()) << (i * 8);
    }
    Some(acc)
}

/// 从单条指令的 `MemRead` 事件切片中重组 `[base_addr, base_addr + 16)` 的低/高 64 位具体样本值
fn sample_16b_from_reads(reads: &[&ExtRecord], base_addr: u64) -> (Option<u64>, Option<u64>) {
    (
        sample_bytes_from_reads(reads, base_addr, 8),
        sample_bytes_from_reads(reads, base_addr.wrapping_add(8), 8),
    )
}

// ============================================================================
// 4. 精简伪 C 生成器（含连续输入缓冲归并 + CSE 公共子表达式提取）与 SMT-LIB2 导出
// ============================================================================

struct MemBufGroup {
    name: String,
    base_addr: u64,
    len: usize,
    samples: Vec<Option<u8>>,
}

struct OutputChunkSpec {
    byte_offset: usize,
    byte_len: usize,
    root: NodeId,
    expected: Option<u64>,
    evaluated: Option<u64>,
}

struct EmitMeta<'a> {
    is_multi_buf: bool,
    fn_name: &'a str,
    expected_out: Option<u64>,
    eval_out: Option<u64>,
    expected_bytes_hex: Option<&'a str>,
    eval_bytes_hex: Option<&'a str>,
    verified: Option<bool>,
}

struct CCodeEmitter<'a> {
    arena: &'a BvArena,
    /// `addr -> (buf_idx, offset)`
    mem_map: HashMap<u64, (usize, usize)>,
    mem_bufs: Vec<MemBufGroup>,
    sym_regs: Vec<(u8, String, u8, Option<u64>)>,
    used_tables: BTreeSet<usize>,
    need_load16: bool,
    need_load32: bool,
    need_load64: bool,
    need_store16: bool,
    need_store32: bool,
    need_store64: bool,
    need_aes_aese: bool,
    need_aes_aesd: bool,
    need_aes_mc: bool,
    need_aes_imc: bool,
    need_rotr32: bool,
    need_rotr64: bool,
    need_bswap16: bool,
    need_bswap32: bool,
    need_bswap64: bool,
    need_rbit32: bool,
    need_rbit64: bool,
    need_clz32: bool,
    need_clz64: bool,
    need_ashr8: bool,
    need_ashr16: bool,
    need_ashr32: bool,
    need_ashr64: bool,
    need_udiv32: bool,
    need_udiv64: bool,
    need_sdiv32: bool,
    need_sdiv64: bool,
    need_umulh64: bool,
    need_smulh64: bool,
    suppress_mulh_hint: bool,
    cse_names: HashMap<NodeId, String>,
    stmts: Vec<String>,
}

impl<'a> CCodeEmitter<'a> {
    fn emit_multi(
        arena: &'a BvArena,
        chunks: &[OutputChunkSpec],
        meta: &EmitMeta<'_>,
    ) -> (String, Vec<DecompiledInput>, Vec<DecompiledTable>) {
        let is_multi_buf = meta.is_multi_buf;
        let fn_name = meta.fn_name;
        let expected_out = meta.expected_out;
        let eval_out = meta.eval_out;
        let expected_bytes_hex = meta.expected_bytes_hex;
        let eval_bytes_hex = meta.eval_bytes_hex;
        let verified = meta.verified;
        // 1. 收集从全部输出根可达的符号输入与查找表
        let mut reachable = HashSet::new();
        for ch in chunks {
            arena.visit_reachable(ch.root, &mut reachable);
        }

        let mut raw_mem_addrs: BTreeMap<u64, Option<u8>> = BTreeMap::new();
        let mut reg_map: BTreeMap<(u8, String), (String, u8, Option<u64>)> = BTreeMap::new();
        let mut used_tables = BTreeSet::new();

        for &id in &reachable {
            match arena.get(id) {
                BvNode::SymMemByte { addr, sample } => {
                    raw_mem_addrs.insert(*addr, *sample);
                }
                BvNode::SymReg {
                    reg_slot,
                    name,
                    width,
                    sample,
                } => {
                    let key = (*reg_slot, name.clone());
                    reg_map
                        .entry(key)
                        .and_modify(|e| {
                            e.1 = e.1.max(*width);
                            if e.2.is_none() {
                                e.2 = *sample;
                            }
                        })
                        .or_insert_with(|| (name.clone(), *width, *sample));
                }
                BvNode::TableLoad { table_id, .. } => {
                    used_tables.insert(*table_id);
                }
                _ => {}
            }
        }

        // 将相邻（间隔 <= 16 字节）的符号输入内存归并成连续输入缓冲区 `in_0`, `in_1`
        let mut mem_bufs: Vec<MemBufGroup> = Vec::new();
        let mut mem_map: HashMap<u64, (usize, usize)> = HashMap::new();
        for (addr, sample) in raw_mem_addrs {
            let attach_prev = mem_bufs.last().and_then(|b| {
                let end = b.base_addr.wrapping_add(b.len as u64);
                if addr >= b.base_addr && addr <= end.wrapping_add(16) {
                    Some(addr - b.base_addr)
                } else {
                    None
                }
            });
            if let Some(off) = attach_prev {
                let bidx = mem_bufs.len() - 1;
                let off_usize = off as usize;
                let buf = &mut mem_bufs[bidx];
                if off_usize >= buf.len {
                    buf.samples.resize(off_usize + 1, None);
                    buf.len = off_usize + 1;
                }
                buf.samples[off_usize] = sample;
                mem_map.insert(addr, (bidx, off_usize));
            } else {
                let bidx = mem_bufs.len();
                mem_bufs.push(MemBufGroup {
                    name: format!("in_{bidx}"),
                    base_addr: addr,
                    len: 1,
                    samples: vec![sample],
                });
                mem_map.insert(addr, (bidx, 0));
            }
        }

        let sym_regs: Vec<(u8, String, u8, Option<u64>)> = reg_map
            .into_iter()
            .map(|((slot, _), (name, w, s))| (slot, name, w, s))
            .collect();

        // 2. 跨全部输出根联合统计父引用次数，一次共享 CSE 抽公共子表达式
        let mut ref_count: HashMap<NodeId, usize> = HashMap::new();
        let mut order: Vec<NodeId> = Vec::new();
        let mut visited = HashSet::new();
        for ch in chunks {
            collect_postorder(arena, ch.root, &mut visited, &mut ref_count, &mut order);
        }
        let root_set: HashSet<NodeId> = chunks.iter().map(|c| c.root).collect();

        let mut emitter = Self {
            arena,
            mem_map,
            mem_bufs,
            sym_regs,
            used_tables,
            need_load16: false,
            need_load32: false,
            need_load64: false,
            need_store16: false,
            need_store32: false,
            need_store64: false,
            need_aes_aese: false,
            need_aes_aesd: false,
            need_aes_mc: false,
            need_aes_imc: false,
            need_rotr32: false,
            need_rotr64: false,
            need_bswap16: false,
            need_bswap32: false,
            need_bswap64: false,
            need_rbit32: false,
            need_rbit64: false,
            need_clz32: false,
            need_clz64: false,
            need_ashr8: false,
            need_ashr16: false,
            need_ashr32: false,
            need_ashr64: false,
            need_udiv32: false,
            need_udiv64: false,
            need_sdiv32: false,
            need_sdiv64: false,
            need_umulh64: false,
            need_smulh64: false,
            suppress_mulh_hint: false,
            cse_names: HashMap::new(),
            stmts: Vec::new(),
        };

        // 将引用次数 >= 2 且非叶子的节点提升为局部变量 `t0, t1, ...`
        let mut tmp_idx = 0usize;
        for &id in &order {
            if !is_multi_buf && root_set.contains(&id) {
                continue;
            }
            let rc = ref_count.get(&id).copied().unwrap_or(0);
            if rc >= 2 && !is_leaf_or_trivial(arena, id) {
                let expr = emitter.fmt_expr(id, 0);
                let cname = format!("t{tmp_idx}");
                tmp_idx += 1;
                let ctype = c_uint_type(arena.width(id));
                emitter.stmts.push(format!("    {ctype} {cname} = {expr};"));
                emitter.cse_names.insert(id, cname);
            }
        }

        let mut body_tail = String::new();
        let ret_type = if is_multi_buf {
            for ch in chunks {
                let expr = emitter.fmt_expr(ch.root, 0);
                let off = ch.byte_offset;
                let dst = if off == 0 {
                    "out".to_string()
                } else {
                    format!("out + {off}")
                };
                match ch.byte_len {
                    1 => body_tail.push_str(&format!("    out[{off}] = {expr};\n")),
                    2 => {
                        emitter.need_store16 = true;
                        body_tail.push_str(&format!("    STORE16_LE({dst}, {expr});\n"));
                    }
                    4 => {
                        emitter.need_store32 = true;
                        body_tail.push_str(&format!("    STORE32_LE({dst}, {expr});\n"));
                    }
                    _ => {
                        emitter.need_store64 = true;
                        body_tail.push_str(&format!("    STORE64_LE({dst}, {expr});\n"));
                    }
                }
            }
            "void"
        } else {
            let root = chunks[0].root;
            let root_expr = emitter.fmt_expr(root, 0);
            body_tail.push_str(&format!("    return {root_expr};\n"));
            c_uint_type(arena.width(root))
        };

        // 3. 拼装完整自包含 C 代码
        let mut code = String::new();
        code.push_str("#include <stdint.h>\n\n");
        let mut any_helper = false;
        if emitter.need_load16 {
            code.push_str("static inline uint16_t LOAD16_LE(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8)); }\n");
            any_helper = true;
        }
        if emitter.need_load32 {
            code.push_str("static inline uint32_t LOAD32_LE(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }\n");
            any_helper = true;
        }
        if emitter.need_load64 {
            code.push_str("static inline uint64_t LOAD64_LE(const uint8_t *p) { return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56); }\n");
            any_helper = true;
        }
        if emitter.need_store16 {
            code.push_str("static inline void STORE16_LE(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }\n");
            any_helper = true;
        }
        if emitter.need_store32 {
            code.push_str("static inline void STORE32_LE(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }\n");
            any_helper = true;
        }
        if emitter.need_store64 {
            code.push_str("static inline void STORE64_LE(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (i * 8)); }\n");
            any_helper = true;
        }
        if emitter.need_rotr32 {
            code.push_str("static inline uint32_t ROTR32(uint32_t x, unsigned n) { return (x >> (n & 31)) | (x << ((32 - n) & 31)); }\n");
            any_helper = true;
        }
        if emitter.need_rotr64 {
            code.push_str("static inline uint64_t ROTR64(uint64_t x, unsigned n) { return (x >> (n & 63)) | (x << ((64 - n) & 63)); }\n");
            any_helper = true;
        }
        if emitter.need_bswap16 {
            code.push_str("static inline uint16_t BSWAP16(uint16_t x) { return (uint16_t)((x << 8) | (x >> 8)); }\n");
            any_helper = true;
        }
        if emitter.need_bswap32 {
            code.push_str("static inline uint32_t BSWAP32(uint32_t x) { return __builtin_bswap32(x); }\n");
            any_helper = true;
        }
        if emitter.need_bswap64 {
            code.push_str("static inline uint64_t BSWAP64(uint64_t x) { return __builtin_bswap64(x); }\n");
            any_helper = true;
        }
        if emitter.need_rbit32 {
            code.push_str("static inline uint32_t RBIT32(uint32_t x) { uint32_t r = 0; for (int i = 0; i < 32; ++i) { r = (r << 1) | (x & 1u); x >>= 1; } return r; }\n");
            any_helper = true;
        }
        if emitter.need_rbit64 {
            code.push_str("static inline uint64_t RBIT64(uint64_t x) { uint64_t r = 0; for (int i = 0; i < 64; ++i) { r = (r << 1) | (x & 1ull); x >>= 1; } return r; }\n");
            any_helper = true;
        }
        if emitter.need_clz32 {
            code.push_str("static inline uint32_t CLZ32(uint32_t x) { return x ? (uint32_t)__builtin_clz(x) : 32u; }\n");
            any_helper = true;
        }
        if emitter.need_clz64 {
            code.push_str("static inline uint64_t CLZ64(uint64_t x) { return x ? (uint64_t)__builtin_clzll(x) : 64ull; }\n");
            any_helper = true;
        }
        if emitter.need_ashr8 {
            code.push_str("static inline uint8_t ASHR8(uint8_t x, uint32_t n) { return (uint8_t)((int8_t)x >> (n & 7u)); }\n");
            any_helper = true;
        }
        if emitter.need_ashr16 {
            code.push_str("static inline uint16_t ASHR16(uint16_t x, uint32_t n) { return (uint16_t)((int16_t)x >> (n & 15u)); }\n");
            any_helper = true;
        }
        if emitter.need_ashr32 {
            code.push_str("static inline uint32_t ASHR32(uint32_t x, uint32_t n) { return (uint32_t)((int32_t)x >> (n & 31u)); }\n");
            any_helper = true;
        }
        if emitter.need_ashr64 {
            code.push_str("static inline uint64_t ASHR64(uint64_t x, uint64_t n) { return (uint64_t)((int64_t)x >> (n & 63u)); }\n");
            any_helper = true;
        }
        if emitter.need_udiv32 {
            code.push_str("static inline uint32_t UDIV32(uint32_t a, uint32_t b) { return b ? (a / b) : 0u; }\n");
            any_helper = true;
        }
        if emitter.need_udiv64 {
            code.push_str("static inline uint64_t UDIV64(uint64_t a, uint64_t b) { return b ? (a / b) : 0ull; }\n");
            any_helper = true;
        }
        if emitter.need_sdiv32 {
            code.push_str("static inline uint32_t SDIV32(uint32_t a, uint32_t b) { int32_t sa = (int32_t)a, sb = (int32_t)b; if (sb == 0) return 0u; if (sa == (-2147483647 - 1) && sb == -1) return a; return (uint32_t)(sa / sb); }\n");
            any_helper = true;
        }
        if emitter.need_sdiv64 {
            code.push_str("static inline uint64_t SDIV64(uint64_t a, uint64_t b) { int64_t sa = (int64_t)a, sb = (int64_t)b; if (sb == 0) return 0ull; if (sa == (-9223372036854775807LL - 1) && sb == -1) return a; return (uint64_t)(sa / sb); }\n");
            any_helper = true;
        }
        if emitter.need_umulh64 {
            code.push_str("#ifdef __SIZEOF_INT128__\nstatic inline uint64_t UMULH64(uint64_t a, uint64_t b) { return (uint64_t)(((unsigned __int128)a * (unsigned __int128)b) >> 64); }\n#else\nstatic inline uint64_t UMULH64(uint64_t a, uint64_t b) { uint64_t a0 = a & 0xffffffffull, a1 = a >> 32, b0 = b & 0xffffffffull, b1 = b >> 32; uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1; uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffull) + (p10 & 0xffffffffull); return p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32); }\n#endif\n");
            any_helper = true;
        }
        if emitter.need_smulh64 {
            code.push_str("#ifdef __SIZEOF_INT128__\nstatic inline uint64_t SMULH64(uint64_t a, uint64_t b) { return (uint64_t)(((__int128)(int64_t)a * (__int128)(int64_t)b) >> 64); }\n#else\nstatic inline uint64_t SMULH64(uint64_t a, uint64_t b) { uint64_t ua = a, ub = b, hi = 0; uint64_t a0 = ua & 0xffffffffull, a1 = ua >> 32, b0 = ub & 0xffffffffull, b1 = ub >> 32; uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1; uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffull) + (p10 & 0xffffffffull); hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32); if ((int64_t)a < 0) hi -= ub; if ((int64_t)b < 0) hi -= ua; return hi; }\n#endif\n");
            any_helper = true;
        }
        if emitter.need_aes_aese || emitter.need_aes_aesd || emitter.need_aes_mc || emitter.need_aes_imc {
            emit_c_aes_helpers(
                &mut code,
                emitter.need_aes_aese,
                emitter.need_aes_aesd,
                emitter.need_aes_mc,
                emitter.need_aes_imc,
            );
            any_helper = true;
        }
        if any_helper {
            code.push('\n');
        }

        let safe_fn_name = sanitize_c_ident(fn_name);

        // 函数签名
        let mut params: Vec<String> = Vec::new();
        for buf in &emitter.mem_bufs {
            params.push(format!("const uint8_t *{}", buf.name));
        }
        for (_, name, w, _) in &emitter.sym_regs {
            params.push(format!("{} {}", c_uint_type(*w), name));
        }
        let mut out_tables = Vec::new();
        for &tid in &emitter.used_tables {
            let tbl = &arena.tables[tid];
            out_tables.push(tbl.clone());
            let elem_ty = c_uint_type(tbl.elem_bytes * 8);
            params.push(format!("const {elem_ty} *{}", tbl.name));
        }
        if is_multi_buf {
            params.push("uint8_t *out".to_string());
        }
        let param_str = if params.is_empty() {
            "void".to_string()
        } else {
            params.join(", ")
        };

        code.push_str(&format!("{ret_type} {safe_fn_name}({param_str}) {{\n"));
        for st in &emitter.stmts {
            code.push_str(st);
            code.push('\n');
        }
        code.push_str(&body_tail);
        code.push_str("}\n");

        // 附加输入/表/自校验样本注释，方便逆向工程师直接对照或写单元测试
        code.push_str("\n/* Trace concrete sample:\n");
        let mut out_inputs = Vec::new();
        for buf in &emitter.mem_bufs {
            let hex_bytes = buf
                .samples
                .iter()
                .map(|b| match b {
                    Some(v) => format!("{v:02x}"),
                    None => "??".to_string(),
                })
                .collect::<Vec<_>>()
                .join(" ");
            code.push_str(&format!(
                " *   {} @ 0x{:016x} ({}B) = [{}]\n",
                buf.name, buf.base_addr, buf.len, hex_bytes
            ));
            out_inputs.push(DecompiledInput {
                name: buf.name.clone(),
                kind: "mem",
                addr: Some(buf.base_addr),
                width_bytes: buf.len,
                sample_hex: Some(hex_bytes),
            });
        }
        for (slot, name, w, sample) in &emitter.sym_regs {
            let sh = sample.map(|v| format!("0x{v:x}"));
            code.push_str(&format!(
                " *   {} ({}b) = {}\n",
                name,
                w,
                sh.as_deref().unwrap_or("<unknown>")
            ));
            out_inputs.push(DecompiledInput {
                name: name.clone(),
                kind: if *slot >= 96 { "hle_source" } else { "reg" },
                addr: None,
                width_bytes: (*w as usize) / 8,
                sample_hex: sh,
            });
        }
        for tbl in &out_tables {
            let entries = tbl
                .observed_entries
                .iter()
                .take(16)
                .map(|(k, v)| format!("[0x{k:x}]=0x{v:x}"))
                .collect::<Vec<_>>()
                .join(", ");
            code.push_str(&format!(
                " *   {} @ 0x{:016x} ({}B/elem): {entries}\n",
                tbl.name, tbl.base_addr, tbl.elem_bytes
            ));
        }
        if is_multi_buf {
            if let Some(exp_hex) = expected_bytes_hex {
                code.push_str(&format!(" *   expected_output  = [{exp_hex}]\n"));
            }
            if let Some(ev_hex) = eval_bytes_hex {
                code.push_str(&format!(" *   evaluated_output = [{ev_hex}]\n"));
            }
        } else {
            if let Some(exp) = expected_out {
                code.push_str(&format!(" *   expected_output  = 0x{exp:x}\n"));
            }
            if let Some(ev) = eval_out {
                code.push_str(&format!(" *   evaluated_output = 0x{ev:x}\n"));
            }
        }
        code.push_str(&format!(" *   verified         = {verified:?}\n"));
        code.push_str(" */\n");

        (code, out_inputs, out_tables)
    }

    /// 识别连续小端输入字节加载链：`in_k[off] | (in_k[off+1] << 8) | ...` -> `(buf_idx, off)`
    fn match_le_mem_load(&self, root_or: NodeId, width: u8) -> Option<(usize, usize)> {
        let num_bytes = (width / 8) as usize;
        let mut terms = Vec::with_capacity(num_bytes);
        let mut stack = vec![root_or];
        while let Some(cur) = stack.pop() {
            if cur != root_or && self.cse_names.contains_key(&cur) {
                return None;
            }
            if let BvNode::BinOp {
                op: BvBinOp::Or,
                a,
                b,
                width: w,
            } = self.arena.get(cur)
            {
                if *w == width {
                    stack.push(*b);
                    stack.push(*a);
                    continue;
                }
            }
            terms.push(cur);
            if terms.len() > num_bytes {
                return None;
            }
        }
        if terms.len() != num_bytes {
            return None;
        }
        let mut lanes: Vec<Option<(usize, usize, u64)>> = vec![None; num_bytes];
        for term in terms {
            if self.cse_names.contains_key(&term) {
                return None;
            }
            let (inner, lane) = match self.arena.get(term) {
                BvNode::BinOp {
                    op: BvBinOp::Shl,
                    a,
                    b,
                    ..
                } => {
                    let sh = self.arena.as_const(*b)?;
                    if !sh.is_multiple_of(8) || sh >= u64::from(width) {
                        return None;
                    }
                    (*a, (sh / 8) as usize)
                }
                _ => (term, 0usize),
            };
            let addr = self.extract_sym_mem_addr(inner)?;
            let &(bidx, off) = self.mem_map.get(&addr)?;
            if lane >= num_bytes || lanes[lane].is_some() {
                return None;
            }
            lanes[lane] = Some((bidx, off, addr));
        }
        let (bidx0, off0, addr0) = lanes[0]?;
        for (i, item) in lanes.iter().enumerate().skip(1) {
            let (bi, oi, ai) = (*item)?;
            if bi != bidx0 || oi != off0 + i || ai != addr0.wrapping_add(i as u64) {
                return None;
            }
        }
        Some((bidx0, off0))
    }

    fn extract_sym_mem_addr(&self, mut id: NodeId) -> Option<u64> {
        loop {
            if self.cse_names.contains_key(&id) {
                return None;
            }
            match self.arena.get(id) {
                BvNode::SymMemByte { addr, .. } => return Some(*addr),
                BvNode::UnOp {
                    op: BvUnOp::ZExt,
                    x,
                    ..
                } => id = *x,
                BvNode::BinOp {
                    op: BvBinOp::And,
                    a,
                    b,
                    ..
                } if self.arena.as_const(*b) == Some(0xFF) => id = *a,
                _ => return None,
            }
        }
    }

    fn fmt_expr(&mut self, id: NodeId, parent_prec: u8) -> String {
        if let Some(name) = self.cse_names.get(&id) {
            return name.clone();
        }
        match self.arena.get(id).clone() {
            BvNode::Const { val, width } => {
                if width > 32 {
                    if val <= 9 {
                        format!("{val}ULL")
                    } else {
                        format!("0x{val:x}ULL")
                    }
                } else if val <= 9 {
                    format!("{val}u")
                } else {
                    format!("0x{val:x}u")
                }
            }
            BvNode::SymReg { name, .. } => name,
            BvNode::SymMemByte { addr, .. } => {
                if let Some(&(bidx, off)) = self.mem_map.get(&addr) {
                    format!("{}[{off}]", self.mem_bufs[bidx].name)
                } else {
                    format!("MEM_U8(0x{addr:x}ULL)")
                }
            }
            BvNode::TableLoad {
                table_id,
                idx,
                ..
            } => {
                let sidx = self.fmt_expr(idx, 0);
                format!("{}[{sidx}]", self.arena.tables[table_id].name)
            }
            BvNode::AesOp {
                kind,
                state_lo,
                state_hi,
                key_lo,
                key_hi,
                hi_half,
            } => {
                let slo = self.fmt_expr(state_lo, 0);
                let shi = self.fmt_expr(state_hi, 0);
                let half = if hi_half { "HI" } else { "LO" };
                match kind {
                    AesOpKind::Aese => {
                        self.need_aes_aese = true;
                        let klo = key_lo.map(|k| self.fmt_expr(k, 0)).unwrap_or_else(|| "0ULL".to_string());
                        let khi = key_hi.map(|k| self.fmt_expr(k, 0)).unwrap_or_else(|| "0ULL".to_string());
                        format!("AES_AESE_{half}({slo}, {shi}, {klo}, {khi})")
                    }
                    AesOpKind::Aesd => {
                        self.need_aes_aesd = true;
                        let klo = key_lo.map(|k| self.fmt_expr(k, 0)).unwrap_or_else(|| "0ULL".to_string());
                        let khi = key_hi.map(|k| self.fmt_expr(k, 0)).unwrap_or_else(|| "0ULL".to_string());
                        format!("AES_AESD_{half}({slo}, {shi}, {klo}, {khi})")
                    }
                    AesOpKind::Aesmc => {
                        self.need_aes_mc = true;
                        format!("AES_MC_{half}({slo}, {shi})")
                    }
                    AesOpKind::Aesimc => {
                        self.need_aes_imc = true;
                        format!("AES_IMC_{half}({slo}, {shi})")
                    }
                }
            }
            BvNode::Opaque { asm, width, .. } => {
                let safe = asm.replace("*/", "* /").replace("/*", "/ *");
                let lit = if width > 32 { "0ULL" } else { "0u" };
                format!("(/* opaque: {safe} */ {lit})")
            }
            BvNode::Extract { x, lsb, width } => {
                let sx = self.fmt_expr(x, 14);
                let mask = width_mask(width);
                let ty = c_uint_type(width);
                let suffix = if width > 32 || self.arena.width(x) > 32 {
                    "ULL"
                } else {
                    "u"
                };
                if lsb == 0 {
                    format!("({ty})({sx} & 0x{mask:x}{suffix})")
                } else {
                    format!("({ty})(({sx} >> {lsb}u) & 0x{mask:x}{suffix})")
                }
            }
            BvNode::UnOp { op, x, width } => match op {
                BvUnOp::Not => {
                    let sx = self.fmt_expr(x, 14);
                    if width < 32 {
                        let ty = c_uint_type(width);
                        wrap_prec(format!("({ty})(~(uint32_t){sx})"), 14, parent_prec)
                    } else {
                        wrap_prec(format!("~{sx}"), 14, parent_prec)
                    }
                }
                BvUnOp::Neg => {
                    let sx = self.fmt_expr(x, 14);
                    if width < 32 {
                        let ty = c_uint_type(width);
                        wrap_prec(format!("({ty})(-(uint32_t){sx})"), 14, parent_prec)
                    } else {
                        wrap_prec(format!("-{sx}"), 14, parent_prec)
                    }
                }
                BvUnOp::Bswap => {
                    let sx = self.fmt_expr(x, 0);
                    if width <= 16 {
                        self.need_bswap16 = true;
                        format!("BSWAP16({sx})")
                    } else if width <= 32 {
                        self.need_bswap32 = true;
                        format!("BSWAP32({sx})")
                    } else {
                        self.need_bswap64 = true;
                        format!("BSWAP64({sx})")
                    }
                }
                BvUnOp::Rbit => {
                    let sx = self.fmt_expr(x, 0);
                    if width <= 32 {
                        self.need_rbit32 = true;
                        format!("RBIT32({sx})")
                    } else {
                        self.need_rbit64 = true;
                        format!("RBIT64({sx})")
                    }
                }
                BvUnOp::Clz => {
                    let sx = self.fmt_expr(x, 0);
                    if width <= 32 {
                        self.need_clz32 = true;
                        format!("CLZ32({sx})")
                    } else {
                        self.need_clz64 = true;
                        format!("CLZ64({sx})")
                    }
                }
                BvUnOp::ZExt | BvUnOp::Trunc => {
                    let sx = self.fmt_expr(x, 14);
                    let ty = c_uint_type(width);
                    wrap_prec(format!("({ty}){sx}"), 14, parent_prec)
                }
                BvUnOp::SExt => {
                    let from_w = self.arena.width(x);
                    let sx = self.fmt_expr(x, 14);
                    let sty = c_int_type(from_w);
                    let uty = c_uint_type(width);
                    wrap_prec(format!("({uty})({sty}){sx}"), 14, parent_prec)
                }
            },
            BvNode::BinOp { op, a, b, width } => {
                if op == BvBinOp::Or && matches!(width, 16 | 32 | 64) {
                    if let Some((bidx, off)) = self.match_le_mem_load(id, width) {
                        let ptr = if off == 0 {
                            self.mem_bufs[bidx].name.clone()
                        } else {
                            format!("{} + {off}", self.mem_bufs[bidx].name)
                        };
                        return match width {
                            16 => {
                                self.need_load16 = true;
                                format!("LOAD16_LE({ptr})")
                            }
                            32 => {
                                self.need_load32 = true;
                                format!("LOAD32_LE({ptr})")
                            }
                            _ => {
                                self.need_load64 = true;
                                format!("LOAD64_LE({ptr})")
                            }
                        };
                    }
                }
                if op == BvBinOp::Ror {
                    let sa = self.fmt_expr(a, 0);
                    let sb = self.fmt_expr(b, 0);
                    return if width <= 32 {
                        self.need_rotr32 = true;
                        format!("ROTR32({sa}, {sb})")
                    } else {
                        self.need_rotr64 = true;
                        format!("ROTR64({sa}, {sb})")
                    };
                }
                if op == BvBinOp::UMulh {
                    self.need_umulh64 = true;
                    let sa = self.fmt_expr(a, 0);
                    let sb = self.fmt_expr(b, 0);
                    let hint = if self.suppress_mulh_hint {
                        String::new()
                    } else {
                        self.arena
                            .as_const(b)
                            .and_then(|m| detect_magic_udiv(m, 0))
                            .map(|d| format!(" /* ~= / {d} */"))
                            .unwrap_or_default()
                    };
                    return format!("UMULH64({sa}, {sb}){hint}");
                }
                if op == BvBinOp::SMulh {
                    self.need_smulh64 = true;
                    let sa = self.fmt_expr(a, 0);
                    let sb = self.fmt_expr(b, 0);
                    let hint = if self.suppress_mulh_hint {
                        String::new()
                    } else {
                        self.arena
                            .as_const(b)
                            .and_then(|m| detect_magic_sdiv(m, 0))
                            .map(|d| format!(" /* ~= / {d} */"))
                            .unwrap_or_default()
                    };
                    return format!("SMULH64({sa}, {sb}){hint}");
                }
                if op == BvBinOp::Ashr {
                    let hint = self
                        .arena
                        .as_const(b)
                        .and_then(|sh| {
                            if let BvNode::BinOp {
                                op: BvBinOp::SMulh,
                                b: mul_rhs,
                                ..
                            } = self.arena.get(a)
                            {
                                self.arena
                                    .as_const(*mul_rhs)
                                    .and_then(|m| detect_magic_sdiv(m, sh as u32))
                            } else {
                                None
                            }
                        })
                        .map(|d| format!(" /* ~= / {d} */"))
                        .unwrap_or_default();
                    let prev_sup = self.suppress_mulh_hint;
                    if !hint.is_empty() {
                        self.suppress_mulh_hint = true;
                    }
                    let sa = self.fmt_expr(a, 0);
                    self.suppress_mulh_hint = prev_sup;
                    let sb = self.fmt_expr(b, 0);
                    return if width <= 8 {
                        self.need_ashr8 = true;
                        format!("ASHR8({sa}, {sb}){hint}")
                    } else if width <= 16 {
                        self.need_ashr16 = true;
                        format!("ASHR16({sa}, {sb}){hint}")
                    } else if width <= 32 {
                        self.need_ashr32 = true;
                        format!("ASHR32({sa}, {sb}){hint}")
                    } else {
                        self.need_ashr64 = true;
                        format!("ASHR64({sa}, {sb}){hint}")
                    };
                }
                if op == BvBinOp::UDiv {
                    let sa = self.fmt_expr(a, 0);
                    let sb = self.fmt_expr(b, 0);
                    return if width <= 32 {
                        self.need_udiv32 = true;
                        format!("UDIV32({sa}, {sb})")
                    } else {
                        self.need_udiv64 = true;
                        format!("UDIV64({sa}, {sb})")
                    };
                }
                if op == BvBinOp::SDiv {
                    let sa = self.fmt_expr(a, 0);
                    let sb = self.fmt_expr(b, 0);
                    return if width <= 32 {
                        self.need_sdiv32 = true;
                        format!("SDIV32({sa}, {sb})")
                    } else {
                        self.need_sdiv64 = true;
                        format!("SDIV64({sa}, {sb})")
                    };
                }
                if matches!(op, BvBinOp::Shl | BvBinOp::Lshr) {
                    let sym = if op == BvBinOp::Shl { "<<" } else { ">>" };
                    let hint = if op == BvBinOp::Lshr && width >= 32 {
                        self.arena
                            .as_const(b)
                            .and_then(|sh| {
                                if let BvNode::BinOp {
                                    op: BvBinOp::UMulh,
                                    b: mul_rhs,
                                    ..
                                } = self.arena.get(a)
                                {
                                    self.arena
                                        .as_const(*mul_rhs)
                                        .and_then(|m| detect_magic_udiv(m, sh as u32))
                                } else {
                                    None
                                }
                            })
                            .map(|d| format!(" /* ~= / {d} */"))
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    let prev_sup = self.suppress_mulh_hint;
                    if !hint.is_empty() {
                        self.suppress_mulh_hint = true;
                    }
                    let sa_raw = self.fmt_expr(a, 14);
                    self.suppress_mulh_hint = prev_sup;
                    let sa = if width < 32 {
                        format!("(uint32_t){sa_raw}")
                    } else {
                        sa_raw
                    };
                    let mask = width.saturating_sub(1);
                    let sb = if let Some(cv) = self.arena.as_const(b) {
                        format!("{}u", cv % u64::from(width.max(1)))
                    } else {
                        let raw_b = self.fmt_expr(b, 14);
                        format!("({raw_b} & {mask}u)")
                    };
                    if width < 32 {
                        let ty = c_uint_type(width);
                        return wrap_prec(format!("({ty})({sa} {sym} {sb})"), 14, parent_prec);
                    }
                    return wrap_prec(format!("{sa} {sym} {sb}{hint}"), 11, parent_prec);
                }
                let (sym, prec, child_l_prec, child_r_prec) = match op {
                    BvBinOp::Mul => ("*", 13, 13, 14),
                    BvBinOp::Add => ("+", 12, 12, 13),
                    BvBinOp::Sub => ("-", 12, 12, 13),
                    // 混合位运算与算术/移位时给子表达式加括号（同时满足 GCC `-Werror=parentheses` 与 Clang `-Wbitwise-op-parentheses`）
                    BvBinOp::And => ("&", 8, 13, 13),
                    BvBinOp::Xor => ("^", 7, 13, 13),
                    BvBinOp::Or => ("|", 6, 13, 13),
                    BvBinOp::Ror
                    | BvBinOp::Ashr
                    | BvBinOp::UDiv
                    | BvBinOp::SDiv
                    | BvBinOp::UMulh
                    | BvBinOp::SMulh
                    | BvBinOp::Shl
                    | BvBinOp::Lshr => unreachable!(),
                };
                if width < 32 {
                    let sa = self.fmt_expr(a, 14);
                    let sb = self.fmt_expr(b, 14);
                    let ty = c_uint_type(width);
                    return wrap_prec(
                        format!("({ty})((uint32_t){sa} {sym} (uint32_t){sb})"),
                        14,
                        parent_prec,
                    );
                }
                // 当父节点是移位（prec==11）或异构位运算时强制保留外层括号，避免 `-Wshift-op-parentheses`
                let sa = self.fmt_expr(a, child_l_prec);
                let sb = self.fmt_expr(b, child_r_prec);
                wrap_prec(format!("{sa} {sym} {sb}"), prec, parent_prec)
            }
        }
    }
}

fn emit_c_aes_helpers(code: &mut String, aese: bool, aesd: bool, mc: bool, imc: bool) {
    let push_table = |out: &mut String, name: &str, tbl: &[u8; 256]| {
        out.push_str(&format!("static const uint8_t {name}[256] = {{"));
        for (i, &b) in tbl.iter().enumerate() {
            if i % 16 == 0 {
                out.push_str("\n    ");
            }
            out.push_str(&format!("0x{b:02x}"));
            if i + 1 < 256 {
                out.push_str(", ");
            }
        }
        out.push_str("\n};\n");
    };
    code.push_str("static inline uint64_t aes_pack64(const uint8_t *p) { uint64_t r = 0; for (int i = 0; i < 8; ++i) r |= ((uint64_t)p[i] << (i * 8)); return r; }\n");
    code.push_str("static inline void aes_unpack128(uint64_t lo, uint64_t hi, uint8_t out[16]) { for (int i = 0; i < 8; ++i) { out[i] = (uint8_t)(lo >> (i * 8)); out[i + 8] = (uint8_t)(hi >> (i * 8)); } }\n");
    if aese {
        push_table(code, "AES_SBOX", &AES_SBOX);
        code.push_str("static inline void AES_AESE_128(uint64_t slo, uint64_t shi, uint64_t klo, uint64_t khi, uint8_t out[16]) { uint8_t s[16]; aes_unpack128(slo ^ klo, shi ^ khi, s); for (int c = 0; c < 4; ++c) for (int r = 0; r < 4; ++r) out[c * 4 + r] = AES_SBOX[s[((c + r) & 3) * 4 + r]]; }\n");
        code.push_str("static inline uint64_t AES_AESE_LO(uint64_t slo, uint64_t shi, uint64_t klo, uint64_t khi) { uint8_t o[16]; AES_AESE_128(slo, shi, klo, khi, o); return aes_pack64(o); }\n");
        code.push_str("static inline uint64_t AES_AESE_HI(uint64_t slo, uint64_t shi, uint64_t klo, uint64_t khi) { uint8_t o[16]; AES_AESE_128(slo, shi, klo, khi, o); return aes_pack64(o + 8); }\n");
    }
    if aesd {
        push_table(code, "AES_INV_SBOX", &AES_INV_SBOX);
        code.push_str("static inline void AES_AESD_128(uint64_t slo, uint64_t shi, uint64_t klo, uint64_t khi, uint8_t out[16]) { uint8_t s[16]; aes_unpack128(slo ^ klo, shi ^ khi, s); for (int c = 0; c < 4; ++c) for (int r = 0; r < 4; ++r) out[c * 4 + r] = AES_INV_SBOX[s[((c + 4 - r) & 3) * 4 + r]]; }\n");
        code.push_str("static inline uint64_t AES_AESD_LO(uint64_t slo, uint64_t shi, uint64_t klo, uint64_t khi) { uint8_t o[16]; AES_AESD_128(slo, shi, klo, khi, o); return aes_pack64(o); }\n");
        code.push_str("static inline uint64_t AES_AESD_HI(uint64_t slo, uint64_t shi, uint64_t klo, uint64_t khi) { uint8_t o[16]; AES_AESD_128(slo, shi, klo, khi, o); return aes_pack64(o + 8); }\n");
    }
    if mc || imc {
        code.push_str("static inline uint8_t aes_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0u)); }\n");
    }
    if mc {
        code.push_str("static inline void AES_MC_128(uint64_t slo, uint64_t shi, uint8_t out[16]) { uint8_t s[16]; aes_unpack128(slo, shi, s); for (int c = 0; c < 4; ++c) { uint8_t b0 = s[c*4], b1 = s[c*4+1], b2 = s[c*4+2], b3 = s[c*4+3]; uint8_t x0 = aes_xtime(b0), x1 = aes_xtime(b1), x2 = aes_xtime(b2), x3 = aes_xtime(b3); out[c*4] = x0 ^ x1 ^ b1 ^ b2 ^ b3; out[c*4+1] = b0 ^ x1 ^ x2 ^ b2 ^ b3; out[c*4+2] = b0 ^ b1 ^ x2 ^ x3 ^ b3; out[c*4+3] = x0 ^ b0 ^ b1 ^ b2 ^ x3; } }\n");
        code.push_str("static inline uint64_t AES_MC_LO(uint64_t slo, uint64_t shi) { uint8_t o[16]; AES_MC_128(slo, shi, o); return aes_pack64(o); }\n");
        code.push_str("static inline uint64_t AES_MC_HI(uint64_t slo, uint64_t shi) { uint8_t o[16]; AES_MC_128(slo, shi, o); return aes_pack64(o + 8); }\n");
    }
    if imc {
        code.push_str("static inline uint8_t aes_gmul(uint8_t a, uint8_t b) { uint8_t p = 0; for (int i = 0; i < 8; ++i) { if (b & 1u) p ^= a; a = aes_xtime(a); b >>= 1; } return p; }\n");
        code.push_str("static inline void AES_IMC_128(uint64_t slo, uint64_t shi, uint8_t out[16]) { uint8_t s[16]; aes_unpack128(slo, shi, s); for (int c = 0; c < 4; ++c) { uint8_t b0 = s[c*4], b1 = s[c*4+1], b2 = s[c*4+2], b3 = s[c*4+3]; out[c*4] = aes_gmul(b0, 0x0e) ^ aes_gmul(b1, 0x0b) ^ aes_gmul(b2, 0x0d) ^ aes_gmul(b3, 0x09); out[c*4+1] = aes_gmul(b0, 0x09) ^ aes_gmul(b1, 0x0e) ^ aes_gmul(b2, 0x0b) ^ aes_gmul(b3, 0x0d); out[c*4+2] = aes_gmul(b0, 0x0d) ^ aes_gmul(b1, 0x09) ^ aes_gmul(b2, 0x0e) ^ aes_gmul(b3, 0x0b); out[c*4+3] = aes_gmul(b0, 0x0b) ^ aes_gmul(b1, 0x0d) ^ aes_gmul(b2, 0x09) ^ aes_gmul(b3, 0x0e); } }\n");
        code.push_str("static inline uint64_t AES_IMC_LO(uint64_t slo, uint64_t shi) { uint8_t o[16]; AES_IMC_128(slo, shi, o); return aes_pack64(o); }\n");
        code.push_str("static inline uint64_t AES_IMC_HI(uint64_t slo, uint64_t shi) { uint8_t o[16]; AES_IMC_128(slo, shi, o); return aes_pack64(o + 8); }\n");
    }
}

fn sanitize_c_ident(raw: &str) -> String {
    const C_KEYWORDS: &[&str] = &[
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
        "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
        "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
        "union", "unsigned", "void", "volatile", "while", "uint8_t", "uint16_t", "uint32_t",
        "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "out", "LOAD16_LE", "LOAD32_LE",
        "LOAD64_LE", "STORE16_LE", "STORE32_LE", "STORE64_LE", "AES_SBOX", "AES_INV_SBOX",
        "AES_AESE_128", "AES_AESE_LO", "AES_AESE_HI", "AES_AESD_128", "AES_AESD_LO", "AES_AESD_HI",
        "AES_MC_128", "AES_MC_LO", "AES_MC_HI", "AES_IMC_128", "AES_IMC_LO", "AES_IMC_HI",
        "aes_pack64", "aes_unpack128", "aes_xtime", "aes_gmul", "ROTR32", "ROTR64", "BSWAP16",
        "BSWAP32", "BSWAP64", "RBIT32", "RBIT64", "CLZ32", "CLZ64", "ASHR8", "ASHR16", "ASHR32",
        "ASHR64", "UDIV32", "UDIV64", "SDIV32", "SDIV64", "UMULH64", "SMULH64",
    ];
    let trimmed = raw.trim();
    let mut out = String::with_capacity(trimmed.len());
    for (i, ch) in trimmed.chars().enumerate() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if i == 0 && ch.is_ascii_digit() {
                out.push('_');
            }
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.chars().all(|c| c == '_') || C_KEYWORDS.contains(&out.as_str()) {
        "decompiled_slice".to_string()
    } else {
        out
    }
}

/// 魔数无符号除法反推：识别编译器生成的 `UMULH64(x, M) >> s`（如 `/ 1000`、`/ 60000`）
fn detect_magic_udiv(magic: u64, shift: u32) -> Option<u64> {
    if magic < (1u64 << 32) || shift >= 64 {
        return None;
    }
    let total_shift = 64 + shift;
    if total_shift >= 127 {
        return None;
    }
    let numer = 1u128 << total_shift;
    let d128 = numer.div_ceil(u128::from(magic));
    if d128 < 3 || d128 > u128::from(u32::MAX) {
        return None;
    }
    let d = d128 as u64;
    let hi_mult = (u64::MAX / d).saturating_mul(d);
    for &probe in &[
        0u64,
        d - 1,
        d,
        d.saturating_mul(7) + 1,
        d.saturating_mul(12345),
        hi_mult.saturating_sub(1),
        u64::MAX,
    ] {
        let got = ((u128::from(probe) * u128::from(magic)) >> total_shift) as u64;
        if got != probe / d {
            return None;
        }
    }
    Some(d)
}

/// 魔数有符号除法反推：识别编译器生成的 `SMULH64(x, M) >> s`（如 `/ 1000`、`/ 60000`）
fn detect_magic_sdiv(magic: u64, shift: u32) -> Option<u64> {
    let m = magic as i64;
    if m <= 0 || (m as u64) < (1u64 << 32) || shift >= 63 {
        return None;
    }
    let total_shift = 64 + shift;
    if total_shift >= 127 {
        return None;
    }
    let numer = 1u128 << total_shift;
    let d128 = numer.div_ceil(m as u128);
    if d128 < 3 || d128 > u128::from(u32::MAX) {
        return None;
    }
    let d = d128 as u64;
    let di = d as i64;
    let hi_mult = (i64::MAX / di).saturating_mul(di);
    for &probe in &[
        0i64,
        di - 1,
        di,
        di.saturating_mul(19) + 1,
        di.saturating_mul(10000),
        hi_mult.saturating_sub(1),
        i64::MAX,
    ] {
        let got = ((i128::from(probe) * i128::from(m)) >> total_shift) as i64;
        if got != probe / di {
            return None;
        }
    }
    Some(d)
}

fn c_uint_type(width: u8) -> &'static str {
    match width {
        0..=8 => "uint8_t",
        9..=16 => "uint16_t",
        17..=32 => "uint32_t",
        _ => "uint64_t",
    }
}

fn c_int_type(width: u8) -> &'static str {
    match width {
        0..=8 => "int8_t",
        9..=16 => "int16_t",
        17..=32 => "int32_t",
        _ => "int64_t",
    }
}

fn wrap_prec(s: String, prec: u8, parent_prec: u8) -> String {
    if prec < parent_prec {
        format!("({s})")
    } else {
        s
    }
}

fn is_leaf_or_trivial(arena: &BvArena, id: NodeId) -> bool {
    match arena.get(id) {
        BvNode::Const { .. } | BvNode::SymReg { .. } | BvNode::SymMemByte { .. } => true,
        BvNode::UnOp {
            op: BvUnOp::ZExt | BvUnOp::Trunc,
            x,
            ..
        } => matches!(
            arena.get(*x),
            BvNode::SymMemByte { .. } | BvNode::SymReg { .. }
        ),
        _ => false,
    }
}

fn collect_postorder(
    arena: &BvArena,
    id: NodeId,
    visited: &mut HashSet<NodeId>,
    ref_count: &mut HashMap<NodeId, usize>,
    order: &mut Vec<NodeId>,
) {
    *ref_count.entry(id).or_insert(0) += 1;
    if !visited.insert(id) {
        return;
    }
    match arena.get(id) {
        BvNode::Const { .. } | BvNode::SymReg { .. } | BvNode::SymMemByte { .. } => {}
        BvNode::UnOp { x, .. } | BvNode::Extract { x, .. } => {
            collect_postorder(arena, *x, visited, ref_count, order);
        }
        BvNode::BinOp { a, b, .. } => {
            collect_postorder(arena, *a, visited, ref_count, order);
            collect_postorder(arena, *b, visited, ref_count, order);
        }
        BvNode::TableLoad { idx, .. } => {
            collect_postorder(arena, *idx, visited, ref_count, order);
        }
        BvNode::AesOp {
            state_lo,
            state_hi,
            key_lo,
            key_hi,
            ..
        } => {
            collect_postorder(arena, *state_lo, visited, ref_count, order);
            collect_postorder(arena, *state_hi, visited, ref_count, order);
            if let Some(k) = key_lo {
                collect_postorder(arena, *k, visited, ref_count, order);
            }
            if let Some(k) = key_hi {
                collect_postorder(arena, *k, visited, ref_count, order);
            }
        }
        BvNode::Opaque { .. } => {
            // Opaque 在 C/SMT2 导出中作为独立占位符，不遍历其 args，避免产生未被引用的 CSE 临时变量
        }
    }
    order.push(id);
}

/// 将化简后的 Bit-Vector DAG（支持多输出缓冲区）导出为标准 `QF_BV` / `QF_UFBV` SMT-LIB2（可直接喂给 Z3 / Bitwuzla）
fn emit_smt2_multi(arena: &BvArena, chunks: &[OutputChunkSpec]) -> String {
    let mut visited = HashSet::new();
    let mut ref_count = HashMap::new();
    let mut order = Vec::new();
    for ch in chunks {
        collect_postorder(arena, ch.root, &mut visited, &mut ref_count, &mut order);
    }

    let has_uf = order.iter().any(|&id| {
        matches!(
            arena.get(id),
            BvNode::TableLoad { .. } | BvNode::AesOp { .. }
        )
    });
    let mut out = if has_uf {
        String::from("(set-logic QF_UFBV)\n")
    } else {
        String::from("(set-logic QF_BV)\n")
    };
    let mut declared_syms = BTreeSet::new();
    let mut declared_tables: HashMap<(usize, u8), String> = HashMap::new();
    let mut declared_aes: HashSet<(AesOpKind, bool)> = HashSet::new();
    let mut names: HashMap<NodeId, String> = HashMap::new();

    for &id in &order {
        match arena.get(id) {
            BvNode::SymReg { name, width, .. } => {
                if declared_syms.insert(name.clone()) {
                    out.push_str(&format!("(declare-const {name} (_ BitVec {width}))\n"));
                }
                names.insert(id, name.clone());
            }
            BvNode::SymMemByte { addr, .. } => {
                let name = format!("mem_{addr:x}");
                if declared_syms.insert(name.clone()) {
                    out.push_str(&format!("(declare-const {name} (_ BitVec 8))\n"));
                }
                names.insert(id, name);
            }
            BvNode::Opaque { asm, width, .. } => {
                let name = format!("opaque_{id}");
                let safe_asm = asm.replace('\n', " ");
                out.push_str(&format!(
                    "; unmodeled opaque instruction: {safe_asm}\n(declare-const {name} (_ BitVec {width}))\n"
                ));
                names.insert(id, name);
            }
            BvNode::TableLoad {
                table_id,
                idx,
                width,
                ..
            } => {
                let idx_w = arena.width(*idx).max(1);
                let key = (*table_id, idx_w);
                if let std::collections::hash_map::Entry::Vacant(ent) = declared_tables.entry(key) {
                    let tname = format!("sbox_{table_id}_w{idx_w}");
                    out.push_str(&format!(
                        "(declare-fun {tname} ((_ BitVec {idx_w})) (_ BitVec {width}))\n"
                    ));
                    for (&k, &v) in &arena.tables[*table_id].observed_entries {
                        let km = k & width_mask(idx_w);
                        let vm = v & width_mask(*width);
                        out.push_str(&format!(
                            "(assert (= ({tname} (_ bv{km} {idx_w})) (_ bv{vm} {width})))\n"
                        ));
                    }
                    ent.insert(tname);
                }
            }
            BvNode::AesOp { kind, hi_half, .. } if declared_aes.insert((*kind, *hi_half)) => {
                let fname = smt_aes_fn_name(*kind, *hi_half);
                if matches!(kind, AesOpKind::Aese | AesOpKind::Aesd) {
                    out.push_str(&format!(
                        "(declare-fun {fname} ((_ BitVec 64) (_ BitVec 64) (_ BitVec 64) (_ BitVec 64)) (_ BitVec 64))\n"
                    ));
                } else {
                    out.push_str(&format!(
                        "(declare-fun {fname} ((_ BitVec 64) (_ BitVec 64)) (_ BitVec 64))\n"
                    ));
                }
            }
            _ => {}
        }
    }

    for &id in &order {
        if names.contains_key(&id) {
            continue;
        }
        let w = arena.width(id).max(1);
        let expr = match arena.get(id) {
            BvNode::Const { val, width } => format!("(_ bv{val} {})", (*width).max(1)),
            BvNode::UnOp { op, x, width } => {
                let sx = &names[x];
                let xw = arena.width(*x).max(1);
                let tw = (*width).max(1);
                match op {
                    BvUnOp::Not => format!("(bvnot {sx})"),
                    BvUnOp::Neg => format!("(bvneg {sx})"),
                    BvUnOp::ZExt => format!("((_ zero_extend {}) {sx})", tw.saturating_sub(xw)),
                    BvUnOp::SExt => format!("((_ sign_extend {}) {sx})", tw.saturating_sub(xw)),
                    BvUnOp::Trunc => {
                        let hi = tw.min(xw).saturating_sub(1);
                        format!("((_ extract {hi} 0) {sx})")
                    }
                    BvUnOp::Bswap => smt_bswap(sx, tw),
                    BvUnOp::Rbit => smt_rbit(sx, tw),
                    BvUnOp::Clz => smt_clz(sx, tw),
                }
            }
            BvNode::Extract { x, lsb, width } => {
                let sx = &names[x];
                let xw = arena.width(*x).max(1);
                let tw = (*width).max(1);
                let lo = (*lsb).min(xw - 1);
                let hi = lo.saturating_add(tw - 1).min(xw - 1);
                format!("((_ extract {hi} {lo}) {sx})")
            }
            BvNode::BinOp { op, a, b, width } => {
                let sa = &names[a];
                let sb = &names[b];
                let tw = (*width).max(1);
                let sb_mod = smt_shift_mod(sb, tw);
                match op {
                    BvBinOp::Add => format!("(bvadd {sa} {sb})"),
                    BvBinOp::Sub => format!("(bvsub {sa} {sb})"),
                    BvBinOp::Mul => format!("(bvmul {sa} {sb})"),
                    BvBinOp::UMulh => format!(
                        "((_ extract 127 64) (bvmul ((_ zero_extend 64) {sa}) ((_ zero_extend 64) {sb})))"
                    ),
                    BvBinOp::SMulh => format!(
                        "((_ extract 127 64) (bvmul ((_ sign_extend 64) {sa}) ((_ sign_extend 64) {sb})))"
                    ),
                    BvBinOp::UDiv => format!("(ite (= {sb} (_ bv0 {tw})) (_ bv0 {tw}) (bvudiv {sa} {sb}))"),
                    BvBinOp::SDiv => format!("(ite (= {sb} (_ bv0 {tw})) (_ bv0 {tw}) (bvsdiv {sa} {sb}))"),
                    BvBinOp::And => format!("(bvand {sa} {sb})"),
                    BvBinOp::Or => format!("(bvor {sa} {sb})"),
                    BvBinOp::Xor => format!("(bvxor {sa} {sb})"),
                    BvBinOp::Shl => format!("(bvshl {sa} {sb_mod})"),
                    BvBinOp::Lshr => format!("(bvlshr {sa} {sb_mod})"),
                    BvBinOp::Ashr => format!("(bvashr {sa} {sb_mod})"),
                    BvBinOp::Ror => {
                        if let Some(k) = arena.as_const(*b) {
                            let km = k % u64::from(tw);
                            format!("((_ rotate_right {km}) {sa})")
                        } else {
                            format!(
                                "(ite (= {sb_mod} (_ bv0 {tw})) {sa} (bvor (bvlshr {sa} {sb_mod}) (bvshl {sa} (bvsub (_ bv{tw} {tw}) {sb_mod}))))"
                            )
                        }
                    }
                }
            }
            BvNode::TableLoad { table_id, idx, .. } => {
                let sidx = &names[idx];
                let idx_w = arena.width(*idx).max(1);
                let tname = &declared_tables[&(*table_id, idx_w)];
                format!("({tname} {sidx})")
            }
            BvNode::AesOp {
                kind,
                state_lo,
                state_hi,
                key_lo,
                key_hi,
                hi_half,
            } => {
                let fname = smt_aes_fn_name(*kind, *hi_half);
                let slo = &names[state_lo];
                let shi = &names[state_hi];
                if matches!(kind, AesOpKind::Aese | AesOpKind::Aesd) {
                    let klo = key_lo.map(|k| names[&k].as_str()).unwrap_or("(_ bv0 64)");
                    let khi = key_hi.map(|k| names[&k].as_str()).unwrap_or("(_ bv0 64)");
                    format!("({fname} {slo} {shi} {klo} {khi})")
                } else {
                    format!("({fname} {slo} {shi})")
                }
            }
            BvNode::Opaque { .. } | BvNode::SymReg { .. } | BvNode::SymMemByte { .. } => {
                unreachable!()
            }
        };
        let nname = format!("n{id}");
        out.push_str(&format!("(define-fun {nname} () (_ BitVec {w}) {expr})\n"));
        names.insert(id, nname);
    }

    for ch in chunks {
        let root_name = &names[&ch.root];
        let rw = arena.width(ch.root).max(1);
        if let Some(exp) = ch.expected {
            let em = exp & width_mask(rw);
            out.push_str(&format!("(assert (= {root_name} (_ bv{em} {rw})))\n"));
        }
    }
    out.push_str("(check-sat)\n(get-model)\n");
    out
}

fn smt_aes_fn_name(kind: AesOpKind, hi_half: bool) -> &'static str {
    match (kind, hi_half) {
        (AesOpKind::Aese, false) => "aes_aese_lo",
        (AesOpKind::Aese, true) => "aes_aese_hi",
        (AesOpKind::Aesd, false) => "aes_aesd_lo",
        (AesOpKind::Aesd, true) => "aes_aesd_hi",
        (AesOpKind::Aesmc, false) => "aes_mc_lo",
        (AesOpKind::Aesmc, true) => "aes_mc_hi",
        (AesOpKind::Aesimc, false) => "aes_imc_lo",
        (AesOpKind::Aesimc, true) => "aes_imc_hi",
    }
}

fn smt_shift_mod(sb: &str, width: u8) -> String {
    if width.is_power_of_two() {
        format!("(bvand {sb} (_ bv{} {width}))", width - 1)
    } else {
        format!("(bvurem {sb} (_ bv{width} {width}))")
    }
}

fn smt_bswap(sx: &str, width: u8) -> String {
    let bytes = usize::from(width) / 8;
    if bytes <= 1 || !usize::from(width).is_multiple_of(8) {
        return sx.to_string();
    }
    let mut expr = format!("((_ extract {} {}) {sx})", width - 1, width - 8);
    for b in (0..(bytes - 1)).rev() {
        let lo = b * 8;
        let hi = lo + 7;
        expr = format!("(concat ((_ extract {hi} {lo}) {sx}) {expr})");
    }
    expr
}

fn smt_rbit(sx: &str, width: u8) -> String {
    if width <= 1 {
        return sx.to_string();
    }
    let mut expr = format!("((_ extract {} {}) {sx})", width - 1, width - 1);
    for bit in (0..(width - 1)).rev() {
        expr = format!("(concat ((_ extract {bit} {bit}) {sx}) {expr})");
    }
    expr
}

fn smt_clz(sx: &str, width: u8) -> String {
    let mut expr = format!("(_ bv{width} {width})");
    for bit in 0..width {
        let leading = width - 1 - bit;
        expr = format!(
            "(ite (= ((_ extract {bit} {bit}) {sx}) (_ bv1 1)) (_ bv{leading} {width}) {expr})"
        );
    }
    expr
}

// ============================================================================
// 5. TraceReader 入口方法
// ============================================================================

impl TraceReader {
    /// 动态污点切片 → 单路径符号提升 → 代数/MBA 化简 → 自校验精简伪 C（及可选 SMT-LIB2）
    pub fn decompile_slice(&self, seed: &TaintSeed, opts: &DecompileOptions) -> DecompileReport {
        // 内部使用 max_steps: usize::MAX 避免截断因果链导致中段指令静默常量折叠；返回前再按 opts.max_steps 截取展示步数
        let taint_opts = TaintOptions {
            anchor_idx: opts.anchor_idx,
            min_idx: opts.from_idx,
            stop_at_pcs: opts.stop_at_pcs.clone(),
            stop_mem_ranges: opts.stop_mem_ranges.clone(),
            max_insns: opts.max_insns,
            max_steps: usize::MAX,
            track_mem_index: opts.track_mem_index,
            track_sp: opts.track_sp,
        };
        let bwd = self.taint_backward(seed, &taint_opts);

        let anchor_idx = bwd.anchor_idx;
        let stop_idx = bwd.stop_idx;
        let slice_idxs: HashSet<usize> = bwd.steps.iter().map(|s| s.idx).collect();

        // 收集反向切片给出的「输入起源」寄存器与内存字节
        let mut origin_regs = HashSet::new();
        for (rname, _) in &bwd.tainted_regs {
            if let Some(slot) = parse_reg_slot(rname) {
                origin_regs.insert(slot);
            }
        }
        let mut origin_mem_addrs = HashSet::new();
        for &(base, len, _) in &bwd.tainted_mem_ranges {
            for off in 0..len {
                origin_mem_addrs.insert(base.wrapping_add(off as u64));
            }
        }

        // 若扫描起点大于 0，仍从 `0` 开始跟踪具体寄存器值与写集合，以捕获边界寄存器初始值及可写内存集合（供 --fold-rodata 判断）
        let hle_events = self.hle_events();
        let mut hle_by_seq: HashMap<u32, Vec<HleTraceEvent>> = HashMap::new();
        for ev in hle_events {
            hle_by_seq.entry(ev.seq_low32).or_default().push(ev);
        }

        let mut lifter = SliceLifter::new(
            self,
            origin_regs,
            origin_mem_addrs,
            opts.stop_mem_ranges.clone(),
            opts.fold_rodata,
            &opts.initial_regs,
            opts.track_sp,
        );

        let mut last_mem_write_bytes: HashMap<u64, u8> = HashMap::new();

        // P1-3: 当开启 --fold-rodata 时，单遍线性 O(E) 预扫描整个 Trace 的 .ext 写事件（含全部 HLE），
        // 避免逐条指令二分/分配开销，并防止「先读后写」（含 --at 之后才写入）的可变内存被误折成常量。
        if opts.fold_rodata {
            for i in 0..self.ext_len() {
                if let Some(ev) = self.get_ext(i) {
                    if ev.kind == ExtKind::MemWrite as u8 {
                        let sz = (ev.size_or_reg as usize).clamp(1, 16);
                        let base = ev.addr;
                        for b in 0..sz {
                            lifter.ever_written_mem.insert(base.wrapping_add(b as u64));
                        }
                    }
                }
            }
            for ev in hle_by_seq.values().flatten() {
                let is_mem_writer = matches!(
                    ev.op,
                    "memcpy" | "memmove" | "realloc_copy" | "memset" | "bzero" | "calloc_zero"
                ) || (is_hle_entropy_or_time_mem(ev.op) && ev.dst != 0)
                    || (ev.op == "time" && ev.dst != 0);
                if is_mem_writer && ev.dst != 0 {
                    let len = ev.len.min(64 * 1024);
                    for i in 0..len {
                        lifter.ever_written_mem.insert(ev.dst.wrapping_add(i));
                    }
                }
            }
        }

        if !self.is_empty() {
            // 若 Trace 头部记录了入口初始寄存器快照（如进程内混合引擎 `runidbg-zygisk`），先预装具体值，
            // 使符号提升后的 `arg_x0..arg_x7` 自动带有真实入口样本并可直接通过 bit-exact 自校验。
            for (reg_id, val) in self.initial_reg_snapshot() {
                if (reg_id as usize) < lifter.concrete_regs.len() {
                    lifter.concrete_regs[reg_id as usize].get_or_insert(val);
                }
            }
            let end_idx = anchor_idx.min(self.len() - 1);
            for idx in 0..=end_idx {
                let Some(rec) = self.get(idx) else {
                    break;
                };
                let seq = rec.seq_low32;
                let mem_evs = self.mem_events_for(idx);
                let post_deltas = self.reg_deltas_for(idx);

                // 记录内存写具体值与曾被写入的地址集合（用于 expected_output 与 --fold-rodata）
                for ev in &mem_evs {
                    if ev.kind == ExtKind::MemWrite as u8 {
                        let sz = (ev.size_or_reg as usize).clamp(1, 16);
                        for b in 0..sz {
                            let a = ev.addr.wrapping_add(b as u64);
                            lifter.ever_written_mem.insert(a);
                            if b < 8 {
                                last_mem_write_bytes
                                    .insert(a, ((ev.value >> (b * 8)) & 0xFF) as u8);
                            } else {
                                last_mem_write_bytes.remove(&a);
                            }
                        }
                    }
                }

                if idx >= stop_idx && slice_idxs.contains(&idx) {
                    if let Ok(insn) = bad64::decode(rec.opcode, rec.pc) {
                        lifter.lift_insn(idx, &insn, &mem_evs, &post_deltas);
                    }
                } else if idx >= stop_idx {
                    // 非切片指令覆写了曾经带符号的寄存器或内存时，必须清除脏符号状态！
                    for &(reg_id, _) in &post_deltas {
                        if (reg_id as usize) < 64 {
                            lifter.sym_regs[reg_id as usize] = None;
                            if reg_id >= 32 {
                                lifter.sym_vec_hi[(reg_id - 32) as usize] = None;
                            }
                        }
                    }
                    if let Ok(insn) = bad64::decode(rec.opcode, rec.pc) {
                        let mnem = insn.op().to_string().to_ascii_lowercase();
                        if !matches!(
                            mnem.as_str(),
                            "str" | "stur" | "strb" | "sturb" | "strh" | "sturh" | "stp" | "stnp"
                                | "stlr" | "stlrb" | "stlrh" | "st1" | "cmp" | "cmn" | "tst"
                                | "cbz" | "cbnz" | "tbz" | "tbnz" | "b" | "br" | "ret"
                        ) && !mnem.starts_with("b.")
                        {
                            match insn.operands().first() {
                                Some(Operand::Reg { reg, .. }) => {
                                    if let Some(slot) = parse_reg_slot(reg.name()) {
                                        if (slot as usize) < 64 {
                                            lifter.sym_regs[slot as usize] = None;
                                            if slot >= 32 {
                                                lifter.sym_vec_hi[(slot - 32) as usize] = None;
                                            }
                                        }
                                    }
                                    // LDP/LDNP/LDPSW/LDXP/LDAXP 同时覆写 ops[1]
                                    if matches!(
                                        mnem.as_str(),
                                        "ldp" | "ldnp" | "ldpsw" | "ldxp" | "ldaxp"
                                    ) {
                                        if let Some(Operand::Reg { reg: r2, .. }) =
                                            insn.operands().get(1)
                                        {
                                            if let Some(slot2) = parse_reg_slot(r2.name()) {
                                                if (slot2 as usize) < 64 {
                                                    lifter.sym_regs[slot2 as usize] = None;
                                                    if slot2 >= 32 {
                                                        lifter.sym_vec_hi
                                                            [(slot2 - 32) as usize] = None;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Some(Operand::MultiReg { regs, .. }) => {
                                    for r in regs.iter().flatten() {
                                        if let Some(slot) = parse_reg_slot(r.name()) {
                                            if (slot as usize) < 64 {
                                                lifter.sym_regs[slot as usize] = None;
                                                if slot >= 32 {
                                                    lifter.sym_vec_hi[(slot - 32) as usize] = None;
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    for ev in &mem_evs {
                        if ev.kind == ExtKind::MemWrite as u8 {
                            let sz = (ev.size_or_reg as usize).clamp(1, 16);
                            for b in 0..sz {
                                lifter.sym_mem.remove(&ev.addr.wrapping_add(b as u64));
                            }
                        }
                    }
                }
                if let Some(evs) = hle_by_seq.get(&seq) {
                    if idx >= stop_idx {
                        lifter.apply_hle_events(evs, &last_mem_write_bytes);
                        // 外部熵源/时钟源 HLE：直接将 X0 或写入缓冲提升为具名符号（如 rand_0 / time_0），并保留真实样本值！
                        for ev in evs {
                            if is_hle_entropy_or_time_reg(ev.op) && slice_idxs.contains(&idx) {
                                let sample = post_deltas
                                    .iter()
                                    .find(|&&(r, _)| r == 0)
                                    .map(|&(_, v)| v)
                                    .or(Some(ev.src));
                                let sym = lifter.alloc_entropy_sym(ev.op, 64, sample);
                                lifter.sym_regs[0] = Some(sym);
                            }
                            let is_hle_mem_source = (is_hle_entropy_or_time_mem(ev.op)
                                || ev.op == "time")
                                && ev.dst != 0
                                && ev.len > 0;
                            if is_hle_mem_source {
                                let len = ev.len.min(64 * 1024);
                                let first8 = ev.src.to_le_bytes();
                                for b in 0..len {
                                    let a = ev.dst.wrapping_add(b);
                                    if b < 8 && slice_idxs.contains(&idx) {
                                        let node = lifter
                                            .arena
                                            .sym_mem_byte(a, Some(first8[b as usize]));
                                        lifter.sym_mem.insert(a, node);
                                    } else {
                                        // bytes >= 8（如 tv_usec/tv_nsec/getrandom[8..]）：清除旧 sym_mem 并标记为起源地址，
                                        // 令后续 LDR 从真实 MemRead 样本中延迟构造精确 SymMemByte！
                                        lifter.sym_mem.remove(&a);
                                        if slice_idxs.contains(&idx) {
                                            lifter.origin_mem_addrs.insert(a);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // 同步具体内存镜像与 ever_written_mem（针对 HLE memcpy/memset/entropy）
                    for ev in evs {
                        match ev.op {
                            "memcpy" | "memmove" | "realloc_copy" => {
                                let len = ev.len.min(64 * 1024);
                                let snap: Vec<(u64, Option<u8>)> = (0..len)
                                    .map(|i| {
                                        (
                                            ev.dst.wrapping_add(i),
                                            last_mem_write_bytes.get(&ev.src.wrapping_add(i)).copied(),
                                        )
                                    })
                                    .collect();
                                for (d, v) in snap {
                                    lifter.ever_written_mem.insert(d);
                                    if let Some(b) = v {
                                        last_mem_write_bytes.insert(d, b);
                                    } else {
                                        last_mem_write_bytes.remove(&d);
                                    }
                                }
                            }
                            "memset" | "bzero" | "calloc_zero" => {
                                let len = ev.len.min(64 * 1024);
                                let fill = (ev.src & 0xFF) as u8;
                                for i in 0..len {
                                    let d = ev.dst.wrapping_add(i);
                                    lifter.ever_written_mem.insert(d);
                                    last_mem_write_bytes.insert(d, fill);
                                }
                            }
                            op if (is_hle_entropy_or_time_mem(op) || op == "time")
                                && ev.dst != 0 =>
                            {
                                let len = ev.len.min(64 * 1024);
                                let first8 = ev.src.to_le_bytes();
                                for i in 0..len {
                                    let d = ev.dst.wrapping_add(i);
                                    lifter.ever_written_mem.insert(d);
                                    if i < 8 {
                                        last_mem_write_bytes.insert(d, first8[i as usize]);
                                    } else {
                                        last_mem_write_bytes.remove(&d);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                lifter.update_concrete_from_step(idx);
            }
        }

        // 取出目标 Seed 对应的最终符号表达式（标量 1..8B 或多输出缓冲区 9..64B）与真实输出期望值
        let mut is_multi_buf = false;
        let output_len: usize;
        let mut chunks: Vec<OutputChunkSpec> = Vec::new();
        let mut expected_bytes_opt: Option<Vec<Option<u8>>> = None;

        match *seed {
            TaintSeed::Reg { reg_id } => {
                let sample = if (reg_id as usize) < 64 {
                    lifter.concrete_regs[reg_id as usize]
                } else {
                    None
                };
                let expr = if (reg_id as usize) < 64 {
                    lifter.sym_regs[reg_id as usize].unwrap_or_else(|| {
                        if let Some(v) = sample {
                            lifter.arena.c(v, 64)
                        } else {
                            lifter.arena.sym_reg(reg_id, 64, None)
                        }
                    })
                } else {
                    lifter.arena.c(0, 64)
                };
                let w = lifter.arena.width(expr);
                output_len = (w as usize).div_ceil(8).clamp(1, 8);
                let exp = sample.map(|v| v & width_mask(w));
                chunks.push(OutputChunkSpec {
                    byte_offset: 0,
                    byte_len: output_len,
                    root: expr,
                    expected: exp,
                    evaluated: None,
                });
            }
            TaintSeed::Mem { addr, len } => {
                let len = len.max(1);
                if len <= 8 {
                    let eff_len = match len {
                        1 => 1,
                        2 => 2,
                        3..=4 => 4,
                        _ => 8,
                    };
                    output_len = eff_len;
                    let mut exp_acc = 0u64;
                    let mut all_known = true;
                    for i in 0..eff_len {
                        if let Some(&b) = last_mem_write_bytes.get(&addr.wrapping_add(i as u64)) {
                            exp_acc |= u64::from(b) << (i * 8);
                        } else {
                            all_known = false;
                        }
                    }
                    let exp = all_known.then_some(exp_acc);
                    let expr = lifter.load_sym_bytes_ex(addr, eff_len, exp, false);
                    chunks.push(OutputChunkSpec {
                        byte_offset: 0,
                        byte_len: eff_len,
                        root: expr,
                        expected: exp,
                        evaluated: None,
                    });
                } else {
                    is_multi_buf = true;
                    let eff_len = len.min(64);
                    output_len = eff_len;
                    let mut raw_exp_bytes = Vec::with_capacity(eff_len);
                    for i in 0..eff_len {
                        raw_exp_bytes.push(
                            last_mem_write_bytes
                                .get(&addr.wrapping_add(i as u64))
                                .copied(),
                        );
                    }
                    expected_bytes_opt = Some(raw_exp_bytes);

                    let mut off = 0usize;
                    while off < eff_len {
                        let rem = eff_len - off;
                        let clen = if rem >= 8 {
                            8
                        } else if rem >= 4 {
                            4
                        } else if rem >= 2 {
                            2
                        } else {
                            1
                        };
                        let mut exp_acc = 0u64;
                        let mut all_known = true;
                        for b in 0..clen {
                            if let Some(&val_b) =
                                last_mem_write_bytes.get(&addr.wrapping_add((off + b) as u64))
                            {
                                exp_acc |= u64::from(val_b) << (b * 8);
                            } else {
                                all_known = false;
                            }
                        }
                        let exp = all_known.then_some(exp_acc);
                        let expr = lifter.load_sym_bytes_ex(
                            addr.wrapping_add(off as u64),
                            clen,
                            exp,
                            false,
                        );
                        chunks.push(OutputChunkSpec {
                            byte_offset: off,
                            byte_len: clen,
                            root: expr,
                            expected: exp,
                            evaluated: None,
                        });
                        off += clen;
                    }
                }
            }
        }

        let raw_roots: Vec<NodeId> = chunks.iter().map(|c| c.root).collect();
        let raw_nodes = lifter.arena.count_reachable_many(&raw_roots);
        if opts.simplify {
            for ch in &mut chunks {
                ch.root = lifter.arena.simplify_root(ch.root);
            }
        }
        let final_roots: Vec<NodeId> = chunks.iter().map(|c| c.root).collect();
        let simplified_nodes = lifter.arena.count_reachable_many(&final_roots);

        let mut any_mismatch = false;
        let mut all_verified = !chunks.is_empty();
        for ch in &mut chunks {
            ch.evaluated = lifter.arena.eval_sample(ch.root);
            match (ch.expected, ch.evaluated) {
                (Some(exp), Some(ev)) => {
                    let m = width_mask(lifter.arena.width(ch.root));
                    if (exp & m) != (ev & m) {
                        any_mismatch = true;
                    }
                }
                _ => {
                    all_verified = false;
                }
            }
        }
        let verified = if any_mismatch {
            Some(false)
        } else if all_verified {
            Some(true)
        } else {
            None
        };

        let expected_output = if is_multi_buf {
            None
        } else {
            chunks.first().and_then(|c| c.expected)
        };
        let evaluated_output = if is_multi_buf {
            None
        } else {
            chunks.first().and_then(|c| c.evaluated)
        };

        let expected_output_bytes_hex = if let Some(ref bytes) = expected_bytes_opt {
            if bytes.iter().any(Option::is_some) {
                let mut s = String::with_capacity(bytes.len() * 2);
                for b in bytes {
                    match b {
                        Some(v) => s.push_str(&format!("{v:02x}")),
                        None => s.push_str("??"),
                    }
                }
                Some(s)
            } else {
                None
            }
        } else {
            expected_output.map(|v| {
                let le = v.to_le_bytes();
                le[..output_len]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            })
        };

        let evaluated_output_bytes_hex = if chunks.iter().all(|c| c.evaluated.is_some()) {
            let mut s = String::with_capacity(output_len * 2);
            for ch in &chunks {
                let le = ch.evaluated.unwrap().to_le_bytes();
                for b in &le[..ch.byte_len] {
                    s.push_str(&format!("{b:02x}"));
                }
            }
            Some(s)
        } else {
            None
        };

        let (c_code, inputs, tables) = CCodeEmitter::emit_multi(
            &lifter.arena,
            &chunks,
            &EmitMeta {
                is_multi_buf,
                fn_name: &opts.function_name,
                expected_out: expected_output,
                eval_out: evaluated_output,
                expected_bytes_hex: expected_output_bytes_hex.as_deref(),
                eval_bytes_hex: evaluated_output_bytes_hex.as_deref(),
                verified,
            },
        );
        let smt2 = opts
            .emit_smt2
            .then(|| emit_smt2_multi(&lifter.arena, &chunks));

        let slice_insns = bwd.steps.len();
        let taint_steps = if opts.max_steps > 0 && bwd.steps.len() > opts.max_steps {
            bwd.steps[bwd.steps.len() - opts.max_steps..].to_vec()
        } else {
            bwd.steps
        };

        DecompileReport {
            seed_desc: bwd.seed_desc,
            anchor_idx: bwd.anchor_idx,
            stop_idx,
            scanned_insns: bwd.scanned_insns,
            slice_insns,
            raw_nodes,
            simplified_nodes,
            inputs,
            tables,
            origin_annotations: bwd.origin_annotations,
            output_len,
            expected_output,
            evaluated_output,
            expected_output_bytes_hex,
            evaluated_output_bytes_hex,
            verified,
            c_code,
            smt2,
            taint_steps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bv_mba_and_rotate_simplification() {
        let mut arena = BvArena::default();
        let a = arena.sym_reg(0, 32, Some(0x1234_5678));
        let b = arena.sym_reg(1, 32, Some(0x9ABC_DEF0));

        // 1. MBA: (a ^ b) + ((a & b) << 1)  ==>  a + b
        let xab = arena.binop(BvBinOp::Xor, a, b, 32);
        let aab = arena.binop(BvBinOp::And, a, b, 32);
        let one = arena.c(1, 32);
        let twice = arena.binop(BvBinOp::Shl, aab, one, 32);
        let mba_add = arena.binop(BvBinOp::Add, xab, twice, 32);
        let simp_add = arena.simplify_root(mba_add);
        let expect_add = arena.binop(BvBinOp::Add, a, b, 32);
        assert_eq!(simp_add, expect_add);
        assert_eq!(
            arena.eval_sample(simp_add),
            Some(u64::from(0x1234_5678u32.wrapping_add(0x9ABC_DEF0u32)))
        );

        // 2. MBA: (a | b) - (a & b)  ==>  a ^ b
        let oab = arena.binop(BvBinOp::Or, a, b, 32);
        let mba_xor = arena.binop(BvBinOp::Sub, oab, aab, 32);
        let simp_xor = arena.simplify_root(mba_xor);
        assert_eq!(simp_xor, xab);

        // 3. MBA: (a ^ b) - 2 * (~a & b)  ==>  a - b
        let na = arena.unop(BvUnOp::Not, a, 32);
        let nab = arena.binop(BvBinOp::And, na, b, 32);
        let two = arena.c(2, 32);
        let t_nab = arena.binop(BvBinOp::Mul, nab, two, 32);
        let mba_sub = arena.binop(BvBinOp::Sub, xab, t_nab, 32);
        let simp_sub = arena.simplify_root(mba_sub);
        let expect_sub = arena.binop(BvBinOp::Sub, a, b, 32);
        assert_eq!(simp_sub, expect_sub);

        // 4. Rotate: (a >> 7) | (a << 25)  ==>  ROTR32(a, 7)
        let c7 = arena.c(7, 32);
        let c25 = arena.c(25, 32);
        let r = arena.binop(BvBinOp::Lshr, a, c7, 32);
        let l = arena.binop(BvBinOp::Shl, a, c25, 32);
        let rot_raw = arena.binop(BvBinOp::Or, r, l, 32);
        let rot_simp = arena.simplify_root(rot_raw);
        assert_eq!(rot_simp, arena.binop(BvBinOp::Ror, a, c7, 32));
        assert_eq!(
            arena.eval_sample(rot_simp),
            Some(u64::from(0x1234_5678u32.rotate_right(7)))
        );
    }
}
