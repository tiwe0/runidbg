pub mod archive;
pub mod decompile;
pub mod engine;
pub mod reader;
pub mod record;
pub mod taint;
pub mod vm;

pub use archive::{
    TraceArchive, TraceArchiveInfo, TraceArchivePackOptions, TraceArchiveUnpackResult,
    RTRACE_MAGIC, RTRACE_VERSION,
};
pub use decompile::{DecompileOptions, DecompileReport, DecompiledInput, DecompiledTable};

pub use engine::{attach_code_hook, attach_mem_trace_hook, BinaryTracer};
pub use reader::{
    resolve_sibling_ext_path, CallTreeNode, CryptoHitGroup, DiffTaintByteSpan, DiffTaintReport,
    MemPatternHit, TraceDiffEntry, TraceDiffSummary, TraceQueryHit, TraceReader,
};
pub use record::{
    decode_instruction_with_reg, format_ascii_hint, ExtKind, ExtRecord, HleOpEvent, HleTraceEvent,
    TraceFilter, TraceLevel, TraceRecord, TraceStats,
};
pub use taint::{format_reg_slot, parse_reg_slot, TaintOptions, TaintReport, TaintSeed, TaintStep};
pub use vm::{
    parse_gpr_slot, VmAnalysisOptions, VmAnalysisReport, VmBitField, VmDecodedWord,
    VmDispatcherCandidate, VmHandlerStat, VmRegDiff, VmRegfileConfig, VmStep, VmWordLayout,
};
