use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::thread;

use anyhow::{anyhow, Result};
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use unicorn_engine::RegisterARM64;

use crate::backend::CpuBackend;
use crate::timetravel::{TimeTravelPlayer, TimeTravelStop, WatchKind};
use crate::tracer::{format_ascii_hint, BinaryTracer, TraceReader};

/// 嵌入的单页 Web UI（零外部依赖，离线可用）
pub const INDEX_HTML: &str = include_str!("index.html");

/// Axum 路由处理器：返回单页 Web UI HTML（同时供 `runidbg-cli ui` 与 `runidbg-cli serve /ui` 复用）
pub async fn serve_spa_html() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// 可选自动拉起宿主机默认浏览器打开指定 URL
pub fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
}

struct TraceUiState {
    reader: TraceReader,
    trace_path: String,
    has_ext: bool,
    base_addr: u64,
}

impl TraceUiState {
    fn rel_offset(&self, pc: u64) -> Option<String> {
        (self.base_addr != 0 && pc >= self.base_addr)
            .then(|| format!("+0x{:x}", pc - self.base_addr))
    }
}

/// 离线 Trace Web UI 服务句柄（支持 `wait()` 阻塞或 `shutdown()` 优雅退出）
pub struct TraceUiHandle {
    local_addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    server_thread: Option<thread::JoinHandle<()>>,
}

impl TraceUiHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn wait(mut self) {
        if let Some(h) = self.server_thread.take() {
            let _ = h.join();
        }
    }

    pub fn shutdown(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.server_thread.take() {
            let _ = h.join();
        }
    }
}

impl Drop for TraceUiHandle {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// 启动离线 Trace 可视化 Web UI 服务
pub fn start_trace_ui_server(
    idx_path: &Path,
    ext_path: Option<&Path>,
    base_addr: u64,
    listen_addr: &str,
) -> Result<TraceUiHandle> {
    let reader = TraceReader::open(idx_path, ext_path)?;
    if reader.missing_ext_warning() {
        let lvl = reader.recorded_level_name().unwrap_or("full");
        eprintln!(
            "WARN: {} 录制于 {lvl} 级别但未加载到伴生 .ext 文件（扩展事件=0）；请确认同级 .ext 未遗漏或通过 --ext 指定路径",
            idx_path.display()
        );
    }
    let effective_base = if base_addr != 0 {
        base_addr
    } else {
        reader.archive_base_addr().unwrap_or(0)
    };
    let has_ext = reader.has_ext();
    let state = Arc::new(TraceUiState {
        reader,
        trace_path: idx_path.display().to_string(),
        has_ext,
        base_addr: effective_base,
    });

    let listen = listen_addr.to_string();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<SocketAddr>>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_thread = thread::Builder::new()
        .name("runidbg-ui-http".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(anyhow!("Tokio Runtime 启动失败: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(&listen).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow!("绑定 {listen} 失败: {e}")));
                        return;
                    }
                };
                let addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow!("读取监听地址失败: {e}")));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(addr));

                let app = Router::new()
                    .route("/", get(serve_spa_html))
                    .route("/ui", get(serve_spa_html))
                    .route("/api/info", get(handle_info))
                    .route("/api/trace/dump", get(handle_dump))
                    .route("/api/trace/calltree", get(handle_calltree))
                    .route("/api/trace/crypto", get(handle_crypto))
                    .route("/api/trace/stats", get(handle_stats))
                    .route("/api/trace/search", get(handle_search))
                    .with_state(state);

                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
        })?;

    let local_addr = ready_rx
        .recv()
        .map_err(|_| anyhow!("Web UI 服务线程意外退出"))??;

    Ok(TraceUiHandle {
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        server_thread: Some(server_thread),
    })
}

fn json_resp(val: Value) -> Response {
    let mut resp = (StatusCode::OK, val.to_string()).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    resp
}

async fn handle_info(State(st): State<Arc<TraceUiState>>) -> Response {
    json_resp(json!({
        "mode": "trace",
        "tracePath": st.trace_path,
        "base": st.base_addr,
        "baseHex": format!("0x{:x}", st.base_addr),
        "totalRecords": st.reader.len(),
        "totalExtRecords": st.reader.ext_len(),
    }))
}

fn parse_query_map(uri: &Uri) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(q) = uri.query() else {
        return map;
    };
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(percent_decode(k), percent_decode(v));
        }
    }
    map
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn handle_dump(State(st): State<Arc<TraceUiState>>, uri: Uri) -> Response {
    let params = parse_query_map(&uri);
    let skip: usize = params.get("skip").and_then(|s| s.parse().ok()).unwrap_or(0);
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .min(500);
    let end = st.reader.len().min(skip.saturating_add(limit));
    let mut items = Vec::with_capacity(end.saturating_sub(skip));
    for idx in skip..end {
        if let Some(rec) = st.reader.get(idx) {
            let pc = rec.pc;
            let op = rec.opcode;
            let asm = match bad64::decode(op, pc) {
                Ok(insn) => insn.to_string(),
                Err(_) => format!(".word 0x{op:08x}"),
            };
            let regs: Vec<Value> = st
                .reader
                .reg_deltas_for(idx)
                .into_iter()
                .map(|(rid, rval)| {
                    let name = if rid == 31 {
                        "SP".to_string()
                    } else {
                        format!("X{rid}")
                    };
                    json!({
                        "name": name,
                        "valHex": format!("0x{rval:016x}"),
                        "ascii": format_ascii_hint(rval, 8),
                    })
                })
                .collect();
            let mems: Vec<String> = if st.has_ext {
                st.reader
                    .mem_and_hle_lines_for(idx)
                    .into_iter()
                    .map(|line| line.trim().to_string())
                    .collect()
            } else {
                Vec::new()
            };
            items.push(json!({
                "idx": idx,
                "pcHex": format!("0x{pc:016x}"),
                "offset": st.rel_offset(pc),
                "asm": asm,
                "regs": regs,
                "mems": mems,
            }));
        }
    }
    json_resp(json!({
        "skip": skip,
        "returned": items.len(),
        "total": st.reader.len(),
        "items": items,
    }))
}

async fn handle_calltree(State(st): State<Arc<TraceUiState>>, uri: Uri) -> Response {
    let params = parse_query_map(&uri);
    let max_depth: usize = params
        .get("maxDepth")
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    let min_insns: usize = params
        .get("minInsns")
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let total = st.reader.len().max(1);
    let all = st.reader.build_calltree();
    let nodes: Vec<Value> = all
        .iter()
        .filter(|n| n.depth <= max_depth && (n.depth == 0 || n.insn_count() >= min_insns))
        .take(limit)
        .map(|n| {
            let cnt = n.insn_count();
            let pct = ((cnt as f64) * 1000.0 / (total as f64)).round() / 10.0;
            json!({
                "depth": n.depth,
                "startIdx": n.start_idx,
                "endIdx": n.end_idx,
                "insnCount": cnt,
                "percent": pct,
                "targetHex": format!("0x{:016x}", n.target_pc),
                "targetOffset": st.rel_offset(n.target_pc),
            })
        })
        .collect();
    json_resp(json!({
        "totalNodes": all.len(),
        "returned": nodes.len(),
        "nodes": nodes,
    }))
}

async fn handle_crypto(State(st): State<Arc<TraceUiState>>) -> Response {
    let groups: Vec<Value> = st
        .reader
        .scan_crypto()
        .into_iter()
        .map(|g| {
            let consts: Vec<String> = g
                .distinct_constants
                .iter()
                .map(|c| format!("0x{c:08x}"))
                .collect();
            json!({
                "algorithm": g.algorithm,
                "startIdx": g.start_idx,
                "endIdx": g.end_idx,
                "firstPcHex": format!("0x{:016x}", g.first_pc),
                "firstPcOffset": st.rel_offset(g.first_pc),
                "hitCount": g.hit_count,
                "distinctConstants": consts,
            })
        })
        .collect();
    json_resp(json!({
        "count": groups.len(),
        "groups": groups,
    }))
}

async fn handle_stats(State(st): State<Arc<TraceUiState>>, uri: Uri) -> Response {
    let params = parse_query_map(&uri);
    let top_n: usize = params.get("top").and_then(|s| s.parse().ok()).unwrap_or(20);
    let mut pc_counts: HashMap<u64, u64> = HashMap::new();
    let mut bl_targets: HashMap<u64, u64> = HashMap::new();
    for idx in 0..st.reader.len() {
        if let Some(rec) = st.reader.get(idx) {
            let pc = rec.pc;
            let op = rec.opcode;
            *pc_counts.entry(pc).or_insert(0) += 1;
            if (op & 0xFC00_0000) == 0x9400_0000 {
                let imm26 = ((op & 0x03FF_FFFF) as i32) << 6 >> 6;
                let target = pc.wrapping_add((imm26 as i64 * 4) as u64);
                *bl_targets.entry(target).or_insert(0) += 1;
            }
        }
    }
    let unique_pcs = pc_counts.len();
    let unique_bl = bl_targets.len();
    let mut top_bl: Vec<(u64, u64)> = bl_targets.into_iter().collect();
    top_bl.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut top_pc: Vec<(u64, u64)> = pc_counts.into_iter().collect();
    top_pc.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    json_resp(json!({
        "totalRecords": st.reader.len(),
        "uniquePcs": unique_pcs,
        "uniqueBl": unique_bl,
        "topBl": top_bl.into_iter().take(top_n).map(|(addr, count)| json!({
            "addrHex": format!("0x{addr:016x}"),
            "offset": st.rel_offset(addr),
            "count": count,
        })).collect::<Vec<_>>(),
        "topPc": top_pc.into_iter().take(top_n).map(|(addr, count)| json!({
            "addrHex": format!("0x{addr:016x}"),
            "offset": st.rel_offset(addr),
            "count": count,
        })).collect::<Vec<_>>(),
    }))
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != ':')
        .collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        out.push(u8::from_str_radix(&cleaned[i..i + 2], 16).ok()?);
    }
    Some(out)
}

async fn handle_search(State(st): State<Arc<TraceUiState>>, uri: Uri) -> Response {
    let params = parse_query_map(&uri);
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .min(500);
    let mut hits: Vec<Value> = Vec::new();
    let mut total = 0usize;

    if let Some(val_s) = params.get("val") {
        if let Some(target) = parse_hex_u64(val_s) {
            let found = st.reader.search_value_attributed(target);
            total = found.len();
            for (idx, rec, rid) in found.into_iter().take(limit) {
                let pc = rec.pc;
                let op = rec.opcode;
                let off = st
                    .rel_offset(pc)
                    .map(|o| format!(" [{o}]"))
                    .unwrap_or_default();
                let line = format!(
                    "#{idx:06}{off} {}",
                    crate::tracer::decode_instruction_with_reg(pc, op, Some((rid, target)))
                );
                hits.push(json!({ "idx": idx, "text": line }));
            }
        }
    } else if let Some(ascii) = params.get("ascii") {
        let found = st.reader.search_mem_bytes(ascii.as_bytes());
        total = found.len();
        for h in found.into_iter().take(limit) {
            let off = st
                .rel_offset(h.pc)
                .map(|o| format!(" [{o}]"))
                .unwrap_or_default();
            let text = format!(
                "seq={} pc=0x{:016x}{off} [MEM W] addr=0x{:016x} len={} (\"{ascii}\")",
                h.seq_low32, h.pc, h.addr, h.matched_len
            );
            hits.push(json!({ "idx": h.seq_low32, "text": text }));
        }
    } else if let Some(bytes_s) = params.get("bytes") {
        if let Some(pat) = parse_hex_bytes(bytes_s) {
            let found = st.reader.search_mem_bytes(&pat);
            total = found.len();
            for h in found.into_iter().take(limit) {
                let off = st
                    .rel_offset(h.pc)
                    .map(|o| format!(" [{o}]"))
                    .unwrap_or_default();
                let text = format!(
                    "seq={} pc=0x{:016x}{off} [MEM W] addr=0x{:016x} len={}",
                    h.seq_low32, h.pc, h.addr, h.matched_len
                );
                hits.push(json!({ "idx": h.seq_low32, "text": text }));
            }
        }
    } else if let Some(addr_s) = params.get("addr") {
        if let Some(target_addr) = parse_hex_u64(addr_s) {
            let found = st.reader.search_mem_addr(target_addr);
            total = found.len();
            for ext in found.into_iter().take(limit) {
                let seq = ext.seq_low32;
                let pc = ext.pc;
                let off = st
                    .rel_offset(pc)
                    .map(|o| format!(" [{o}]"))
                    .unwrap_or_default();
                let text = format!(
                    "seq={seq} pc=0x{pc:016x}{off} {}",
                    BinaryTracer::format_ext_record(&ext).trim()
                );
                hits.push(json!({ "idx": seq, "text": text }));
            }
        }
    }

    json_resp(json!({
        "total": total,
        "returned": hits.len(),
        "hits": hits,
    }))
}

// ============================================================================
// M2.4: `.rtape` 二期时间旅行可视化 Web UI 服务（单线程专有 Worker 承载 !Send Unicorn）
// ============================================================================

enum TtUiCmd {
    Info,
    State,
    SeekInsn(u64),
    SeekBookmark(String),
    Step(i64),
    Watch {
        addr: u64,
        len: u64,
        kind: WatchKind,
        backward: bool,
    },
    MemRead {
        addr: u64,
        len: usize,
    },
    Verify,
}

type TtUiReq = (TtUiCmd, tokio::sync::oneshot::Sender<Result<Value>>);

#[derive(Clone)]
struct TtUiProxy {
    tx: mpsc::Sender<TtUiReq>,
}

impl TtUiProxy {
    async fn call(&self, cmd: TtUiCmd) -> Result<Value> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.tx
            .send((cmd, reply_tx))
            .map_err(|_| anyhow!("TimeTravel UI 工作线程已退出"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("TimeTravel UI 工作线程未返回响应"))?
    }
}

fn json_err_resp(status: StatusCode, msg: impl Into<String>) -> Response {
    let mut resp = (status, json!({ "error": msg.into() }).to_string()).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    resp
}

fn build_tt_info_json(player: &TimeTravelPlayer, tape_path: &str) -> Value {
    let ev = player.event_log();
    let tl = ev.to_timeline_info();
    let keyframes: Vec<Value> = player
        .tape()
        .checkpoints()
        .into_iter()
        .map(|cp| {
            json!({
                "index": cp.index,
                "label": cp.label,
                "insn": cp.insn_count,
                "isDelta": cp.is_delta,
                "storedPages": cp.stored_pages,
            })
        })
        .collect();
    let bookmarks: Vec<Value> = player
        .bookmarks()
        .iter()
        .map(|(insn, label)| json!({ "insn": insn, "label": label }))
        .collect();
    let modules: Vec<Value> = player
        .emu()
        .linker()
        .all_modules()
        .into_iter()
        .map(|m| {
            json!({
                "name": m.name,
                "base": m.base_addr,
                "baseHex": format!("0x{:016x}", m.base_addr),
                "size": m.image_size,
            })
        })
        .collect();
    json!({
        "mode": "timetravel",
        "tapePath": tape_path,
        "startInsn": player.start_insn(),
        "totalInsns": player.total_insns(),
        "currentInsn": player.current_insn(),
        "keyframeInterval": tl.keyframe_interval,
        "keyframes": keyframes,
        "bookmarks": bookmarks,
        "modules": modules,
        "events": {
            "total": ev.events.len(),
            "clock": tl.clock_events,
            "jni": tl.jni_events,
            "hostFiles": tl.host_file_count,
        },
    })
}

fn build_tt_state_json(player: &TimeTravelPlayer) -> Result<Value> {
    let pc = player
        .emu()
        .cpu()
        .reg_read(RegisterARM64::PC)
        .map_err(|e| anyhow!("{e}"))?;
    let regs_ordered = player
        .snapshot_regs_ordered()
        .map_err(|e| anyhow!("{e}"))?;
    let regs: Vec<Value> = regs_ordered
        .into_iter()
        .map(|(name, val)| {
            json!({
                "name": name,
                "valHex": format!("0x{val:016x}"),
                "valDec": val.to_string(),
            })
        })
        .collect();

    // 反汇编当前 PC 前后各 6 条 ARM64 指令（仅读取已映射页，失败安全跳过）
    let mut disasm = Vec::new();
    if pc >= 24 && pc != crate::cpu::RET_MAGIC_ADDR {
        let win_start = pc.saturating_sub(24);
        for i in 0..13u64 {
            let addr = win_start.saturating_add(i * 4);
            let mut raw = [0u8; 4];
            if player.emu().cpu().mem_read(addr, &mut raw).is_ok() {
                let op = u32::from_le_bytes(raw);
                let asm = match bad64::decode(op, addr) {
                    Ok(insn) => insn.to_string(),
                    Err(_) => format!(".word 0x{op:08x}"),
                };
                disasm.push(json!({
                    "pcHex": format!("0x{addr:016x}"),
                    "location": player.describe_location(addr),
                    "opcodeHex": format!("0x{op:08x}"),
                    "asm": asm,
                    "isCurrent": addr == pc,
                }));
            }
        }
    }

    Ok(json!({
        "currentInsn": player.current_insn(),
        "startInsn": player.start_insn(),
        "totalInsns": player.total_insns(),
        "isLiveForked": player.is_live_forked(),
        "pc": pc,
        "pcHex": format!("0x{pc:016x}"),
        "location": player.describe_location(pc),
        "regs": regs,
        "disasm": disasm,
    }))
}

fn format_tt_stop_json(player: &TimeTravelPlayer, stop: &TimeTravelStop) -> Value {
    match stop {
        TimeTravelStop::Step { insn, pc } => json!({
            "reason": "step",
            "insn": insn,
            "pcHex": format!("0x{pc:016x}"),
            "location": player.describe_location(*pc),
        }),
        TimeTravelStop::Breakpoint { insn, pc } => json!({
            "reason": "breakpoint",
            "insn": insn,
            "pcHex": format!("0x{pc:016x}"),
            "location": player.describe_location(*pc),
        }),
        TimeTravelStop::Watchpoint {
            insn,
            pc,
            access_addr,
            size,
            kind,
            is_write,
            value,
            ..
        } => json!({
            "reason": "watchpoint",
            "insn": insn,
            "pcHex": format!("0x{pc:016x}"),
            "location": player.describe_location(*pc),
            "addrHex": format!("0x{access_addr:x}"),
            "size": size,
            "kind": match kind {
                WatchKind::Write => "write",
                WatchKind::Read => "read",
                WatchKind::Access => "access",
            },
            "actualKind": if *is_write { "write" } else { "read" },
            "valueHex": format!("0x{:x}", *value as u64),
        }),
        TimeTravelStop::LogBegin { insn, pc } => json!({
            "reason": "log_begin",
            "insn": insn,
            "pcHex": format!("0x{pc:016x}"),
            "location": player.describe_location(*pc),
        }),
        TimeTravelStop::LogEnd { insn, pc } => json!({
            "reason": "log_end",
            "insn": insn,
            "pcHex": format!("0x{pc:016x}"),
            "location": player.describe_location(*pc),
        }),
    }
}

fn format_hexdump_lines(base: u64, bytes: &[u8]) -> Vec<Value> {
    let mut lines = Vec::new();
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let addr = base.saturating_add((row * 16) as u64);
        let hex_cols: String = chunk
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if i == 7 {
                    format!("{b:02x}  ")
                } else if i + 1 == chunk.len() {
                    format!("{b:02x}")
                } else {
                    format!("{b:02x} ")
                }
            })
            .collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..=0x7e).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        lines.push(json!({
            "addrHex": format!("0x{addr:016x}"),
            "hex": hex_cols,
            "ascii": ascii,
        }));
    }
    lines
}

fn run_tt_ui_worker(
    tape_path: std::path::PathBuf,
    rx: mpsc::Receiver<TtUiReq>,
    init_tx: mpsc::SyncSender<Result<()>>,
) {
    let tape_display = tape_path.display().to_string();
    let mut player = match TimeTravelPlayer::open(&tape_path) {
        Ok(p) => {
            let _ = init_tx.send(Ok(()));
            p
        }
        Err(e) => {
            let _ = init_tx.send(Err(anyhow!("打开时间旅行磁带失败: {e}")));
            return;
        }
    };

    while let Ok((cmd, reply_tx)) = rx.recv() {
        let res = match cmd {
            TtUiCmd::Info => Ok(build_tt_info_json(&player, &tape_display)),
            TtUiCmd::State => build_tt_state_json(&player),
            TtUiCmd::SeekInsn(insn) => player
                .seek_insn(insn)
                .map_err(|e| anyhow!("{e}"))
                .and_then(|stop| {
                    let st = build_tt_state_json(&player)?;
                    Ok(json!({ "stop": format_tt_stop_json(&player, &stop), "state": st }))
                }),
            TtUiCmd::SeekBookmark(label) => player
                .seek_bookmark(&label)
                .map_err(|e| anyhow!("{e}"))
                .and_then(|stop| {
                    let st = build_tt_state_json(&player)?;
                    Ok(json!({ "stop": format_tt_stop_json(&player, &stop), "state": st }))
                }),
            TtUiCmd::Step(delta) => {
                let stop_res = if delta == 0 {
                    player.seek_insn(player.current_insn())
                } else if delta < 0 {
                    player.step_backward(delta.unsigned_abs())
                } else {
                    player.step_forward(delta as u64)
                };
                stop_res.map_err(|e| anyhow!("{e}")).and_then(|stop| {
                    let st = build_tt_state_json(&player)?;
                    Ok(json!({ "stop": format_tt_stop_json(&player, &stop), "state": st }))
                })
            }
            TtUiCmd::Watch {
                addr,
                len,
                kind,
                backward,
            } => {
                let hit_res = if backward {
                    player.find_prev_mem_access(addr, len, kind)
                } else {
                    player.find_next_mem_access(addr, len, kind)
                };
                hit_res.map_err(|e| anyhow!("{e}")).and_then(|maybe_hit| {
                    let st = build_tt_state_json(&player)?;
                    let hit_json = maybe_hit.map(|h| {
                        json!({
                            "insn": h.insn,
                            "pcHex": format!("0x{:016x}", h.pc),
                            "location": player.describe_location(h.pc),
                            "addrHex": format!("0x{:x}", h.addr),
                            "size": h.size,
                            "kind": match h.kind {
                                WatchKind::Write => "write",
                                WatchKind::Read => "read",
                                WatchKind::Access => "access",
                            },
                            "actualKind": if h.is_write { "write" } else { "read" },
                            "valueHex": format!("0x{:x}", h.value as u64),
                        })
                    });
                    Ok(json!({ "hit": hit_json, "state": st }))
                })
            }
            TtUiCmd::MemRead { addr, len } => {
                let capped = len.clamp(1, 4096);
                player
                    .emu()
                    .cpu()
                    .mem_read_as_vec(addr, capped)
                    .map_err(|e| anyhow!("读取内存 0x{addr:x} ({capped}B) 失败: {e}"))
                    .map(|bytes| {
                        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                        json!({
                            "addrHex": format!("0x{addr:016x}"),
                            "len": bytes.len(),
                            "currentInsn": player.current_insn(),
                            "hex": hex,
                            "lines": format_hexdump_lines(addr, &bytes),
                        })
                    })
            }
            TtUiCmd::Verify => {
                let prev = player.current_insn();
                let verified = player.verify_determinism().map_err(|e| anyhow!("{e}"));
                let _ = player.seek_insn(prev);
                verified.map(|n| json!({ "ok": true, "verifiedKeyframes": n }))
            }
        };
        let _ = reply_tx.send(res);
    }
}

/// 启动 `.rtape` 二期时间旅行可视化 Web UI 服务（提供交互式时间轴、反向观察点、寄存器 diff 与内存查看器）
pub fn start_timetravel_ui_server(tape_path: &Path, listen_addr: &str) -> Result<TraceUiHandle> {
    let path_buf = tape_path.to_path_buf();
    let (cmd_tx, cmd_rx) = mpsc::channel::<TtUiReq>();
    let (init_tx, init_rx) = mpsc::sync_channel::<Result<()>>(1);

    let worker_handle = thread::Builder::new()
        .name("runidbg-tt-ui-worker".to_string())
        .spawn(move || run_tt_ui_worker(path_buf, cmd_rx, init_tx))?;

    init_rx
        .recv()
        .map_err(|_| anyhow!("TimeTravel UI 工作线程意外退出"))??;

    let proxy = TtUiProxy { tx: cmd_tx };
    let listen = listen_addr.to_string();
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr>>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_thread = thread::Builder::new()
        .name("runidbg-tt-ui-http".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(anyhow!("Tokio Runtime 启动失败: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(&listen).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow!("绑定 {listen} 失败: {e}")));
                        return;
                    }
                };
                let addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow!("读取监听地址失败: {e}")));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(addr));

                let app = Router::new()
                    .route("/", get(serve_spa_html))
                    .route("/ui", get(serve_spa_html))
                    .route("/api/info", get(handle_tt_info))
                    .route("/api/tt/state", get(handle_tt_state))
                    .route("/api/tt/seek", post(handle_tt_seek))
                    .route("/api/tt/step", post(handle_tt_step))
                    .route("/api/tt/watch", post(handle_tt_watch))
                    .route("/api/tt/mem", get(handle_tt_mem))
                    .route("/api/tt/verify", post(handle_tt_verify))
                    .with_state(proxy);

                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
            // Axum 退出并 drop `proxy` 后，worker_handle 会随 channel 关闭自动退出
            let _ = worker_handle.join();
        })?;

    let local_addr = ready_rx
        .recv()
        .map_err(|_| anyhow!("TimeTravel Web UI 服务线程意外退出"))??;

    Ok(TraceUiHandle {
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        server_thread: Some(server_thread),
    })
}

async fn handle_tt_info(State(proxy): State<TtUiProxy>) -> Response {
    match proxy.call(TtUiCmd::Info).await {
        Ok(v) => json_resp(v),
        Err(e) => json_err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn handle_tt_state(State(proxy): State<TtUiProxy>) -> Response {
    match proxy.call(TtUiCmd::State).await {
        Ok(v) => json_resp(v),
        Err(e) => json_err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn handle_tt_seek(State(proxy): State<TtUiProxy>, body: String) -> Response {
    let Ok(val) = serde_json::from_str::<Value>(&body) else {
        return json_err_resp(StatusCode::BAD_REQUEST, "无效 JSON 请求体");
    };
    let cmd = if let Some(bm) = val.get("bookmark").and_then(Value::as_str) {
        TtUiCmd::SeekBookmark(bm.to_string())
    } else if let Some(insn) = val.get("insn").and_then(Value::as_u64) {
        TtUiCmd::SeekInsn(insn)
    } else {
        return json_err_resp(StatusCode::BAD_REQUEST, "缺少 insn 或 bookmark 参数");
    };
    match proxy.call(cmd).await {
        Ok(v) => json_resp(v),
        Err(e) => json_err_resp(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn handle_tt_step(State(proxy): State<TtUiProxy>, body: String) -> Response {
    let Ok(val) = serde_json::from_str::<Value>(&body) else {
        return json_err_resp(StatusCode::BAD_REQUEST, "无效 JSON 请求体");
    };
    let Some(delta) = val.get("delta").and_then(Value::as_i64) else {
        return json_err_resp(StatusCode::BAD_REQUEST, "缺少整数参数 delta");
    };
    match proxy.call(TtUiCmd::Step(delta)).await {
        Ok(v) => json_resp(v),
        Err(e) => json_err_resp(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

fn parse_json_addr(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str().and_then(parse_hex_u64)
}

async fn handle_tt_watch(State(proxy): State<TtUiProxy>, body: String) -> Response {
    let Ok(val) = serde_json::from_str::<Value>(&body) else {
        return json_err_resp(StatusCode::BAD_REQUEST, "无效 JSON 请求体");
    };
    let Some(addr) = parse_json_addr(val.get("addr")) else {
        return json_err_resp(StatusCode::BAD_REQUEST, "缺少有效地址参数 addr");
    };
    let len = val.get("len").and_then(Value::as_u64).unwrap_or(4).max(1);
    let kind = match val
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("write")
        .to_ascii_lowercase()
        .as_str()
    {
        "write" | "w" => WatchKind::Write,
        "read" | "r" => WatchKind::Read,
        "access" | "rw" | "a" => WatchKind::Access,
        other => {
            return json_err_resp(
                StatusCode::BAD_REQUEST,
                format!("无效观察点类型: {other}"),
            )
        }
    };
    let backward = !matches!(
        val.get("direction")
            .and_then(Value::as_str)
            .unwrap_or("prev")
            .to_ascii_lowercase()
            .as_str(),
        "next" | "forward" | "fwd"
    );
    match proxy
        .call(TtUiCmd::Watch {
            addr,
            len,
            kind,
            backward,
        })
        .await
    {
        Ok(v) => json_resp(v),
        Err(e) => json_err_resp(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn handle_tt_mem(State(proxy): State<TtUiProxy>, uri: Uri) -> Response {
    let params = parse_query_map(&uri);
    let Some(addr) = params.get("addr").and_then(|s| parse_hex_u64(s)) else {
        return json_err_resp(StatusCode::BAD_REQUEST, "缺少有效查询参数 addr");
    };
    let len = params
        .get("len")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(128)
        .clamp(1, 4096);
    match proxy.call(TtUiCmd::MemRead { addr, len }).await {
        Ok(v) => json_resp(v),
        Err(e) => json_err_resp(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn handle_tt_verify(State(proxy): State<TtUiProxy>) -> Response {
    match proxy.call(TtUiCmd::Verify).await {
        Ok(v) => json_resp(v),
        Err(e) => json_err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
