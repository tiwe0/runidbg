use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rquickjs::{
    Array, BigInt, Ctx, Error as JsError, Exception, Function, Object, Persistent, TypedArray,
    Value,
};
use unicorn_engine::Unicorn;

use crate::backend::{BackendKind, BackendWithData, CpuBackend};
use crate::emulator::{EmuState, DEFAULT_HEAP_BASE};
use crate::jni::{JObject, JObjectRef, JValue};
use crate::loader::LoadedModule;
use crate::memory::read_guest_cstr;
use crate::tape::{Tape, TapeCheckpointInfo, TapeSelector, TapeSummary};
use crate::timetravel::{RecordConfig, TimeTravelPlayer, TimeTravelStop, WatchHit, WatchKind};
use crate::tracer::{BinaryTracer, TraceLevel};
use crate::AndroidEmulator;

use super::hooks::{
    dump_regs, encode_arm64_nop, encode_arm64_ret, parse_hex_pattern, parse_reg_name, scan_memory,
    with_active_uc, JsNativeHookTable, SYSCALL_WILDCARD,
};
use super::jni_bridge::{
    current_js_ctx, with_active_objects, JsCtxGuard, JsHookTable, JsJniHandler, CURRENT_JS_CTX,
};
use super::{EmuEntry, SharedHost, SharedLogSink};

/// 统一可重入 CPU 后端访问器（兼容 Unicorn / Dynarmic / KVM / Hypervisor）：
/// 在原生 Hook 回调期间直接复用线程局部 `ACTIVE_UC`，非回调期间借用 `ScriptHost`。
fn with_uc<R>(
    ctx: &Ctx<'_>,
    host: &SharedHost,
    emu_id: usize,
    f: impl FnOnce(&mut dyn BackendWithData<EmuState>) -> rquickjs::Result<R>,
) -> rquickjs::Result<R> {
    let mut f = Some(f);
    if let Some(res) = with_active_uc(|uc| (f.take().unwrap())(uc)) {
        return res;
    }
    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
    let entry = h
        .emus
        .get_mut(emu_id)
        .ok_or_else(|| throw_err(ctx, "无效的 emuId"))?;
    (f.take().unwrap())(entry.emu.cpu_mut())
}

/// 仅 Unicorn 后端可用的访问器（供逐指令/内存/Syscall 原生 Hook 使用，其他后端返回明确错误）
fn with_unicorn_only<R>(
    ctx: &Ctx<'_>,
    host: &SharedHost,
    emu_id: usize,
    op_name: &str,
    f: impl FnOnce(&mut Unicorn<'static, EmuState>) -> rquickjs::Result<R>,
) -> rquickjs::Result<R> {
    let mut f = Some(f);
    if let Some(res) = with_active_uc(|uc| (f.take().unwrap())(uc)) {
        return res;
    }
    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用",
        )
    })?;
    let entry = h
        .emus
        .get_mut(emu_id)
        .ok_or_else(|| throw_err(ctx, "无效的 emuId"))?;
    let kind = entry.emu.backend_kind();
    let uc = entry.emu.try_uc_mut().ok_or_else(|| {
        throw_err(
            ctx,
            format!("当前后端 `{kind}` 仅支持仿真模式，不支持 `{op_name}`（仅 `unicorn` 后端支持原生指令/内存/Syscall Hook）"),
        )
    })?;
    (f.take().unwrap())(uc)
}

fn throw_err(ctx: &Ctx<'_>, msg: impl std::fmt::Display) -> JsError {
    Exception::throw_message(ctx, &msg.to_string())
}

fn tape_checkpoint_to_js<'js>(
    ctx: &Ctx<'js>,
    info: &TapeCheckpointInfo,
) -> rquickjs::Result<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("index", info.index as f64)?;
    obj.set("label", info.label.as_str())?;
    obj.set("timestampMs", info.timestamp_ms as f64)?;
    obj.set("sourceBackend", info.source_backend.as_str())?;
    obj.set("insnCount", info.insn_count as f64)?;
    obj.set("isDelta", info.is_delta)?;
    obj.set("storedPages", info.stored_pages as f64)?;
    obj.set("zeroedPages", info.zeroed_pages as f64)?;
    obj.set("removedPages", info.removed_pages as f64)?;
    obj.set("compressedBytes", info.compressed_bytes as f64)?;
    obj.set("uncompressedBytes", info.uncompressed_bytes as f64)?;
    let mods = Array::new(ctx.clone())?;
    for (i, m) in info.modules.iter().enumerate() {
        mods.set(i, m.as_str())?;
    }
    obj.set("modules", mods)?;
    Ok(obj)
}

fn tape_summary_to_js<'js>(
    ctx: &Ctx<'js>,
    summary: &TapeSummary,
) -> rquickjs::Result<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("version", summary.version as f64)?;
    obj.set("fileSize", summary.file_size as f64)?;
    let arr = Array::new(ctx.clone())?;
    for (i, cp) in summary.checkpoints.iter().enumerate() {
        arr.set(i, tape_checkpoint_to_js(ctx, cp)?)?;
    }
    obj.set("checkpoints", arr)?;
    if let Some(tl) = &summary.timeline {
        let t = Object::new(ctx.clone())?;
        t.set("startInsn", tl.start_insn as f64)?;
        t.set("endInsn", tl.end_insn as f64)?;
        t.set("keyframeInterval", tl.keyframe_interval as f64)?;
        t.set("eventCount", tl.event_count as f64)?;
        t.set("clockEvents", tl.clock_events as f64)?;
        t.set("jniEvents", tl.jni_events as f64)?;
        t.set("hookEvents", tl.hook_events as f64)?;
        t.set("hostFileCount", tl.host_file_count as f64)?;
        let bms = Array::new(ctx.clone())?;
        for (i, (ins, lbl)) in tl.bookmarks.iter().enumerate() {
            let b = Object::new(ctx.clone())?;
            b.set("insn", *ins as f64)?;
            b.set("label", lbl.as_str())?;
            bms.set(i, b)?;
        }
        t.set("bookmarks", bms)?;
        obj.set("timeline", t)?;
    } else {
        obj.set("timeline", rquickjs::Null)?;
    }
    Ok(obj)
}

fn tt_stop_to_js<'js>(
    ctx: &Ctx<'js>,
    player: &TimeTravelPlayer,
    stop: &TimeTravelStop,
) -> rquickjs::Result<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    let (reason, insn, pc) = match stop {
        TimeTravelStop::Step { insn, pc } => ("step", *insn, *pc),
        TimeTravelStop::Breakpoint { insn, pc } => ("breakpoint", *insn, *pc),
        TimeTravelStop::Watchpoint {
            insn,
            pc,
            addr,
            access_addr,
            size,
            kind,
            is_write,
            value,
        } => {
            obj.set("watchAddr", *addr as f64)?;
            obj.set("watchAddrHex", format!("0x{addr:x}"))?;
            obj.set("watchAccessAddr", *access_addr as f64)?;
            obj.set("watchAccessAddrHex", format!("0x{access_addr:x}"))?;
            obj.set("watchSize", *size as f64)?;
            obj.set(
                "watchKind",
                match kind {
                    WatchKind::Write => "write",
                    WatchKind::Read => "read",
                    WatchKind::Access => "access",
                },
            )?;
            obj.set("watchActualKind", if *is_write { "write" } else { "read" })?;
            let val_u64 = *value as u64;
            obj.set("watchValue", val_u64 as f64)?;
            obj.set("watchValueHex", format!("0x{val_u64:x}"))?;
            ("watchpoint", *insn, *pc)
        }
        TimeTravelStop::LogBegin { insn, pc } => ("log_begin", *insn, *pc),
        TimeTravelStop::LogEnd { insn, pc } => ("log_end", *insn, *pc),
    };
    obj.set("reason", reason)?;
    obj.set("insn", insn as f64)?;
    obj.set("pc", pc as f64)?;
    obj.set("pcHex", format!("0x{pc:016x}"))?;
    obj.set("location", player.describe_location(pc))?;
    Ok(obj)
}

fn tt_watch_hit_to_js<'js>(
    ctx: &Ctx<'js>,
    player: &TimeTravelPlayer,
    hit: &WatchHit,
) -> rquickjs::Result<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("insn", hit.insn as f64)?;
    obj.set("pc", hit.pc as f64)?;
    obj.set("pcHex", format!("0x{:016x}", hit.pc))?;
    obj.set("location", player.describe_location(hit.pc))?;
    obj.set("addr", hit.addr as f64)?;
    obj.set("addrHex", format!("0x{:x}", hit.addr))?;
    obj.set("size", hit.size as f64)?;
    obj.set(
        "kind",
        match hit.kind {
            WatchKind::Write => "write",
            WatchKind::Read => "read",
            WatchKind::Access => "access",
        },
    )?;
    obj.set("actualKind", if hit.is_write { "write" } else { "read" })?;
    let val_u64 = hit.value as u64;
    obj.set("value", val_u64 as f64)?;
    obj.set("valueHex", format!("0x{val_u64:x}"))?;
    Ok(obj)
}

fn parse_watch_kind(ctx: &Ctx<'_>, s: &str) -> rquickjs::Result<WatchKind> {
    match s.trim().to_ascii_lowercase().as_str() {
        "write" | "w" => Ok(WatchKind::Write),
        "read" | "r" => Ok(WatchKind::Read),
        "access" | "rw" | "a" => Ok(WatchKind::Access),
        other => Err(throw_err(
            ctx,
            format!("无效的观察点类型 `{other}`（支持 write / read / access）"),
        )),
    }
}

fn js_addr_to_u64_strict<'js>(ctx: &Ctx<'js>, v: &Value<'js>) -> rquickjs::Result<u64> {
    if v.as_big_int().is_some() {
        // QuickJS 的 BigInt::to_i64 会按 mod 2^64 符号回绕（导致 > i64::MAX 误判负数、>= 2^64 静默回绕），
        // 直接经 JS String(v) 转为精确十进制字符串解析可无损覆盖完整 [0, u64::MAX] 并严格拒绝负数/越界。
        let str_fn = ctx
            .globals()
            .get::<_, Function>("String")
            .map_err(|_| throw_err(ctx, "无法解析 BigInt"))?;
        let s: String = str_fn
            .call((v.clone(),))
            .map_err(|_| throw_err(ctx, "无法序列化 BigInt"))?;
        if s.starts_with('-') {
            return Err(throw_err(ctx, "地址/数值不能为负数"));
        }
        return s
            .parse::<u64>()
            .map_err(|_| throw_err(ctx, "BigInt 地址/数值超出 u64 范围"));
    }
    if let Some(i) = v.as_int() {
        if i < 0 {
            return Err(throw_err(ctx, "地址不能为负数"));
        }
        return Ok(i as u64);
    }
    if let Some(n) = v.as_number() {
        if !n.is_finite() || n < 0.0 || n.fract() != 0.0 {
            return Err(throw_err(ctx, "地址必须为非负整数"));
        }
        if n > 9_007_199_254_740_991.0 {
            return Err(throw_err(
                ctx,
                "数值超过 JS Number 安全整数上限 (2^53 - 1)，会丢失低位精度；请改用 BigInt (0x...n) 或十六进制字符串 (\"0x...\")",
            ));
        }
        return Ok(n as u64);
    }
    if let Some(s) = v.as_string().and_then(|js| js.to_string().ok()) {
        let t = s.trim();
        let parsed = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else {
            t.parse::<u64>().ok()
        };
        if let Some(addr) = parsed {
            return Ok(addr);
        }
        return Err(throw_err(ctx, format!("无效的地址字符串: {s}")));
    }
    Err(throw_err(ctx, "地址必须为非负整数、BigInt 或 0x 十六进制字符串"))
}

fn require_nonneg_int(ctx: &Ctx<'_>, v: f64, name: &str) -> rquickjs::Result<u64> {
    if !v.is_finite() || v < 0.0 || v.fract() != 0.0 {
        return Err(throw_err(ctx, format!("{name} 必须为非负整数")));
    }
    if v > 9_007_199_254_740_991.0 {
        return Err(throw_err(
            ctx,
            format!("{name} 超过 JS Number 安全整数上限 (2^53 - 1)"),
        ));
    }
    Ok(v as u64)
}

fn get_tt<'a>(
    ctx: &Ctx<'_>,
    host: &'a super::ScriptHost,
    tt_id: usize,
) -> rquickjs::Result<&'a TimeTravelPlayer> {
    host.time_travels
        .get(tt_id)
        .and_then(Option::as_ref)
        .ok_or_else(|| throw_err(ctx, "无效或已关闭的 ttId"))
}

fn get_tt_mut<'a>(
    ctx: &Ctx<'_>,
    host: &'a mut super::ScriptHost,
    tt_id: usize,
) -> rquickjs::Result<&'a mut TimeTravelPlayer> {
    host.time_travels
        .get_mut(tt_id)
        .and_then(Option::as_mut)
        .ok_or_else(|| throw_err(ctx, "无效或已关闭的 ttId"))
}

fn js_val_to_jvalue(v: &Value<'_>) -> JValue {
    if let Some(b) = v.as_bool() {
        JValue::Boolean(b)
    } else if let Some(i) = v.as_int() {
        JValue::Int(i)
    } else if let Some(n) = v.as_number() {
        JValue::Double(n)
    } else if let Some(bi) = v.as_big_int() {
        JValue::Long(bi.clone().to_i64().unwrap_or(0))
    } else {
        JValue::Object(JObjectRef::NULL)
    }
}

fn js_field_val_to_jvalue<'js>(
    val: Value<'js>,
    sig_str: &str,
    objects: &mut crate::jni::ObjectTable,
) -> rquickjs::Result<JValue> {
    if val.is_null() || val.is_undefined() {
        Ok(JValue::Object(JObjectRef::NULL))
    } else if let Some(b) = val.as_bool() {
        Ok(JValue::Boolean(b))
    } else if let Some(s) = val.as_string() {
        let rust_s = s.to_string()?;
        let r = if sig_str == "[C" {
            objects.add_char_array(rust_s.encode_utf16().collect::<Vec<u16>>())
        } else {
            objects.add_string(rust_s)
        };
        Ok(JValue::Object(r))
    } else if let Ok(ta) = TypedArray::<u8>::from_value(val.clone()) {
        let r = objects.add_byte_array(ta.as_bytes().unwrap_or(&[]).to_vec());
        Ok(JValue::Object(r))
    } else if let Ok(ta) = TypedArray::<u16>::from_value(val.clone()) {
        let chars: Vec<u16> = ta
            .as_bytes()
            .unwrap_or(&[])
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        let r = objects.add_char_array(chars);
        Ok(JValue::Object(r))
    } else if let Ok(ta) = TypedArray::<i32>::from_value(val.clone()) {
        let ints: Vec<i32> = ta
            .as_bytes()
            .unwrap_or(&[])
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&c| i32::from_le_bytes(c))
            .collect();
        let r = objects.add_int_array(ints);
        Ok(JValue::Object(r))
    } else if let Ok(ta) = TypedArray::<i64>::from_value(val.clone()) {
        let longs: Vec<i64> = ta
            .as_bytes()
            .unwrap_or(&[])
            .as_chunks::<8>()
            .0
            .iter()
            .map(|&c| i64::from_le_bytes(c))
            .collect();
        let r = objects.add_long_array(longs);
        Ok(JValue::Object(r))
    } else if let Some(bi) = val.as_big_int() {
        Ok(JValue::Long(bi.clone().to_i64().unwrap_or(0)))
    } else if let Some(n) = val.as_number() {
        Ok(match sig_str {
            "Z" => JValue::Boolean(n != 0.0),
            "B" => JValue::Byte(n as i8),
            "C" => JValue::Char(n as u16),
            "S" => JValue::Short(n as i16),
            "I" => JValue::Int(n as i32),
            "J" => JValue::Long(n as i64),
            "F" => JValue::Float(n as f32),
            "D" => JValue::Double(n),
            _ => {
                let cand = JObjectRef(n as u64);
                if objects.get(cand).is_some() {
                    JValue::Object(cand)
                } else {
                    JValue::Int(n as i32)
                }
            }
        })
    } else {
        Ok(JValue::Object(JObjectRef::NULL))
    }
}

fn jvalue_opt_to_js<'js>(ctx: &Ctx<'js>, stored: Option<JValue>) -> rquickjs::Result<Value<'js>> {
    match stored {
        None | Some(JValue::Void) => Ok(Value::new_null(ctx.clone())),
        Some(JValue::Boolean(b)) => Ok(Value::new_bool(ctx.clone(), b)),
        Some(JValue::Byte(v)) => Ok(Value::new_int(ctx.clone(), i32::from(v))),
        Some(JValue::Char(v)) => Ok(Value::new_int(ctx.clone(), i32::from(v))),
        Some(JValue::Short(v)) => Ok(Value::new_int(ctx.clone(), i32::from(v))),
        Some(JValue::Int(v)) => Ok(Value::new_int(ctx.clone(), v)),
        Some(JValue::Long(v)) => Ok(Value::new_number(ctx.clone(), v as f64)),
        Some(JValue::Float(v)) => Ok(Value::new_float(ctx.clone(), f64::from(v))),
        Some(JValue::Double(v)) => Ok(Value::new_float(ctx.clone(), v)),
        Some(JValue::Object(r)) => {
            if r.is_null() {
                Ok(Value::new_null(ctx.clone()))
            } else {
                Ok(Value::new_number(ctx.clone(), r.0 as f64))
            }
        }
    }
}

fn object_kind_str(obj: &JObject) -> &'static str {
    match obj {
        JObject::Class { .. } => "class",
        JObject::String(_) => "string",
        JObject::BooleanArray(_) => "boolean[]",
        JObject::ByteArray(_) => "byte[]",
        JObject::CharArray(_) => "char[]",
        JObject::ShortArray(_) => "short[]",
        JObject::IntArray(_) => "int[]",
        JObject::LongArray(_) => "long[]",
        JObject::FloatArray(_) => "float[]",
        JObject::DoubleArray(_) => "double[]",
        JObject::ObjectArray(_) => "object[]",
        JObject::DirectBuffer { .. } => "directBuffer",
        JObject::Custom { .. } => "custom",
        _ => "builtin",
    }
}

fn jni_trace_event_to_js<'js>(
    ctx: &Ctx<'js>,
    ev: &crate::jni::JniTraceEvent,
) -> rquickjs::Result<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("seq", ev.seq as f64)?;
    obj.set("op", ev.op.as_str())?;
    obj.set("className", ev.class_name.as_str())?;
    obj.set("targetRef", ev.target_ref as f64)?;
    obj.set("member", ev.member.as_str())?;
    obj.set("sig", ev.sig.as_str())?;
    let args = Array::new(ctx.clone())?;
    for (i, a) in ev.args.iter().enumerate() {
        args.set(i, a.as_str())?;
    }
    obj.set("args", args)?;
    obj.set("ret", ev.ret.as_str())?;
    obj.set("isNull", ev.is_null)?;
    obj.set("handled", ev.handled)?;
    match ev.hook_id {
        Some(id) => obj.set("hookId", id as f64)?,
        None => obj.set("hookId", Value::new_null(ctx.clone()))?,
    }
    Ok(obj)
}

fn dex_value_to_js<'js>(
    ctx: &Ctx<'js>,
    val: &crate::loader::DexValue,
) -> rquickjs::Result<Value<'js>> {
    use crate::loader::DexValue;
    match val {
        DexValue::Null => Ok(Value::new_null(ctx.clone())),
        DexValue::Boolean(b) => Ok(Value::new_bool(ctx.clone(), *b)),
        DexValue::Byte(v) => Ok(Value::new_int(ctx.clone(), i32::from(*v))),
        DexValue::Short(v) => Ok(Value::new_int(ctx.clone(), i32::from(*v))),
        DexValue::Char(v) => Ok(Value::new_int(ctx.clone(), i32::from(*v))),
        DexValue::Int(v) => Ok(Value::new_int(ctx.clone(), *v)),
        DexValue::Long(v) => Ok(Value::new_number(ctx.clone(), *v as f64)),
        DexValue::Float(v) => Ok(Value::new_float(ctx.clone(), f64::from(*v))),
        DexValue::Double(v) => Ok(Value::new_float(ctx.clone(), *v)),
        DexValue::String(s) | DexValue::Type(s) => {
            Ok(rquickjs::String::from_str(ctx.clone(), s)?.into_value())
        }
        DexValue::Array(elems) => {
            let arr = Array::new(ctx.clone())?;
            for (i, e) in elems.iter().enumerate() {
                arr.set(i, dex_value_to_js(ctx, e)?)?;
            }
            Ok(arr.into_value())
        }
    }
}

fn js_val_to_u64(ctx: &Ctx<'_>, v: &Value<'_>) -> rquickjs::Result<u64> {
    if let Some(i) = v.as_int() {
        Ok(i as i64 as u64)
    } else if let Some(n) = v.as_number() {
        Ok(n as i64 as u64)
    } else if let Some(bi) = v.as_big_int() {
        bi.clone()
            .to_i64()
            .map(|x| x as u64)
            .map_err(|e| throw_err(ctx, format!("BigInt 转换 u64 失败: {e}")))
    } else if let Some(b) = v.as_bool() {
        Ok(u64::from(b))
    } else {
        Err(throw_err(ctx, "期望 number 或 bigint"))
    }
}

#[derive(Clone)]
struct EmuSharedHandles {
    jni_hooks: Rc<RefCell<JsHookTable>>,
    native_hooks: Rc<RefCell<JsNativeHookTable>>,
    modules: Rc<RefCell<Vec<Option<LoadedModule>>>>,
}

type SharedHandlesTable = Rc<RefCell<Vec<EmuSharedHandles>>>;

fn get_emu_handles(
    ctx: &Ctx<'_>,
    handles: &SharedHandlesTable,
    emu_id: usize,
) -> rquickjs::Result<EmuSharedHandles> {
    handles
        .borrow()
        .get(emu_id)
        .cloned()
        .ok_or_else(|| throw_err(ctx, "无效的 emuId"))
}

pub(super) fn register_native_bridge<'js>(
    ctx: &Ctx<'js>,
    host: &SharedHost,
    log_sink: &SharedLogSink,
    cli_args: &[String],
) -> rquickjs::Result<()> {
    let globals = ctx.globals();
    let native = Object::new(ctx.clone())?;
    let handles_table: SharedHandlesTable = Rc::new(RefCell::new(Vec::new()));

    // 全局 args 数组
    let js_args = Array::new(ctx.clone())?;
    for (i, a) in cli_args.iter().enumerate() {
        js_args.set(i, a.as_str())?;
    }
    globals.set("args", js_args)?;

    // print(level, msg)
    {
        let sink = Rc::clone(log_sink);
        native.set(
            "print",
            Function::new(ctx.clone(), move |level: String, msg: String| {
                if sink.capture {
                    sink.buf.borrow_mut().push(format!("[{level}] {msg}"));
                } else {
                    match level.as_str() {
                        "warn" | "error" => eprintln!("{msg}"),
                        _ => println!("{msg}"),
                    }
                }
            })?,
        )?;
    }

    // emuCompiledBackends() -> string[]
    native.set(
        "emuCompiledBackends",
        Function::new(ctx.clone(), move || -> rquickjs::Result<Vec<String>> {
            Ok(BackendKind::compiled_backends()
                .iter()
                .map(|b| b.as_str().to_string())
                .collect())
        })?,
    )?;

    // emuBackend(emuId) -> string
    {
        let host = Rc::clone(host);
        native.set(
            "emuBackend",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<String> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.backend_kind().as_str().to_string())
                },
            )?,
        )?;
    }

    // emuCreate(packageName, searchPaths, hleAccel, heapSize, backendName?) -> emuId
    {
        let host = Rc::clone(host);
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "emuCreate",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      pkg: String,
                      search_paths: Vec<String>,
                      hle_accel: bool,
                      heap_size: f64,
                      backend_name: Option<String>|
                      -> rquickjs::Result<usize> {
                    let backend_kind: BackendKind = match backend_name.as_deref() {
                        Some(s) if !s.trim().is_empty() => {
                            s.parse().map_err(|e| throw_err(&ctx, e))?
                        }
                        _ => BackendKind::Unicorn,
                    };
                    let hooks = Rc::new(RefCell::new(JsHookTable::default()));
                    let native_hooks = Rc::new(RefCell::new(JsNativeHookTable::default()));
                    let modules = Rc::new(RefCell::new(Vec::new()));
                    let mut builder = AndroidEmulator::builder()
                        .backend(backend_kind)
                        .package_name(pkg)
                        .hle_accel(hle_accel)
                        .heap(DEFAULT_HEAP_BASE, (heap_size as u64).max(4 * 1024 * 1024))
                        .jni_handler(Box::new(JsJniHandler::new(Rc::clone(&hooks))));
                    for p in search_paths {
                        builder = builder.add_search_path(p);
                    }
                    let emu = builder.build().map_err(|e| throw_err(&ctx, e))?;
                    {
                        let mut hb = hooks.borrow_mut();
                        hb.diag = emu.diag().clone();
                        hb.breadcrumbs = emu.breadcrumbs().clone();
                    }
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let id = h.emus.len();
                    handles_table.borrow_mut().push(EmuSharedHandles {
                        jni_hooks: Rc::clone(&hooks),
                        native_hooks: Rc::clone(&native_hooks),
                        modules: Rc::clone(&modules),
                    });
                    h.emus.push(EmuEntry {
                        emu,
                        hooks,
                        native_hooks,
                        modules,
                        snapshots: Vec::new(),
                    });
                    Ok(id)
                },
            )?,
        )?;
    }

    // emuLoad(emuId, path, runInit) -> { id, name, base, size }
    {
        let host = Rc::clone(host);
        native.set(
            "emuLoad",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      path: String,
                      run_init: bool|
                      -> rquickjs::Result<Object<'js>> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let module = entry
                        .emu
                        .load_library_with_init(&path, run_init)
                        .map_err(|e| throw_err(&ctx, e))?;
                    let mut mods = entry.modules.borrow_mut();
                    let mod_id = mods.len();
                    let obj = Object::new(ctx.clone())?;
                    obj.set("id", mod_id)?;
                    obj.set("name", module.name.as_str())?;
                    obj.set("base", module.base_addr as f64)?;
                    obj.set("size", module.image_size as f64)?;
                    mods.push(Some(module));
                    Ok(obj)
                },
            )?,
        )?;
    }

    // modRunInit(emuId, modId) -> void
    {
        let host = Rc::clone(host);
        native.set(
            "modRunInit",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, mod_id: usize| -> rquickjs::Result<()> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let module = entry
                        .modules
                        .borrow()
                        .get(mod_id)
                        .and_then(|m| m.clone())
                        .ok_or_else(|| throw_err(&ctx, "无效或已随磁带倒带失效的 modId"))?;
                    entry
                        .emu
                        .run_module_init_array(&module)
                        .map_err(|e| throw_err(&ctx, e))?;
                    if let Some(uc) = entry.emu.try_uc_mut() {
                        let nh = Rc::clone(&entry.native_hooks);
                        JsNativeHookTable::flush_ret_magic_leaves(&nh, emu_id, uc);
                    }
                    Ok(())
                },
            )?,
        )?;
    }

    // emuJniOnLoad(emuId, modId) -> version or -1
    {
        let host = Rc::clone(host);
        native.set(
            "emuJniOnLoad",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, mod_id: usize| -> rquickjs::Result<i32> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let module = entry
                        .modules
                        .borrow()
                        .get(mod_id)
                        .and_then(|m| m.clone())
                        .ok_or_else(|| throw_err(&ctx, "无效或已随磁带倒带失效的 modId"))?;
                    let ver = entry
                        .emu
                        .call_jni_onload(&module)
                        .map_err(|e| throw_err(&ctx, e))?;
                    Ok(ver.unwrap_or(-1))
                },
            )?,
        )?;
    }

    // modSymbol(emuId, modId, name) -> addr or 0
    {
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "modSymbol",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      mod_id: usize,
                      name: String|
                      -> rquickjs::Result<f64> {
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    let mods = handles.modules.borrow();
                    let module = mods
                        .get(mod_id)
                        .and_then(|m| m.as_ref())
                        .ok_or_else(|| throw_err(&ctx, "无效或已随磁带倒带失效的 modId"))?;
                    Ok(module.find_symbol(&name).unwrap_or(0) as f64)
                },
            )?,
        )?;
    }

    // modExports(emuId, modId) -> string[]
    {
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "modExports",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, mod_id: usize| -> rquickjs::Result<Vec<String>> {
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    let mods = handles.modules.borrow();
                    let module = mods
                        .get(mod_id)
                        .and_then(|m| m.as_ref())
                        .ok_or_else(|| throw_err(&ctx, "无效或已随磁带倒带失效的 modId"))?;
                    let mut names: Vec<String> = module.symbols.keys().cloned().collect();
                    names.sort();
                    Ok(names)
                },
            )?,
        )?;
    }

    // modCallSymbol(emuId, modId, sym, args[]) -> f64
    {
        let host = Rc::clone(host);
        native.set(
            "modCallSymbol",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      mod_id: usize,
                      sym: String,
                      raw_args: Vec<f64>|
                      -> rquickjs::Result<f64> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let module = entry
                        .modules
                        .borrow()
                        .get(mod_id)
                        .and_then(|m| m.clone())
                        .ok_or_else(|| throw_err(&ctx, "无效或已随磁带倒带失效的 modId"))?;
                    let args_u64: Vec<u64> = raw_args.into_iter().map(|v| v as u64).collect();
                    let _ret = entry
                        .emu
                        .call_symbol(&module, &sym, &args_u64)
                        .map_err(|e| throw_err(&ctx, e))?;
                    if let Some(uc) = entry.emu.try_uc_mut() {
                        let nh = Rc::clone(&entry.native_hooks);
                        JsNativeHookTable::flush_ret_magic_leaves(&nh, emu_id, uc);
                    }
                    let final_ret = entry
                        .emu
                        .cpu()
                        .reg_read(unicorn_engine::RegisterARM64::X0)
                        .unwrap_or(_ret);
                    Ok(final_ret as f64)
                },
            )?,
        )?;
    }

    // emuCallAddr(emuId, addr, args[]) -> f64
    {
        let host = Rc::clone(host);
        native.set(
            "emuCallAddr",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      addr: f64,
                      raw_args: Vec<f64>|
                      -> rquickjs::Result<f64> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let args_u64: Vec<u64> = raw_args.into_iter().map(|v| v as u64).collect();
                    let _ret = entry
                        .emu
                        .call_address(addr as u64, &args_u64)
                        .map_err(|e| throw_err(&ctx, e))?;
                    if let Some(uc) = entry.emu.try_uc_mut() {
                        let nh = Rc::clone(&entry.native_hooks);
                        JsNativeHookTable::flush_ret_magic_leaves(&nh, emu_id, uc);
                    }
                    let final_ret = entry
                        .emu
                        .cpu()
                        .reg_read(unicorn_engine::RegisterARM64::X0)
                        .unwrap_or(_ret);
                    Ok(final_ret as f64)
                },
            )?,
        )?;
    }

    // jniHook(emuId, className, methodName, fn)
    {
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "jniHook",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      cls: String,
                      method: String,
                      func: Function<'js>|
                      -> rquickjs::Result<()> {
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    let pfn = Persistent::save(&ctx, func);
                    handles.jni_hooks.borrow_mut().insert_hook(&cls, &method, pfn);
                    Ok(())
                },
            )?,
        )?;
    }

    // jniHookField(emuId, className, fieldKey, fn)
    {
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "jniHookField",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      cls: String,
                      field_key: String,
                      func: Function<'js>|
                      -> rquickjs::Result<()> {
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    let pfn = Persistent::save(&ctx, func);
                    handles
                        .jni_hooks
                        .borrow_mut()
                        .insert_field_hook(&cls, &field_key, pfn);
                    Ok(())
                },
            )?,
        )?;
    }

    // jniHookMethod(emuId, className, methodKey, fn)
    {
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "jniHookMethod",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      cls: String,
                      method_key: String,
                      func: Function<'js>|
                      -> rquickjs::Result<()> {
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    let pfn = Persistent::save(&ctx, func);
                    handles
                        .jni_hooks
                        .borrow_mut()
                        .insert_method_hook(&cls, &method_key, pfn);
                    Ok(())
                },
            )?,
        )?;
    }

    // jniListHooks(emuId) -> Array<{ id, kind, className, name, sig, hits }>
    {
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "jniListHooks",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Array<'js>> {
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    let list = handles.jni_hooks.borrow().list_hooks();
                    let arr = Array::new(ctx.clone())?;
                    for (i, info) in list.into_iter().enumerate() {
                        let obj = Object::new(ctx.clone())?;
                        obj.set("id", info.id as f64)?;
                        obj.set("kind", info.kind)?;
                        obj.set("className", info.class_name)?;
                        obj.set("name", info.name)?;
                        match info.sig {
                            Some(s) => obj.set("sig", s)?,
                            None => obj.set("sig", Value::new_null(ctx.clone()))?,
                        }
                        obj.set("hits", info.hits as f64)?;
                        arr.set(i, obj)?;
                    }
                    Ok(arr)
                },
            )?,
        )?;
    }

    // jniOnUnhandled(emuId, fn)
    {
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "jniOnUnhandled",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, func: Function<'js>| -> rquickjs::Result<()> {
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    let pfn = Persistent::save(&ctx, func);
                    handles.jni_hooks.borrow_mut().set_unhandled(pfn);
                    Ok(())
                },
            )?,
        )?;
    }

    // jniRegisteredNatives(emuId) -> [{ className, name, sig, fnPtr }]
    {
        let host = Rc::clone(host);
        native.set(
            "jniRegisteredNatives",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Array<'js>> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let arr = Array::new(ctx.clone())?;
                    for (i, reg) in entry.emu.jni().registered_natives.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("className", reg.class_name.as_str())?;
                        o.set("name", reg.name.as_str())?;
                        o.set("sig", reg.sig.as_str())?;
                        o.set("fnPtr", reg.fn_ptr as f64)?;
                        arr.set(i, o)?;
                    }
                    Ok(arr)
                },
            )?,
        )?;
    }

    // jniCallNative(emuId, className, methodName, extraArgs[]) -> f64
    {
        let host = Rc::clone(host);
        native.set(
            "jniCallNative",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      cls: String,
                      method: String,
                      raw_args: Vec<f64>,
                      this_obj: f64|
                      -> rquickjs::Result<f64> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let args_u64: Vec<u64> = raw_args.into_iter().map(|v| v as u64).collect();
                    let this_ref = if this_obj > 0.0 {
                        Some(JObjectRef(this_obj as u64))
                    } else {
                        None
                    };
                    let _ret = entry
                        .emu
                        .call_registered_native_with_this(&cls, &method, this_ref, &args_u64)
                        .map_err(|e| throw_err(&ctx, e))?;
                    if let Some(uc) = entry.emu.try_uc_mut() {
                        let nh = Rc::clone(&entry.native_hooks);
                        JsNativeHookTable::flush_ret_magic_leaves(&nh, emu_id, uc);
                    }
                    let final_ret = entry
                        .emu
                        .cpu()
                        .reg_read(unicorn_engine::RegisterARM64::X0)
                        .unwrap_or(_ret);
                    Ok(final_ret as f64)
                },
            )?,
        )?;
    }

    // jniNewString(emuId, str) -> handle (支持在 JNI 回调内部重入调用)
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewString",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, s: String| -> rquickjs::Result<f64> {
                    if let Some(r) = with_active_objects(|objs| objs.add_string(s.clone())) {
                        return Ok(r.0 as f64);
                    }
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.new_jstring(s).0 as f64)
                },
            )?,
        )?;
    }

    // jniNewByteArray(emuId, Uint8Array) -> handle
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewByteArray",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      bytes: TypedArray<'js, u8>|
                      -> rquickjs::Result<f64> {
                    let vec = bytes.as_bytes().unwrap_or(&[]).to_vec();
                    if let Some(r) = with_active_objects(|objs| objs.add_byte_array(vec.clone())) {
                        return Ok(r.0 as f64);
                    }
                    with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc.get_data_mut().jni.objects.add_byte_array(vec).0 as f64)
                    })
                },
            )?,
        )?;
    }

    // jniNewCharArray(emuId, string | Uint16Array | number[]) -> handle
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewCharArray",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, input: Value<'js>| -> rquickjs::Result<f64> {
                    let chars: Vec<u16> = if let Some(s) = input.as_string() {
                        s.to_string()?.encode_utf16().collect()
                    } else if let Ok(ta) = TypedArray::<u16>::from_value(input.clone()) {
                        ta.as_bytes()
                            .unwrap_or(&[])
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|&c| u16::from_le_bytes(c))
                            .collect()
                    } else if let Some(arr) = input.as_array() {
                        let mut v = Vec::with_capacity(arr.len());
                        for i in 0..arr.len() {
                            let n = arr.get::<f64>(i).unwrap_or(0.0);
                            v.push(n as u16);
                        }
                        v
                    } else {
                        return Err(throw_err(
                            &ctx,
                            "newCharArray 需要 string、Uint16Array 或 number[]",
                        ));
                    };
                    if let Some(r) = with_active_objects(|objs| objs.add_char_array(chars.clone()))
                    {
                        return Ok(r.0 as f64);
                    }
                    with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc.get_data_mut().jni.objects.add_char_array(chars).0 as f64)
                    })
                },
            )?,
        )?;
    }

    // jniNewIntArray(emuId, Int32Array | number[]) -> handle
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewIntArray",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, input: Value<'js>| -> rquickjs::Result<f64> {
                    let ints: Vec<i32> = if let Ok(ta) = TypedArray::<i32>::from_value(input.clone())
                    {
                        ta.as_bytes()
                            .unwrap_or(&[])
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .map(|&c| i32::from_le_bytes(c))
                            .collect()
                    } else if let Some(arr) = input.as_array() {
                        let mut v = Vec::with_capacity(arr.len());
                        for i in 0..arr.len() {
                            v.push(arr.get::<f64>(i).unwrap_or(0.0) as i32);
                        }
                        v
                    } else {
                        return Err(throw_err(&ctx, "newIntArray 需要 Int32Array 或 number[]"));
                    };
                    if let Some(r) = with_active_objects(|objs| objs.add_int_array(ints.clone())) {
                        return Ok(r.0 as f64);
                    }
                    with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc.get_data_mut().jni.objects.add_int_array(ints).0 as f64)
                    })
                },
            )?,
        )?;
    }

    // jniNewLongArray(emuId, BigInt64Array | Array<number | bigint>) -> handle
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewLongArray",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, input: Value<'js>| -> rquickjs::Result<f64> {
                    let longs: Vec<i64> =
                        if let Ok(ta) = TypedArray::<i64>::from_value(input.clone()) {
                            ta.as_bytes()
                                .unwrap_or(&[])
                                .as_chunks::<8>()
                                .0
                                .iter()
                                .map(|&c| i64::from_le_bytes(c))
                                .collect()
                        } else if let Some(arr) = input.as_array() {
                            let mut v = Vec::with_capacity(arr.len());
                            for i in 0..arr.len() {
                                let item = arr.get::<Value<'js>>(i)?;
                                let n = if let Some(bi) = item.as_big_int() {
                                    bi.clone().to_i64().unwrap_or(0)
                                } else {
                                    item.as_number().unwrap_or(0.0) as i64
                                };
                                v.push(n);
                            }
                            v
                        } else {
                            return Err(throw_err(
                                &ctx,
                                "newLongArray 需要 BigInt64Array 或 Array<number|bigint>",
                            ));
                        };
                    if let Some(r) = with_active_objects(|objs| objs.add_long_array(longs.clone()))
                    {
                        return Ok(r.0 as f64);
                    }
                    with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc.get_data_mut().jni.objects.add_long_array(longs).0 as f64)
                    })
                },
            )?,
        )?;
    }

    // jniNewObject(emuId, className, fieldsObj?) -> handle
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewObject",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      cls: String,
                      fields_val: Value<'js>|
                      -> rquickjs::Result<f64> {
                    let mut fields = HashMap::new();
                    if let Some(obj) = fields_val.as_object() {
                        for (k, v) in obj.props::<String, Value<'js>>().flatten() {
                            fields.insert(k, js_val_to_jvalue(&v));
                        }
                    }
                    let jobj = JObject::Custom {
                        class_name: cls.replace('.', "/"),
                        fields,
                    };
                    if let Some(r) = with_active_objects(|objs| objs.add_local(jobj.clone())) {
                        return Ok(r.0 as f64);
                    }
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.jni_mut().objects.add_local(jobj).0 as f64)
                },
            )?,
        )?;
    }

    // jniGetString(emuId, ref) -> string | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetString",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, r: f64| -> rquickjs::Result<Option<String>> {
                    let jref = JObjectRef(r as u64);
                    if let Some(res) =
                        with_active_objects(|objs| objs.get_string(jref).map(str::to_string))
                    {
                        return Ok(res);
                    }
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.read_jstring(jref).map(str::to_string))
                },
            )?,
        )?;
    }

    // jniFindClass(emuId, className) -> jclass handle
    {
        let host = Rc::clone(host);
        native.set(
            "jniFindClass",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, cls: String| -> rquickjs::Result<f64> {
                    let norm = cls.replace('.', "/");
                    if let Some(r) = with_active_objects(|objs| objs.find_or_create_class(&norm)) {
                        return Ok(r.0 as f64);
                    }
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.jni_mut().objects.find_or_create_class(&norm).0 as f64)
                },
            )?,
        )?;
    }

    // jniNewStringArray(emuId, string[]) -> jobjectArray handle
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewStringArray",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, items: Vec<String>| -> rquickjs::Result<f64> {
                    let build = |objs: &mut crate::jni::ObjectTable| {
                        let refs: Vec<JObjectRef> =
                            items.iter().map(|s| objs.add_string(s.as_str())).collect();
                        objs.add_local(JObject::ObjectArray(refs))
                    };
                    if let Some(r) = with_active_objects(build) {
                        return Ok(r.0 as f64);
                    }
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let refs: Vec<JObjectRef> = items
                        .into_iter()
                        .map(|s| entry.emu.jni_mut().objects.add_string(s))
                        .collect();
                    let arr = entry
                        .emu
                        .jni_mut()
                        .objects
                        .add_local(JObject::ObjectArray(refs));
                    Ok(arr.0 as f64)
                },
            )?,
        )?;
    }

    // jniGetStringArray(emuId, ref) -> (string | null)[] | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetStringArray",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      r: f64|
                      -> rquickjs::Result<Option<Vec<Option<String>>>> {
                    let jref = JObjectRef(r as u64);
                    let read = |objs: &crate::jni::ObjectTable| match objs.get(jref) {
                        Some(JObject::ObjectArray(elems)) => Some(
                            elems
                                .iter()
                                .map(|&e| objs.get_string(e).map(str::to_string))
                                .collect::<Vec<_>>(),
                        ),
                        _ => None,
                    };
                    if let Some(res) = with_active_objects(|objs| read(objs)) {
                        return Ok(res);
                    }
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(read(&entry.emu.jni().objects))
                },
            )?,
        )?;
    }

    // jniNewObjectArray(emuId, refs[]) -> jobjectArray handle
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewObjectArray",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, refs: Vec<f64>| -> rquickjs::Result<f64> {
                    let jrefs: Vec<JObjectRef> = refs.into_iter().map(|v| JObjectRef(v as u64)).collect();
                    if let Some(r) =
                        with_active_objects(|objs| objs.add_local(JObject::ObjectArray(jrefs.clone())))
                    {
                        return Ok(r.0 as f64);
                    }
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry
                        .emu
                        .jni_mut()
                        .objects
                        .add_local(JObject::ObjectArray(jrefs))
                        .0 as f64)
                },
            )?,
        )?;
    }

    // jniGetObjectArray(emuId, ref) -> number[] | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetObjectArray",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, r: f64| -> rquickjs::Result<Option<Vec<f64>>> {
                    let jref = JObjectRef(r as u64);
                    let read = |objs: &crate::jni::ObjectTable| match objs.get(jref) {
                        Some(JObject::ObjectArray(elems)) => {
                            Some(elems.iter().map(|e| e.0 as f64).collect::<Vec<_>>())
                        }
                        _ => None,
                    };
                    if let Some(res) = with_active_objects(|objs| read(objs)) {
                        return Ok(res);
                    }
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(read(&entry.emu.jni().objects))
                },
            )?,
        )?;
    }

    // jniGetBytes(emuId, ref) -> Uint8Array | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetBytes",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      r: f64|
                      -> rquickjs::Result<Option<TypedArray<'js, u8>>> {
                    let jref = JObjectRef(r as u64);
                    let bytes = if let Some(res) =
                        with_active_objects(|objs| objs.get_bytes(jref).map(|b| b.to_vec()))
                    {
                        res
                    } else {
                        with_uc(&ctx, &host, emu_id, |uc| {
                            Ok(uc
                                .get_data()
                                .jni
                                .objects
                                .get_bytes(jref)
                                .map(|b| b.to_vec()))
                        })?
                    };
                    match bytes {
                        Some(v) => Ok(Some(TypedArray::new(ctx.clone(), v)?)),
                        None => Ok(None),
                    }
                },
            )?,
        )?;
    }

    // jniGetChars(emuId, ref) -> Uint16Array | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetChars",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      r: f64|
                      -> rquickjs::Result<Option<TypedArray<'js, u16>>> {
                    let jref = JObjectRef(r as u64);
                    let chars = if let Some(res) =
                        with_active_objects(|objs| objs.get_chars(jref).map(|c| c.to_vec()))
                    {
                        res
                    } else {
                        with_uc(&ctx, &host, emu_id, |uc| {
                            Ok(uc
                                .get_data()
                                .jni
                                .objects
                                .get_chars(jref)
                                .map(|c| c.to_vec()))
                        })?
                    };
                    match chars {
                        Some(v) => Ok(Some(TypedArray::new(ctx.clone(), v)?)),
                        None => Ok(None),
                    }
                },
            )?,
        )?;
    }

    // jniGetInts(emuId, ref) -> Int32Array | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetInts",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      r: f64|
                      -> rquickjs::Result<Option<TypedArray<'js, i32>>> {
                    let jref = JObjectRef(r as u64);
                    let ints = if let Some(res) =
                        with_active_objects(|objs| objs.get_ints(jref).map(|v| v.to_vec()))
                    {
                        res
                    } else {
                        with_uc(&ctx, &host, emu_id, |uc| {
                            Ok(uc
                                .get_data()
                                .jni
                                .objects
                                .get_ints(jref)
                                .map(|v| v.to_vec()))
                        })?
                    };
                    match ints {
                        Some(v) => Ok(Some(TypedArray::new(ctx.clone(), v)?)),
                        None => Ok(None),
                    }
                },
            )?,
        )?;
    }

    // jniGetLongs(emuId, ref) -> BigInt64Array | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetLongs",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      r: f64|
                      -> rquickjs::Result<Option<TypedArray<'js, i64>>> {
                    let jref = JObjectRef(r as u64);
                    let longs = if let Some(res) =
                        with_active_objects(|objs| objs.get_longs(jref).map(|v| v.to_vec()))
                    {
                        res
                    } else {
                        with_uc(&ctx, &host, emu_id, |uc| {
                            Ok(uc
                                .get_data()
                                .jni
                                .objects
                                .get_longs(jref)
                                .map(|v| v.to_vec()))
                        })?
                    };
                    match longs {
                        Some(v) => Ok(Some(TypedArray::new(ctx.clone(), v)?)),
                        None => Ok(None),
                    }
                },
            )?,
        )?;
    }

    // jniSetField(emuId, objRef, fieldName, val, sig?) -> void（支持在 JNI 回调内重入调用）
    {
        let host = Rc::clone(host);
        native.set(
            "jniSetField",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      obj_ref: f64,
                      field_name: String,
                      val: Value<'js>,
                      sig: Option<String>|
                      -> rquickjs::Result<()> {
                    let jref = JObjectRef(obj_ref as u64);
                    let sig_str = sig.as_deref().unwrap_or("");
                    let mut val_opt = Some(val);
                    if let Some(res) = with_active_objects(|objs| {
                        let jval =
                            js_field_val_to_jvalue(val_opt.take().unwrap(), sig_str, objs)?;
                        if let JValue::Object(r) = jval {
                            if !r.is_null() {
                                objs.new_global(r);
                            }
                        }
                        if let Some(JObject::Custom { fields, .. }) = objs.get_mut(jref) {
                            fields.insert(field_name.clone(), jval);
                        }
                        Ok(())
                    }) {
                        return res;
                    }
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let vm = &mut uc.get_data_mut().jni;
                        let jval = js_field_val_to_jvalue(
                            val_opt.take().unwrap(),
                            sig_str,
                            &mut vm.objects,
                        )?;
                        vm.set_instance_field(jref, &field_name, jval);
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    // jniGetField(emuId, objRef, fieldName) -> Value（支持在 JNI 回调内重入调用）
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetField",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      obj_ref: f64,
                      field_name: String|
                      -> rquickjs::Result<Value<'js>> {
                    let jref = JObjectRef(obj_ref as u64);
                    let stored = if let Some(res) = with_active_objects(|objs| {
                        if let Some(JObject::Custom { fields, .. }) = objs.get(jref) {
                            fields.get(&field_name).copied()
                        } else {
                            None
                        }
                    }) {
                        res
                    } else {
                        with_uc(&ctx, &host, emu_id, |uc| {
                            Ok(uc.get_data().jni.get_instance_field(jref, &field_name))
                        })?
                    };
                    jvalue_opt_to_js(&ctx, stored)
                },
            )?,
        )?;
    }

    // jniSetStaticField(emuId, className, fieldName, val, sig?) -> void
    {
        let host = Rc::clone(host);
        native.set(
            "jniSetStaticField",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      cls: String,
                      field_name: String,
                      val: Value<'js>,
                      sig: Option<String>|
                      -> rquickjs::Result<()> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let vm = &mut uc.get_data_mut().jni;
                        let jval = js_field_val_to_jvalue(
                            val,
                            sig.as_deref().unwrap_or(""),
                            &mut vm.objects,
                        )?;
                        vm.set_static_field(&cls, &field_name, jval);
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    // jniGetStaticField(emuId, className, fieldName) -> Value
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetStaticField",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      cls: String,
                      field_name: String|
                      -> rquickjs::Result<Value<'js>> {
                    let stored = with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc
                            .get_data()
                            .jni
                            .get_static_field(&cls, &field_name)
                            .copied())
                    })?;
                    jvalue_opt_to_js(&ctx, stored)
                },
            )?,
        )?;
    }

    // jniSetStrictFindClass(emuId, enabled) -> void
    {
        let host = Rc::clone(host);
        native.set(
            "jniSetStrictFindClass",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, enabled: bool| -> rquickjs::Result<()> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.get_data_mut().jni.strict_find_class = enabled;
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    // jniDescribeField(emuId, fieldId) -> { id, className, name, sig, isStatic } | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniDescribeField",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, fid: f64| -> rquickjs::Result<Value<'js>> {
                    let fid_u64 = fid as u64;
                    let info = with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc.get_data().jni.describe_field(fid_u64).cloned())
                    })?;
                    let Some(f) = info else {
                        return Ok(Value::new_null(ctx.clone()));
                    };
                    let obj = Object::new(ctx.clone())?;
                    obj.set("id", fid_u64 as f64)?;
                    obj.set("className", f.class_name)?;
                    obj.set("name", f.name)?;
                    obj.set("sig", f.sig)?;
                    obj.set("isStatic", f.is_static)?;
                    Ok(obj.into_value())
                },
            )?,
        )?;
    }

    // jniListFields(emuId) -> Array<{ id, className, name, sig, isStatic }>
    {
        let host = Rc::clone(host);
        native.set(
            "jniListFields",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Array<'js>> {
                    let items = with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc
                            .get_data()
                            .jni
                            .list_fields()
                            .into_iter()
                            .map(|(id, f)| (id, f.clone()))
                            .collect::<Vec<_>>())
                    })?;
                    let arr = Array::new(ctx.clone())?;
                    for (i, (id, f)) in items.into_iter().enumerate() {
                        let obj = Object::new(ctx.clone())?;
                        obj.set("id", id as f64)?;
                        obj.set("className", f.class_name)?;
                        obj.set("name", f.name)?;
                        obj.set("sig", f.sig)?;
                        obj.set("isStatic", f.is_static)?;
                        arr.set(i, obj)?;
                    }
                    Ok(arr)
                },
            )?,
        )?;
    }

    // jniDescribeMethod(emuId, methodId) -> { id, className, name, sig, isStatic } | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniDescribeMethod",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, mid: f64| -> rquickjs::Result<Value<'js>> {
                    let mid_u64 = mid as u64;
                    let info = with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc.get_data().jni.describe_method(mid_u64).cloned())
                    })?;
                    let Some(m) = info else {
                        return Ok(Value::new_null(ctx.clone()));
                    };
                    let obj = Object::new(ctx.clone())?;
                    obj.set("id", mid_u64 as f64)?;
                    obj.set("className", m.class_name)?;
                    obj.set("name", m.name)?;
                    obj.set("sig", m.sig)?;
                    obj.set("isStatic", m.is_static)?;
                    Ok(obj.into_value())
                },
            )?,
        )?;
    }

    // jniListMethods(emuId) -> Array<{ id, className, name, sig, isStatic }>
    {
        let host = Rc::clone(host);
        native.set(
            "jniListMethods",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Array<'js>> {
                    let items = with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc
                            .get_data()
                            .jni
                            .list_methods()
                            .into_iter()
                            .map(|(id, m)| (id, m.clone()))
                            .collect::<Vec<_>>())
                    })?;
                    let arr = Array::new(ctx.clone())?;
                    for (i, (id, m)) in items.into_iter().enumerate() {
                        let obj = Object::new(ctx.clone())?;
                        obj.set("id", id as f64)?;
                        obj.set("className", m.class_name)?;
                        obj.set("name", m.name)?;
                        obj.set("sig", m.sig)?;
                        obj.set("isStatic", m.is_static)?;
                        arr.set(i, obj)?;
                    }
                    Ok(arr)
                },
            )?,
        )?;
    }

    // jniDescribeObject(emuId, objRef) -> { ref, className, kind } | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniDescribeObject",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, obj_ref: f64| -> rquickjs::Result<Value<'js>> {
                    let r = JObjectRef(obj_ref as u64);
                    let info = if let Some(res) = with_active_objects(|objs| {
                        objs.get(r).map(|o| (o.class_name().to_string(), object_kind_str(o)))
                    }) {
                        res
                    } else {
                        with_uc(&ctx, &host, emu_id, |uc| {
                            Ok(uc.get_data().jni.describe_object(r))
                        })?
                    };
                    let Some((class_name, kind)) = info else {
                        return Ok(Value::new_null(ctx.clone()));
                    };
                    let obj = Object::new(ctx.clone())?;
                    obj.set("ref", r.0 as f64)?;
                    obj.set("className", class_name)?;
                    obj.set("kind", kind)?;
                    Ok(obj.into_value())
                },
            )?,
        )?;
    }

    // jniTraceStart(emuId, maxStrLen, maxEvents)
    {
        let host = Rc::clone(host);
        native.set(
            "jniTraceStart",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      max_str_len: usize,
                      max_events: usize|
                      -> rquickjs::Result<()> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.get_data_mut()
                            .jni
                            .jni_tracer
                            .start(max_str_len, max_events);
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    // jniTraceStop(emuId)
    {
        let host = Rc::clone(host);
        native.set(
            "jniTraceStop",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<()> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.get_data_mut().jni.jni_tracer.stop();
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    // jniTraceClear(emuId)
    {
        let host = Rc::clone(host);
        native.set(
            "jniTraceClear",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<()> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.get_data_mut().jni.jni_tracer.clear();
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    // jniTraceEvents(emuId) -> JniTraceEvent[]
    {
        let host = Rc::clone(host);
        native.set(
            "jniTraceEvents",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Array<'js>> {
                    let events = with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc.get_data().jni.jni_tracer.events().to_vec())
                    })?;
                    let arr = Array::new(ctx.clone())?;
                    for (i, ev) in events.iter().enumerate() {
                        arr.set(i, jni_trace_event_to_js(&ctx, ev)?)?;
                    }
                    Ok(arr)
                },
            )?,
        )?;
    }

    // jniTraceOnEvent(emuId, fn | null)
    {
        let host = Rc::clone(host);
        native.set(
            "jniTraceOnEvent",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, cb: Value<'js>| -> rquickjs::Result<()> {
                    if cb.is_null() || cb.is_undefined() {
                        return with_uc(&ctx, &host, emu_id, |uc| {
                            uc.get_data_mut().jni.jni_tracer.set_listener(None);
                            Ok(())
                        });
                    }
                    let func = cb
                        .into_function()
                        .ok_or_else(|| throw_err(&ctx, "jni.trace.onEvent 需要函数或 null"))?;
                    let persistent = Persistent::save(&ctx, func);
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.get_data_mut().jni.jni_tracer.set_listener(Some(Box::new(
                            move |ev| {
                                let Some(raw_ctx) = current_js_ctx() else {
                                    return;
                                };
                                // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 有效
                                let js_ctx = unsafe { Ctx::from_raw(raw_ctx) };
                                if let (Ok(f), Ok(js_ev)) = (
                                    persistent.clone().restore(&js_ctx),
                                    jni_trace_event_to_js(&js_ctx, ev),
                                ) {
                                    if let Err(err) = f.call::<_, Value<'_>>((js_ev,)) {
                                        eprintln!("[JS JNI EVENT ERROR] {}: {err}", ev.op);
                                    }
                                }
                            },
                        )));
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    // emuLoadDex(emuId, pathOrPaths) -> { classes, addedClasses, totalClasses, dexCount }
    {
        let host = Rc::clone(host);
        native.set(
            "emuLoadDex",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      paths: Vec<String>|
                      -> rquickjs::Result<Object<'js>> {
                    let mut dex_files: Vec<PathBuf> = Vec::new();
                    for raw in paths {
                        let p = PathBuf::from(&raw);
                        if p.is_dir() {
                            let mut dir_entries: Vec<PathBuf> = fs::read_dir(&p)
                                .map_err(|e| throw_err(&ctx, format!("读取 DEX 目录失败 {raw}: {e}")))?
                                .filter_map(|e| e.ok().map(|ent| ent.path()))
                                .filter(|fp| {
                                    fp.is_file()
                                        && fp
                                            .extension()
                                            .and_then(|s| s.to_str())
                                            .is_some_and(|ext| ext.eq_ignore_ascii_case("dex"))
                                })
                                .collect();
                            // 自然排序：classes.dex < classes2.dex < classes10.dex
                            dir_entries.sort_by(|a, b| {
                                let na = a.file_name().and_then(|s| s.to_str()).unwrap_or("");
                                let nb = b.file_name().and_then(|s| s.to_str()).unwrap_or("");
                                (na.len(), na).cmp(&(nb.len(), nb))
                            });
                            dex_files.extend(dir_entries);
                        } else {
                            dex_files.push(p);
                        }
                    }

                    let (added_total, total_classes, dex_count) =
                        with_uc(&ctx, &host, emu_id, |uc| {
                            let mut added_sum = 0usize;
                            for p in &dex_files {
                                let name = p
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| "classes.dex".to_string());
                                let bytes = fs::read(p).map_err(|e| {
                                    throw_err(&ctx, format!("读取 DEX 失败 {}: {e}", p.display()))
                                })?;
                                let data = uc.get_data_mut();
                                let pkg = data.vfs.package_name.clone();
                                data.vfs.add_overlay_file(
                                    format!("/data/app/{pkg}/{name}"),
                                    bytes.clone(),
                                );
                                added_sum += data
                                    .jni
                                    .dex_index
                                    .add_dex_bytes(&bytes)
                                    .map_err(|e| throw_err(&ctx, e))?;
                            }
                            let idx = &uc.get_data().jni.dex_index;
                            Ok((added_sum, idx.class_count(), idx.dex_count()))
                        })?;
                    let obj = Object::new(ctx.clone())?;
                    obj.set("classes", added_total)?;
                    obj.set("addedClasses", added_total)?;
                    obj.set("totalClasses", total_classes)?;
                    obj.set("dexCount", dex_count)?;
                    Ok(obj)
                },
            )?,
        )?;
    }

    // hookImportResolve(emuId, symbolName) -> trampolineAddr
    {
        let host = Rc::clone(host);
        native.set(
            "hookImportResolve",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, sym_name: String| -> rquickjs::Result<f64> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let mut mem = std::mem::replace(
                            &mut uc.get_data_mut().mem,
                            crate::memory::MemoryManager::new(0, 0),
                        );
                        let mut tramp = std::mem::take(&mut uc.get_data_mut().trampolines);
                        let res = tramp.resolve_or_register_import(uc, &mut mem, &sym_name);
                        uc.get_data_mut().mem = mem;
                        uc.get_data_mut().trampolines = tramp;
                        res.map(|a| a as f64).map_err(|e| throw_err(&ctx, e))
                    })
                },
            )?,
        )?;
    }

    // dexClasses(emuId, prefix?) -> string[]
    {
        let host = Rc::clone(host);
        native.set(
            "dexClasses",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      prefix: Option<String>|
                      -> rquickjs::Result<Vec<String>> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc
                            .get_data()
                            .jni
                            .dex_index
                            .list_classes(prefix.as_deref()))
                    })
                },
            )?,
        )?;
    }

    // dexClassInfo(emuId, className) -> { name, superClass, interfaces, fields, methods, staticValues } | null
    {
        let host = Rc::clone(host);
        native.set(
            "dexClassInfo",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      class_name: String|
                      -> rquickjs::Result<Value<'js>> {
                    let info = with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc.get_data().jni.dex_index.get_class(&class_name).cloned())
                    })?;
                    let Some(info) = info else {
                        return Ok(Value::new_null(ctx.clone()));
                    };
                    let obj = Object::new(ctx.clone())?;
                    obj.set("name", info.name)?;
                    match info.super_class {
                        Some(sc) => obj.set("superClass", sc)?,
                        None => obj.set("superClass", Value::new_null(ctx.clone()))?,
                    }
                    let ifaces = Array::new(ctx.clone())?;
                    for (i, iface) in info.interfaces.iter().enumerate() {
                        ifaces.set(i, iface.as_str())?;
                    }
                    obj.set("interfaces", ifaces)?;

                    let fields = Array::new(ctx.clone())?;
                    for (i, f) in info.fields.iter().enumerate() {
                        let fo = Object::new(ctx.clone())?;
                        fo.set("name", f.name.as_str())?;
                        fo.set("sig", f.sig.as_str())?;
                        fo.set("isStatic", f.is_static)?;
                        fields.set(i, fo)?;
                    }
                    obj.set("fields", fields)?;

                    let methods = Array::new(ctx.clone())?;
                    for (i, m) in info.methods.iter().enumerate() {
                        let mo = Object::new(ctx.clone())?;
                        mo.set("name", m.name.as_str())?;
                        mo.set("sig", m.sig.as_str())?;
                        mo.set("isDirect", m.is_direct)?;
                        methods.set(i, mo)?;
                    }
                    obj.set("methods", methods)?;

                    let sv_obj = Object::new(ctx.clone())?;
                    for (k, v) in &info.static_values {
                        sv_obj.set(k.as_str(), dex_value_to_js(&ctx, v)?)?;
                    }
                    obj.set("staticValues", sv_obj)?;
                    Ok(obj.into_value())
                },
            )?,
        )?;
    }

    // jniPushLocalFrame(emuId) -> void
    {
        let host = Rc::clone(host);
        native.set(
            "jniPushLocalFrame",
            Function::new(ctx.clone(), move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<()> {
                let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                let entry = h
                    .emus
                    .get_mut(emu_id)
                    .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                entry.emu.jni_mut().objects.push_local_frame();
                Ok(())
            })?,
        )?;
    }

    // jniPopLocalFrame(emuId, keepRef) -> number (removed count)
    {
        let host = Rc::clone(host);
        native.set(
            "jniPopLocalFrame",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, keep_ref: f64| -> rquickjs::Result<usize> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let d = uc.get_data_mut();
                        Ok(d.jni.pop_local_frame(&mut d.mem, JObjectRef(keep_ref as u64)))
                    })
                },
            )?,
        )?;
    }

    // jniObjectCount(emuId) -> number
    {
        let host = Rc::clone(host);
        native.set(
            "jniObjectCount",
            Function::new(ctx.clone(), move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<usize> {
                let h = host.borrow();
                let entry = h
                    .emus
                    .get(emu_id)
                    .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                Ok(entry.emu.jni().objects.len())
            })?,
        )?;
    }

    // ---- Memory APIs (支持原生 Hook 内重入) ----
    {
        let host = Rc::clone(host);
        native.set(
            "memAlloc",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, size: f64| -> rquickjs::Result<f64> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let req_sz = (size as u64).max(1);
                        let frozen = uc.get_data().mem.is_layout_frozen();
                        let addr = if frozen {
                            let mut mem = std::mem::replace(
                                &mut uc.get_data_mut().mem,
                                crate::memory::MemoryManager::new(0, 0),
                            );
                            let res = mem.alloc_host_scratch(uc, req_sz);
                            uc.get_data_mut().mem = mem;
                            res.map_err(|e| throw_err(&ctx, e))?
                        } else {
                            uc.get_data_mut()
                                .mem
                                .alloc_heap(req_sz)
                                .map_err(|e| throw_err(&ctx, e))?
                        };
                        Ok(addr as f64)
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memAllocScratch",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, size: f64| -> rquickjs::Result<f64> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let req_sz = (size as u64).max(1);
                        let mut mem = std::mem::replace(
                            &mut uc.get_data_mut().mem,
                            crate::memory::MemoryManager::new(0, 0),
                        );
                        let res = mem.alloc_host_scratch(uc, req_sz);
                        uc.get_data_mut().mem = mem;
                        let addr = res.map_err(|e| throw_err(&ctx, e))?;
                        Ok(addr as f64)
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memSetFreezeLayout",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, enabled: bool| -> rquickjs::Result<()> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.get_data_mut().mem.set_freeze_layout(enabled);
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memHeapLayout",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, limit: f64| -> rquickjs::Result<Object<'js>> {
                    let cap = if limit.is_finite() && limit > 0.0 {
                        limit as usize
                    } else {
                        512
                    };
                    let (frozen, heap_base, heap_used, heap_hwm, total_allocs, items) =
                        with_uc(&ctx, &host, emu_id, |uc| {
                            let mem = &uc.get_data().mem;
                            let log = mem.heap_alloc_log();
                            let start = log.len().saturating_sub(cap);
                            Ok((
                                mem.is_layout_frozen(),
                                mem.heap_ref().base(),
                                mem.heap_ref().used(),
                                mem.heap_ref().high_water_mark(),
                                log.len(),
                                log.iter().skip(start).cloned().collect::<Vec<_>>(),
                            ))
                        })?;
                    let out = Object::new(ctx.clone())?;
                    out.set("frozen", frozen)?;
                    out.set("heapBaseHex", format!("0x{heap_base:016x}"))?;
                    out.set("heapUsed", heap_used as f64)?;
                    out.set("heapHighWater", heap_hwm as f64)?;
                    out.set("totalAllocs", total_allocs as f64)?;
                    let arr = Array::new(ctx.clone())?;
                    for (i, rec) in items.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("seq", rec.seq as f64)?;
                        o.set("op", rec.op)?;
                        o.set("ptr", rec.ptr as f64)?;
                        o.set("ptrHex", format!("0x{:016x}", rec.ptr))?;
                        o.set("size", rec.size as f64)?;
                        o.set("callerPc", rec.caller_pc as f64)?;
                        o.set("callerPcHex", format!("0x{:016x}", rec.caller_pc))?;
                        o.set("freed", rec.freed)?;
                        arr.set(i, o)?;
                    }
                    out.set("allocations", arr)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "isDefaultFreezeLayout",
            Function::new(ctx.clone(), move || {
                host.try_borrow().map(|h| h.default_freeze_layout).unwrap_or(false)
            })?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memFree",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, addr: f64| -> rquickjs::Result<bool> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc.get_data_mut().mem.hle_free(addr as u64))
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memHeapUsed",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<f64> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(uc.get_data().mem.heap_used() as f64)
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memReadBytes",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr_val: Value<'js>,
                      len: usize|
                      -> rquickjs::Result<TypedArray<'js, u8>> {
                    let addr = js_addr_to_u64_strict(&ctx, &addr_val)?;
                    let buf = with_uc(&ctx, &host, emu_id, |uc| {
                        let mut buf = vec![0u8; len];
                        if len > 0 {
                            uc.mem_read(addr, &mut buf)
                                .map_err(|e| throw_err(&ctx, format!("mem_read 失败: {e:?}")))?;
                        }
                        Ok(buf)
                    })?;
                    TypedArray::new(ctx.clone(), buf)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memWriteBytes",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      bytes: TypedArray<'js, u8>|
                      -> rquickjs::Result<()> {
                    let slice = bytes.as_bytes().unwrap_or(&[]);
                    with_uc(&ctx, &host, emu_id, |uc| {
                        if !slice.is_empty() {
                            uc.mem_write(addr as u64, slice)
                                .map_err(|e| throw_err(&ctx, format!("mem_write 失败: {e:?}")))?;
                        }
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memReadCString",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      addr: f64,
                      max_len: usize|
                      -> rquickjs::Result<String> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(read_guest_cstr(uc, addr as u64, max_len))
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memWriteCString",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      addr: f64,
                      s: String|
                      -> rquickjs::Result<usize> {
                    let mut bytes = s.into_bytes();
                    bytes.push(0);
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.mem_write(addr as u64, &bytes)
                            .map_err(|e| throw_err(&ctx, format!("mem_write 失败: {e:?}")))?;
                        Ok(bytes.len())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memReadU32",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, addr: f64| -> rquickjs::Result<f64> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let mut b = [0u8; 4];
                        uc.mem_read(addr as u64, &mut b)
                            .map_err(|e| throw_err(&ctx, format!("mem_read 失败: {e:?}")))?;
                        Ok(f64::from(u32::from_le_bytes(b)))
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memWriteU32",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, addr: f64, v: f64| -> rquickjs::Result<()> {
                    let raw = (v as i64) as u32;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.mem_write(addr as u64, &raw.to_le_bytes())
                            .map_err(|e| throw_err(&ctx, format!("mem_write 失败: {e:?}")))?;
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memReadU64",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, addr: f64| -> rquickjs::Result<BigInt<'js>> {
                    let val = with_uc(&ctx, &host, emu_id, |uc| {
                        let mut b = [0u8; 8];
                        uc.mem_read(addr as u64, &mut b)
                            .map_err(|e| throw_err(&ctx, format!("mem_read 失败: {e:?}")))?;
                        Ok(u64::from_le_bytes(b))
                    })?;
                    BigInt::from_u64(ctx.clone(), val)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memWriteU64",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      v: BigInt<'js>|
                      -> rquickjs::Result<()> {
                    let raw = v.to_i64().unwrap_or(0) as u64;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.mem_write(addr as u64, &raw.to_le_bytes())
                            .map_err(|e| throw_err(&ctx, format!("mem_write 失败: {e:?}")))?;
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    // V2: memScan(emuId, start, len, pattern) -> number[]
    {
        let host = Rc::clone(host);
        native.set(
            "memScan",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      start: f64,
                      len: f64,
                      pattern: String|
                      -> rquickjs::Result<Vec<f64>> {
                    let pat = parse_hex_pattern(&pattern).map_err(|e| throw_err(&ctx, e))?;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let hits = scan_memory(uc, start as u64, len.max(0.0) as u64, &pat);
                        Ok(hits.into_iter().map(|a| a as f64).collect())
                    })
                },
            )?,
        )?;
    }

    // V2: memPatch(emuId, addr, bytes) -> writtenLen
    {
        let host = Rc::clone(host);
        native.set(
            "memPatch",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      bytes: TypedArray<'js, u8>|
                      -> rquickjs::Result<usize> {
                    let slice = bytes.as_bytes().unwrap_or(&[]);
                    with_uc(&ctx, &host, emu_id, |uc| {
                        if !slice.is_empty() {
                            let a = addr as u64;
                            uc.mem_write(a, slice)
                                .map_err(|e| throw_err(&ctx, format!("memPatch 失败: {e:?}")))?;
                            let _ = uc.flush_cache(a, a.saturating_add(slice.len() as u64));
                        }
                        Ok(slice.len())
                    })
                },
            )?,
        )?;
    }

    // V2: memNop(emuId, addr, count) -> writtenBytes
    {
        let host = Rc::clone(host);
        native.set(
            "memNop",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, addr: f64, count: usize| -> rquickjs::Result<usize> {
                    let bytes = encode_arm64_nop(count.max(1));
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let a = addr as u64;
                        uc.mem_write(a, &bytes)
                            .map_err(|e| throw_err(&ctx, format!("memNop 失败: {e:?}")))?;
                        let _ = uc.flush_cache(a, a.saturating_add(bytes.len() as u64));
                        Ok(bytes.len())
                    })
                },
            )?,
        )?;
    }

    // V2: memRet(emuId, addr, hasVal, val) -> writtenBytes
    {
        let host = Rc::clone(host);
        native.set(
            "memRet",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      addr: f64,
                      has_val: bool,
                      val: Value<'_>|
                      -> rquickjs::Result<usize> {
                    let retval = if has_val {
                        Some(js_val_to_u64(&ctx, &val)? as i64)
                    } else {
                        None
                    };
                    let bytes = encode_arm64_ret(retval);
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let a = addr as u64;
                        uc.mem_write(a, &bytes)
                            .map_err(|e| throw_err(&ctx, format!("memRet 失败: {e:?}")))?;
                        let _ = uc.flush_cache(a, a.saturating_add(bytes.len() as u64));
                        Ok(bytes.len())
                    })
                },
            )?,
        )?;
    }

    // good64: asmEncode(source, pc) -> Uint8Array
    {
        native.set(
            "asmEncode",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, source: String, pc: Value<'js>| -> rquickjs::Result<TypedArray<'js, u8>> {
                    let base_pc = js_addr_to_u64_strict(&ctx, &pc)?;
                    let bytes = crate::good64::assemble(&source, base_pc)
                        .map_err(|e| throw_err(&ctx, format!("good64 汇编失败: {e}")))?;
                    TypedArray::new(ctx.clone(), bytes)
                },
            )?,
        )?;
    }

    // good64: asmRelocate(bytes, oldPc, newPc) -> Uint8Array
    {
        native.set(
            "asmRelocate",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      bytes: TypedArray<'js, u8>,
                      old_pc: Value<'js>,
                      new_pc: Value<'js>|
                      -> rquickjs::Result<TypedArray<'js, u8>> {
                    let old_p = js_addr_to_u64_strict(&ctx, &old_pc)?;
                    let new_p = js_addr_to_u64_strict(&ctx, &new_pc)?;
                    let slice = bytes.as_bytes().ok_or_else(|| {
                        throw_err(&ctx, "asmRelocate: Uint8Array 缓冲区已分离".to_string())
                    })?;
                    let relocated = crate::good64::relocate_instructions(slice, old_p, new_p)
                        .map_err(|e| throw_err(&ctx, format!("good64 重定位失败: {e}")))?;
                    TypedArray::new(ctx.clone(), relocated)
                },
            )?,
        )?;
    }

    // good64: memPatchAsm(emuId, addr, source) -> writtenBytes
    {
        let host = Rc::clone(host);
        native.set(
            "memPatchAsm",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: Value<'js>,
                      source: String|
                      -> rquickjs::Result<usize> {
                    let a = js_addr_to_u64_strict(&ctx, &addr)?;
                    let bytes = crate::good64::assemble(&source, a)
                        .map_err(|e| throw_err(&ctx, format!("good64 汇编失败: {e}")))?;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        if !bytes.is_empty() {
                            uc.mem_write(a, &bytes)
                                .map_err(|e| throw_err(&ctx, format!("memPatchAsm 写入失败: {e:?}")))?;
                            let _ = uc.flush_cache(a, a.saturating_add(bytes.len() as u64));
                        }
                        Ok(bytes.len())
                    })
                },
            )?,
        )?;
    }

    // good64: memInlineJump(emuId, fromAddr, targetAddr) -> writtenBytes (4B B or 16B LDR+BR)
    {
        let host = Rc::clone(host);
        native.set(
            "memInlineJump",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      from_addr: Value<'js>,
                      target_addr: Value<'js>|
                      -> rquickjs::Result<usize> {
                    let from = js_addr_to_u64_strict(&ctx, &from_addr)?;
                    let target = js_addr_to_u64_strict(&ctx, &target_addr)?;
                    if (from & 3) != 0 || (target & 3) != 0 {
                        return Err(throw_err(
                            &ctx,
                            format!(
                                "memInlineJump 地址必须 4 字节对齐: from=0x{from:x}, target=0x{target:x}"
                            ),
                        ));
                    }
                    let bytes = crate::good64::encode_branch_trampoline(from, target);
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.mem_write(from, &bytes).map_err(|e| {
                            throw_err(&ctx, format!("memInlineJump 写入失败: {e:?}"))
                        })?;
                        let _ = uc.flush_cache(from, from.saturating_add(bytes.len() as u64));
                        Ok(bytes.len())
                    })
                },
            )?,
        )?;
    }

    // ---- VFS APIs ----
    {
        let host = Rc::clone(host);
        native.set(
            "vfsSetProperty",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, k: String, v: String| -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.vfs_mut().set_property(k, v);
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "vfsWriteText",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      path: String,
                      text: String|
                      -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.vfs_mut().add_overlay_file(path, text.into_bytes());
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "vfsWriteBytes",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      path: String,
                      bytes: TypedArray<'js, u8>|
                      -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry
                        .emu
                        .vfs_mut()
                        .add_overlay_file(path, bytes.as_bytes().unwrap_or(&[]).to_vec());
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "vfsReadFile",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      path: String|
                      -> rquickjs::Result<Option<TypedArray<'js, u8>>> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    match entry.emu.cpu().get_data().vfs.get_overlay_file(&path) {
                        Some(data) => Ok(Some(TypedArray::new(ctx.clone(), data.to_vec())?)),
                        None => Ok(None),
                    }
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "vfsMountOverlay",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      guest_dir: String,
                      host_dir: String|
                      -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.vfs_mut().mount_readonly(guest_dir, host_dir);
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "vfsSetTime",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, unix_secs: f64| -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.vfs_mut().set_clock_secs(unix_secs.max(0.0) as u64);
                    Ok(())
                },
            )?,
        )?;
    }

    // ---- Network / Virtual NIC / Packet Capture APIs ----
    {
        let host = Rc::clone(host);
        native.set(
            "netConfigure",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, opts: Value<'js>| -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let cfg = &mut entry.emu.vfs_mut().net.config;
                    if let Some(b) = opts.as_bool() {
                        cfg.enabled = b;
                        if b {
                            cfg.capture_packets = true;
                        }
                        return Ok(());
                    }
                    if let Some(obj) = opts.as_object() {
                        if let Ok(en) = obj.get::<_, bool>("enabled") {
                            cfg.enabled = en;
                        }
                        if let Ok(cap) = obj.get::<_, bool>("capture") {
                            cfg.capture_packets = cap;
                        }
                        if let Ok(hosts) = obj.get::<_, Vec<String>>("allowHosts") {
                            cfg.allow_hosts = hosts;
                        }
                        if let Ok(nic_obj) = obj.get::<_, Object<'js>>("nic") {
                            apply_nic_js_obj(&mut cfg.nic, &nic_obj);
                        }
                    }
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "netSetNic",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, obj: Object<'js>| -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    apply_nic_js_obj(&mut entry.emu.vfs_mut().net.config.nic, &obj);
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "netNic",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Object<'js>> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let nic = &entry.emu.cpu().get_data().vfs.net.config.nic;
                    let out = Object::new(ctx.clone())?;
                    out.set("name", nic.name.as_str())?;
                    out.set("ipv4", nic.ipv4_string())?;
                    out.set("gateway", nic.gateway_string())?;
                    out.set("mac", nic.mac_string())?;
                    out.set("ipv6", nic.ipv6.as_str())?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "netPackets",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Array<'js>> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let pkts = entry.emu.cpu().get_data().vfs.net.packets();
                    let arr = Array::new(ctx.clone())?;
                    for (i, p) in pkts.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("fd", p.fd)?;
                        o.set("dir", p.dir)?;
                        o.set("peer", p.peer.as_str())?;
                        o.set("len", p.data.len())?;
                        let hex: String = p.data.iter().map(|b| format!("{b:02x}")).collect();
                        o.set("hex", hex)?;
                        o.set("text", String::from_utf8_lossy(&p.data).into_owned())?;
                        arr.set(i, o)?;
                    }
                    Ok(arr)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "netClearPackets",
            Function::new(ctx.clone(), move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<()> {
                let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                let entry = h
                    .emus
                    .get_mut(emu_id)
                    .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                entry.emu.vfs_mut().net.clear_packets();
                Ok(())
            })?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "netSetInterceptor",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      is_send: bool,
                      cb: Option<Function<'js>>|
                      -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let interceptor = cb.map(|func| {
                        let persisted = Persistent::save(&ctx, func);
                        let closure: crate::os::net::PacketInterceptor =
                            Box::new(move |fd: i32, peer: &str, data: &[u8]| -> Option<Vec<u8>> {
                                let raw_ctx = CURRENT_JS_CTX.with(|c| c.get())?;
                                // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 有效
                                let js_ctx: Ctx<'_> = unsafe { Ctx::from_raw(raw_ctx) };
                                let f = persisted.clone().restore(&js_ctx).ok()?;
                                let pkt = Object::new(js_ctx.clone()).ok()?;
                                let _ = pkt.set("fd", fd);
                                let _ = pkt.set("peer", peer);
                                if let Ok(ta) = TypedArray::new(js_ctx.clone(), data.to_vec()) {
                                    let _ = pkt.set("data", ta);
                                }
                                let _ = pkt.set("text", String::from_utf8_lossy(data).into_owned());
                                let ret: Value<'_> = f.call((pkt,)).ok()?;
                                if ret.is_undefined() || ret.is_null() {
                                    return None;
                                }
                                if let Some(s) = ret.as_string().and_then(|s| s.to_string().ok()) {
                                    return Some(s.into_bytes());
                                }
                                if let Some(obj) = ret.as_object() {
                                    if let Some(ta) = obj.as_typed_array::<u8>() {
                                        if let Some(bytes) = ta.as_bytes() {
                                            return Some(bytes.to_vec());
                                        }
                                    }
                                }
                                None
                            });
                        closure
                    });
                    if is_send {
                        entry.emu.vfs_mut().net.set_on_send(interceptor);
                    } else {
                        entry.emu.vfs_mut().net.set_on_recv(interceptor);
                    }
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "vfsUseRealClock",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, enabled: bool| -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.vfs_mut().set_use_real_clock(enabled);
                    Ok(())
                },
            )?,
        )?;
    }

    // vfsSetDevice(emuId, presetOrObj)
    {
        let host = Rc::clone(host);
        native.set(
            "vfsSetDevice",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, val: Value<'js>| -> rquickjs::Result<()> {
                    let mut profile = if let Some(s) = val.as_string() {
                        let name = s.to_string()?;
                        crate::os::DeviceProfile::from_preset(&name).ok_or_else(|| {
                            throw_err(
                                &ctx,
                                format!("未知的设备预设: {name}（支持 pixel5 / pixel8pro / s24ultra / xiaomi14）"),
                            )
                        })?
                    } else if let Some(obj) = val.as_object() {
                        let mut base = if let Ok(Some(preset)) = obj.get::<_, Option<String>>("preset") {
                            crate::os::DeviceProfile::from_preset(&preset).ok_or_else(|| {
                                throw_err(&ctx, format!("未知的设备预设: {preset}"))
                            })?
                        } else {
                            let h = host.borrow();
                            let entry = h
                                .emus
                                .get(emu_id)
                                .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                            entry.emu.vfs().device_profile().clone()
                        };
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("brand") { base.brand = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("manufacturer") { base.manufacturer = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("model") { base.model = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("device") { base.device = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("product") { base.product = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("board") { base.board = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("hardware") { base.hardware = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("socPlatform") { base.soc_platform = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("fingerprint") { base.fingerprint = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("buildId") { base.build_id = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("buildDisplay") { base.build_display = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("incremental") { base.incremental = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("securityPatch") { base.security_patch = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("androidRelease") { base.android_release = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<u32>>("sdkInt") { base.sdk_int = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("abi") { base.abi = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("abiList") { base.abi_list = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<u32>>("cpuCores") { base.cpu_cores = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<f64>>("ramTotalKb") { base.ram_total_kb = v.max(0.0) as u64; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("kernelRelease") { base.kernel_release = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("kernelVersion") { base.kernel_version = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<u32>>("screenWidth") { base.screen_width = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<u32>>("screenHeight") { base.screen_height = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<u32>>("screenDpi") { base.screen_dpi = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("locale") { base.locale = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("timezone") { base.timezone = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("carrierName") { base.carrier_name = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("carrierMccMnc") { base.carrier_mcc_mnc = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("serialNo") { base.serial_no = v; }
                        if let Ok(Some(v)) = obj.get::<_, Option<String>>("androidId") { base.android_id = v; }
                        base
                    } else {
                        return Err(throw_err(&ctx, "vfs.setDevice 参数必须为预设名称字符串或配置对象"));
                    };
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    // 同步更新 VFS 与 JNI Build 字段
                    let _ = &mut profile;
                    entry.emu.apply_device_profile(profile);
                    Ok(())
                },
            )?,
        )?;
    }

    // vfsDeviceProfile(emuId) -> DeviceProfile object
    {
        let host = Rc::clone(host);
        native.set(
            "vfsDeviceProfile",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Object<'js>> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let dp = entry.emu.vfs().device_profile();
                    let obj = Object::new(ctx.clone())?;
                    obj.set("brand", dp.brand.as_str())?;
                    obj.set("manufacturer", dp.manufacturer.as_str())?;
                    obj.set("model", dp.model.as_str())?;
                    obj.set("device", dp.device.as_str())?;
                    obj.set("product", dp.product.as_str())?;
                    obj.set("board", dp.board.as_str())?;
                    obj.set("hardware", dp.hardware.as_str())?;
                    obj.set("socPlatform", dp.soc_platform.as_str())?;
                    obj.set("fingerprint", dp.fingerprint.as_str())?;
                    obj.set("buildId", dp.build_id.as_str())?;
                    obj.set("buildDisplay", dp.build_display.as_str())?;
                    obj.set("incremental", dp.incremental.as_str())?;
                    obj.set("securityPatch", dp.security_patch.as_str())?;
                    obj.set("androidRelease", dp.android_release.as_str())?;
                    obj.set("sdkInt", dp.sdk_int)?;
                    obj.set("abi", dp.abi.as_str())?;
                    obj.set("abiList", dp.abi_list.as_str())?;
                    obj.set("cpuCores", dp.cpu_cores)?;
                    obj.set("ramTotalKb", dp.ram_total_kb as f64)?;
                    obj.set("kernelRelease", dp.kernel_release.as_str())?;
                    obj.set("kernelVersion", dp.kernel_version.as_str())?;
                    obj.set("screenWidth", dp.screen_width)?;
                    obj.set("screenHeight", dp.screen_height)?;
                    obj.set("screenDpi", dp.screen_dpi)?;
                    obj.set("locale", dp.locale.as_str())?;
                    obj.set("timezone", dp.timezone.as_str())?;
                    obj.set("carrierName", dp.carrier_name.as_str())?;
                    obj.set("carrierMccMnc", dp.carrier_mcc_mnc.as_str())?;
                    obj.set("serialNo", dp.serial_no.as_str())?;
                    obj.set("androidId", dp.android_id.as_str())?;
                    Ok(obj)
                },
            )?,
        )?;
    }

    // ---- Trace & Snapshot APIs ----
    {
        let host = Rc::clone(host);
        native.set(
            "traceStart",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      output: String,
                      level_str: String,
                      start: f64,
                      end: f64,
                      capacity: f64|
                      -> rquickjs::Result<()> {
                    const MAX_JS_TRACE_CAPACITY: u64 = 100_000_000;
                    let cap_u64 = require_nonneg_int(&ctx, capacity, "capacity")?;
                    if cap_u64 > MAX_JS_TRACE_CAPACITY {
                        return Err(throw_err(
                            &ctx,
                            format!("trace capacity 超过上限 ({MAX_JS_TRACE_CAPACITY}): {cap_u64}"),
                        ));
                    }
                    let cap = (cap_u64 as usize).max(1024);
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    if !entry.emu.backend_kind().supports_trace() {
                        return Err(throw_err(
                            &ctx,
                            format!(
                                "当前后端 `{}` 仅支持仿真模式，不支持 Trace 模式（Trace 仅支持 `unicorn` 后端）",
                                entry.emu.backend_kind()
                            ),
                        ));
                    }
                    let level = match level_str.as_str() {
                        "fast" => TraceLevel::Fast,
                        "full" => TraceLevel::Full,
                        _ => TraceLevel::RegDelta,
                    };
                    let mut tracer = if output.is_empty() {
                        const MAX_IN_MEM_CAPACITY: usize = 8_000_000;
                        if cap > MAX_IN_MEM_CAPACITY {
                            return Err(throw_err(
                                &ctx,
                                format!("纯内存模式 trace capacity 超过上限 ({MAX_IN_MEM_CAPACITY})，请指定 output 文件路径"),
                            ));
                        }
                        BinaryTracer::new_in_memory_with_level(cap, level)
                    } else if level == TraceLevel::Full {
                        let ext = if output.ends_with(".idx") {
                            Path::new(&output)
                                .with_extension("ext")
                                .to_string_lossy()
                                .into_owned()
                        } else {
                            format!("{output}.ext")
                        };
                        BinaryTracer::new_dual_mmap(
                            &output,
                            &ext,
                            cap,
                            cap.saturating_mul(2),
                            level,
                        )
                        .map_err(|e| throw_err(&ctx, e))?
                    } else {
                        let mut t = BinaryTracer::new_mmap(&output, cap)
                            .map_err(|e| throw_err(&ctx, e))?;
                        t.set_level(level);
                        t
                    };
                    let begin = start.max(0.0) as u64;
                    let finish = if end < 0.0 { u64::MAX } else { end as u64 };
                    if begin > 0 || finish < u64::MAX {
                        tracer.filter_mut().allow_range(begin, finish);
                    }
                    entry.emu.set_tracer(tracer).map_err(|e| throw_err(&ctx, e))?;
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "traceStop",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Object<'js>> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    if !entry.emu.backend_kind().supports_trace() {
                        return Err(throw_err(
                            &ctx,
                            format!(
                                "当前后端 `{}` 仅支持仿真模式，不支持 Trace 模式（Trace 仅支持 `unicorn` 后端）",
                                entry.emu.backend_kind()
                            ),
                        ));
                    }
                    entry.emu.detach_tracer().map_err(|e| throw_err(&ctx, e))?;
                    let stats = entry.emu.tracer().stats;
                    let obj = Object::new(ctx.clone())?;
                    obj.set("records", stats.recorded_insns as f64)?;
                    obj.set("extRecords", stats.recorded_ext as f64)?;
                    obj.set("totalInsns", stats.total_insns as f64)?;
                    obj.set("droppedInsns", stats.dropped_insns as f64)?;
                    obj.set("droppedExt", stats.dropped_ext as f64)?;
                    Ok(obj)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuSnapshot",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<usize> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let snap = entry
                        .emu
                        .capture_snapshot()
                        .map_err(|e| throw_err(&ctx, e))?;
                    let id = entry.snapshots.len();
                    entry.snapshots.push(snap);
                    Ok(id)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuRestore",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, snap_id: usize| -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let snap = entry
                        .snapshots
                        .get(snap_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 snapshotId"))?;
                    entry
                        .emu
                        .restore_snapshot(snap)
                        .map_err(|e| throw_err(&ctx, e))?;
                    Ok(())
                },
            )?,
        )?;
    }

    // ---- .rtape 持久化多检查点磁带 API ----
    {
        let host = Rc::clone(host);
        native.set(
            "emuSaveTape",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      path: String,
                      label: Option<String>|
                      -> rquickjs::Result<Object<'js>> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
                        throw_err(&ctx, "当前处于原生/JNI 回调重入上下文，不可执行磁带录制")
                    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let nh = Rc::clone(&entry.native_hooks);
                    if let Some(uc) = entry.emu.try_uc_mut() {
                        nh.borrow().temporarily_restore_replace_insns(uc);
                    }
                    let res = entry
                        .emu
                        .save_tape(&path, label.unwrap_or_else(|| "base".to_string()));
                    if let Some(uc) = entry.emu.try_uc_mut() {
                        nh.borrow().reapply_replace_ret_insns(uc);
                    }
                    let summary = res.map_err(|e| throw_err(&ctx, e))?;
                    tape_summary_to_js(&ctx, &summary)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuCheckpointTape",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      path: String,
                      label: Option<String>|
                      -> rquickjs::Result<Object<'js>> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
                        throw_err(&ctx, "当前处于原生/JNI 回调重入上下文，不可追加磁带检查点")
                    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let nh = Rc::clone(&entry.native_hooks);
                    if let Some(uc) = entry.emu.try_uc_mut() {
                        nh.borrow().temporarily_restore_replace_insns(uc);
                    }
                    let res = entry
                        .emu
                        .append_tape_checkpoint(&path, label.unwrap_or_default());
                    if let Some(uc) = entry.emu.try_uc_mut() {
                        nh.borrow().reapply_replace_ret_insns(uc);
                    }
                    let info = res.map_err(|e| throw_err(&ctx, e))?;
                    tape_checkpoint_to_js(&ctx, &info)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "emuLoadTape",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      path: String,
                      checkpoint: Option<String>,
                      backend_name: Option<String>,
                      search_paths: Option<Vec<String>>|
                      -> rquickjs::Result<Object<'js>> {
                    let backend_kind: BackendKind = match backend_name.as_deref() {
                        Some(s) if !s.trim().is_empty() => {
                            s.parse().map_err(|e| throw_err(&ctx, e))?
                        }
                        _ => BackendKind::Unicorn,
                    };
                    let selector = match checkpoint.as_deref() {
                        Some(s) => TapeSelector::parse(s),
                        None => TapeSelector::Latest,
                    };
                    let hooks = Rc::new(RefCell::new(JsHookTable::default()));
                    let native_hooks = Rc::new(RefCell::new(JsNativeHookTable::default()));
                    let mut builder = AndroidEmulator::builder()
                        .backend(backend_kind)
                        .jni_handler(Box::new(JsJniHandler::new(Rc::clone(&hooks))));
                    if let Some(paths) = search_paths {
                        for p in paths {
                            builder = builder.add_search_path(p);
                        }
                    }
                    let (emu, info) =
                        AndroidEmulator::from_tape_with_builder(&path, &selector, builder)
                            .map_err(|e| throw_err(&ctx, e))?;
                    {
                        let mut hb = hooks.borrow_mut();
                        hb.diag = emu.diag().clone();
                        hb.breadcrumbs = emu.breadcrumbs().clone();
                    }
                    let loaded_mods: Vec<Option<LoadedModule>> =
                        emu.linker().all_modules().into_iter().map(Some).collect();
                    let modules = Rc::new(RefCell::new(loaded_mods));
                    let mut h = host.try_borrow_mut().map_err(|_| {
                        throw_err(&ctx, "当前处于重入回调上下文，不可创建新模拟器实例")
                    })?;
                    let id = h.emus.len();
                    handles_table.borrow_mut().push(EmuSharedHandles {
                        jni_hooks: Rc::clone(&hooks),
                        native_hooks: Rc::clone(&native_hooks),
                        modules: Rc::clone(&modules),
                    });
                    h.emus.push(EmuEntry {
                        emu,
                        hooks,
                        native_hooks,
                        modules,
                        snapshots: Vec::new(),
                    });
                    let out = Object::new(ctx.clone())?;
                    out.set("emuId", id)?;
                    out.set("checkpoint", tape_checkpoint_to_js(&ctx, &info)?)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuSeekTape",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      path: String,
                      checkpoint: Option<String>|
                      -> rquickjs::Result<Object<'js>> {
                    let selector = match checkpoint.as_deref() {
                        Some(s) => TapeSelector::parse(s),
                        None => TapeSelector::Latest,
                    };
                    let mut h = host.try_borrow_mut().map_err(|_| {
                        throw_err(&ctx, "当前处于重入回调上下文，不可执行磁带倒带/快进")
                    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let info = entry
                        .emu
                        .seek_tape_file(&path, &selector)
                        .map_err(|e| throw_err(&ctx, e))?;
                    let nh = Rc::clone(&entry.native_hooks);
                    if let Some(uc) = entry.emu.try_uc_mut() {
                        nh.borrow().sync_after_tape_seek(uc);
                    }
                    // 就地同步已存在 mod._id 槽位（保留句柄稳定性），卸载的置 None，新增的追加到末尾
                    let synced = entry.emu.linker().all_modules();
                    let mut mods = entry.modules.borrow_mut();
                    for slot in mods.iter_mut() {
                        if let Some(existing) = slot.as_ref() {
                            if let Some(fresh) = synced
                                .iter()
                                .find(|m| m.name == existing.name && m.base_addr == existing.base_addr)
                            {
                                *slot = Some(fresh.clone());
                            } else {
                                *slot = None;
                            }
                        }
                    }
                    for lm in synced {
                        if !mods.iter().any(|slot| {
                            slot.as_ref()
                                .is_some_and(|m| m.name == lm.name && m.base_addr == lm.base_addr)
                        }) {
                            mods.push(Some(lm));
                        }
                    }
                    tape_checkpoint_to_js(&ctx, &info)
                },
            )?,
        )?;
    }

    native.set(
        "emuInspectTape",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, path: String| -> rquickjs::Result<Object<'js>> {
                let summary = Tape::inspect_file(&path).map_err(|e| throw_err(&ctx, e))?;
                tape_summary_to_js(&ctx, &summary)
            },
        )?,
    )?;

    {
        let host = Rc::clone(host);
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "emuModules",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Array<'js>> {
                    if let Ok(h) = host.try_borrow() {
                        let entry = h
                            .emus
                            .get(emu_id)
                            .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                        let mut mods = entry.modules.borrow_mut();
                        let linker_mods = entry.emu.linker().all_modules();
                        for lm in linker_mods {
                            if !mods.iter().any(|slot| {
                                slot.as_ref().is_some_and(|m| {
                                    m.name == lm.name && m.base_addr == lm.base_addr
                                })
                            }) {
                                mods.push(Some(lm));
                            }
                        }
                    }
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    let mods = handles.modules.borrow();
                    let arr = Array::new(ctx.clone())?;
                    let mut out_idx = 0usize;
                    for (idx, slot) in mods.iter().enumerate() {
                        if let Some(m) = slot.as_ref() {
                            let obj = Object::new(ctx.clone())?;
                            obj.set("id", idx)?;
                            obj.set("name", m.name.as_str())?;
                            obj.set("base", m.base_addr as f64)?;
                            obj.set("size", m.image_size as f64)?;
                            arr.set(out_idx, obj)?;
                            out_idx += 1;
                        }
                    }
                    Ok(arr)
                },
            )?,
        )?;
    }

    // ---- 二期 .rtape 确定性时间旅行录制与回放 API ----
    {
        let host = Rc::clone(host);
        native.set(
            "emuRecordStart",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      kf_interval: f64,
                      max_insns: f64,
                      capture_jni: bool|
                      -> rquickjs::Result<()> {
                    let keyframe_interval = require_nonneg_int(&ctx, kf_interval, "keyframeInterval")?;
                    let max_insns = require_nonneg_int(&ctx, max_insns, "maxInsns")?;
                    let mut h = host.try_borrow_mut().map_err(|_| {
                        throw_err(&ctx, "当前处于重入回调上下文，不可启动时间旅行录制")
                    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    if entry.native_hooks.borrow().has_mutating_hooks() {
                        return Err(throw_err(
                            &ctx,
                            "当前存在活跃的 JS Native Hook（replace/attach/code/syscall），离线回放无法复现其副作用且 replace 补丁会写入代码页；请先移除相关 Hook 再开启时间旅行录制",
                        ));
                    }
                    let cfg = RecordConfig {
                        keyframe_interval,
                        max_insns,
                        capture_jni,
                    };
                    entry
                        .emu
                        .start_time_travel_record(cfg)
                        .map_err(|e| throw_err(&ctx, e))
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuRecordBookmark",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, label: String| -> rquickjs::Result<f64> {
                    let h = host.try_borrow().map_err(|_| {
                        throw_err(&ctx, "当前处于重入回调上下文，不可打时间旅行书签")
                    })?;
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let insn = entry
                        .emu
                        .record_bookmark(label)
                        .map_err(|e| throw_err(&ctx, e))?;
                    Ok(insn as f64)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuRecordInsns",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<f64> {
                    let h = host.try_borrow().map_err(|_| {
                        throw_err(&ctx, "当前处于重入回调上下文，不可查询录制指令数")
                    })?;
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.recorded_insns() as f64)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuRecordIsRecording",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<bool> {
                    let h = host.try_borrow().map_err(|_| {
                        throw_err(&ctx, "当前处于重入回调上下文，不可查询录制状态")
                    })?;
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.is_time_travel_recording())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuRecordStop",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, path: String| -> rquickjs::Result<Object<'js>> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
                        throw_err(&ctx, "当前处于重入回调上下文，不可停止时间旅行录制")
                    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let summary = entry
                        .emu
                        .stop_time_travel_record(&path)
                        .map_err(|e| throw_err(&ctx, e))?;
                    tape_summary_to_js(&ctx, &summary)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttOpen",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, path: String| -> rquickjs::Result<Object<'js>> {
                    let player =
                        TimeTravelPlayer::open(&path).map_err(|e| throw_err(&ctx, e))?;
                    let start_insn = player.start_insn();
                    let total_insns = player.total_insns();
                    let keyframes = player.tape().len();
                    let bms_vec = player.bookmarks().to_vec();
                    let mods_vec = player.emu().linker().all_modules();
                    let mut h = host.try_borrow_mut().map_err(|_| {
                        throw_err(&ctx, "当前处于重入回调上下文，不可打开时间旅行会话")
                    })?;
                    let tt_id = h.time_travels.len();
                    h.time_travels.push(Some(player));

                    let out = Object::new(ctx.clone())?;
                    out.set("ttId", tt_id)?;
                    out.set("startInsn", start_insn as f64)?;
                    out.set("totalInsns", total_insns as f64)?;
                    out.set("keyframes", keyframes as f64)?;
                    let bms = Array::new(ctx.clone())?;
                    for (i, (ins, lbl)) in bms_vec.iter().enumerate() {
                        let b = Object::new(ctx.clone())?;
                        b.set("insn", *ins as f64)?;
                        b.set("label", lbl.as_str())?;
                        bms.set(i, b)?;
                    }
                    out.set("bookmarks", bms)?;
                    let mods = Array::new(ctx.clone())?;
                    for (i, m) in mods_vec.iter().enumerate() {
                        let mo = Object::new(ctx.clone())?;
                        mo.set("name", m.name.as_str())?;
                        mo.set("base", m.base_addr as f64)?;
                        mo.set("baseHex", format!("0x{:x}", m.base_addr))?;
                        mo.set("size", m.image_size as f64)?;
                        mods.set(i, mo)?;
                    }
                    out.set("modules", mods)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttClose",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, tt_id: usize| -> rquickjs::Result<bool> {
                    let mut h = host.try_borrow_mut().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    if let Some(slot) = h.time_travels.get_mut(tt_id) {
                        Ok(slot.take().is_some())
                    } else {
                        Ok(false)
                    }
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttCurrentInsn",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, tt_id: usize| -> rquickjs::Result<f64> {
                    let h = host.try_borrow().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let p = get_tt(&ctx, &h, tt_id)?;
                    Ok(p.current_insn() as f64)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttIsLiveForked",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, tt_id: usize| -> rquickjs::Result<bool> {
                    let h = host.try_borrow().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let p = get_tt(&ctx, &h, tt_id)?;
                    Ok(p.is_live_forked())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttSeekInsn",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, tt_id: usize, insn: f64| -> rquickjs::Result<Object<'js>> {
                    let target = require_nonneg_int(&ctx, insn, "target insn")?;
                    let mut h = host.try_borrow_mut().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let p = get_tt_mut(&ctx, &mut h, tt_id)?;
                    let stop = p.seek_insn(target).map_err(|e| throw_err(&ctx, e))?;
                    tt_stop_to_js(&ctx, p, &stop)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttSeekBookmark",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, tt_id: usize, label: String| -> rquickjs::Result<Object<'js>> {
                    let mut h = host.try_borrow_mut().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let p = get_tt_mut(&ctx, &mut h, tt_id)?;
                    let stop = p.seek_bookmark(&label).map_err(|e| throw_err(&ctx, e))?;
                    tt_stop_to_js(&ctx, p, &stop)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttStep",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, tt_id: usize, delta: f64| -> rquickjs::Result<Object<'js>> {
                    if !delta.is_finite() || delta.fract() != 0.0 {
                        return Err(throw_err(&ctx, "delta 必须为有限整数"));
                    }
                    let mut h = host.try_borrow_mut().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let p = get_tt_mut(&ctx, &mut h, tt_id)?;
                    let stop = if delta == 0.0 {
                        p.seek_insn(p.current_insn())
                    } else if delta < 0.0 {
                        p.step_backward((-delta) as u64)
                    } else {
                        p.step_forward(delta as u64)
                    }
                    .map_err(|e| throw_err(&ctx, e))?;
                    tt_stop_to_js(&ctx, p, &stop)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttFindMemAccess",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      tt_id: usize,
                      addr_val: Value<'js>,
                      len: f64,
                      kind: String,
                      backward: bool|
                      -> rquickjs::Result<Value<'js>> {
                    let addr = js_addr_to_u64_strict(&ctx, &addr_val)?;
                    let len_u64 = require_nonneg_int(&ctx, len, "len")?;
                    if len_u64 == 0 {
                        return Err(throw_err(&ctx, "len 必须为正整数 (>= 1)"));
                    }
                    let wk = parse_watch_kind(&ctx, &kind)?;
                    let mut h = host.try_borrow_mut().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let p = get_tt_mut(&ctx, &mut h, tt_id)?;
                    let res = if backward {
                        p.find_prev_mem_access(addr, len_u64, wk)
                    } else {
                        p.find_next_mem_access(addr, len_u64, wk)
                    }
                    .map_err(|e| throw_err(&ctx, e))?;
                    match res {
                        Some(hit) => Ok(tt_watch_hit_to_js(&ctx, p, &hit)?.into_value()),
                        None => Ok(Value::new_null(ctx.clone())),
                    }
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttRegs",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, tt_id: usize| -> rquickjs::Result<Object<'js>> {
                    let h = host.try_borrow().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let p = get_tt(&ctx, &h, tt_id)?;
                    let ordered = p.snapshot_regs_ordered().map_err(|e| throw_err(&ctx, e))?;
                    let obj = Object::new(ctx.clone())?;
                    for (k, v) in ordered {
                        obj.set(k.as_str(), v as f64)?;
                    }
                    Ok(obj)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttMemReadBytes",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      tt_id: usize,
                      addr_val: Value<'js>,
                      len_f: f64|
                      -> rquickjs::Result<TypedArray<'js, u8>> {
                    let addr = js_addr_to_u64_strict(&ctx, &addr_val)?;
                    let len_u64 = require_nonneg_int(&ctx, len_f, "len")?;
                    let len = usize::try_from(len_u64)
                        .map_err(|_| throw_err(&ctx, "len 超出平台范围"))?;
                    let h = host.try_borrow().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let p = get_tt(&ctx, &h, tt_id)?;
                    let bytes = p
                        .emu()
                        .cpu()
                        .mem_read_as_vec(addr, len)
                        .map_err(|e| throw_err(&ctx, e))?;
                    TypedArray::new(ctx.clone(), bytes)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "ttVerifyDeterminism",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, tt_id: usize| -> rquickjs::Result<Object<'js>> {
                    let mut h = host.try_borrow_mut().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let p = get_tt_mut(&ctx, &mut h, tt_id)?;
                    let verified = p.verify_determinism().map_err(|e| throw_err(&ctx, e))?;
                    let out = Object::new(ctx.clone())?;
                    out.set("verifiedKeyframes", verified as f64)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    // ---- V2: CPU 寄存器 & 仿真控制 ----
    {
        let host = Rc::clone(host);
        native.set(
            "regGet",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, name: String| -> rquickjs::Result<f64> {
                    let reg = parse_reg_name(&name)
                        .ok_or_else(|| throw_err(&ctx, format!("未知寄存器: {name}")))?;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let v = uc
                            .reg_read(reg)
                            .map_err(|e| throw_err(&ctx, format!("reg_read 失败: {e:?}")))?;
                        Ok(v as f64)
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "regGetBigInt",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, name: String| -> rquickjs::Result<BigInt<'js>> {
                    let reg = parse_reg_name(&name)
                        .ok_or_else(|| throw_err(&ctx, format!("未知寄存器: {name}")))?;
                    let val = with_uc(&ctx, &host, emu_id, |uc| {
                        uc.reg_read(reg)
                            .map_err(|e| throw_err(&ctx, format!("reg_read 失败: {e:?}")))
                    })?;
                    BigInt::from_u64(ctx.clone(), val)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "regSet",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      name: String,
                      val: Value<'_>|
                      -> rquickjs::Result<()> {
                    let reg = parse_reg_name(&name)
                        .ok_or_else(|| throw_err(&ctx, format!("未知寄存器: {name}")))?;
                    let raw = js_val_to_u64(&ctx, &val)?;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.reg_write(reg, raw)
                            .map_err(|e| throw_err(&ctx, format!("reg_write 失败: {e:?}")))?;
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "regDump",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Object<'js>> {
                    let pairs = with_uc(&ctx, &host, emu_id, |uc| Ok(dump_regs(uc)))?;
                    let obj = Object::new(ctx.clone())?;
                    for (name, val) in pairs {
                        obj.set(name, val as f64)?;
                    }
                    Ok(obj)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuStop",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<()> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.get_data_mut().manual_stop = true;
                        uc.stop()
                            .map_err(|e| throw_err(&ctx, format!("emu_stop 失败: {e:?}")))?;
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuSetLimits",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      timeout_ms: f64,
                      max_insns: f64|
                      -> rquickjs::Result<()> {
                    let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let timeout_us = if timeout_ms > 0.0 {
                        (timeout_ms * 1000.0) as u64
                    } else {
                        0
                    };
                    let max_instructions = if max_insns > 0.0 {
                        max_insns as usize
                    } else {
                        0
                    };
                    entry.emu.set_execution_limits(timeout_us, max_instructions);
                    Ok(())
                },
            )?,
        )?;
    }

    // ---- Phase 2: EnvDiag (缺环境自动诊断与模板生成) ----
    {
        let host = Rc::clone(host);
        native.set(
            "diagSetEnabled",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, enabled: bool| -> rquickjs::Result<()> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    if enabled {
                        entry.emu.diag().enable();
                    } else {
                        entry.emu.diag().disable();
                    }
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "diagClear",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<()> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.diag().clear();
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "diagReport",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Object<'js>> {
                    let snap = {
                        let h = host.borrow();
                        let entry = h
                            .emus
                            .get(emu_id)
                            .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                        entry.emu.diag().snapshot()
                    };
                    let out = Object::new(ctx.clone())?;
                    let files = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_files {
                        files.set(k, v as f64)?;
                    }
                    let props = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_properties {
                        props.set(k, v as f64)?;
                    }
                    let syscalls = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_syscalls {
                        syscalls.set(k.to_string(), v as f64)?;
                    }
                    let jni = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_jni {
                        jni.set(k, v as f64)?;
                    }
                    let hle = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_hle {
                        hle.set(k, v as f64)?;
                    }
                    let jni_fields = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_jni_fields {
                        jni_fields.set(k, v as f64)?;
                    }
                    let auxv = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_auxv {
                        auxv.set(k.to_string(), v as f64)?;
                    }
                    out.set("missingFiles", files)?;
                    out.set("missingProperties", props)?;
                    out.set("missingSyscalls", syscalls)?;
                    out.set("missingJni", jni)?;
                    out.set("missingHle", hle)?;
                    out.set("missingJniFields", jni_fields)?;
                    out.set("missingAuxv", auxv)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "diagGeneratePatchJs",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<String> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.diag().generate_patch_js())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuLastCrash",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Value<'js>> {
                    let report = {
                        let h = host.borrow();
                        let entry = h
                            .emus
                            .get(emu_id)
                            .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                        entry.emu.last_crash().cloned()
                    };
                    let Some(r) = report else {
                        return Ok(Value::new_null(ctx.clone()));
                    };
                    let obj = Object::new(ctx.clone())?;
                    obj.set("reason", r.reason.as_str())?;
                    obj.set("pc", r.pc as f64)?;
                    obj.set("pcHex", format!("0x{:016x}", r.pc))?;
                    obj.set("pcLocation", r.pc_location.as_str())?;
                    obj.set("lr", r.lr as f64)?;
                    obj.set("lrLocation", r.lr_location.as_str())?;
                    obj.set("sp", r.sp as f64)?;
                    obj.set("fp", r.fp as f64)?;

                    let disasm_arr = Array::new(ctx.clone())?;
                    for (i, d) in r.disasm.iter().enumerate() {
                        let item = Object::new(ctx.clone())?;
                        item.set("addr", format!("0x{:016x}", d.addr))?;
                        item.set("word", format!("0x{:08x}", d.word))?;
                        item.set("asm", d.asm.as_str())?;
                        item.set("isPc", d.is_pc)?;
                        disasm_arr.set(i, item)?;
                    }
                    obj.set("disasm", disasm_arr)?;

                    let bt_arr = Array::new(ctx.clone())?;
                    for (i, f) in r.backtrace.iter().enumerate() {
                        let item = Object::new(ctx.clone())?;
                        item.set("index", f.index as f64)?;
                        item.set("addr", format!("0x{:016x}", f.addr))?;
                        item.set("location", f.location.as_str())?;
                        bt_arr.set(i, item)?;
                    }
                    obj.set("backtrace", bt_arr)?;

                    let bc_arr = Array::new(ctx.clone())?;
                    for (i, b) in r.breadcrumbs.iter().enumerate() {
                        bc_arr.set(i, b.as_str())?;
                    }
                    obj.set("breadcrumbs", bc_arr)?;
                    obj.set("formatted", r.format_pretty())?;
                    Ok(obj.into_value())
                },
            )?,
        )?;
    }

    // ---- Phase 2: APK 一键加载 ----
    {
        let host = Rc::clone(host);
        native.set(
            "emuLoadApk",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, path: String| -> rquickjs::Result<Object<'js>> {
                    #[cfg(feature = "apk")]
                    {
                        let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                        let entry = h
                            .emus
                            .get_mut(emu_id)
                            .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                        let apk = entry
                            .emu
                            .load_apk(&path)
                            .map_err(|e| throw_err(&ctx, e))?;
                        let obj = Object::new(ctx.clone())?;
                        if let Some(pkg) = apk.package_name {
                            obj.set("packageName", pkg)?;
                        } else {
                            obj.set("packageName", Value::new_null(ctx.clone()))?;
                        }
                        obj.set("abi", apk.abi)?;
                        let libs = Array::new(ctx.clone())?;
                        for (i, name) in apk.native_libs.keys().enumerate() {
                            libs.set(i, name.as_str())?;
                        }
                        obj.set("libs", libs)?;
                        let assets = Array::new(ctx.clone())?;
                        for (i, name) in apk.assets.keys().enumerate() {
                            assets.set(i, name.as_str())?;
                        }
                        obj.set("assets", assets)?;
                        obj.set(
                            "signatureSize",
                            apk.signature_cert.as_ref().map_or(0usize, Vec::len) as f64,
                        )?;
                        Ok(obj)
                    }
                    #[cfg(not(feature = "apk"))]
                    {
                        let _ = (&host, emu_id, path);
                        Err(throw_err(
                            &ctx,
                            "当前构建未启用 `apk` feature，无法调用 loadApk",
                        ))
                    }
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuLoadApkLib",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      lib_name: String,
                      run_init: bool|
                      -> rquickjs::Result<Object<'js>> {
                    #[cfg(feature = "apk")]
                    {
                        let _guard = JsCtxGuard::enter(&ctx);
                        let mut h = host.try_borrow_mut().map_err(|_| {
        throw_err(
            &ctx,
            "当前处于原生/JNI 回调重入上下文，此 API 不可重入调用（请改用支持重入的 getString/getField/setField/getByteArray/newString/describeObject 等接口）",
        )
    })?;
                        let entry = h
                            .emus
                            .get_mut(emu_id)
                            .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                        let module = entry
                            .emu
                            .load_apk_library_with_init(&lib_name, run_init)
                            .map_err(|e| throw_err(&ctx, e))?;
                        let mut mods = entry.modules.borrow_mut();
                        let mod_id = mods.len();
                        let name = module.name.clone();
                        let base = module.base_addr;
                        let size = module.image_size;
                        mods.push(Some(module));
                        let obj = Object::new(ctx.clone())?;
                        obj.set("id", mod_id)?;
                        obj.set("name", name)?;
                        obj.set("base", base as f64)?;
                        obj.set("size", size as f64)?;
                        Ok(obj)
                    }
                    #[cfg(not(feature = "apk"))]
                    {
                        let _ = (&host, emu_id, lib_name, run_init);
                        Err(throw_err(
                            &ctx,
                            "当前构建未启用 `apk` feature，无法调用 loadApkLib",
                        ))
                    }
                },
            )?,
        )?;
    }

    // ---- V2: Native Hooks (code / mem / replace / attach / syscall / detach) ----
    // 全部使用 handles_table + with_uc，允许在 Hook 回调内安全重入增删 Hook（不会触发 RefCell already borrowed）
    {
        let host = Rc::clone(host);
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "hookCode",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      begin_val: Value<'js>,
                      end_val: Value<'js>,
                      max_hits: f64,
                      func: Function<'js>|
                      -> rquickjs::Result<usize> {
                    let begin = js_addr_to_u64_strict(&ctx, &begin_val)?;
                    let end = js_addr_to_u64_strict(&ctx, &end_val)?;
                    if begin > end {
                        return Err(throw_err(
                            &ctx,
                            format!("hook.code 区间非法: begin(0x{begin:x}) > end(0x{end:x})"),
                        ));
                    }
                    let persistent = Persistent::save(&ctx, func);
                    let limit = if max_hits < 0.0 {
                        None
                    } else {
                        Some(require_nonneg_int(&ctx, max_hits, "maxHits")?)
                    };
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    with_unicorn_only(&ctx, &host, emu_id, "hook.code", |uc| {
                        handles
                            .native_hooks
                            .borrow_mut()
                            .add_code_hook(emu_id, uc, begin, end, limit, persistent)
                            .map_err(|e| throw_err(&ctx, e))
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "hookMem",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      begin_val: Value<'js>,
                      end_val: Value<'js>,
                      opts: Object<'js>,
                      func: Function<'js>|
                      -> rquickjs::Result<Object<'js>> {
                    let begin = js_addr_to_u64_strict(&ctx, &begin_val)?;
                    let end = js_addr_to_u64_strict(&ctx, &end_val)?;
                    if begin > end {
                        return Err(throw_err(
                            &ctx,
                            format!("hook.mem 地址区间无效: begin(0x{begin:x}) > end(0x{end:x})"),
                        ));
                    }
                    let read: bool = opts.get("read").unwrap_or(true);
                    let write: bool = opts.get("write").unwrap_or(true);
                    let big_int: bool = opts.get("bigInt").unwrap_or(false);
                    let filter_val: Option<u64> = match opts.get::<_, Value<'js>>("value") {
                        Ok(v) if !v.is_undefined() && !v.is_null() => {
                            Some(js_addr_to_u64_strict(&ctx, &v)?)
                        }
                        _ => None,
                    };
                    let filter_size: Option<usize> = match opts.get::<_, Value<'js>>("size") {
                        Ok(v) if !v.is_undefined() && !v.is_null() => {
                            Some(js_addr_to_u64_strict(&ctx, &v)? as usize)
                        }
                        _ => None,
                    };
                    let filter_pc_range: Option<(u64, u64)> =
                        match opts.get::<_, Value<'js>>("pcRange") {
                            Ok(v) if !v.is_undefined() && !v.is_null() => {
                                let arr = v.into_array().ok_or_else(|| {
                                    throw_err(&ctx, "hook.mem pcRange 必须为 [lo, hi] 数组")
                                })?;
                                if arr.len() < 2 {
                                    return Err(throw_err(
                                        &ctx,
                                        "hook.mem pcRange 必须包含至少 2 个元素 [lo, hi]",
                                    ));
                                }
                                let lo_v: Value<'js> = arr.get(0)?;
                                let hi_v: Value<'js> = arr.get(1)?;
                                let pc_lo = js_addr_to_u64_strict(&ctx, &lo_v)?;
                                let pc_hi = js_addr_to_u64_strict(&ctx, &hi_v)?;
                                if pc_lo > pc_hi {
                                    return Err(throw_err(
                                        &ctx,
                                        format!(
                                            "hook.mem pcRange 无效: lo(0x{pc_lo:x}) > hi(0x{pc_hi:x})"
                                        ),
                                    ));
                                }
                                Some((pc_lo, pc_hi))
                            }
                            _ => None,
                        };
                    let filter = super::hooks::MemHookFilter {
                        value: filter_val,
                        size: filter_size,
                        pc_range: filter_pc_range,
                        big_int,
                    };
                    let persistent = Persistent::save(&ctx, func);
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    let (id, unmapped) =
                        with_unicorn_only(&ctx, &host, emu_id, "hook.mem", |uc| {
                            handles
                                .native_hooks
                                .borrow_mut()
                                .add_mem_hook(emu_id, uc, begin, end, read, write, filter, persistent)
                                .map_err(|e| throw_err(&ctx, e))
                        })?;
                    let out = Object::new(ctx.clone())?;
                    out.set("id", id)?;
                    out.set("unmapped", unmapped)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    // ---- 离线 Trace 查询与双跑差分（Trace.open / Trace.diff）----
    {
        let host = Rc::clone(host);
        native.set(
            "traceOpen",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      idx_path: String,
                      ext_opt: Option<String>|
                      -> rquickjs::Result<Object<'js>> {
                    let idx_p = std::path::PathBuf::from(&idx_path);
                    let resolved_ext = if let Some(ep) = ext_opt {
                        Some(std::path::PathBuf::from(ep))
                    } else {
                        crate::tracer::resolve_sibling_ext_path(&idx_p)
                    };
                    let reader = crate::tracer::TraceReader::open(&idx_p, resolved_ext.as_deref())
                        .map_err(|e| throw_err(&ctx, e))?;
                    let total_insns = reader.len();
                    let total_ext = reader.ext_len();
                    let missing_ext = reader.missing_ext_warning();
                    let recorded_level = reader.recorded_level_name();
                    let is_archive = reader.is_archive();
                    let archive_base = reader.archive_base_addr();
                    let mut h = host
                        .try_borrow_mut()
                        .map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let trace_id = h.trace_readers.len();
                    h.trace_readers.push(Some(reader));
                    let out = Object::new(ctx.clone())?;
                    out.set("traceId", trace_id)?;
                    out.set("totalInsns", total_insns as f64)?;
                    out.set("totalExt", total_ext as f64)?;
                    out.set("missingExtWarning", missing_ext)?;
                    out.set("isArchive", is_archive)?;
                    if let Some(b) = archive_base {
                        out.set("archiveBaseAddrHex", format!("0x{b:016x}"))?;
                    } else {
                        out.set("archiveBaseAddrHex", Value::new_null(ctx.clone()))?;
                    }
                    if let Some(lvl) = recorded_level {
                        out.set("recordedLevel", lvl)?;
                    } else {
                        out.set("recordedLevel", Value::new_null(ctx.clone()))?;
                    }
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "traceClose",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, trace_id: usize| -> rquickjs::Result<bool> {
                    let mut h = host
                        .try_borrow_mut()
                        .map_err(|_| throw_err(&ctx, "不可重入"))?;
                    Ok(h.trace_readers
                        .get_mut(trace_id)
                        .and_then(Option::take)
                        .is_some())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "traceQuery",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, trace_id: usize, opts: Object<'js>| -> rquickjs::Result<Array<'js>> {
                    let h = host.try_borrow().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let reader = h
                        .trace_readers
                        .get(trace_id)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| throw_err(&ctx, "无效或已关闭的 traceId"))?;
                    let limit: usize = match opts.get::<_, f64>("limit") {
                        Ok(v) if v.is_finite() && v > 0.0 => v as usize,
                        _ => 200,
                    };
                    let parse_opt_seq = |key: &str| -> rquickjs::Result<Option<u32>> {
                        match opts.get::<_, Value<'js>>(key) {
                            Ok(v) if !v.is_undefined() && !v.is_null() => {
                                let n = js_addr_to_u64_strict(&ctx, &v)?;
                                Ok(Some(n.min(u32::MAX as u64) as u32))
                            }
                            _ => Ok(None),
                        }
                    };
                    let at_seq = parse_opt_seq("at")?;
                    let min_seq = parse_opt_seq("minSeq")?;
                    let max_seq = parse_opt_seq("maxSeq")?;

                    let val_opt = opts
                        .get::<_, Value<'js>>("value")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null());
                    let addr_opt = opts
                        .get::<_, Value<'js>>("addr")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null());
                    if val_opt.is_some() && addr_opt.is_some() {
                        return Err(throw_err(&ctx, "trace.query 的 value 与 addr 参数互斥，请只提供其中一个"));
                    }
                    let upper_seq = max_seq.or(at_seq);

                    let hits = if let Some(v) = val_opt {
                        let target = js_addr_to_u64_strict(&ctx, &v)?;
                        let width = opts
                            .get::<_, f64>("width")
                            .ok()
                            .filter(|w| w.is_finite())
                            .or_else(|| {
                                opts.get::<_, f64>("align")
                                    .ok()
                                    .filter(|w| w.is_finite())
                            })
                            .map(|w| (w.clamp(1.0, 8.0)) as u8)
                            .unwrap_or_else(|| if target > u32::MAX as u64 { 8 } else { 4 });
                        reader.query_writes_by_value(target, width, min_seq, upper_seq, limit)
                    } else if let Some(av) = addr_opt {
                        let addr = js_addr_to_u64_strict(&ctx, &av)?;
                        let len = match opts.get::<_, Value<'js>>("len") {
                            Ok(v) if !v.is_undefined() && !v.is_null() => {
                                let n = v.as_number().ok_or_else(|| {
                                    throw_err(&ctx, "trace.query 参数 len 必须为正整数")
                                })?;
                                let u = require_nonneg_int(&ctx, n, "len")?;
                                if u == 0 {
                                    return Err(throw_err(&ctx, "trace.query 参数 len 必须 >= 1"));
                                }
                                u
                            }
                            _ => 1,
                        };
                        let writes_only: Option<bool> = match opts.get::<_, Value<'js>>("writesOnly") {
                            Ok(v) if !v.is_undefined() && !v.is_null() => Some(
                                v.as_bool().ok_or_else(|| {
                                    throw_err(&ctx, "trace.query 参数 writesOnly 必须为布尔值")
                                })?,
                            ),
                            _ => None,
                        };
                        let kind_str: Option<String> = match opts.get::<_, Value<'js>>("kind") {
                            Ok(v) if !v.is_undefined() && !v.is_null() => Some(
                                v.as_string()
                                    .and_then(|s| s.to_string().ok())
                                    .ok_or_else(|| {
                                        throw_err(&ctx, "trace.query 参数 kind 必须为字符串 (\"r\" | \"w\" | \"rw\")")
                                    })?
                                    .to_ascii_lowercase(),
                            ),
                            _ => None,
                        };
                        let (include_reads, include_writes) = match (kind_str.as_deref(), writes_only) {
                            (Some("r" | "read" | "reads"), Some(true)) => {
                                return Err(throw_err(
                                    &ctx,
                                    "trace.query 参数 kind=\"r\" 与 writesOnly=true 互斥",
                                ));
                            }
                            (Some("r" | "read" | "reads"), _) => (true, false),
                            (Some("w" | "write" | "writes"), _) => (false, true),
                            (Some("rw" | "all"), Some(true)) => {
                                return Err(throw_err(
                                    &ctx,
                                    "trace.query 参数 kind=\"rw\" 与 writesOnly=true 互斥",
                                ));
                            }
                            (Some("rw" | "all"), _) => (true, true),
                            (None, Some(true)) => (false, true),
                            (None, _) => (true, true),
                            (Some(other), _) => {
                                return Err(throw_err(
                                    &ctx,
                                    format!("无效的 trace.query kind `{other}`（支持 \"r\" | \"w\" | \"rw\"）"),
                                ));
                            }
                        };
                        let include_hle: bool = match opts.get::<_, Value<'js>>("includeHle") {
                            Ok(v) if !v.is_undefined() && !v.is_null() => v.as_bool().ok_or_else(|| {
                                throw_err(&ctx, "trace.query 参数 includeHle 必须为布尔值")
                            })?,
                            _ => true,
                        };
                        reader.query_addr_history_filtered(
                            addr,
                            len,
                            min_seq,
                            upper_seq,
                            include_reads,
                            include_writes,
                            include_hle,
                            limit,
                        )
                    } else {
                        return Err(throw_err(&ctx, "trace.query 需要提供 value 或 addr 参数"));
                    };

                    let arr = Array::new(ctx.clone())?;
                    for (i, hit) in hits.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("seq", hit.seq_low32 as f64)?;
                        o.set("pc", hit.pc as f64)?;
                        o.set("pcHex", format!("0x{:016x}", hit.pc))?;
                        o.set("addr", hit.addr as f64)?;
                        o.set("addrHex", format!("0x{:016x}", hit.addr))?;
                        o.set("size", hit.size as f64)?;
                        o.set("kind", hit.kind)?;
                        o.set("value", hit.value as f64)?;
                        o.set("value64", BigInt::from_u64(ctx.clone(), hit.value)?)?;
                        o.set("valueHex", format!("0x{:x}", hit.value))?;
                        if hit.src != 0 {
                            o.set("src", hit.src as f64)?;
                            o.set("srcHex", format!("0x{:016x}", hit.src))?;
                        }
                        arr.set(i, o)?;
                    }
                    Ok(arr)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "traceHleEvents",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, trace_id: usize, limit: f64| -> rquickjs::Result<Array<'js>> {
                    let h = host.try_borrow().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let reader = h
                        .trace_readers
                        .get(trace_id)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| throw_err(&ctx, "无效或已关闭的 traceId"))?;
                    let cap = if limit.is_finite() && limit > 0.0 { limit as usize } else { 500 };
                    let evs = reader.hle_events();
                    let arr = Array::new(ctx.clone())?;
                    for (i, ev) in evs.into_iter().take(cap).enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("seq", ev.seq_low32 as f64)?;
                        o.set("op", ev.op)?;
                        o.set("dst", ev.dst as f64)?;
                        o.set("dstHex", format!("0x{:016x}", ev.dst))?;
                        o.set("src", ev.src as f64)?;
                        o.set("srcHex", format!("0x{:016x}", ev.src))?;
                        o.set("len", ev.len as f64)?;
                        o.set("pc", ev.pc as f64)?;
                        o.set("pcHex", format!("0x{:016x}", ev.pc))?;
                        arr.set(i, o)?;
                    }
                    Ok(arr)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "traceReconstructMem",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      trace_id: usize,
                      addr_val: Value<'js>,
                      len: f64,
                      at_seq_val: Value<'js>|
                      -> rquickjs::Result<Object<'js>> {
                    let addr = js_addr_to_u64_strict(&ctx, &addr_val)?;
                    let byte_len_u64 = require_nonneg_int(&ctx, len, "len")?;
                    if byte_len_u64 > 65536 {
                        return Err(throw_err(
                            &ctx,
                            format!("reconstructMem 参数 len 超出上限 65536: {byte_len_u64}"),
                        ));
                    }
                    let byte_len = byte_len_u64 as usize;
                    let seq = if at_seq_val.is_undefined() || at_seq_val.is_null() {
                        u32::MAX
                    } else {
                        js_addr_to_u64_strict(&ctx, &at_seq_val)?.min(u32::MAX as u64) as u32
                    };
                    let h = host.try_borrow().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let reader = h
                        .trace_readers
                        .get(trace_id)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| throw_err(&ctx, "无效或已关闭的 traceId"))?;
                    if byte_len == 0 {
                        let out = Object::new(ctx.clone())?;
                        out.set("addrHex", format!("0x{addr:016x}"))?;
                        out.set("atSeq", seq as f64)?;
                        out.set("knownBytes", 0.0f64)?;
                        out.set("hex", "")?;
                        out.set("bytes", TypedArray::new(ctx.clone(), Vec::<u8>::new())?)?;
                        return Ok(out);
                    }
                    let bytes = reader.reconstruct_mem_at(addr, byte_len, seq);
                    let mut hex = String::with_capacity(byte_len * 2);
                    let mut known = 0usize;
                    let raw: Vec<u8> = bytes
                        .iter()
                        .map(|mb| match mb {
                            Some(b) => {
                                known += 1;
                                hex.push_str(&format!("{b:02x}"));
                                *b
                            }
                            None => {
                                hex.push_str("??");
                                0
                            }
                        })
                        .collect();
                    let out = Object::new(ctx.clone())?;
                    out.set("addrHex", format!("0x{addr:016x}"))?;
                    out.set("atSeq", seq as f64)?;
                    out.set("knownBytes", known as f64)?;
                    out.set("hex", hex)?;
                    out.set("bytes", TypedArray::new(ctx.clone(), raw)?)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "traceTaint",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      trace_id: usize,
                      mode: String,
                      opts: Object<'js>|
                      -> rquickjs::Result<Object<'js>> {
                    let reg_val = opts
                        .get::<_, Value<'js>>("reg")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null());
                    let addr_val = opts
                        .get::<_, Value<'js>>("addr")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null());
                    if reg_val.is_some() && addr_val.is_some() {
                        return Err(throw_err(&ctx, "taint 的 addr 与 reg 参数互斥，请只提供其中一个"));
                    }
                    let seed = if let Some(rv) = reg_val {
                        let reg_name = rv
                            .as_string()
                            .and_then(|s| s.to_string().ok())
                            .ok_or_else(|| throw_err(&ctx, "taint 参数 reg 必须为字符串"))?;
                        let slot = crate::tracer::parse_reg_slot(&reg_name).ok_or_else(|| {
                            throw_err(&ctx, format!("无效的寄存器名: {reg_name}"))
                        })?;
                        crate::tracer::TaintSeed::Reg { reg_id: slot }
                    } else if let Some(av) = addr_val {
                        let addr = js_addr_to_u64_strict(&ctx, &av)?;
                        let len = opts
                            .get::<_, f64>("len")
                            .ok()
                            .filter(|l| l.is_finite() && *l >= 1.0)
                            .map(|l| (l as usize).clamp(1, 65536))
                            .unwrap_or(8);
                        crate::tracer::TaintSeed::Mem { addr, len }
                    } else {
                        return Err(throw_err(&ctx, "taint 需要提供 addr 或 reg 参数"));
                    };

                    let anchor_idx: Option<usize> = opts
                        .get::<_, Value<'js>>("atIdx")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                        .or_else(|| {
                            opts.get::<_, Value<'js>>("startIdx")
                                .ok()
                                .filter(|v| !v.is_undefined() && !v.is_null())
                        })
                        .or_else(|| {
                            opts.get::<_, Value<'js>>("at")
                                .ok()
                                .filter(|v| !v.is_undefined() && !v.is_null())
                        })
                        .map(|v| js_addr_to_u64_strict(&ctx, &v).map(|n| n as usize))
                        .transpose()?;

                    let min_idx: Option<usize> = opts
                        .get::<_, Value<'js>>("fromIdx")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                        .or_else(|| {
                            opts.get::<_, Value<'js>>("minIdx")
                                .ok()
                                .filter(|v| !v.is_undefined() && !v.is_null())
                        })
                        .map(|v| js_addr_to_u64_strict(&ctx, &v).map(|n| n as usize))
                        .transpose()?;

                    let mut stop_at_pcs: Vec<u64> = Vec::new();
                    if let Ok(pcs_val) = opts.get::<_, Value<'js>>("stopAtPcs") {
                        if !pcs_val.is_undefined() && !pcs_val.is_null() {
                            let arr = pcs_val.as_array().ok_or_else(|| {
                                throw_err(&ctx, "taint 参数 stopAtPcs 必须为地址数组")
                            })?;
                            for idx_i in 0..arr.len() {
                                let v: Value<'js> = arr.get(idx_i)?;
                                stop_at_pcs.push(js_addr_to_u64_strict(&ctx, &v)?);
                            }
                        }
                    }
                    let mut stop_mem_ranges: Vec<(u64, usize)> = Vec::new();
                    if let Ok(sm_val) = opts.get::<_, Value<'js>>("stopMem") {
                        if !sm_val.is_undefined() && !sm_val.is_null() {
                            let arr = sm_val.as_array().ok_or_else(|| {
                                throw_err(&ctx, "taint 参数 stopMem 必须为 { addr, len? } 对象数组")
                            })?;
                            for idx_i in 0..arr.len() {
                                let item: Value<'js> = arr.get(idx_i)?;
                                let obj = item.as_object().ok_or_else(|| {
                                    throw_err(&ctx, "taint 参数 stopMem 数组元素必须为对象")
                                })?;
                                let av: Value<'js> = obj.get("addr")?;
                                let a = js_addr_to_u64_strict(&ctx, &av)?;
                                let l = match obj.get::<_, Value<'js>>("len") {
                                    Ok(lv) if !lv.is_undefined() && !lv.is_null() => {
                                        let n = lv.as_number().ok_or_else(|| {
                                            throw_err(&ctx, "stopMem[].len 必须为正整数")
                                        })?;
                                        let u = require_nonneg_int(&ctx, n, "stopMem[].len")?;
                                        if u == 0 || u > 65536 {
                                            return Err(throw_err(
                                                &ctx,
                                                format!("stopMem[].len 必须在 1..=65536 之间，收到 {u}"),
                                            ));
                                        }
                                        u as usize
                                    }
                                    _ => 8,
                                };
                                stop_mem_ranges.push((a, l));
                            }
                        }
                    }

                    let max_insns = opts
                        .get::<_, f64>("maxInsns")
                        .ok()
                        .filter(|v| v.is_finite() && *v >= 0.0)
                        .map(|v| v as usize)
                        .unwrap_or(0);
                    let max_steps = opts
                        .get::<_, f64>("maxSteps")
                        .ok()
                        .filter(|v| v.is_finite() && *v > 0.0)
                        .map(|v| v as usize)
                        .unwrap_or(512);
                    let track_mem_index: bool = opts.get("trackMemIndex").unwrap_or(true);
                    let track_sp: bool = opts.get("trackSp").unwrap_or(false);

                    let taint_opts = crate::tracer::TaintOptions {
                        anchor_idx,
                        min_idx,
                        stop_at_pcs,
                        stop_mem_ranges,
                        max_insns,
                        max_steps,
                        track_mem_index,
                        track_sp,
                    };

                    let h = host.try_borrow().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let reader = h
                        .trace_readers
                        .get(trace_id)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| throw_err(&ctx, "无效或已关闭的 traceId"))?;

                    let report = match mode.to_ascii_lowercase().as_str() {
                        "forward" | "fwd" => reader.taint_forward(&seed, &taint_opts),
                        "backward" | "bwd" | "slice" => reader.taint_backward(&seed, &taint_opts),
                        other => {
                            return Err(throw_err(
                                &ctx,
                                format!("无效的 taint mode `{other}`（支持 forward / backward）"),
                            ));
                        }
                    };

                    let out = Object::new(ctx.clone())?;
                    out.set("mode", report.mode)?;
                    out.set("seed", report.seed_desc)?;
                    out.set("anchorIdx", report.anchor_idx as f64)?;
                    out.set("stopIdx", report.stop_idx as f64)?;
                    out.set("scannedInsns", report.scanned_insns as f64)?;
                    out.set("totalMatchingSteps", report.total_matching_steps as f64)?;
                    let orig_arr = Array::new(ctx.clone())?;
                    for (i, o_str) in report.origin_annotations.iter().enumerate() {
                        orig_arr.set(i, o_str.as_str())?;
                    }
                    out.set("originAnnotations", orig_arr)?;

                    let steps_arr = Array::new(ctx.clone())?;
                    for (i, s) in report.steps.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("idx", s.idx as f64)?;
                        o.set("seq", s.seq as f64)?;
                        o.set("pc", s.pc as f64)?;
                        o.set("pcHex", format!("0x{:016x}", s.pc))?;
                        o.set("asm", s.asm.as_str())?;
                        o.set("kind", s.kind)?;
                        let src_arr = Array::new(ctx.clone())?;
                        for (j, src) in s.sources.iter().enumerate() {
                            src_arr.set(j, src.as_str())?;
                        }
                        o.set("sources", src_arr)?;
                        let dst_arr = Array::new(ctx.clone())?;
                        for (j, dst) in s.dests.iter().enumerate() {
                            dst_arr.set(j, dst.as_str())?;
                        }
                        o.set("dests", dst_arr)?;
                        o.set("tagMaskHex", format!("0x{:x}", s.tag_mask))?;
                        if let Some(v) = s.value {
                            o.set("value", v as f64)?;
                            o.set("valueHex", format!("0x{v:x}"))?;
                        }
                        steps_arr.set(i, o)?;
                    }
                    out.set("steps", steps_arr)?;

                    let regs_arr = Array::new(ctx.clone())?;
                    for (i, (name, mask)) in report.tainted_regs.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("name", name.as_str())?;
                        o.set("tagMaskHex", format!("0x{mask:x}"))?;
                        regs_arr.set(i, o)?;
                    }
                    out.set("taintedRegs", regs_arr)?;

                    let mem_arr = Array::new(ctx.clone())?;
                    for (i, &(addr, len, mask)) in report.tainted_mem_ranges.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("addr", addr as f64)?;
                        o.set("addrHex", format!("0x{addr:016x}"))?;
                        o.set("len", len as f64)?;
                        o.set("tagMaskHex", format!("0x{mask:x}"))?;
                        mem_arr.set(i, o)?;
                    }
                    out.set("taintedMemRanges", mem_arr)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "traceDecompileSlice",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      trace_id: usize,
                      opts: Object<'js>|
                      -> rquickjs::Result<Object<'js>> {
                    let has_reg = match opts.get::<_, Value<'js>>("reg") {
                        Ok(v) if !v.is_undefined() && !v.is_null() => Some(v),
                        _ => None,
                    };
                    let has_addr = match opts.get::<_, Value<'js>>("addr") {
                        Ok(v) if !v.is_undefined() && !v.is_null() => Some(v),
                        _ => None,
                    };
                    if has_reg.is_some() && has_addr.is_some() {
                        return Err(throw_err(
                            &ctx,
                            "decompileSlice 的 reg 与 addr 参数互斥，请只提供其中一个",
                        ));
                    }
                    let seed = if let Some(rv) = has_reg {
                        let reg_name = rv
                            .as_string()
                            .and_then(|s| s.to_string().ok())
                            .ok_or_else(|| throw_err(&ctx, "decompileSlice 参数 reg 必须为字符串"))?;
                        let slot = crate::tracer::parse_reg_slot(&reg_name)
                            .ok_or_else(|| throw_err(&ctx, format!("无效的寄存器名: {reg_name}")))?;
                        crate::tracer::TaintSeed::Reg { reg_id: slot }
                    } else if let Some(av) = has_addr {
                        let addr = js_addr_to_u64_strict(&ctx, &av)?;
                        let len: usize = match opts.get::<_, Value<'js>>("len") {
                            Ok(lv) if !lv.is_undefined() && !lv.is_null() => {
                                let n = lv.as_number().ok_or_else(|| {
                                    throw_err(&ctx, "decompileSlice 参数 len 必须为正整数")
                                })?;
                                let u = require_nonneg_int(&ctx, n, "len")?;
                                if u == 0 || u > 64 {
                                    return Err(throw_err(
                                        &ctx,
                                        format!("decompileSlice 参数 len 必须在 1..=64 之间，收到 {u}"),
                                    ));
                                }
                                u as usize
                            }
                            _ => 4,
                        };
                        crate::tracer::TaintSeed::Mem { addr, len }
                    } else {
                        return Err(throw_err(&ctx, "decompileSlice 需要提供 addr 或 reg 参数"));
                    };

                    let anchor_idx: Option<usize> = opts
                        .get::<_, Value<'js>>("atIdx")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                        .map(|v| js_addr_to_u64_strict(&ctx, &v).map(|n| n as usize))
                        .transpose()?;
                    let from_idx: Option<usize> = opts
                        .get::<_, Value<'js>>("fromIdx")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                        .or_else(|| {
                            opts.get::<_, Value<'js>>("minIdx")
                                .ok()
                                .filter(|v| !v.is_undefined() && !v.is_null())
                        })
                        .map(|v| js_addr_to_u64_strict(&ctx, &v).map(|n| n as usize))
                        .transpose()?;
                    let mut stop_at_pcs: Vec<u64> = Vec::new();
                    if let Ok(pcs_val) = opts.get::<_, Value<'js>>("stopAtPcs") {
                        if !pcs_val.is_undefined() && !pcs_val.is_null() {
                            let arr = pcs_val.as_array().ok_or_else(|| {
                                throw_err(&ctx, "taint 参数 stopAtPcs 必须为地址数组")
                            })?;
                            for idx_i in 0..arr.len() {
                                let v: Value<'js> = arr.get(idx_i)?;
                                stop_at_pcs.push(js_addr_to_u64_strict(&ctx, &v)?);
                            }
                        }
                    }
                    let mut stop_mem_ranges: Vec<(u64, usize)> = Vec::new();
                    if let Ok(sm_val) = opts.get::<_, Value<'js>>("stopMem") {
                        if !sm_val.is_undefined() && !sm_val.is_null() {
                            let arr = sm_val.as_array().ok_or_else(|| {
                                throw_err(&ctx, "taint 参数 stopMem 必须为 { addr, len? } 对象数组")
                            })?;
                            for idx_i in 0..arr.len() {
                                let item: Value<'js> = arr.get(idx_i)?;
                                let obj = item.as_object().ok_or_else(|| {
                                    throw_err(&ctx, "taint 参数 stopMem 数组元素必须为对象")
                                })?;
                                let av: Value<'js> = obj.get("addr")?;
                                let a = js_addr_to_u64_strict(&ctx, &av)?;
                                let l = match obj.get::<_, Value<'js>>("len") {
                                    Ok(lv) if !lv.is_undefined() && !lv.is_null() => {
                                        let n = lv.as_number().ok_or_else(|| {
                                            throw_err(&ctx, "stopMem[].len 必须为正整数")
                                        })?;
                                        let u = require_nonneg_int(&ctx, n, "stopMem[].len")?;
                                        if u == 0 || u > 65536 {
                                            return Err(throw_err(
                                                &ctx,
                                                format!("stopMem[].len 必须在 1..=65536 之间，收到 {u}"),
                                            ));
                                        }
                                        u as usize
                                    }
                                    _ => 8,
                                };
                                stop_mem_ranges.push((a, l));
                            }
                        }
                    }
                    let fold_rodata: bool = opts.get("foldRodata").unwrap_or(false);
                    let max_insns: usize = opts
                        .get::<_, f64>("maxInsns")
                        .ok()
                        .filter(|v| v.is_finite() && *v >= 0.0)
                        .map(|v| v as usize)
                        .unwrap_or(0);
                    let max_steps: usize = opts
                        .get::<_, f64>("maxSteps")
                        .ok()
                        .filter(|v| v.is_finite() && *v >= 1.0)
                        .map(|v| v as usize)
                        .unwrap_or(4096);
                    let track_mem_index: bool = opts.get("trackMemIndex").unwrap_or(true);
                    let track_sp: bool = opts.get("trackSp").unwrap_or(false);
                    let simplify: bool = opts.get("simplify").unwrap_or(true);
                    let emit_smt2: bool = opts.get("emitSmt2").unwrap_or(false);
                    let function_name: String = opts
                        .get::<_, String>("functionName")
                        .ok()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| "decompiled_slice".to_string());

                    let mut initial_regs = std::collections::HashMap::new();
                    if let Ok(ir_val) = opts.get::<_, Value<'js>>("initialRegs") {
                        if let Some(ir_obj) = ir_val.as_object() {
                            for (k, v) in ir_obj.props::<String, Value<'js>>().flatten() {
                                if let Some(slot) = crate::tracer::parse_reg_slot(&k) {
                                    let val = js_addr_to_u64_strict(&ctx, &v)?;
                                    initial_regs.insert(slot, val);
                                }
                            }
                        }
                    }

                    let decomp_opts = crate::tracer::DecompileOptions {
                        anchor_idx,
                        from_idx,
                        stop_at_pcs,
                        stop_mem_ranges,
                        fold_rodata,
                        max_insns,
                        max_steps,
                        track_mem_index,
                        track_sp,
                        function_name,
                        simplify,
                        emit_smt2,
                        initial_regs,
                    };

                    let h = host.try_borrow().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let reader = h
                        .trace_readers
                        .get(trace_id)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| throw_err(&ctx, "无效或已关闭的 traceId"))?;
                    let report = reader.decompile_slice(&seed, &decomp_opts);

                    let out = Object::new(ctx.clone())?;
                    out.set("seed", report.seed_desc)?;
                    out.set("anchorIdx", report.anchor_idx as f64)?;
                    out.set("stopIdx", report.stop_idx as f64)?;
                    out.set("scannedInsns", report.scanned_insns as f64)?;
                    let orig_arr = Array::new(ctx.clone())?;
                    for (i, o_str) in report.origin_annotations.iter().enumerate() {
                        orig_arr.set(i, o_str.as_str())?;
                    }
                    out.set("originAnnotations", orig_arr)?;
                    out.set("sliceInsns", report.slice_insns as f64)?;
                    out.set("rawNodes", report.raw_nodes as f64)?;
                    out.set("simplifiedNodes", report.simplified_nodes as f64)?;
                    out.set("outputLen", report.output_len as f64)?;
                    if let Some(exp) = report.expected_output {
                        out.set("expectedOutputHex", format!("0x{exp:x}"))?;
                    }
                    if let Some(ev) = report.evaluated_output {
                        out.set("evaluatedOutputHex", format!("0x{ev:x}"))?;
                    }
                    if let Some(ref exp_b) = report.expected_output_bytes_hex {
                        out.set("expectedOutputBytesHex", exp_b.as_str())?;
                    }
                    if let Some(ref ev_b) = report.evaluated_output_bytes_hex {
                        out.set("evaluatedOutputBytesHex", ev_b.as_str())?;
                    }
                    if let Some(v) = report.verified {
                        out.set("verified", v)?;
                    } else {
                        out.set("verified", rquickjs::Null)?;
                    }
                    out.set("cCode", report.c_code)?;
                    if let Some(smt) = report.smt2 {
                        out.set("smt2", smt)?;
                    } else {
                        out.set("smt2", rquickjs::Null)?;
                    }

                    let inputs_arr = Array::new(ctx.clone())?;
                    for (i, inp) in report.inputs.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("name", inp.name.as_str())?;
                        o.set("kind", inp.kind)?;
                        if let Some(a) = inp.addr {
                            o.set("addrHex", format!("0x{a:016x}"))?;
                        }
                        o.set("widthBytes", inp.width_bytes as f64)?;
                        if let Some(ref sh) = inp.sample_hex {
                            o.set("sampleHex", sh.as_str())?;
                        }
                        inputs_arr.set(i, o)?;
                    }
                    out.set("inputs", inputs_arr)?;

                    let tables_arr = Array::new(ctx.clone())?;
                    for (i, tbl) in report.tables.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("name", tbl.name.as_str())?;
                        o.set("baseAddrHex", format!("0x{:016x}", tbl.base_addr))?;
                        o.set("elemBytes", tbl.elem_bytes as f64)?;
                        o.set("observedCount", tbl.observed_entries.len() as f64)?;
                        tables_arr.set(i, o)?;
                    }
                    out.set("tables", tables_arr)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "traceVmAnalyze",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      trace_id: usize,
                      opts: Object<'js>|
                      -> rquickjs::Result<Object<'js>> {
                    let mut cfg = crate::tracer::VmAnalysisOptions::default();

                    let parse_opt_u64 = |key: &str| -> rquickjs::Result<Option<u64>> {
                        match opts.get::<_, Value<'js>>(key) {
                            Ok(v) if !v.is_undefined() && !v.is_null() => {
                                let n = v.as_number().ok_or_else(|| {
                                    throw_err(&ctx, format!("vmAnalyze 参数 {key} 必须为非负整数"))
                                })?;
                                Ok(Some(require_nonneg_int(&ctx, n, key)?))
                            }
                            _ => Ok(None),
                        }
                    };
                    let parse_bit_u8 = |v: Value<'js>, label: &str| -> rquickjs::Result<u8> {
                        let n = v.as_number().ok_or_else(|| {
                            throw_err(&ctx, format!("{label} 必须为非负整数"))
                        })?;
                        let u = require_nonneg_int(&ctx, n, label)?;
                        if u > 64 {
                            return Err(throw_err(
                                &ctx,
                                format!("{label} 超出合法位域范围 [0, 64]: {u}"),
                            ));
                        }
                        Ok(u as u8)
                    };

                    if let Some(v) = opts
                        .get::<_, Value<'js>>("dispatcherPc")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                    {
                        cfg.dispatcher_pc = Some(js_addr_to_u64_strict(&ctx, &v)?);
                    }
                    if let Some(v) = opts
                        .get::<_, Value<'js>>("bcReg")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                    {
                        let s = v
                            .as_string()
                            .and_then(|js| js.to_string().ok())
                            .ok_or_else(|| throw_err(&ctx, "vmAnalyze 参数 bcReg 必须为字符串"))?;
                        let slot = crate::tracer::parse_gpr_slot(&s).ok_or_else(|| {
                            throw_err(&ctx, format!("无效的 bcReg 寄存器名: {s}"))
                        })?;
                        cfg.bc_reg = Some(slot);
                    }
                    if let Some(v) = opts
                        .get::<_, Value<'js>>("bcDeref")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                    {
                        cfg.bc_deref = v
                            .as_bool()
                            .ok_or_else(|| throw_err(&ctx, "vmAnalyze 参数 bcDeref 必须为布尔值"))?;
                    }
                    if let Some(v) = opts
                        .get::<_, Value<'js>>("bcPtrAddr")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                    {
                        cfg.bc_ptr_addr = Some(js_addr_to_u64_strict(&ctx, &v)?);
                    }
                    if cfg.bc_reg.is_some() && cfg.bc_ptr_addr.is_some() {
                        return Err(throw_err(
                            &ctx,
                            "vmAnalyze 参数 bcReg 与 bcPtrAddr 互斥，请只提供其中一个",
                        ));
                    }
                    if cfg.bc_deref && cfg.bc_reg.is_none() {
                        return Err(throw_err(
                            &ctx,
                            "vmAnalyze 参数 bcDeref: true 必须配合 bcReg 使用",
                        ));
                    }

                    // 无论是否传 baseReg，都严格校验 regCount / regSize 合法性
                    let reg_count = match parse_opt_u64("regCount")? {
                        Some(n) => {
                            if !(1..=256).contains(&n) {
                                return Err(throw_err(&ctx, format!("regCount 必须在 [1, 256] 之间，收到 {n}")));
                            }
                            n as usize
                        }
                        None => 32,
                    };
                    let reg_size = match parse_opt_u64("regSize")? {
                        Some(4) => 4u8,
                        Some(8) => 8u8,
                        Some(other) => {
                            return Err(throw_err(&ctx, format!("regSize 仅支持 4 或 8，收到 {other}")));
                        }
                        None => 8u8,
                    };
                    if let Some(v) = opts
                        .get::<_, Value<'js>>("baseReg")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                    {
                        let s = v
                            .as_string()
                            .and_then(|js| js.to_string().ok())
                            .ok_or_else(|| throw_err(&ctx, "vmAnalyze 参数 baseReg 必须为字符串"))?;
                        let base_reg = crate::tracer::parse_gpr_slot(&s).ok_or_else(|| {
                            throw_err(&ctx, format!("无效的 baseReg 寄存器名: {s}"))
                        })?;
                        cfg.regfile = Some(crate::tracer::VmRegfileConfig {
                            base_reg,
                            count: reg_count,
                            size: reg_size,
                        });
                    }
                    if let Some(lv) = opts
                        .get::<_, Value<'js>>("layout")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                    {
                        if let Some(s) = lv.as_string().and_then(|js| js.to_string().ok()) {
                            cfg.layout = Some(
                                crate::tracer::VmWordLayout::parse_spec(&s)
                                    .map_err(|e| throw_err(&ctx, e))?,
                            );
                        } else if let Some(lo) = lv.as_object() {
                            if lv.is_array() {
                                return Err(throw_err(&ctx, "layout 必须为字符串或 { op, fields } 对象"));
                            }
                            let op_val = lo
                                .get::<_, Value<'js>>("op")
                                .map_err(|_| throw_err(&ctx, "layout.op 必须为 [lsb, width] 数组"))?;
                            let op_arr = op_val
                                .as_array()
                                .ok_or_else(|| throw_err(&ctx, "layout.op 必须为 [lsb, width] 数组"))?;
                            if op_arr.len() != 2 {
                                return Err(throw_err(&ctx, "layout.op 必须为 2 元素数组 [lsb, width]"));
                            }
                            let op_lsb = parse_bit_u8(op_arr.get::<Value<'js>>(0)?, "layout.op[0]")?;
                            let op_w = parse_bit_u8(op_arr.get::<Value<'js>>(1)?, "layout.op[1]")?;
                            let op_bf = crate::tracer::VmBitField::new(op_lsb, op_w)
                                .ok_or_else(|| throw_err(&ctx, format!("layout.op 位域越界: lsb={op_lsb}, width={op_w}")))?;
                            let mut raw_fields: Vec<(u8, Option<u8>)> = Vec::new();
                            if let Ok(fv_prop) = lo.get::<_, Value<'js>>("fields") {
                                if !fv_prop.is_undefined() && !fv_prop.is_null() {
                                    let f_arr = fv_prop.as_array().ok_or_else(|| {
                                        throw_err(&ctx, "layout.fields 必须为数组")
                                    })?;
                                    for i in 0..f_arr.len() {
                                        let fv: Value<'js> = f_arr.get(i)?;
                                        if let Some(sub) = fv.as_array() {
                                            if sub.len() != 2 {
                                                return Err(throw_err(&ctx, "layout.fields 元素若为数组则必须为 [lsb, width]"));
                                            }
                                            let lsb = parse_bit_u8(sub.get::<Value<'js>>(0)?, "field lsb")?;
                                            let w = parse_bit_u8(sub.get::<Value<'js>>(1)?, "field width")?;
                                            raw_fields.push((lsb, Some(w)));
                                        } else if fv.is_number() {
                                            let lsb = parse_bit_u8(fv, "field lsb")?;
                                            raw_fields.push((lsb, None));
                                        } else {
                                            return Err(throw_err(&ctx, "layout.fields 元素必须为整数或 [lsb, width]"));
                                        }
                                    }
                                }
                            }
                            let mut fields = Vec::with_capacity(raw_fields.len());
                            for (i, &(lsb, w_opt)) in raw_fields.iter().enumerate() {
                                let w = match w_opt {
                                    Some(w) => w,
                                    None => {
                                        if let Some(&(next_lsb, _)) = raw_fields.get(i + 1) {
                                            if next_lsb > lsb && (next_lsb - lsb) <= 16 {
                                                next_lsb - lsb
                                            } else {
                                                5u8.min(64u8.saturating_sub(lsb))
                                            }
                                        } else {
                                            5u8.min(64u8.saturating_sub(lsb))
                                        }
                                    }
                                };
                                let bf = crate::tracer::VmBitField::new(lsb, w)
                                    .ok_or_else(|| throw_err(&ctx, format!("layout.fields 位域越界: lsb={lsb}, width={w}")))?;
                                fields.push(bf);
                            }
                            cfg.layout = Some(crate::tracer::VmWordLayout { op: op_bf, fields });
                        } else {
                            return Err(throw_err(&ctx, "layout 必须为字符串或 { op, fields } 对象"));
                        }
                    }
                    if let Some(n) = parse_opt_u64("minHandlers")? {
                        if n == 0 {
                            return Err(throw_err(&ctx, "minHandlers 必须 >= 1"));
                        }
                        cfg.min_handlers = n as usize;
                    }
                    if let Some(n) = parse_opt_u64("minDispatches")? {
                        if n == 0 {
                            return Err(throw_err(&ctx, "minDispatches 必须 >= 1"));
                        }
                        cfg.min_dispatches = n as usize;
                    }
                    if let Some(n) = parse_opt_u64("minIdx")? {
                        cfg.min_idx = Some(n as usize);
                    }
                    if let Some(n) = parse_opt_u64("maxIdx")? {
                        cfg.max_idx = Some(n as usize);
                    }
                    if let (Some(lo), Some(hi)) = (cfg.min_idx, cfg.max_idx) {
                        if lo > hi {
                            return Err(throw_err(
                                &ctx,
                                format!("vmAnalyze 参数 minIdx ({lo}) 不能大于 maxIdx ({hi})"),
                            ));
                        }
                    }
                    if let Some(n) = parse_opt_u64("maxInsns")? {
                        cfg.max_insns = n as usize;
                    }
                    if let Some(n) = parse_opt_u64("maxSteps")? {
                        cfg.max_steps = n as usize;
                    }
                    let base_addr = opts
                        .get::<_, Value<'js>>("baseAddr")
                        .ok()
                        .filter(|v| !v.is_undefined() && !v.is_null())
                        .map(|v| js_addr_to_u64_strict(&ctx, &v))
                        .transpose()?
                        .unwrap_or(0);

                    let h = host.try_borrow().map_err(|_| throw_err(&ctx, "不可重入"))?;
                    let reader = h
                        .trace_readers
                        .get(trace_id)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| throw_err(&ctx, "无效或已关闭的 traceId"))?;
                    let report = reader.analyze_vm(&cfg);

                    let out = Object::new(ctx.clone())?;
                    out.set("scannedInsns", report.scanned_insns as f64)?;
                    out.set("totalVmSteps", report.total_vm_steps as f64)?;
                    if let Some(pc) = report.selected_dispatcher {
                        out.set("selectedDispatcher", pc as f64)?;
                        out.set("selectedDispatcherHex", format!("0x{pc:016x}"))?;
                    } else {
                        out.set("selectedDispatcher", Value::new_null(ctx.clone()))?;
                        out.set("selectedDispatcherHex", Value::new_null(ctx.clone()))?;
                    }
                    if let Some(ref r) = report.detected_bc_reg {
                        out.set("detectedBcReg", r.as_str())?;
                    } else {
                        out.set("detectedBcReg", Value::new_null(ctx.clone()))?;
                    }
                    if let Some(a) = report.detected_bc_mem_addr {
                        out.set("detectedBcMemAddr", a as f64)?;
                        out.set("detectedBcMemAddrHex", format!("0x{a:016x}"))?;
                    } else {
                        out.set("detectedBcMemAddr", Value::new_null(ctx.clone()))?;
                        out.set("detectedBcMemAddrHex", Value::new_null(ctx.clone()))?;
                    }

                    let disp_arr = Array::new(ctx.clone())?;
                    for (i, d) in report.dispatchers.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("pc", d.pc as f64)?;
                        o.set("pcHex", format!("0x{:016x}", d.pc))?;
                        o.set("kind", d.kind)?;
                        o.set("targetReg", crate::tracer::format_reg_slot(d.target_reg))?;
                        o.set("totalDispatches", d.total_dispatches as f64)?;
                        o.set("uniqueHandlers", d.unique_handlers as f64)?;
                        o.set("score", d.score as f64)?;
                        if let Some(tb) = d.jump_table_base {
                            o.set("jumpTableBase", tb as f64)?;
                            o.set("jumpTableBaseHex", format!("0x{tb:016x}"))?;
                        }
                        if let Some(esz) = d.jump_table_entry_size {
                            o.set("jumpTableEntrySize", esz as f64)?;
                        }
                        if let Some(r) = d.detected_bc_reg {
                            o.set("detectedBcReg", crate::tracer::format_reg_slot(r))?;
                        }
                        if let Some(a) = d.detected_bc_mem_addr {
                            o.set("detectedBcMemAddrHex", format!("0x{a:016x}"))?;
                        }
                        disp_arr.set(i, o)?;
                    }
                    out.set("dispatchers", disp_arr)?;

                    let h_arr = Array::new(ctx.clone())?;
                    for (i, hs) in report.handlers.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("handlerPc", hs.handler_pc as f64)?;
                        o.set("handlerPcHex", format!("0x{:016x}", hs.handler_pc))?;
                        let op_arr = Array::new(ctx.clone())?;
                        let op_hex_arr = Array::new(ctx.clone())?;
                        for (j, &op) in hs.opcodes.iter().enumerate() {
                            op_arr.set(j, op as f64)?;
                            op_hex_arr.set(j, format!("0x{op:x}"))?;
                        }
                        o.set("opcodes", op_arr)?;
                        o.set("opcodeHexes", op_hex_arr)?;
                        o.set("hitCount", hs.hit_count as f64)?;
                        o.set("minArm64Insns", hs.min_arm64_insns as f64)?;
                        o.set("maxArm64Insns", hs.max_arm64_insns as f64)?;
                        o.set("avgArm64Insns", hs.avg_arm64_insns())?;
                        o.set("firstStep", hs.first_step as f64)?;
                        o.set("firstTraceIdx", hs.first_trace_idx as f64)?;
                        let hist_obj = Object::new(ctx.clone())?;
                        for (&st, &cnt) in &hs.bc_step_hist {
                            hist_obj.set(st.to_string(), cnt as f64)?;
                        }
                        o.set("bcStepHist", hist_obj)?;
                        h_arr.set(i, o)?;
                    }
                    out.set("handlers", h_arr)?;

                    let s_arr = Array::new(ctx.clone())?;
                    for (i, st) in report.steps.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("step", st.step as f64)?;
                        o.set("traceIdx", st.trace_idx as f64)?;
                        o.set("seq", st.seq as f64)?;
                        o.set("dispatcherPcHex", format!("0x{:016x}", st.dispatcher_pc))?;
                        o.set("handlerPc", st.handler_pc as f64)?;
                        o.set("handlerPcHex", format!("0x{:016x}", st.handler_pc))?;
                        o.set("arm64Insns", st.arm64_insns as f64)?;
                        if let Some(bp) = st.bc_pc {
                            o.set("bcPc", bp as f64)?;
                            o.set("bcPcHex", format!("0x{bp:016x}"))?;
                        }
                        if let Some(bs) = st.bc_step {
                            o.set("bcStep", bs as f64)?;
                        }
                        if let Some(w) = st.raw_word {
                            o.set("rawWord", w as f64)?;
                            o.set("rawWordHex", format!("0x{w:x}"))?;
                        }
                        if let Some(ref dec) = st.decoded {
                            o.set("op", dec.op as f64)?;
                            o.set("opHex", format!("0x{:x}", dec.op))?;
                            let fa = Array::new(ctx.clone())?;
                            let fha = Array::new(ctx.clone())?;
                            for (j, &fv) in dec.fields.iter().enumerate() {
                                fa.set(j, fv as f64)?;
                                fha.set(j, format!("0x{fv:x}"))?;
                            }
                            o.set("fields", fa)?;
                            o.set("fieldsHex", fha)?;
                            o.set("decodedText", dec.format_compact())?;
                        } else if let Some(top) = st.table_opcode {
                            o.set("op", top as f64)?;
                            o.set("opHex", format!("0x{top:x}"))?;
                        }
                        if let Some(rfb) = st.regfile_base {
                            o.set("regfileBaseHex", format!("0x{rfb:016x}"))?;
                        }
                        o.set("baseRelocated", st.base_relocated)?;
                        let da = Array::new(ctx.clone())?;
                        for (j, d) in st.reg_diffs.iter().enumerate() {
                            let do_ = Object::new(ctx.clone())?;
                            do_.set("reg", d.reg_index as f64)?;
                            do_.set("name", format!("R[{}]", d.reg_index))?;
                            if let Some(ov) = d.old_val {
                                do_.set("oldHex", format!("0x{ov:x}"))?;
                            } else {
                                do_.set("oldHex", Value::new_null(ctx.clone()))?;
                            }
                            do_.set("newHex", format!("0x{:x}", d.new_val))?;
                            do_.set("text", d.format_compact())?;
                            da.set(j, do_)?;
                        }
                        o.set("regDiffs", da)?;
                        s_arr.set(i, o)?;
                    }
                    out.set("steps", s_arr)?;
                    out.set("summaryText", report.format_summary(base_addr))?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        native.set(
            "traceDiff",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      idx_a: String,
                      idx_b: String,
                      max_diffs: f64|
                      -> rquickjs::Result<Object<'js>> {
                    let pa = std::path::PathBuf::from(&idx_a);
                    let pb = std::path::PathBuf::from(&idx_b);
                    let ea = crate::tracer::resolve_sibling_ext_path(&pa);
                    let eb = crate::tracer::resolve_sibling_ext_path(&pb);
                    let ra = crate::tracer::TraceReader::open(&pa, ea.as_deref())
                        .map_err(|e| throw_err(&ctx, e))?;
                    let rb = crate::tracer::TraceReader::open(&pb, eb.as_deref())
                        .map_err(|e| throw_err(&ctx, e))?;
                    let cap = if max_diffs.is_finite() && max_diffs > 0.0 {
                        max_diffs as usize
                    } else {
                        100
                    };
                    let sum = crate::tracer::TraceReader::diff_traces(&ra, &rb, cap);
                    let out = Object::new(ctx.clone())?;
                    out.set("totalA", sum.total_a as f64)?;
                    out.set("totalB", sum.total_b as f64)?;
                    out.set("commonPrefixInsns", sum.common_prefix_insns as f64)?;
                    if let Some(i) = sum.first_control_divergence_idx {
                        out.set("firstControlDivergenceIdx", i as f64)?;
                    } else {
                        out.set("firstControlDivergenceIdx", Value::new_null(ctx.clone()))?;
                    }
                    if let Some(i) = sum.first_data_divergence_idx {
                        out.set("firstDataDivergenceIdx", i as f64)?;
                    } else {
                        out.set("firstDataDivergenceIdx", Value::new_null(ctx.clone()))?;
                    }
                    let arr = Array::new(ctx.clone())?;
                    for (i, d) in sum.diffs.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("idx", d.idx as f64)?;
                        o.set("kind", d.kind)?;
                        o.set("pcA", d.pc_a as f64)?;
                        o.set("pcAHex", format!("0x{:016x}", d.pc_a))?;
                        o.set("pcB", d.pc_b as f64)?;
                        o.set("pcBHex", format!("0x{:016x}", d.pc_b))?;
                        o.set("detail", d.detail.as_str())?;
                        arr.set(i, o)?;
                    }
                    out.set("diffs", arr)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        native.set(
            "traceDiffTaint",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      idx_a: String,
                      idx_b: String,
                      addr_val: Value<'js>,
                      len: f64,
                      max_insns: f64|
                      -> rquickjs::Result<Object<'js>> {
                    let target_addr = js_addr_to_u64_strict(&ctx, &addr_val)?;
                    let byte_len_u64 = require_nonneg_int(&ctx, len, "len")?;
                    if byte_len_u64 == 0 || byte_len_u64 > 4096 {
                        return Err(throw_err(
                            &ctx,
                            format!("Trace.diffTaint 参数 len 必须在 1..=4096 之间，收到 {byte_len_u64}"),
                        ));
                    }
                    let byte_len = byte_len_u64 as usize;
                    let mi = require_nonneg_int(&ctx, max_insns, "maxInsns")? as usize;
                    let pa = std::path::PathBuf::from(&idx_a);
                    let pb = std::path::PathBuf::from(&idx_b);
                    let ea = crate::tracer::resolve_sibling_ext_path(&pa);
                    let eb = crate::tracer::resolve_sibling_ext_path(&pb);
                    let ra = crate::tracer::TraceReader::open(&pa, ea.as_deref())
                        .map_err(|e| throw_err(&ctx, e))?;
                    let rb = crate::tracer::TraceReader::open(&pb, eb.as_deref())
                        .map_err(|e| throw_err(&ctx, e))?;
                    let report = crate::tracer::TraceReader::diff_taint_bytes(
                        &ra,
                        &rb,
                        target_addr,
                        byte_len,
                        mi,
                    );
                    let out = Object::new(ctx.clone())?;
                    out.set("targetAddrHex", format!("0x{:016x}", report.target_addr))?;
                    out.set("len", report.len as f64)?;
                    out.set("identicalBytes", report.identical_bytes as f64)?;
                    out.set("differingBytes", report.differing_bytes as f64)?;
                    out.set("summaryText", report.format_summary())?;
                    let spans_arr = Array::new(ctx.clone())?;
                    let fmt_opt_bytes = |bs: &[Option<u8>]| -> String {
                        let mut s = String::with_capacity(bs.len() * 2);
                        for b in bs {
                            match b {
                                Some(v) => s.push_str(&format!("{v:02x}")),
                                None => s.push_str("??"),
                            }
                        }
                        s
                    };
                    for (i, sp) in report.spans.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("offset", sp.offset as f64)?;
                        o.set("addrHex", format!("0x{:016x}", sp.addr))?;
                        o.set("len", sp.len as f64)?;
                        o.set("bytesAHex", fmt_opt_bytes(&sp.bytes_a))?;
                        o.set("bytesBHex", fmt_opt_bytes(&sp.bytes_b))?;
                        let to_str_arr = |items: &[String]| -> rquickjs::Result<Array<'js>> {
                            let a = Array::new(ctx.clone())?;
                            for (j, it) in items.iter().enumerate() {
                                a.set(j, it.as_str())?;
                            }
                            Ok(a)
                        };
                        let to_mem_arr = |items: &[(u64, usize)]| -> rquickjs::Result<Array<'js>> {
                            let a = Array::new(ctx.clone())?;
                            for (j, &(addr, l)) in items.iter().enumerate() {
                                a.set(j, format!("0x{addr:x}[{l}]"))?;
                            }
                            Ok(a)
                        };
                        o.set("originsARegs", to_str_arr(&sp.origins_a_regs)?)?;
                        o.set("originsAMem", to_mem_arr(&sp.origins_a_mem)?)?;
                        o.set("originsAHle", to_str_arr(&sp.origins_a_hle)?)?;
                        o.set("originsBRegs", to_str_arr(&sp.origins_b_regs)?)?;
                        o.set("originsBMem", to_mem_arr(&sp.origins_b_mem)?)?;
                        o.set("originsBHle", to_str_arr(&sp.origins_b_hle)?)?;
                        spans_arr.set(i, o)?;
                    }
                    out.set("spans", spans_arr)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let archive_info_to_js = |ctx: &Ctx<'js>,
                                  info: &crate::tracer::TraceArchiveInfo|
         -> rquickjs::Result<Object<'js>> {
            let o = Object::new(ctx.clone())?;
            o.set("version", info.version as f64)?;
            o.set("hasExt", info.has_ext)?;
            o.set("compressed", info.compressed)?;
            o.set("baseAddr", info.base_addr as f64)?;
            o.set("baseAddrHex", format!("0x{:016x}", info.base_addr))?;
            o.set("idxInsns", info.idx_insns as f64)?;
            o.set("idxRawLen", info.idx_raw_len as f64)?;
            o.set("idxCompLen", info.idx_comp_len as f64)?;
            o.set("idxCrc32Hex", format!("0x{:08x}", info.idx_crc32))?;
            o.set("extEvents", info.ext_events as f64)?;
            o.set("extRawLen", info.ext_raw_len as f64)?;
            o.set("extCompLen", info.ext_comp_len as f64)?;
            o.set("extCrc32Hex", format!("0x{:08x}", info.ext_crc32))?;
            o.set("archiveFileLen", info.archive_file_len as f64)?;
            o.set("ratioPercent", info.ratio_percent())?;
            if let Some(ref lvl) = info.recorded_level {
                o.set("recordedLevel", lvl.as_str())?;
            } else {
                o.set("recordedLevel", Value::new_null(ctx.clone()))?;
            }
            if let Some(ref note) = info.note {
                o.set("note", note.as_str())?;
            } else {
                o.set("note", Value::new_null(ctx.clone()))?;
            }
            o.set("summaryText", info.format_summary())?;
            Ok(o)
        };

        native.set(
            "tracePack",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      idx_path: String,
                      out_opt: Option<String>,
                      opts: Object<'js>|
                      -> rquickjs::Result<Object<'js>> {
                    let idx_p = std::path::PathBuf::from(&idx_path);
                    let no_ext: bool = match opts.get::<_, Value<'js>>("noExt") {
                        Ok(v) if !v.is_undefined() && !v.is_null() => v.as_bool().ok_or_else(|| {
                            throw_err(&ctx, "Trace.pack 参数 noExt 必须为布尔值")
                        })?,
                        _ => false,
                    };
                    let explicit_ext = match opts.get::<_, Value<'js>>("extPath") {
                        Ok(v) if !v.is_undefined() && !v.is_null() => {
                            let s = v
                                .as_string()
                                .and_then(|js| js.to_string().ok())
                                .ok_or_else(|| throw_err(&ctx, "Trace.pack 参数 extPath 必须为非空字符串"))?;
                            if s.trim().is_empty() {
                                return Err(throw_err(&ctx, "Trace.pack 参数 extPath 不能为空字符串"));
                            }
                            Some(std::path::PathBuf::from(s))
                        }
                        _ => None,
                    };
                    if no_ext && explicit_ext.is_some() {
                        return Err(throw_err(&ctx, "Trace.pack 参数 extPath 与 noExt=true 互斥"));
                    }
                    let ext_p = if no_ext {
                        None
                    } else if explicit_ext.is_some() {
                        explicit_ext
                    } else {
                        crate::tracer::resolve_sibling_ext_path(&idx_p)
                    };
                    let out_p = match out_opt {
                        Some(s) => {
                            if s.trim().is_empty() {
                                return Err(throw_err(&ctx, "Trace.pack 参数 outPath 不能为空字符串"));
                            }
                            std::path::PathBuf::from(s)
                        }
                        None => idx_p.with_extension("rtrace"),
                    };
                    let mut pack_opts = crate::tracer::TraceArchivePackOptions::default();
                    if let Ok(v) = opts.get::<_, Value<'js>>("baseAddr") {
                        if !v.is_undefined() && !v.is_null() {
                            pack_opts.base_addr = js_addr_to_u64_strict(&ctx, &v)?;
                        }
                    }
                    if let Ok(v) = opts.get::<_, Value<'js>>("note") {
                        if !v.is_undefined() && !v.is_null() {
                            let s = v
                                .as_string()
                                .and_then(|js| js.to_string().ok())
                                .ok_or_else(|| throw_err(&ctx, "Trace.pack 参数 note 必须为字符串"))?;
                            pack_opts.note = Some(s);
                        }
                    }
                    if let Ok(v) = opts.get::<_, Value<'js>>("level") {
                        if !v.is_undefined() && !v.is_null() {
                            let n = v.as_number().ok_or_else(|| {
                                throw_err(&ctx, "Trace.pack 参数 level 必须为整数 (0..=9)")
                            })?;
                            let u = require_nonneg_int(&ctx, n, "level")?;
                            if u > 9 {
                                return Err(throw_err(&ctx, format!("Trace.pack 参数 level 必须在 0..=9 之间，收到 {u}")));
                            }
                            pack_opts.compression_level = u as u32;
                        }
                    }
                    let info = crate::tracer::TraceArchive::pack(
                        &idx_p,
                        ext_p.as_deref(),
                        &out_p,
                        &pack_opts,
                    )
                    .map_err(|e| throw_err(&ctx, e))?;
                    let obj = archive_info_to_js(&ctx, &info)?;
                    obj.set("outPath", out_p.to_string_lossy().as_ref())?;
                    Ok(obj)
                },
            )?,
        )?;

        native.set(
            "traceInspectArchive",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, rtrace_path: String| -> rquickjs::Result<Object<'js>> {
                    let info = crate::tracer::TraceArchive::inspect(&rtrace_path)
                        .map_err(|e| throw_err(&ctx, e))?;
                    archive_info_to_js(&ctx, &info)
                },
            )?,
        )?;

        native.set(
            "traceUnpack",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      rtrace_path: String,
                      out_dir_opt: Option<String>,
                      opts: Object<'js>|
                      -> rquickjs::Result<Object<'js>> {
                    let rp = std::path::PathBuf::from(&rtrace_path);
                    let dir = out_dir_opt
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| {
                            rp.parent()
                                .filter(|p| !p.as_os_str().is_empty())
                                .map(std::path::PathBuf::from)
                                .unwrap_or_else(|| std::path::PathBuf::from("."))
                        });
                    let stem = match opts.get::<_, Value<'js>>("stem") {
                        Ok(v) if !v.is_undefined() && !v.is_null() => Some(
                            v.as_string()
                                .and_then(|js| js.to_string().ok())
                                .ok_or_else(|| throw_err(&ctx, "Trace.unpack 参数 stem 必须为字符串"))?,
                        ),
                        _ => None,
                    };
                    let overwrite: bool = match opts.get::<_, Value<'js>>("overwrite") {
                        Ok(v) if !v.is_undefined() && !v.is_null() => v.as_bool().ok_or_else(|| {
                            throw_err(&ctx, "Trace.unpack 参数 overwrite 必须为布尔值")
                        })?,
                        _ => false,
                    };
                    let res = crate::tracer::TraceArchive::unpack(
                        &rp,
                        &dir,
                        stem.as_deref(),
                        overwrite,
                    )
                    .map_err(|e| throw_err(&ctx, e))?;
                    let o = Object::new(ctx.clone())?;
                    o.set("idxPath", res.idx_path.to_string_lossy().as_ref())?;
                    if let Some(ref ep) = res.ext_path {
                        o.set("extPath", ep.to_string_lossy().as_ref())?;
                    } else {
                        o.set("extPath", Value::new_null(ctx.clone()))?;
                    }
                    o.set("info", archive_info_to_js(&ctx, &res.info)?)?;
                    Ok(o)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "hookReplace",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      func: Function<'js>|
                      -> rquickjs::Result<usize> {
                    let persistent = Persistent::save(&ctx, func);
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    with_unicorn_only(&ctx, &host, emu_id, "hook.replace", |uc| {
                        handles
                            .native_hooks
                            .borrow_mut()
                            .add_replace_hook(emu_id, uc, addr as u64, persistent)
                            .map_err(|e| throw_err(&ctx, e))
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "hookAttach",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      on_enter: Value<'js>,
                      on_leave: Value<'js>|
                      -> rquickjs::Result<usize> {
                    let enter_fn = if on_enter.is_function() {
                        Some(Persistent::save(
                            &ctx,
                            on_enter
                                .into_function()
                                .ok_or_else(|| throw_err(&ctx, "onEnter 不是函数"))?,
                        ))
                    } else {
                        None
                    };
                    let leave_fn = if on_leave.is_function() {
                        Some(Persistent::save(
                            &ctx,
                            on_leave
                                .into_function()
                                .ok_or_else(|| throw_err(&ctx, "onLeave 不是函数"))?,
                        ))
                    } else {
                        None
                    };
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    with_unicorn_only(&ctx, &host, emu_id, "hook.attach", |uc| {
                        handles
                            .native_hooks
                            .borrow_mut()
                            .add_attach_hook(emu_id, uc, addr as u64, enter_fn, leave_fn)
                            .map_err(|e| throw_err(&ctx, e))
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "hookSyscall",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      nr: f64,
                      func: Function<'js>|
                      -> rquickjs::Result<usize> {
                    let persistent = Persistent::save(&ctx, func);
                    let key = if nr < 0.0 { SYSCALL_WILDCARD } else { nr as u64 };
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    with_unicorn_only(&ctx, &host, emu_id, "hook.syscall", |uc| {
                        Ok(handles
                            .native_hooks
                            .borrow_mut()
                            .add_syscall_hook(emu_id, uc, key, persistent))
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        let handles_table = Rc::clone(&handles_table);
        native.set(
            "hookDetach",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, hook_id: usize| -> rquickjs::Result<bool> {
                    let handles = get_emu_handles(&ctx, &handles_table, emu_id)?;
                    with_unicorn_only(&ctx, &host, emu_id, "hook.detach", |uc| {
                        Ok(handles.native_hooks.borrow_mut().detach(hook_id, uc))
                    })
                },
            )?,
        )?;
    }

    // ---- V2: 宿主机文件 I/O (fs) ----
    native.set(
        "fsReadBytes",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, path: String| -> rquickjs::Result<TypedArray<'js, u8>> {
                let data = fs::read(&path)
                    .map_err(|e| throw_err(&ctx, format!("读取文件失败 {path}: {e}")))?;
                TypedArray::new(ctx.clone(), data)
            },
        )?,
    )?;

    native.set(
        "fsReadText",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'_>, path: String| -> rquickjs::Result<String> {
                fs::read_to_string(&path)
                    .map_err(|e| throw_err(&ctx, format!("读取文本失败 {path}: {e}")))
            },
        )?,
    )?;

    native.set(
        "fsWriteBytes",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, path: String, bytes: TypedArray<'js, u8>| -> rquickjs::Result<()> {
                let slice = bytes.as_bytes().unwrap_or(&[]);
                fs::write(&path, slice)
                    .map_err(|e| throw_err(&ctx, format!("写入文件失败 {path}: {e}")))
            },
        )?,
    )?;

    native.set(
        "fsWriteText",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'_>, path: String, text: String| -> rquickjs::Result<()> {
                fs::write(&path, text)
                    .map_err(|e| throw_err(&ctx, format!("写入文本失败 {path}: {e}")))
            },
        )?,
    )?;

    native.set(
        "fsExists",
        Function::new(ctx.clone(), move |path: String| -> bool {
            Path::new(&path).exists()
        })?,
    )?;

    // ---- V2: CommonJS require(specifier) ----
    {
        let host = Rc::clone(host);
        native.set(
            "requireModule",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, specifier: String| -> rquickjs::Result<Value<'js>> {
                    let base_dir = host
                        .borrow()
                        .script_dir_stack
                        .last()
                        .cloned()
                        .unwrap_or_else(|| PathBuf::from("."));
                    let raw_path = Path::new(&specifier);
                    let mut candidate = if raw_path.is_absolute() {
                        raw_path.to_path_buf()
                    } else {
                        base_dir.join(raw_path)
                    };
                    if !candidate.exists() && candidate.extension().is_none() {
                        let with_js = candidate.with_extension("js");
                        if with_js.exists() {
                            candidate = with_js;
                        }
                    }
                    let canonical = fs::canonicalize(&candidate).map_err(|e| {
                        throw_err(&ctx, format!("require(\"{specifier}\") 找不到模块: {e}"))
                    })?;

                    if let Some(cached) = host.borrow().module_cache.get(&canonical).cloned() {
                        return cached.restore(&ctx);
                    }

                    let src = fs::read_to_string(&canonical).map_err(|e| {
                        throw_err(
                            &ctx,
                            format!("读取模块失败 {}: {e}", canonical.display()),
                        )
                    })?;
                    let mod_dir = canonical
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| PathBuf::from("."));

                    let exports_obj = Object::new(ctx.clone())?;
                    let module_obj = Object::new(ctx.clone())?;
                    module_obj.set("exports", exports_obj.clone())?;
                    module_obj.set("filename", canonical.to_string_lossy().as_ref())?;

                    let wrapped = format!(
                        "(function(exports, require, module, __filename, __dirname) {{\n{src}\n}})"
                    );
                    let factory: Function<'js> = ctx.eval(wrapped)?;
                    let require_fn: Function<'js> = ctx.globals().get("require")?;

                    host.borrow_mut().script_dir_stack.push(mod_dir.clone());
                    let call_res = factory.call::<_, Value<'js>>((
                        exports_obj,
                        require_fn,
                        module_obj.clone(),
                        canonical.to_string_lossy().as_ref(),
                        mod_dir.to_string_lossy().as_ref(),
                    ));
                    host.borrow_mut().script_dir_stack.pop();
                    call_res?;

                    let final_exports: Value<'js> = module_obj.get("exports")?;
                    let persistent = Persistent::save(&ctx, final_exports.clone());
                    host.borrow_mut().module_cache.insert(canonical, persistent);
                    Ok(final_exports)
                },
            )?,
        )?;
    }

    globals.set("__native", native)?;
    Ok(())
}

fn apply_nic_js_obj(nic: &mut crate::os::net::VirtualNic, obj: &Object<'_>) {
    if let Ok(name) = obj.get::<_, String>("name") {
        if !name.is_empty() {
            nic.name = name;
        }
    }
    if let Ok(ip_str) = obj.get::<_, String>("ipv4") {
        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
            nic.ipv4 = ip.octets();
        }
    }
    if let Ok(mask_str) = obj.get::<_, String>("netmask") {
        if let Ok(ip) = mask_str.parse::<std::net::Ipv4Addr>() {
            nic.netmask = ip.octets();
        }
    }
    if let Ok(gw_str) = obj.get::<_, String>("gateway") {
        if let Ok(ip) = gw_str.parse::<std::net::Ipv4Addr>() {
            nic.gateway = ip.octets();
        }
    }
    if let Ok(mac_str) = obj.get::<_, String>("mac") {
        let parts: Vec<u8> = mac_str
            .split(':')
            .filter_map(|p| u8::from_str_radix(p.trim(), 16).ok())
            .collect();
        if parts.len() == 6 {
            nic.mac.copy_from_slice(&parts);
        }
    }
    if let Ok(ipv6) = obj.get::<_, String>("ipv6") {
        if !ipv6.is_empty() {
            nic.ipv6 = ipv6;
        }
    }
}
