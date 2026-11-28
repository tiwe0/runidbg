//! 零 `serde` 依赖的轻量配置模型与标准 JSON 解析器
//!
//! 配置文件默认路径（由 Root 侧 Zygisk Companion 读取并下发给目标进程）：
//! `/data/adb/runidbg/config.json`

use runidbg_arm64_emu_tracer::tracer::TraceLevel;

/// JSON 嵌套解析最大深度（防止恶意构造深层嵌套导致目标进程栈溢出）
const MAX_JSON_DEPTH: usize = 64;

/// 目标函数切入点规格
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookTargetSpec {
    /// 拦截目标 `.so` 的 `JNI_OnLoad`
    JniOnLoad { lib: String },
    /// 拦截目标 `.so` 的导出符号
    Symbol { lib: String, symbol: String },
    /// 拦截目标 `.so` 相对基址的固定偏移（如 `libmetasec_ov.so+0x120be0`）
    Offset { lib: String, offset: u64 },
}

/// `runidbg-zygisk` 混合模拟引擎配置
#[derive(Debug, Clone)]
pub struct HybridConfig {
    /// 目标 Android 应用包名 / 进程名（为空时匹配全部——仅限单测使用）
    pub package_name: String,
    /// 核心目标 `.so` 列表（文件名或路径子串，如 `"libmetasec_ov.so"`）
    pub target_libs: Vec<String>,
    /// 是否自动把同应用私有目录（`/data/app/.../lib/arm64/`）下的 `DT_NEEDED` 依赖 `.so` 纳入 Unicorn 白名单
    pub auto_include_app_deps: bool,
    /// 额外手动纳入 Unicorn 模拟的 `.so` 列表
    pub extra_emulate_libs: Vec<String>,
    /// 强制走真机原生逃逸（不进 Unicorn）的 `.so` 列表（优先级高于白名单）
    pub force_native_libs: Vec<String>,
    /// 触发切入 Unicorn 的函数入口列表
    pub hooks: Vec<HookTargetSpec>,
    /// 录制级别：`fast` / `reg_delta` / `full`（默认 `full`）
    pub trace_level: TraceLevel,
    /// 单次调用最大录制指令数（超出后停录并继续把函数跑完；0 表示不限，默认 500_000）
    pub max_insns: usize,
    /// 每个 Hook 最大命中次数（超出后自动回退到 `good64` 重定位原函数，0 表示不限，默认 4）
    pub max_hits: usize,
    /// 单线程最大嵌套重入深度（默认 8）
    pub max_reentry_depth: usize,
    /// 是否启用 `SVC #0` 层 `/proc/self/maps` 与 `/proc/self/status`（`TracerPid: 0`）隐身过滤
    pub stealth: bool,
    /// `.rtrace` 输出目录（Android 上由 Companion 打开 FD 写入 `/data/local/tmp/runidbg`）
    pub output_dir: String,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            package_name: String::new(),
            target_libs: Vec::new(),
            auto_include_app_deps: true,
            extra_emulate_libs: Vec::new(),
            force_native_libs: Vec::new(),
            hooks: Vec::new(),
            trace_level: TraceLevel::Full,
            max_insns: 500_000,
            max_hits: 4,
            max_reentry_depth: 8,
            stealth: true,
            output_dir: "/data/local/tmp/runidbg".to_string(),
        }
    }
}

/// 系统库路径前缀（默认走原生逃逸，绝不拖入 Unicorn）
const SYSTEM_LIB_PREFIXES: &[&str] = &[
    "/system/",
    "/system_ext/",
    "/apex/",
    "/vendor/",
    "/odm/",
    "/product/",
    "/usr/lib/",
    "/System/Library/",
];

impl HybridConfig {
    /// 判断指定路径的 `.so` 是否属于系统库
    pub fn is_system_library_path(path: &str) -> bool {
        SYSTEM_LIB_PREFIXES.iter().any(|p| path.starts_with(p))
    }

    /// 判断给定路径的模块是否应进入 Unicorn 白名单
    pub fn should_emulate_library(&self, path: &str, app_lib_dir: Option<&str>) -> bool {
        if path.is_empty() {
            return false;
        }
        // 绝不把 runidbg_zygisk 自身纳入模拟
        if path.contains("librunidbg_zygisk") || path.contains("runidbg_zygisk") {
            return false;
        }
        // 显式强制原生逃逸表具有最高优先级
        if self.force_native_libs.iter().any(|p| lib_matches(path, p)) {
            return false;
        }
        // 核心目标库与显式额外模拟库
        if self.target_libs.iter().any(|p| lib_matches(path, p))
            || self.extra_emulate_libs.iter().any(|p| lib_matches(path, p))
        {
            return true;
        }
        // 系统库默认走原生逃逸
        if Self::is_system_library_path(path) {
            return false;
        }
        // 自动纳入同应用私有目录下的业务依赖 .so（严格按 `/` 路径分隔边界匹配）
        if self.auto_include_app_deps {
            if let Some(app_dir) = app_lib_dir {
                let dir = app_dir.trim_end_matches('/');
                if !dir.is_empty()
                    && path.starts_with(dir)
                    && path.as_bytes().get(dir.len()) == Some(&b'/')
                {
                    return true;
                }
            }
        }
        false
    }

    /// 解析 JSON 配置字符串
    pub fn from_json_str(input: &str) -> Result<Self, String> {
        let mut p = MiniJsonParser::new(input);
        let root = p.parse_value(0)?;
        if let Some(ch) = p.peek() {
            return Err(format!(
                "JSON 末尾存在多余字符 `{}` (pos={})",
                ch as char, p.pos
            ));
        }
        let MiniJson::Object(entries) = root else {
            return Err("顶层配置必须是 JSON 对象 `{...}`".to_string());
        };
        let mut cfg = Self::default();
        for (k, v) in entries {
            match k.as_str() {
                "package_name" | "package" => {
                    cfg.package_name = v.as_str()?.to_string();
                }
                "target_libs" => {
                    cfg.target_libs = v.into_string_vec()?;
                }
                "auto_include_app_deps" => {
                    cfg.auto_include_app_deps = v.as_bool()?;
                }
                "extra_emulate_libs" => {
                    cfg.extra_emulate_libs = v.into_string_vec()?;
                }
                "force_native_libs" => {
                    cfg.force_native_libs = v.into_string_vec()?;
                }
                "trace_level" => {
                    cfg.trace_level = match v.as_str()?.to_ascii_lowercase().as_str() {
                        "fast" => TraceLevel::Fast,
                        "reg_delta" | "regdelta" => TraceLevel::RegDelta,
                        "full" => TraceLevel::Full,
                        other => return Err(format!("无效的 trace_level: {other}")),
                    };
                }
                "max_insns" => {
                    cfg.max_insns = v.as_u64()? as usize;
                }
                "max_hits" => {
                    cfg.max_hits = v.as_u64()? as usize;
                }
                "max_reentry_depth" => {
                    cfg.max_reentry_depth = (v.as_u64()? as usize).clamp(1, 32);
                }
                "stealth" => {
                    cfg.stealth = v.as_bool()?;
                }
                "output_dir" => {
                    cfg.output_dir = v.as_str()?.to_string();
                }
                "hooks" => {
                    let MiniJson::Array(items) = v else {
                        return Err("hooks 字段必须为数组".to_string());
                    };
                    for item in items {
                        cfg.hooks.push(parse_hook_spec(item)?);
                    }
                }
                _ => {}
            }
        }
        Ok(cfg)
    }
}

fn lib_matches(full_path: &str, pattern: &str) -> bool {
    let p = pattern.trim();
    if p.is_empty() {
        return false;
    }
    if full_path == p {
        return true;
    }
    if let Some(base) = full_path.rsplit('/').next() {
        if base == p {
            return true;
        }
    }
    full_path.contains(p)
}

fn parse_hook_spec(v: MiniJson) -> Result<HookTargetSpec, String> {
    match v {
        MiniJson::String(s) => {
            // 优先按 `!` 拆分（避免 `libc++_shared.so!sym` 被 `+` 误拆）
            if let Some((lib, sym)) = s.split_once('!') {
                let lib = lib.trim();
                let sym = sym.trim();
                if lib.is_empty() || sym.is_empty() {
                    return Err(format!("hook 简写 `{s}` 的库名与符号名均不能为空"));
                }
                if sym == "JNI_OnLoad" {
                    return Ok(HookTargetSpec::JniOnLoad {
                        lib: lib.to_string(),
                    });
                }
                return Ok(HookTargetSpec::Symbol {
                    lib: lib.to_string(),
                    symbol: sym.to_string(),
                });
            }
            // 再从右侧按 `+` 拆分（正确兼容 `libc++_shared.so+0x1234`）
            if let Some((lib, off_str)) = s.rsplit_once('+') {
                let lib = lib.trim();
                let off_str = off_str.trim();
                if lib.is_empty() || off_str.is_empty() {
                    return Err(format!("hook 简写 `{s}` 的库名与偏移量均不能为空"));
                }
                let off = parse_u64_hex_or_dec(off_str)?;
                return Ok(HookTargetSpec::Offset {
                    lib: lib.to_string(),
                    offset: off,
                });
            }
            Err(format!(
                "无效的 hook 简写 `{s}`（支持 `lib.so!symbol` 或 `lib.so+0xoffset`）"
            ))
        }
        MiniJson::Object(entries) => {
            let mut lib = String::new();
            let mut symbol: Option<String> = None;
            let mut offset: Option<u64> = None;
            let mut jni_onload = false;
            for (k, v) in entries {
                match k.as_str() {
                    "lib" => lib = v.as_str()?.trim().to_string(),
                    "symbol" => symbol = Some(v.as_str()?.trim().to_string()),
                    "offset" => {
                        offset = Some(match v {
                            MiniJson::Number(raw) => parse_json_u64(&raw)?,
                            MiniJson::String(s) => parse_u64_hex_or_dec(s.trim())?,
                            _ => return Err("hook.offset 必须为整数或 0x... 字符串".to_string()),
                        });
                    }
                    "jni_onload" => jni_onload = v.as_bool()?,
                    _ => {}
                }
            }
            if lib.is_empty() {
                return Err("hook 对象缺少非空 `lib` 字段".to_string());
            }
            if jni_onload {
                Ok(HookTargetSpec::JniOnLoad { lib })
            } else if let Some(off) = offset {
                Ok(HookTargetSpec::Offset { lib, offset: off })
            } else if let Some(sym) = symbol {
                if sym.is_empty() {
                    return Err("hook.symbol 不能为空".to_string());
                }
                if sym == "JNI_OnLoad" {
                    Ok(HookTargetSpec::JniOnLoad { lib })
                } else {
                    Ok(HookTargetSpec::Symbol { lib, symbol: sym })
                }
            } else {
                Err("hook 对象必须提供 symbol、offset 或 jni_onload: true".to_string())
            }
        }
        _ => Err("hook 数组元素必须为字符串或对象".to_string()),
    }
}

fn parse_u64_hex_or_dec(s: &str) -> Result<u64, String> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).map_err(|e| format!("无效十六进制数 `{s}`: {e}"))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("无效十进制数 `{s}`: {e}"))
    }
}

fn parse_json_u64(raw: &str) -> Result<u64, String> {
    if raw.starts_with('-') || raw.contains('.') || raw.contains('e') || raw.contains('E') {
        return Err(format!("期望非负整数，实际为 `{raw}`"));
    }
    raw.parse::<u64>()
        .map_err(|e| format!("无效非负 JSON 整数 `{raw}`: {e}"))
}

// ── 极简零依赖 RFC 8259 JSON 解析器（支持完整转义/UTF-16 代理对/带符号与浮点数字/深度防护） ──

enum MiniJson {
    Null,
    Bool(bool),
    /// 保留原始 JSON 数字字面量，便于未知字段安全跳过负数/浮点数、已知字段严格校验非负整数
    Number(String),
    String(String),
    Array(Vec<MiniJson>),
    Object(Vec<(String, MiniJson)>),
}

impl MiniJson {
    fn as_str(&self) -> Result<&str, String> {
        match self {
            Self::String(s) => Ok(s.as_str()),
            _ => Err("期望 JSON 字符串".to_string()),
        }
    }

    fn as_bool(&self) -> Result<bool, String> {
        match self {
            Self::Bool(b) => Ok(*b),
            _ => Err("期望 JSON 布尔值".to_string()),
        }
    }

    fn as_u64(&self) -> Result<u64, String> {
        match self {
            Self::Number(raw) => parse_json_u64(raw),
            _ => Err("期望非负 JSON 整数".to_string()),
        }
    }

    fn into_string_vec(self) -> Result<Vec<String>, String> {
        let Self::Array(items) = self else {
            return Err("期望 JSON 字符串数组".to_string());
        };
        let mut out = Vec::with_capacity(items.len());
        for it in items {
            let Self::String(s) = it else {
                return Err("数组元素必须为字符串".to_string());
            };
            out.push(s);
        }
        Ok(out)
    }
}

struct MiniJsonParser<'a> {
    input: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> MiniJsonParser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            input: s,
            bytes: s.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<MiniJson, String> {
        if depth > MAX_JSON_DEPTH {
            return Err(format!("JSON 嵌套深度超过上限 ({MAX_JSON_DEPTH})"));
        }
        match self.peek() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string().map(MiniJson::String),
            Some(b't') => {
                self.expect_lit(b"true")?;
                Ok(MiniJson::Bool(true))
            }
            Some(b'f') => {
                self.expect_lit(b"false")?;
                Ok(MiniJson::Bool(false))
            }
            Some(b'n') => {
                self.expect_lit(b"null")?;
                Ok(MiniJson::Null)
            }
            Some(b'-') => self.parse_number().map(MiniJson::Number),
            Some(c) if c.is_ascii_digit() => self.parse_number().map(MiniJson::Number),
            other => Err(format!(
                "JSON 语法错误，位置 {} 遇到 {:?}",
                self.pos,
                other.map(|b| b as char)
            )),
        }
    }

    fn expect_lit(&mut self, lit: &[u8]) -> Result<(), String> {
        self.skip_ws();
        if self.bytes[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(format!(
                "JSON 位置 {} 期望 {:?}",
                self.pos,
                std::str::from_utf8(lit)
            ))
        }
    }

    fn parse_number(&mut self) -> Result<String, String> {
        self.skip_ws();
        let start = self.pos;
        if self.bytes.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        let int_start = self.pos;
        match self.bytes.get(self.pos) {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(c) if c.is_ascii_digit() => {
                while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
            }
            _ => return Err(format!("位置 {} 无效数字", self.pos)),
        }
        if self.pos == int_start {
            return Err(format!("位置 {} 缺少数字", self.pos));
        }
        if self.bytes.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            let frac_start = self.pos;
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err(format!("位置 {} 小数点后缺少数字", self.pos));
            }
        }
        if matches!(self.bytes.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.bytes.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err(format!("位置 {} 指数后缺少数字", self.pos));
            }
        }
        Ok(self.input[start..self.pos].to_string())
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("不完整的 \\uXXXX 转义序列".to_string());
        }
        let s = &self.input[self.pos..self.pos + 4];
        let v = u16::from_str_radix(s, 16)
            .map_err(|_| format!("无效 \\uXXXX 十六进制转义: `{s}`"))?;
        self.pos += 4;
        Ok(v)
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.skip_ws();
        if self.bytes.get(self.pos) != Some(&b'"') {
            return Err(format!("位置 {} 期望引号", self.pos));
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = *self
                    .bytes
                    .get(self.pos)
                    .ok_or_else(|| "未闭合的转义序列".to_string())?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let code = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&code) {
                            // UTF-16 高代理项，必须紧跟 \uDC00..\uDFFF
                            if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                return Err("无效孤立 UTF-16 高代理项".to_string());
                            }
                            self.pos += 2;
                            let low = self.parse_hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err("无效 UTF-16 低代理项".to_string());
                            }
                            let cp = 0x10000
                                + (((u32::from(code) - 0xD800) << 10)
                                    | (u32::from(low) - 0xDC00));
                            let ch = char::from_u32(cp)
                                .ok_or_else(|| "无效 Unicode 码点".to_string())?;
                            out.push(ch);
                        } else if (0xDC00..=0xDFFF).contains(&code) {
                            return Err("无效孤立 UTF-16 低代理项".to_string());
                        } else {
                            let ch = char::from_u32(u32::from(code))
                                .ok_or_else(|| "无效 Unicode 码点".to_string())?;
                            out.push(ch);
                        }
                    }
                    other => {
                        return Err(format!("不支持的 JSON 转义字符: \\{}", other as char));
                    }
                }
            } else if b < 0x20 {
                return Err(format!("JSON 字符串包含未转义控制字符 0x{b:02x}"));
            } else {
                // O(1)/字符：self.input 已经过 Rust &str UTF-8 合法性保证，直接按当前字节边界切片
                let ch = self.input[self.pos..].chars().next().unwrap();
                out.push(ch);
                self.pos += ch.len_utf8();
            }
        }
        Err("未闭合的 JSON 字符串".to_string())
    }

    fn parse_array(&mut self, depth: usize) -> Result<MiniJson, String> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(MiniJson::Array(items));
        }
        loop {
            items.push(self.parse_value(depth)?);
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(MiniJson::Array(items));
                }
                _ => return Err(format!("JSON 数组位置 {} 期望 `,` 或 `]`", self.pos)),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<MiniJson, String> {
        self.pos += 1; // '{'
        let mut entries = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(MiniJson::Object(entries));
        }
        loop {
            let key = self.parse_string()?;
            if self.peek() != Some(b':') {
                return Err(format!("JSON 对象位置 {} 期望 `:`", self.pos));
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            entries.push((key, val));
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(MiniJson::Object(entries));
                }
                _ => return Err(format!("JSON 对象位置 {} 期望 `,` 或 `}}`", self.pos)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_json_valid_and_cpp_lib_hooks() {
        let json = r#"{
            "package_name": "com.android.settings",
            "target_libs": ["libmetasec_ov.so", "libc++_shared.so"],
            "auto_include_app_deps": true,
            "force_native_libs": ["liblog.so"],
            "trace_level": "full",
            "max_insns": 200000,
            "max_hits": 2,
            "stealth": true,
            "unknown_neg": -42,
            "unknown_float": 3.14e-2,
            "unknown_unicode": "\u0041\u4e2d\ud83d\ude00",
            "hooks": [
                "libc++_shared.so!_Z4testv",
                "libc++_shared.so+0x1234",
                "libmetasec_ov.so!JNI_OnLoad",
                { "lib": "libfoo.so", "offset": "0x2000" }
            ]
        }"#;
        let cfg = HybridConfig::from_json_str(json).expect("valid config should parse");
        assert_eq!(cfg.package_name, "com.android.settings");
        assert_eq!(cfg.max_insns, 200_000);
        assert_eq!(cfg.hooks.len(), 4);
        assert_eq!(
            cfg.hooks[0],
            HookTargetSpec::Symbol {
                lib: "libc++_shared.so".to_string(),
                symbol: "_Z4testv".to_string(),
            }
        );
        assert_eq!(
            cfg.hooks[1],
            HookTargetSpec::Offset {
                lib: "libc++_shared.so".to_string(),
                offset: 0x1234,
            }
        );
        assert_eq!(
            cfg.hooks[2],
            HookTargetSpec::JniOnLoad {
                lib: "libmetasec_ov.so".to_string(),
            }
        );
    }

    #[test]
    fn test_config_json_rejects_malformed_inputs() {
        // 尾随垃圾字符必须报错
        assert!(HybridConfig::from_json_str(r#"{"max_hits": 1} trailing"#).is_err());
        // 空库名 / 空符号名必须报错
        assert!(HybridConfig::from_json_str(r#"{"hooks": ["!sym"]}"#).is_err());
        assert!(HybridConfig::from_json_str(r#"{"hooks": ["liba.so!"]}"#).is_err());
        assert!(HybridConfig::from_json_str(r#"{"hooks": ["+0x10"]}"#).is_err());
        // 未知转义字符必须报错
        assert!(HybridConfig::from_json_str(r#"{"package_name": "\q"}"#).is_err());
        // 超深嵌套必须拒绝而不栈溢出
        let deep = format!("{}{}", "[".repeat(100), "]".repeat(100));
        assert!(HybridConfig::from_json_str(&deep).is_err());
    }

    #[test]
    fn test_should_emulate_library_boundaries() {
        let cfg = HybridConfig {
            target_libs: vec!["libtarget.so".to_string()],
            force_native_libs: vec!["libskip.so".to_string()],
            ..Default::default()
        };

        let app_dir = Some("/data/app/com.demo/lib/arm64");
        assert!(cfg.should_emulate_library("/data/app/com.demo/lib/arm64/libdep.so", app_dir));
        // 必须严格校验 `/` 目录边界，防止误匹配同前缀目录
        assert!(!cfg.should_emulate_library("/data/app/com.demo/lib/arm64_other/libdep.so", app_dir));
        // 系统库走原生逃逸
        assert!(!cfg.should_emulate_library("/system/lib64/libc.so", app_dir));
        // 绝不模拟自身
        assert!(!cfg.should_emulate_library("/data/app/com.demo/lib/arm64/librunidbg_zygisk.so", app_dir));
        // 强制原生逃逸优先级高于自动纳入
        assert!(!cfg.should_emulate_library("/data/app/com.demo/lib/arm64/libskip.so", app_dir));
    }
}
