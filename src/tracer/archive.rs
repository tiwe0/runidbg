//! 单文件压缩 `.rtrace` Trace 归档容器（纯 Rust、零新增依赖、基于 `flate2`）
//!
//! 解决 `.idx` 与 `.ext` 分离存储时拷贝/分享容易遗漏伴生 `.ext`、以及预分配 mmap 尾部全零填充占用数十 MB 的痛点：
//! - 打包时自动裁剪 `.idx`/`.ext` 尾部未使用的零槽位，再通过 Deflate 压缩为单个 `.rtrace` 文件；
//! - 64 字节固定小端文件头内含 `header_crc32`、`idx_crc32`、`ext_crc32`、精确原始/压缩长度与可选模块基址；
//! - 解压阶段严格校验文件总长、头部与数据 CRC32，并对流式解压实施上限拦截（免疫 zip-bomb / OOM）；
//! - [`crate::tracer::TraceReader::open`] 自动嗅探 `RTRC` 魔数透明加载 `.rtrace`，无需手动解包即可供全部离线命令/JS/MCP 使用。

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc};
use memmap2::Mmap;

use crate::error::{EmuError, EmuResult};
use crate::tracer::record::{ExtRecord, TraceRecord};

/// `.rtrace` 单文件归档魔数
pub const RTRACE_MAGIC: [u8; 4] = *b"RTRC";
/// `.rtrace` 容器格式版本号
pub const RTRACE_VERSION: u16 = 1;
/// 固定文件头大小（字节）
pub const RTRACE_HEADER_SIZE: usize = 64;

/// 标志位：归档内包含 `.ext` 扩展访存/HLE 流
pub const RTRACE_FLAG_HAS_EXT: u16 = 1 << 0;
/// 标志位：载荷经 raw Deflate 压缩（未置位则为原始存储）
pub const RTRACE_FLAG_DEFLATE: u16 = 1 << 1;

/// 元数据块最大字节数（64 KiB）
pub const MAX_RTRACE_META_LEN: usize = 64 * 1024;
/// 单个流（`.idx` 或 `.ext`）解压上限（1 GiB，防止 zip-bomb 耗尽内存）
pub const MAX_RTRACE_RAW_STREAM_BYTES: u64 = 1024 * 1024 * 1024;

/// `.rtrace` 打包选项
#[derive(Debug, Clone)]
pub struct TraceArchivePackOptions {
    /// 可选模块加载基址（写入文件头后，离线 `stats`/`dump` 可自动作为默认 `--base`）
    pub base_addr: u64,
    /// 可选人工备注信息（UTF-8）
    pub note: Option<String>,
    /// Deflate 压缩等级：`0` 为不压缩直接存储，`1..=9` 为 Deflate 压缩（默认 `6`）
    pub compression_level: u32,
}

impl Default for TraceArchivePackOptions {
    fn default() -> Self {
        Self {
            base_addr: 0,
            note: None,
            compression_level: 6,
        }
    }
}

/// `.rtrace` 归档元信息与压缩统计
#[derive(Debug, Clone)]
pub struct TraceArchiveInfo {
    pub version: u16,
    pub flags: u16,
    pub has_ext: bool,
    pub compressed: bool,
    pub base_addr: u64,
    pub idx_insns: usize,
    pub idx_raw_len: u64,
    pub idx_comp_len: u64,
    pub idx_crc32: u32,
    pub ext_events: usize,
    pub ext_raw_len: u64,
    pub ext_comp_len: u64,
    pub ext_crc32: u32,
    pub archive_file_len: u64,
    pub recorded_level: Option<String>,
    pub note: Option<String>,
    pub meta: BTreeMap<String, String>,
}

impl TraceArchiveInfo {
    /// 总未压缩有效字节数（`.idx` + `.ext`）
    pub const fn total_raw_bytes(&self) -> u64 {
        self.idx_raw_len.saturating_add(self.ext_raw_len)
    }

    /// 压缩率百分比（`archive / raw * 100`，raw==0 时返回 0.0）
    pub fn ratio_percent(&self) -> f64 {
        let raw = self.total_raw_bytes();
        if raw == 0 {
            0.0
        } else {
            (self.archive_file_len as f64) * 100.0 / (raw as f64)
        }
    }

    /// 生成人类可读的多行摘要
    pub fn format_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# .rtrace 归档信息 (v{}, compressed={}, has_ext={})\n",
            self.version, self.compressed, self.has_ext
        ));
        if let Some(ref lvl) = self.recorded_level {
            out.push_str(&format!("  录制级别 : {lvl}\n"));
        }
        if self.base_addr != 0 {
            out.push_str(&format!("  模块基址 : 0x{:016x}\n", self.base_addr));
        }
        out.push_str(&format!(
            "  指令流   : {} 条 ({} B -> {} B, crc32=0x{:08x})\n",
            self.idx_insns, self.idx_raw_len, self.idx_comp_len, self.idx_crc32
        ));
        if self.has_ext {
            out.push_str(&format!(
                "  扩展流   : {} 条 ({} B -> {} B, crc32=0x{:08x})\n",
                self.ext_events, self.ext_raw_len, self.ext_comp_len, self.ext_crc32
            ));
        } else {
            out.push_str("  扩展流   : 无\n");
        }
        out.push_str(&format!(
            "  归档体积 : {} B (原始有效 {} B, 占比 {:.1}%)\n",
            self.archive_file_len,
            self.total_raw_bytes(),
            self.ratio_percent()
        ));
        if let Some(ref note) = self.note {
            out.push_str(&format!("  备注     : {note}\n"));
        }
        out
    }
}

/// `.rtrace` 解包结果
#[derive(Debug, Clone)]
pub struct TraceArchiveUnpackResult {
    pub idx_path: PathBuf,
    pub ext_path: Option<PathBuf>,
    pub info: TraceArchiveInfo,
}

/// `.rtrace` 归档打包、检查、透明加载与解包入口
pub struct TraceArchive;

struct ParsedHeader {
    version: u16,
    flags: u16,
    base_addr: u64,
    idx_raw_len: u64,
    idx_comp_len: u64,
    idx_crc32: u32,
    ext_crc32: u32,
    ext_raw_len: u64,
    ext_comp_len: u64,
    meta_len: u32,
}

impl TraceArchive {
    /// 嗅探文件前 4 字节是否为 `.rtrace` 魔数 (`RTRC`)
    pub fn is_rtrace_file(path: impl AsRef<Path>) -> bool {
        let Ok(mut f) = File::open(path) else {
            return false;
        };
        let mut magic = [0u8; 4];
        f.read_exact(&mut magic).is_ok() && magic == RTRACE_MAGIC
    }

    /// 将 `trace.idx`（及可选伴生 `trace.ext`）打包压缩为单文件 `.rtrace` 归档
    pub fn pack(
        idx_path: impl AsRef<Path>,
        ext_path: Option<&Path>,
        out_path: impl AsRef<Path>,
        opts: &TraceArchivePackOptions,
    ) -> EmuResult<TraceArchiveInfo> {
        let idx_path = idx_path.as_ref();
        let out_path = out_path.as_ref();

        if Self::is_rtrace_file(idx_path) {
            return Err(invalid_data("输入文件已是 .rtrace 归档，无需重复打包"));
        }
        if same_path(idx_path, out_path) || ext_path.is_some_and(|ep| same_path(ep, out_path)) {
            return Err(invalid_data("输出 .rtrace 路径不能与输入 .idx/.ext 相同"));
        }

        // 1. 读取并裁剪 .idx 有效区间（去除预分配 mmap 尾部全零槽位）
        let idx_file = File::open(idx_path)?;
        let idx_mmap = if idx_file.metadata()?.len() > 0 {
            // SAFETY: 只读映射
            Some(unsafe { Mmap::map(&idx_file)? })
        } else {
            None
        };
        let idx_slice: &[u8] = idx_mmap.as_deref().unwrap_or(&[]);
        let idx_count = scan_active_idx_count(idx_slice);
        let idx_raw_len = (idx_count * size_of::<TraceRecord>()) as u64;
        if idx_raw_len > MAX_RTRACE_RAW_STREAM_BYTES {
            return Err(invalid_data(format!(
                ".idx 有效体积 {idx_raw_len} 字节超出归档上限 ({MAX_RTRACE_RAW_STREAM_BYTES})"
            )));
        }
        let idx_active = &idx_slice[..idx_raw_len as usize];
        let recorded_level = if idx_count > 0 {
            let tag = read_packed_unaligned::<TraceRecord>(idx_active, 0)._reserved[1];
            match tag {
                1 => Some("fast".to_string()),
                2 => Some("reg_delta".to_string()),
                3 => Some("full".to_string()),
                _ => None,
            }
        } else {
            None
        };

        // 2. 读取并裁剪可选 .ext 有效区间
        let mut ext_mmap_holder: Option<Mmap> = None;
        let has_ext = ext_path.is_some();
        let (ext_count, ext_raw_len) = if let Some(ep) = ext_path {
            let ext_file = File::open(ep)?;
            if ext_file.metadata()?.len() > 0 {
                // SAFETY: 只读映射
                ext_mmap_holder = Some(unsafe { Mmap::map(&ext_file)? });
            }
            let ext_slice: &[u8] = ext_mmap_holder.as_deref().unwrap_or(&[]);
            let cnt = scan_active_ext_count(ext_slice);
            let raw_len = (cnt * size_of::<ExtRecord>()) as u64;
            if raw_len > MAX_RTRACE_RAW_STREAM_BYTES {
                return Err(invalid_data(format!(
                    ".ext 有效体积 {raw_len} 字节超出归档上限 ({MAX_RTRACE_RAW_STREAM_BYTES})"
                )));
            }
            (cnt, raw_len)
        } else {
            (0usize, 0u64)
        };
        let ext_active: &[u8] = match &ext_mmap_holder {
            Some(m) => &m[..ext_raw_len as usize],
            None => &[],
        };

        // 3. 计算 CRC32 与压缩载荷
        let level = opts.compression_level.min(9);
        let use_deflate = level > 0;
        let idx_crc32 = crc32_bytes(idx_active);
        let ext_crc32 = if has_ext { crc32_bytes(ext_active) } else { 0 };

        let idx_payload = compress_stream(idx_active, level)?;
        let ext_payload = if has_ext {
            compress_stream(ext_active, level)?
        } else {
            Vec::new()
        };
        // 压缩完毕立即释放输入 mmap，避免与目标文件共享句柄/锁冲突
        drop(idx_mmap);
        drop(ext_mmap_holder);

        // 4. 组装精简 UTF-8 key=value 元数据（零 serde 依赖，兼容 --no-default-features）
        let mut meta = BTreeMap::new();
        if let Some(ref lvl) = recorded_level {
            meta.insert("level".to_string(), lvl.clone());
        }
        meta.insert("insns".to_string(), idx_count.to_string());
        meta.insert("ext_events".to_string(), ext_count.to_string());
        if let Some(fname) = idx_path.file_name().and_then(|s| s.to_str()) {
            meta.insert("source_idx".to_string(), sanitize_meta_value(fname));
        }
        let clean_note = opts
            .note
            .as_deref()
            .map(sanitize_meta_value)
            .filter(|s| !s.is_empty());
        if let Some(ref n) = clean_note {
            meta.insert("note".to_string(), n.clone());
        }
        let meta_bytes = encode_meta(&meta);
        if meta_bytes.len() > MAX_RTRACE_META_LEN {
            return Err(invalid_data(format!(
                "归档元数据长度 {} 超出上限 ({MAX_RTRACE_META_LEN})",
                meta_bytes.len()
            )));
        }

        // 5. 编码 64B 文件头（header_crc32 同时覆盖 60B 头与 meta_bytes 防元数据篡改）并原子写入目标文件
        let mut flags = 0u16;
        if has_ext {
            flags |= RTRACE_FLAG_HAS_EXT;
        }
        if use_deflate {
            flags |= RTRACE_FLAG_DEFLATE;
        }
        let header = encode_header(
            &ParsedHeader {
                version: RTRACE_VERSION,
                flags,
                base_addr: opts.base_addr,
                idx_raw_len,
                idx_comp_len: idx_payload.len() as u64,
                idx_crc32,
                ext_crc32,
                ext_raw_len,
                ext_comp_len: ext_payload.len() as u64,
                meta_len: meta_bytes.len() as u32,
            },
            &meta_bytes,
        );

        let parent_dir = out_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent_dir)?;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_name = format!(
            ".rtrace_tmp_{}_{}.part",
            std::process::id(),
            nanos
        );
        let tmp_path = parent_dir.join(tmp_name);
        let write_res = (|| -> io::Result<()> {
            let tmp_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            let mut writer = BufWriter::new(tmp_file);
            writer.write_all(&header)?;
            writer.write_all(&meta_bytes)?;
            writer.write_all(&idx_payload)?;
            if has_ext {
                writer.write_all(&ext_payload)?;
            }
            writer.flush()?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }
        if let Err(e) = fs::rename(&tmp_path, out_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }

        let archive_file_len = (RTRACE_HEADER_SIZE + meta_bytes.len() + idx_payload.len() + ext_payload.len()) as u64;
        Ok(TraceArchiveInfo {
            version: RTRACE_VERSION,
            flags,
            has_ext,
            compressed: use_deflate,
            base_addr: opts.base_addr,
            idx_insns: idx_count,
            idx_raw_len,
            idx_comp_len: idx_payload.len() as u64,
            idx_crc32,
            ext_events: ext_count,
            ext_raw_len,
            ext_comp_len: ext_payload.len() as u64,
            ext_crc32,
            archive_file_len,
            recorded_level,
            note: clean_note,
            meta,
        })
    }

    /// 直接从内存中的原始 `.idx`（及可选 `.ext`）字节切片裁剪、压缩并编码为完整的 `.rtrace` 归档字节流
    /// （供进程内混合引擎 / Zygisk Companion 直接通过 FD 落盘，无需在沙盒内产生临时 `.idx`/`.ext` 文件）
    pub fn pack_slices_to_vec(
        idx_slice: &[u8],
        ext_slice: Option<&[u8]>,
        source_idx_name: Option<&str>,
        opts: &TraceArchivePackOptions,
    ) -> EmuResult<(Vec<u8>, TraceArchiveInfo)> {
        let idx_count = scan_active_idx_count(idx_slice);
        let idx_raw_len = (idx_count * size_of::<TraceRecord>()) as u64;
        if idx_raw_len > MAX_RTRACE_RAW_STREAM_BYTES {
            return Err(invalid_data(format!(
                ".idx 有效体积 {idx_raw_len} 字节超出归档上限 ({MAX_RTRACE_RAW_STREAM_BYTES})"
            )));
        }
        let idx_active = &idx_slice[..idx_raw_len as usize];
        let recorded_level = if idx_count > 0 {
            let tag = read_packed_unaligned::<TraceRecord>(idx_active, 0)._reserved[1];
            match tag {
                1 => Some("fast".to_string()),
                2 => Some("reg_delta".to_string()),
                3 => Some("full".to_string()),
                _ => None,
            }
        } else {
            None
        };

        let has_ext = ext_slice.is_some();
        let (ext_count, ext_raw_len, ext_active): (usize, u64, &[u8]) = if let Some(es) = ext_slice
        {
            let cnt = scan_active_ext_count(es);
            let raw_len = (cnt * size_of::<ExtRecord>()) as u64;
            if raw_len > MAX_RTRACE_RAW_STREAM_BYTES {
                return Err(invalid_data(format!(
                    ".ext 有效体积 {raw_len} 字节超出归档上限 ({MAX_RTRACE_RAW_STREAM_BYTES})"
                )));
            }
            (cnt, raw_len, &es[..raw_len as usize])
        } else {
            (0usize, 0u64, &[])
        };

        let level = opts.compression_level.min(9);
        let use_deflate = level > 0;
        let idx_crc32 = crc32_bytes(idx_active);
        let ext_crc32 = if has_ext { crc32_bytes(ext_active) } else { 0 };

        let idx_payload = compress_stream(idx_active, level)?;
        let ext_payload = if has_ext {
            compress_stream(ext_active, level)?
        } else {
            Vec::new()
        };

        let mut meta = BTreeMap::new();
        if let Some(ref lvl) = recorded_level {
            meta.insert("level".to_string(), lvl.clone());
        }
        meta.insert("insns".to_string(), idx_count.to_string());
        meta.insert("ext_events".to_string(), ext_count.to_string());
        if let Some(fname) = source_idx_name {
            meta.insert("source_idx".to_string(), sanitize_meta_value(fname));
        }
        let clean_note = opts
            .note
            .as_deref()
            .map(sanitize_meta_value)
            .filter(|s| !s.is_empty());
        if let Some(ref n) = clean_note {
            meta.insert("note".to_string(), n.clone());
        }
        let meta_bytes = encode_meta(&meta);
        if meta_bytes.len() > MAX_RTRACE_META_LEN {
            return Err(invalid_data(format!(
                "归档元数据长度 {} 超出上限 ({MAX_RTRACE_META_LEN})",
                meta_bytes.len()
            )));
        }

        let mut flags = 0u16;
        if has_ext {
            flags |= RTRACE_FLAG_HAS_EXT;
        }
        if use_deflate {
            flags |= RTRACE_FLAG_DEFLATE;
        }
        let header = encode_header(
            &ParsedHeader {
                version: RTRACE_VERSION,
                flags,
                base_addr: opts.base_addr,
                idx_raw_len,
                idx_comp_len: idx_payload.len() as u64,
                idx_crc32,
                ext_crc32,
                ext_raw_len,
                ext_comp_len: ext_payload.len() as u64,
                meta_len: meta_bytes.len() as u32,
            },
            &meta_bytes,
        );

        let total_len =
            RTRACE_HEADER_SIZE + meta_bytes.len() + idx_payload.len() + ext_payload.len();
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&header);
        out.extend_from_slice(&meta_bytes);
        out.extend_from_slice(&idx_payload);
        if has_ext {
            out.extend_from_slice(&ext_payload);
        }

        let info = TraceArchiveInfo {
            version: RTRACE_VERSION,
            flags,
            has_ext,
            compressed: use_deflate,
            base_addr: opts.base_addr,
            idx_insns: idx_count,
            idx_raw_len,
            idx_comp_len: idx_payload.len() as u64,
            idx_crc32,
            ext_events: ext_count,
            ext_raw_len,
            ext_comp_len: ext_payload.len() as u64,
            ext_crc32,
            archive_file_len: total_len as u64,
            recorded_level,
            note: clean_note,
            meta,
        };
        Ok((out, info))
    }

    /// 仅读取并校验 `.rtrace` 文件头与元数据（O(1)，不解压指令/扩展载荷）
    pub fn inspect(rtrace_path: impl AsRef<Path>) -> EmuResult<TraceArchiveInfo> {
        let mut file = File::open(rtrace_path)?;
        let file_len = file.metadata()?.len();
        let (hdr, meta) = read_and_validate_header_and_meta(&mut file, file_len)?;
        Ok(build_info(&hdr, meta, file_len))
    }

    /// 校验头部与 CRC32 后将 `.rtrace` 中的 `.idx`（及可选 `.ext`）流式解压到内存缓冲（供 `TraceReader::open` 透明加载）
    pub fn load_buffers(
        rtrace_path: impl AsRef<Path>,
    ) -> EmuResult<(Vec<u8>, Option<Vec<u8>>, TraceArchiveInfo)> {
        let file = File::open(rtrace_path)?;
        let file_len = file.metadata()?.len();
        let mut reader = BufReader::new(file);
        let (hdr, meta) = read_and_validate_header_and_meta(&mut reader, file_len)?;
        let compressed = (hdr.flags & RTRACE_FLAG_DEFLATE) != 0;
        let has_ext = (hdr.flags & RTRACE_FLAG_HAS_EXT) != 0;

        let idx_bytes = read_and_decompress_stream(
            &mut reader,
            hdr.idx_comp_len,
            hdr.idx_raw_len,
            hdr.idx_crc32,
            compressed,
            ".idx",
        )?;

        let ext_bytes = if has_ext {
            Some(read_and_decompress_stream(
                &mut reader,
                hdr.ext_comp_len,
                hdr.ext_raw_len,
                hdr.ext_crc32,
                compressed,
                ".ext",
            )?)
        } else {
            None
        };

        let info = build_info(&hdr, meta, file_len);
        Ok((idx_bytes, ext_bytes, info))
    }

    /// 将 `.rtrace` 解包还原为标准 `<stem>.idx`（及 `<stem>.ext`），校验 CRC32 并阻止路径穿越与静默覆写
    pub fn unpack(
        rtrace_path: impl AsRef<Path>,
        out_dir: impl AsRef<Path>,
        stem_override: Option<&str>,
        overwrite: bool,
    ) -> EmuResult<TraceArchiveUnpackResult> {
        let rtrace_path = rtrace_path.as_ref();
        let out_dir = out_dir.as_ref();
        let (idx_bytes, ext_bytes, info) = Self::load_buffers(rtrace_path)?;

        let raw_stem = match stem_override {
            Some(explicit) => explicit,
            None => rtrace_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("trace"),
        };
        let safe_stem = sanitize_file_stem(raw_stem, stem_override.is_some())?;

        fs::create_dir_all(out_dir)?;
        let idx_out = out_dir.join(format!("{safe_stem}.idx"));
        let ext_out = ext_bytes
            .as_ref()
            .map(|_| out_dir.join(format!("{safe_stem}.ext")));

        write_unpack_file(&idx_out, &idx_bytes, overwrite)?;
        if let (Some(ref ep), Some(ref eb)) = (&ext_out, &ext_bytes) {
            if let Err(e) = write_unpack_file(ep, eb, overwrite) {
                if !overwrite {
                    let _ = fs::remove_file(&idx_out);
                }
                return Err(e);
            }
        }

        Ok(TraceArchiveUnpackResult {
            idx_path: idx_out,
            ext_path: ext_out,
            info,
        })
    }
}

fn write_unpack_file(path: &Path, data: &[u8], overwrite: bool) -> EmuResult<()> {
    let mut file = if overwrite {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?
    } else {
        // create_new(true) 原子拒绝已存在文件与悬空符号链接，彻底杜绝 TOCTOU 与符号链接写穿
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    EmuError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "目标文件已存在（或为已存在符号链接）: {}（如需覆盖请传入 --force / overwrite=true）",
                            path.display()
                        ),
                    ))
                } else {
                    EmuError::Io(e)
                }
            })?
    };
    file.write_all(data)?;
    file.flush()?;
    Ok(())
}

fn invalid_data(msg: impl Into<String>) -> EmuError {
    EmuError::Io(io::Error::new(io::ErrorKind::InvalidData, msg.into()))
}

fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (fs::metadata(a), fs::metadata(b)) {
            if ma.dev() == mb.dev() && ma.ino() == mb.ino() {
                return true;
            }
        }
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

fn crc32_bytes(data: &[u8]) -> u32 {
    let mut crc = Crc::new();
    crc.update(data);
    crc.sum()
}

fn compress_stream(raw: &[u8], level: u32) -> EmuResult<Vec<u8>> {
    if level == 0 {
        return Ok(raw.to_vec());
    }
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(raw)?;
    Ok(encoder.finish()?)
}

fn encode_header(h: &ParsedHeader, meta_bytes: &[u8]) -> [u8; RTRACE_HEADER_SIZE] {
    let mut buf = [0u8; RTRACE_HEADER_SIZE];
    buf[0..4].copy_from_slice(&RTRACE_MAGIC);
    buf[4..6].copy_from_slice(&h.version.to_le_bytes());
    buf[6..8].copy_from_slice(&h.flags.to_le_bytes());
    buf[8..16].copy_from_slice(&h.base_addr.to_le_bytes());
    buf[16..24].copy_from_slice(&h.idx_raw_len.to_le_bytes());
    buf[24..32].copy_from_slice(&h.idx_comp_len.to_le_bytes());
    buf[32..36].copy_from_slice(&h.idx_crc32.to_le_bytes());
    buf[36..40].copy_from_slice(&h.ext_crc32.to_le_bytes());
    buf[40..48].copy_from_slice(&h.ext_raw_len.to_le_bytes());
    buf[48..56].copy_from_slice(&h.ext_comp_len.to_le_bytes());
    buf[56..60].copy_from_slice(&h.meta_len.to_le_bytes());
    let mut crc = Crc::new();
    crc.update(&buf[0..60]);
    crc.update(meta_bytes);
    buf[60..64].copy_from_slice(&crc.sum().to_le_bytes());
    buf
}

fn read_and_validate_header_and_meta<R: Read>(
    reader: &mut R,
    file_len: u64,
) -> EmuResult<(ParsedHeader, BTreeMap<String, String>)> {
    if file_len < RTRACE_HEADER_SIZE as u64 {
        return Err(invalid_data(format!(
            ".rtrace 文件长度过短 ({file_len} < {RTRACE_HEADER_SIZE})"
        )));
    }
    let mut buf = [0u8; RTRACE_HEADER_SIZE];
    reader.read_exact(&mut buf)?;
    if buf[0..4] != RTRACE_MAGIC {
        return Err(invalid_data("无效的 .rtrace 文件魔数（期望 RTRC）"));
    }
    let stored_hdr_crc = u32::from_le_bytes(buf[60..64].try_into().unwrap());
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if version != RTRACE_VERSION {
        return Err(invalid_data(format!(
            "不支持的 .rtrace 版本 v{version}（当前支持 v{RTRACE_VERSION}）"
        )));
    }
    let flags = u16::from_le_bytes(buf[6..8].try_into().unwrap());
    let known_flags = RTRACE_FLAG_HAS_EXT | RTRACE_FLAG_DEFLATE;
    if (flags & !known_flags) != 0 {
        return Err(invalid_data(format!(
            "不支持的 .rtrace 未知标志位: 0x{flags:04x}"
        )));
    }
    let base_addr = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let idx_raw_len = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let idx_comp_len = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let idx_crc32 = u32::from_le_bytes(buf[32..36].try_into().unwrap());
    let ext_crc32 = u32::from_le_bytes(buf[36..40].try_into().unwrap());
    let ext_raw_len = u64::from_le_bytes(buf[40..48].try_into().unwrap());
    let ext_comp_len = u64::from_le_bytes(buf[48..56].try_into().unwrap());
    let meta_len = u32::from_le_bytes(buf[56..60].try_into().unwrap());

    if (meta_len as usize) > MAX_RTRACE_META_LEN {
        return Err(invalid_data(format!(
            ".rtrace 元数据长度 {meta_len} 超出安全上限 ({MAX_RTRACE_META_LEN})"
        )));
    }
    let expected_file_len = (RTRACE_HEADER_SIZE as u64)
        .checked_add(u64::from(meta_len))
        .and_then(|v| v.checked_add(idx_comp_len))
        .and_then(|v| v.checked_add(ext_comp_len))
        .ok_or_else(|| invalid_data(".rtrace 文件头长度字段溢出"))?;
    if expected_file_len != file_len {
        return Err(invalid_data(format!(
            ".rtrace 文件长度不匹配（截断或尾部损坏: expected={expected_file_len}, actual={file_len}）"
        )));
    }

    let mut meta_buf = vec![0u8; meta_len as usize];
    if !meta_buf.is_empty() {
        reader.read_exact(&mut meta_buf)?;
    }

    // 校验 header_crc32（同时覆盖 60B 文件头与 meta_buf）
    let mut crc = Crc::new();
    crc.update(&buf[0..60]);
    crc.update(&meta_buf);
    let actual_hdr_crc = crc.sum();
    if stored_hdr_crc != actual_hdr_crc {
        return Err(invalid_data(format!(
            ".rtrace 文件头/元数据 CRC32 校验失败 (stored=0x{stored_hdr_crc:08x}, actual=0x{actual_hdr_crc:08x})"
        )));
    }

    if idx_raw_len > MAX_RTRACE_RAW_STREAM_BYTES || ext_raw_len > MAX_RTRACE_RAW_STREAM_BYTES {
        return Err(invalid_data(format!(
            ".rtrace 声明的解压体积超出安全上限 ({MAX_RTRACE_RAW_STREAM_BYTES} B)"
        )));
    }
    if !idx_raw_len.is_multiple_of(size_of::<TraceRecord>() as u64) {
        return Err(invalid_data(format!(
            ".rtrace idx_raw_len ({idx_raw_len}) 未对齐 TraceRecord ({})",
            size_of::<TraceRecord>()
        )));
    }
    if !ext_raw_len.is_multiple_of(size_of::<ExtRecord>() as u64) {
        return Err(invalid_data(format!(
            ".rtrace ext_raw_len ({ext_raw_len}) 未对齐 ExtRecord ({})",
            size_of::<ExtRecord>()
        )));
    }
    let has_ext = (flags & RTRACE_FLAG_HAS_EXT) != 0;
    if !has_ext && (ext_raw_len != 0 || ext_comp_len != 0 || ext_crc32 != 0) {
        return Err(invalid_data(
            ".rtrace 未置位 HAS_EXT 但扩展流长度/CRC 非零",
        ));
    }
    let compressed = (flags & RTRACE_FLAG_DEFLATE) != 0;
    if !compressed && (idx_comp_len != idx_raw_len || (has_ext && ext_comp_len != ext_raw_len)) {
        return Err(invalid_data(
            ".rtrace 未压缩模式下 comp_len 必须严格等于 raw_len",
        ));
    }

    let meta = decode_meta(&meta_buf)?;

    Ok((
        ParsedHeader {
            version,
            flags,
            base_addr,
            idx_raw_len,
            idx_comp_len,
            idx_crc32,
            ext_crc32,
            ext_raw_len,
            ext_comp_len,
            meta_len,
        },
        meta,
    ))
}

fn read_and_decompress_stream<R: Read>(
    reader: &mut R,
    comp_len: u64,
    expected_raw_len: u64,
    expected_crc32: u32,
    compressed: bool,
    label: &str,
) -> EmuResult<Vec<u8>> {
    if !compressed {
        if comp_len != expected_raw_len {
            return Err(invalid_data(format!(
                ".rtrace 未压缩 {label} 长度不匹配 (comp={comp_len}, raw={expected_raw_len})"
            )));
        }
        let mut out = vec![0u8; expected_raw_len as usize];
        reader.read_exact(&mut out)?;
        let actual_crc = crc32_bytes(&out);
        if actual_crc != expected_crc32 {
            return Err(invalid_data(format!(
                ".rtrace {label} CRC32 校验失败 (expected=0x{expected_crc32:08x}, actual=0x{actual_crc:08x})"
            )));
        }
        return Ok(out);
    }

    // 限制仅从底层读取精确 comp_len 字节，并对解压输出施加上限 expected_raw_len + 1 防止 zip-bomb
    let mut comp_reader = reader.take(comp_len);
    let mut decoder = DeflateDecoder::new(&mut comp_reader);
    let mut limited = decoder.by_ref().take(expected_raw_len.saturating_add(1));
    let cap_hint = (comp_len
        .saturating_mul(4)
        .min(expected_raw_len)
        .min(16 * 1024 * 1024)) as usize;
    let mut out = Vec::with_capacity(cap_hint);
    limited.read_to_end(&mut out)?;

    if (out.len() as u64) > expected_raw_len {
        return Err(invalid_data(format!(
            ".rtrace {label} 解压体积超过文件头声明上限 ({expected_raw_len} B，疑似畸形/zip-bomb)"
        )));
    }
    if (out.len() as u64) != expected_raw_len {
        return Err(invalid_data(format!(
            ".rtrace {label} 解压体积不匹配 (expected={expected_raw_len}, actual={})",
            out.len()
        )));
    }
    // 严格要求 Deflate 解码器精确消费全部 comp_len 字节，拒绝帧尾夹带未校验脏字节
    if decoder.total_in() != comp_len {
        return Err(invalid_data(format!(
            ".rtrace {label} 压缩流帧尾存在未消费脏字节 (consumed={}, comp_len={comp_len})",
            decoder.total_in()
        )));
    }

    let actual_crc = crc32_bytes(&out);
    if actual_crc != expected_crc32 {
        return Err(invalid_data(format!(
            ".rtrace {label} CRC32 校验失败 (expected=0x{expected_crc32:08x}, actual=0x{actual_crc:08x})"
        )));
    }
    Ok(out)
}

fn build_info(
    hdr: &ParsedHeader,
    meta: BTreeMap<String, String>,
    file_len: u64,
) -> TraceArchiveInfo {
    let recorded_level = meta.get("level").cloned();
    let note = meta.get("note").cloned();
    let _ = hdr.meta_len;
    TraceArchiveInfo {
        version: hdr.version,
        flags: hdr.flags,
        has_ext: (hdr.flags & RTRACE_FLAG_HAS_EXT) != 0,
        compressed: (hdr.flags & RTRACE_FLAG_DEFLATE) != 0,
        base_addr: hdr.base_addr,
        idx_insns: (hdr.idx_raw_len as usize) / size_of::<TraceRecord>(),
        idx_raw_len: hdr.idx_raw_len,
        idx_comp_len: hdr.idx_comp_len,
        idx_crc32: hdr.idx_crc32,
        ext_events: (hdr.ext_raw_len as usize) / size_of::<ExtRecord>(),
        ext_raw_len: hdr.ext_raw_len,
        ext_comp_len: hdr.ext_comp_len,
        ext_crc32: hdr.ext_crc32,
        archive_file_len: file_len,
        recorded_level,
        note,
        meta,
    }
}

fn sanitize_meta_value(raw: &str) -> String {
    raw.chars()
        .filter(|&c| c != '\n' && c != '\r' && c != '\0')
        .collect::<String>()
        .trim()
        .to_string()
}

fn encode_meta(meta: &BTreeMap<String, String>) -> Vec<u8> {
    let mut out = String::new();
    for (k, v) in meta {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    }
    out.into_bytes()
}

fn decode_meta(bytes: &[u8]) -> EmuResult<BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| invalid_data(format!(".rtrace 元数据不是合法 UTF-8: {e}")))?;
    let mut map = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            if !key.is_empty() {
                map.insert(key.to_string(), v.to_string());
            }
        }
    }
    Ok(map)
}

fn sanitize_file_stem(raw: &str, strict: bool) -> EmuResult<String> {
    const WIN_RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let trimmed_raw = raw.trim();
    if trimmed_raw.is_empty()
        || trimmed_raw.len() > 200
        || trimmed_raw.contains('/')
        || trimmed_raw.contains('\\')
        || trimmed_raw.contains('\0')
        || trimmed_raw.contains("..")
    {
        return Err(invalid_data(format!("无效或不安全的解包文件名前缀: `{raw}`")));
    }
    let out: String = if strict {
        if !trimmed_raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            return Err(invalid_data(format!(
                "解包文件名前缀仅支持 ASCII 字母/数字/下划线/连字符/点号: `{raw}`"
            )));
        }
        trimmed_raw.to_string()
    } else {
        trimmed_raw
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    let final_stem = out.trim_matches('.');
    if final_stem.is_empty() || final_stem.contains("..") {
        return Err(invalid_data(format!("无效或不安全的解包文件名前缀: `{raw}`")));
    }
    let base_upper = final_stem
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    if WIN_RESERVED.contains(&base_upper.as_str()) {
        return Err(invalid_data(format!(
            "解包文件名前缀 `{raw}` 命中系统保留设备名，已拒绝"
        )));
    }
    Ok(final_stem.to_string())
}

fn scan_active_idx_count(bytes: &[u8]) -> usize {
    let total = bytes.len() / size_of::<TraceRecord>();
    let mut count = 0usize;
    for i in 0..total {
        let rec = read_packed_unaligned::<TraceRecord>(bytes, i);
        let pc = rec.pc;
        let op = rec.opcode;
        if pc == 0 && op == 0 {
            break;
        }
        count += 1;
    }
    count
}

fn scan_active_ext_count(bytes: &[u8]) -> usize {
    let total = bytes.len() / size_of::<ExtRecord>();
    let mut count = 0usize;
    for i in 0..total {
        let rec = read_packed_unaligned::<ExtRecord>(bytes, i);
        if rec.kind == 0 {
            break;
        }
        count += 1;
    }
    count
}

#[inline]
fn read_packed_unaligned<T: Copy>(buf: &[u8], index: usize) -> T {
    let offset = index
        .checked_mul(size_of::<T>())
        .expect("record index overflow");
    let end = offset
        .checked_add(size_of::<T>())
        .expect("record offset overflow");
    assert!(end <= buf.len(), "record read out of bounds");
    // SAFETY: 已在 release 与 debug 模式下显式校验 end <= buf.len()，read_unaligned 读取 packed 结构体安全
    unsafe { ptr::read_unaligned(buf.as_ptr().add(offset) as *const T) }
}
