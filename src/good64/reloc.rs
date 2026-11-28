//! `good64` Inline Hook PC 相对指令重定位器（Relocator）
//!
//! 当将原函数头部的 1–N 条指令搬运到 Trampoline 新地址 `new_pc` 执行时，自动检测并重写所有
//! PC 相对指令（`b`/`bl`/`b.cond`/`cbz`/`cbnz`/`tbz`/`tbnz`/`adr`/`adrp`/`ldr literal`）：
//! - 若目标落在被搬运块内部（`[old_pc, old_pc + bytes.len())`），通过多遍不动点布局将其精确重定向到
//!   Trampoline 内对应指令的新偏移，避免原头部被 Inline Hook 跳板覆写后跳入损坏区；
//! - 若新地址与外部目标仍在指令编码范围内，原地重算精确相对偏移（保持 4 字节）；
//! - 若超出范围，自动展开为等价的安全绝对跳转/地址加载序列（使用 `x16` IP0 或目的寄存器本身）。

use anyhow::{bail, Result};

use super::{encode_call_trampoline, encode_mov_imm64};

/// BTI-safe 16 字节绝对分支序列：`ldr x16, #8; ret x16; .quad target`
///
/// 在 ARMv8.5-A `PROT_BTI` 页上，`RET X16` 将 `PSTATE.BTYPE` 置为 `0b00`，
/// 可安全跳转到原函数内部任意非 BTI 标签而不触发 `SIGILL`（与 `BR X16` 的 `BTYPE=0b01` 不同）。
#[inline]
fn encode_bti_safe_abs_branch(target: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&0x5800_0050u32.to_le_bytes()); // ldr x16, #8
    out[4..8].copy_from_slice(&0xD65F_0200u32.to_le_bytes()); // ret x16
    out[8..16].copy_from_slice(&target.to_le_bytes());
    out
}

/// 近距 ±128 MiB 用 4B `B`，远距用 16B BTI-safe `ldr x16, #8; ret x16; .quad target`
#[inline]
fn encode_reloc_branch(from_pc: u64, target_pc: u64) -> Vec<u8> {
    if (from_pc & 3) == 0 && (target_pc & 3) == 0 {
        let delta = (target_pc as i128) - (from_pc as i128);
        if (-0x0800_0000..=0x07FF_FFFC).contains(&delta) {
            let imm26 = ((delta >> 2) as u32) & 0x03FF_FFFF;
            return (0x1400_0000u32 | imm26).to_le_bytes().to_vec();
        }
    }
    encode_bti_safe_abs_branch(target_pc).to_vec()
}

#[inline]
fn sign_extend(val: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((u64::from(val) << shift) as i64) >> shift
}

/// 将在 `old_pc` 处的单条 ARM64 指令重定位到 `new_pc`，返回等价小端机器码字节流
pub fn relocate_instruction(word: u32, old_pc: u64, new_pc: u64) -> Result<Vec<u8>> {
    relocate_instruction_impl(word, old_pc, new_pc, None)
}

fn relocate_instruction_impl(
    word: u32,
    old_pc: u64,
    new_pc: u64,
    override_target: Option<u64>,
) -> Result<Vec<u8>> {
    // 1. B / BL (op0 = 0b000101 / 0b100101)
    if (word & 0x7C00_0000) == 0x1400_0000 {
        let is_bl = (word & 0x8000_0000) != 0;
        let off = sign_extend(word & 0x03FF_FFFF, 26) << 2;
        let target = override_target.unwrap_or_else(|| old_pc.wrapping_add(off as u64));
        return Ok(if is_bl {
            encode_call_trampoline(new_pc, target)
        } else {
            encode_reloc_branch(new_pc, target)
        });
    }

    // 2. B.<cond> (0101_0100 ... 0 cond；bit4=1 为 ARMv8.8 BC.cond，不误匹配)
    if (word & 0xFF00_0010) == 0x5400_0000 {
        let cond = word & 0xF;
        let off = sign_extend((word >> 5) & 0x7_FFFF, 19) << 2;
        let target = override_target.unwrap_or_else(|| old_pc.wrapping_add(off as u64));
        let delta = (target as i128) - (new_pc as i128);
        if (delta & 3) == 0 && (-0x0010_0000..=0x000F_FFFC).contains(&delta) {
            let imm19 = ((delta >> 2) as u32) & 0x7_FFFF;
            return Ok((0x5400_0000 | (imm19 << 5) | cond).to_le_bytes().to_vec());
        }
        if cond >= 0xE {
            // B.AL / B.NV 永远成立，超距直接展开为无条件绝对跳板
            return Ok(encode_reloc_branch(new_pc, target));
        }
        // 超出 ±1 MiB：反转条件跳过 16B BTI-safe 绝对跳板（b.!cond +20; ldr x16, #8; ret x16; .quad target）
        let mut out = Vec::with_capacity(20);
        let inv_cond = cond ^ 1;
        // +0: b.!<cond> +20 (imm19 = 5)
        out.extend_from_slice(&(0x5400_0000 | (5 << 5) | inv_cond).to_le_bytes());
        out.extend_from_slice(&encode_bti_safe_abs_branch(target));
        return Ok(out);
    }

    // 3. CBZ / CBNZ (sf 011010 op imm19 rt)
    if (word & 0x7E00_0000) == 0x3400_0000 {
        let off = sign_extend((word >> 5) & 0x7_FFFF, 19) << 2;
        let target = override_target.unwrap_or_else(|| old_pc.wrapping_add(off as u64));
        let delta = (target as i128) - (new_pc as i128);
        if (delta & 3) == 0 && (-0x0010_0000..=0x000F_FFFC).contains(&delta) {
            let imm19 = ((delta >> 2) as u32) & 0x7_FFFF;
            let rewritten = (word & 0xFF00_001F) | (imm19 << 5);
            return Ok(rewritten.to_le_bytes().to_vec());
        }
        // 反转 cbz <-> cbnz 跳过 16B BTI-safe 绝对跳板
        let mut out = Vec::with_capacity(20);
        let inv = ((word & 0xFF00_001F) ^ (1 << 24)) | (5 << 5);
        out.extend_from_slice(&inv.to_le_bytes());
        out.extend_from_slice(&encode_bti_safe_abs_branch(target));
        return Ok(out);
    }

    // 4. TBZ / TBNZ (b5 011011 op b40 imm14 rt)
    if (word & 0x7E00_0000) == 0x3600_0000 {
        let off = sign_extend((word >> 5) & 0x3FFF, 14) << 2;
        let target = override_target.unwrap_or_else(|| old_pc.wrapping_add(off as u64));
        let delta = (target as i128) - (new_pc as i128);
        if (delta & 3) == 0 && (-0x8000..=0x7FFC).contains(&delta) {
            let imm14 = ((delta >> 2) as u32) & 0x3FFF;
            let rewritten = (word & 0xFFF8_001F) | (imm14 << 5);
            return Ok(rewritten.to_le_bytes().to_vec());
        }
        // 反转 tbz <-> tbnz 跳过 16B BTI-safe 绝对跳板
        let mut out = Vec::with_capacity(20);
        let inv = ((word & 0xFFF8_001F) ^ (1 << 24)) | (5 << 5);
        out.extend_from_slice(&inv.to_le_bytes());
        out.extend_from_slice(&encode_bti_safe_abs_branch(target));
        return Ok(out);
    }

    // 5. ADR / ADRP (op immlo 10000 immhi rd)
    if (word & 0x1F00_0000) == 0x1000_0000 {
        let is_adrp = (word & 0x8000_0000) != 0;
        let rd = (word & 0x1F) as u8;
        if rd == 31 {
            // ADR / ADRP XZR 无副作用，等价 NOP（也避免超距展开误触 Rd=31/SP）
            return Ok(0xD503_201Fu32.to_le_bytes().to_vec());
        }
        let immlo = (word >> 29) & 3;
        let immhi = (word >> 5) & 0x7_FFFF;
        let raw_imm = sign_extend((immhi << 2) | immlo, 21);
        let target = if is_adrp {
            (old_pc & !0xFFF).wrapping_add((raw_imm << 12) as u64)
        } else {
            override_target.unwrap_or_else(|| old_pc.wrapping_add(raw_imm as u64))
        };

        if is_adrp {
            let delta_pages = (((target & !0xFFF) as i128) - ((new_pc & !0xFFF) as i128)) >> 12;
            if (-0x0010_0000..=0x000F_FFFF).contains(&delta_pages) {
                let u = (delta_pages as i64 as u64) & 0x1F_FFFF;
                let lo = (u & 3) as u32;
                let hi = ((u >> 2) & 0x7_FFFF) as u32;
                return Ok((0x9000_0000 | (lo << 29) | (hi << 5) | u32::from(rd))
                    .to_le_bytes()
                    .to_vec());
            }
        } else {
            let delta = (target as i128) - (new_pc as i128);
            if (-0x0010_0000..=0x000F_FFFF).contains(&delta) {
                let u = (delta as i64 as u64) & 0x1F_FFFF;
                let lo = (u & 3) as u32;
                let hi = ((u >> 2) & 0x7_FFFF) as u32;
                return Ok((0x1000_0000 | (lo << 29) | (hi << 5) | u32::from(rd))
                    .to_le_bytes()
                    .to_vec());
            }
        }
        // 超出范围：直接用 MOVZ/MOVK 装入精确 64-bit 目标地址到 Rd（不破坏任何其他寄存器）
        let mut out = Vec::new();
        for w in encode_mov_imm64(rd, target) {
            out.extend_from_slice(&w.to_le_bytes());
        }
        return Ok(out);
    }

    // 6. LDR literal (GPR Wt=0x1800_0000, Xt=0x5800_0000, LDRSW=0x9800_0000, PRFM=0xD800_0000;
    //    FP S/D/Q V=1，排除未分配编码 opc=3,V=1 即 0xDC00_0000)
    if (word & 0x3B00_0000) == 0x1800_0000 && (word & 0xFF00_0000) != 0xDC00_0000 {
        let is_fp = (word & 0x0400_0000) != 0;
        let opc = (word >> 30) & 3;
        let rt = (word & 0x1F) as u8;
        let off = sign_extend((word >> 5) & 0x7_FFFF, 19) << 2;
        let target = old_pc.wrapping_add(off as u64);
        let delta = (target as i128) - (new_pc as i128);
        if (delta & 3) == 0 && (-0x0010_0000..=0x000F_FFFC).contains(&delta) {
            let imm19 = ((delta >> 2) as u32) & 0x7_FFFF;
            let rewritten = (word & 0xFF00_001F) | (imm19 << 5);
            return Ok(rewritten.to_le_bytes().to_vec());
        }
        // 超出 ±1 MiB：GPR 用 Rt 自身做地址基址加载，FP 用 x16 (IP0) 做基址加载
        let mut out = Vec::new();
        if !is_fp {
            if opc == 3 {
                // PRFM literal 仅为缓存预取提示，超距可安全降级为 NOP
                return Ok(0xD503_201Fu32.to_le_bytes().to_vec());
            }
            if rt == 31 {
                // LDR XZR/WZR literal 无副作用，等价 NOP
                return Ok(0xD503_201Fu32.to_le_bytes().to_vec());
            }
            for w in encode_mov_imm64(rt, target) {
                out.extend_from_slice(&w.to_le_bytes());
            }
            let load_word = match opc {
                0 => 0xB940_0000 | (u32::from(rt) << 5) | u32::from(rt), // ldr wt, [xt]
                1 => 0xF940_0000 | (u32::from(rt) << 5) | u32::from(rt), // ldr xt, [xt]
                2 => 0xB980_0000 | (u32::from(rt) << 5) | u32::from(rt), // ldrsw xt, [xt]
                _ => unreachable!(),
            };
            out.extend_from_slice(&load_word.to_le_bytes());
        } else {
            for w in encode_mov_imm64(16, target) {
                out.extend_from_slice(&w.to_le_bytes());
            }
            let load_word = match opc {
                0 => 0xBD40_0200 | u32::from(rt), // ldr st, [x16]
                1 => 0xFD40_0200 | u32::from(rt), // ldr dt, [x16]
                2 => 0x3DC0_0200 | u32::from(rt), // ldr qt, [x16]
                _ => unreachable!(),
            };
            out.extend_from_slice(&load_word.to_le_bytes());
        }
        return Ok(out);
    }

    // 非 PC 相对指令：原样保留
    Ok(word.to_le_bytes().to_vec())
}

/// 若单条 PC 相对分支或 `ADR` 的原始目标落在被搬运块 `[old_pc, end_old)` 内，返回目标指令下标
fn extract_intra_block_target(word: u32, cur_old: u64, old_pc: u64, end_old: u64) -> Option<usize> {
    let target = if (word & 0x7C00_0000) == 0x1400_0000 {
        let off = sign_extend(word & 0x03FF_FFFF, 26) << 2;
        cur_old.wrapping_add(off as u64)
    } else if (word & 0xFF00_0010) == 0x5400_0000 || (word & 0x7E00_0000) == 0x3400_0000 {
        let off = sign_extend((word >> 5) & 0x7_FFFF, 19) << 2;
        cur_old.wrapping_add(off as u64)
    } else if (word & 0x7E00_0000) == 0x3600_0000 {
        let off = sign_extend((word >> 5) & 0x3FFF, 14) << 2;
        cur_old.wrapping_add(off as u64)
    } else if (word & 0x9F00_0000) == 0x1000_0000 {
        // 仅 ADR（排除 ADRP，因为 ADRP 指向 4KB 页基址而非块内单条指令）
        let immlo = (word >> 29) & 3;
        let immhi = (word >> 5) & 0x7_FFFF;
        let raw_imm = sign_extend((immhi << 2) | immlo, 21);
        cur_old.wrapping_add(raw_imm as u64)
    } else {
        return None;
    };

    if target >= old_pc && target < end_old && ((target - old_pc) & 3) == 0 {
        Some(((target - old_pc) / 4) as usize)
    } else {
        None
    }
}

/// 批量重定位一段连续 ARM64 指令字节流（从 `old_pc` 搬运到 `new_pc`）
///
/// 支持多遍不动点布局：若块内存在指向 `[old_pc, old_pc + bytes.len())` 内部的分支/ADR，
/// 会将其目标自动重定向到新地址空间 `new_pc` 下对应指令的新位置。
pub fn relocate_instructions(bytes: &[u8], old_pc: u64, new_pc: u64) -> Result<Vec<u8>> {
    if !bytes.len().is_multiple_of(4) {
        bail!("待重定位指令字节长度 {} 必须为 4 的倍数", bytes.len());
    }
    let words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    if words.is_empty() {
        return Ok(Vec::new());
    }

    let end_old = old_pc.saturating_add(bytes.len() as u64);
    let intra_targets: Vec<Option<usize>> = words
        .iter()
        .enumerate()
        .map(|(i, &w)| {
            let cur_old = old_pc.wrapping_add((i * 4) as u64);
            extract_intra_block_target(w, cur_old, old_pc, end_old)
        })
        .collect();
    let has_intra = intra_targets.iter().any(Option::is_some);

    let mut offsets: Vec<u64> = (0..words.len()).map(|i| (i * 4) as u64).collect();
    let max_passes = if has_intra { 4 } else { 1 };
    let mut final_out = Vec::new();

    for _ in 0..max_passes {
        let mut out = Vec::with_capacity(bytes.len());
        let mut next_offsets = Vec::with_capacity(words.len());
        for (i, &w) in words.iter().enumerate() {
            let cur_old = old_pc.wrapping_add((i * 4) as u64);
            let cur_off = out.len() as u64;
            next_offsets.push(cur_off);
            let cur_new = new_pc.wrapping_add(cur_off);
            let override_target = intra_targets[i].map(|tidx| new_pc.wrapping_add(offsets[tidx]));
            let reloc = relocate_instruction_impl(w, cur_old, cur_new, override_target)?;
            out.extend_from_slice(&reloc);
        }
        final_out = out;
        if next_offsets == offsets {
            break;
        }
        offsets = next_offsets;
    }

    Ok(final_out)
}
