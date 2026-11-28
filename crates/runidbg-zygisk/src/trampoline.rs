//! 纯 Rust ARM64 汇编跳板：Inline Hook 入口保存/恢复 + 原生函数逃逸调用桥
//!
//! 设计原则：
//! 1. 零 C/C++ 外部汇编文件，完全使用 `core::arch::global_asm!`；
//! 2. 严格遵守 AAPCS64（含 `X8` 间接大结构体返回指针、`Q0..Q7` 浮点/NEON 参数与返回值、
//!    最多 256 字节栈参数传递、以及绝不破坏 Android `X18` ShadowCallStack 平台寄存器）；
//! 3. `runidbg_hook_common_trampoline` 采用 **零栈帧尾跳转回退协议**：
//!    - 若 Rust 分发器 `runidbg_hook_dispatch` 返回 `0`：表示 Unicorn 模拟已完成，恢复修改后的返回值并 `ret`；
//!    - 若返回非 `0`（回退跳板地址）：恢复全部原始寄存器与原始 `SP`，执行 `br x16` 无缝直通原函数！

use std::mem::{offset_of, size_of};

/// Inline Hook 入口保存的完整宿主 ARM64 现场（固定 816 字节，16 字节对齐）
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct SavedNativeContext {
    /// 通用寄存器 X0..X30（offset 0..248）
    pub x: [u64; 31],
    /// 进入跳板前的原始 SP（offset 248）
    pub sp: u64,
    /// 条件标志位 NZCV（offset 256）
    pub nzcv: u64,
    /// 16 字节对齐填充（offset 264）
    pub _pad0: u64,
    /// 128-bit NEON/FP 寄存器 Q0..Q31（offset 272..784，每个 16 字节，小端 [lo, hi]）
    pub q: [[u64; 2]; 32],
    /// Per-hook Stub 传入的 Hook ID（offset 784）
    pub hook_id: u64,
    /// 目标函数原始入口 PC（由分发器按 hook_id 填充，offset 792）
    pub target_pc: u64,
    /// 宿主线程 TLS 指针 `TPIDR_EL0`（offset 800）
    pub tpidr_el0: u64,
    /// 宿主只读 TLS 指针 `TPIDRRO_EL0`（macOS TLS，offset 808）
    pub tpidrro_el0: u64,
}

const _: () = {
    assert!(size_of::<SavedNativeContext>() == 816);
    assert!(offset_of!(SavedNativeContext, x) == 0);
    assert!(offset_of!(SavedNativeContext, sp) == 248);
    assert!(offset_of!(SavedNativeContext, nzcv) == 256);
    assert!(offset_of!(SavedNativeContext, q) == 272);
    assert!(offset_of!(SavedNativeContext, hook_id) == 784);
    assert!(offset_of!(SavedNativeContext, target_pc) == 792);
    assert!(offset_of!(SavedNativeContext, tpidr_el0) == 800);
    assert!(offset_of!(SavedNativeContext, tpidrro_el0) == 808);
};

/// 原生函数逃逸调用帧（固定 480 字节，16 字节对齐）
///
/// 由混合引擎外层循环填充后交给 `runidbg_native_escape_call`，
/// 汇编桥将 `x[0..9]`、`q[0..8]` 与 `stack_args` 装填至真实 CPU 并 `BLR target_pc`，
/// 调用完毕后将真实返回值写回 `x[0..9]`、`q[0..8]` 与 `nzcv`。
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct NativeCallFrame {
    /// 宿主原生函数地址（offset 0）
    pub target_pc: u64,
    /// X0..X8（含 X8 间接结构体返回指针，offset 8..80）
    pub x: [u64; 9],
    /// Q0..Q7（浮点/NEON 参数与 HFA 返回值，offset 80..208）
    pub q: [[u64; 2]; 8],
    /// 返回后的 NZCV 条件标志（offset 208）
    pub nzcv: u64,
    /// 有效栈参数字节数（0..=256，offset 216）
    pub stack_arg_bytes: u64,
    /// 从模拟栈顶 `[uc_sp .. uc_sp + 256]` 拷贝的栈参数窗口（offset 224..480）
    pub stack_args: [u8; 256],
}

const _: () = {
    assert!(size_of::<NativeCallFrame>() == 480);
    assert!(offset_of!(NativeCallFrame, target_pc) == 0);
    assert!(offset_of!(NativeCallFrame, x) == 8);
    assert!(offset_of!(NativeCallFrame, q) == 80);
    assert!(offset_of!(NativeCallFrame, nzcv) == 208);
    assert!(offset_of!(NativeCallFrame, stack_arg_bytes) == 216);
    assert!(offset_of!(NativeCallFrame, stack_args) == 224);
};

impl Default for NativeCallFrame {
    fn default() -> Self {
        Self {
            target_pc: 0,
            x: [0; 9],
            q: [[0; 2]; 8],
            nzcv: 0,
            stack_arg_bytes: 0,
            stack_args: [0u8; 256],
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
core::arch::global_asm!(
    r#"
    .section __TEXT,__text,regular,pure_instructions
    .p2align 4
    .globl _runidbg_native_escape_call
    .private_extern _runidbg_native_escape_call
_runidbg_native_escape_call:
    .inst 0xd503245f                  // bti c (NOP on non-BTI)
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x29, sp

    mov x19, x0                       // x19 = NativeCallFrame*
    sub sp, sp, #256                  // 预留 256B 原生栈参数区（保持 16B 对齐）

    // 将 frame->stack_args (offset 224, 256B) 拷贝到 [sp, #0..256]
    add x9, x19, #224
    mov x10, sp
    mov x11, #8                       // 8 * 32 = 256 字节
1:
    ldp x12, x13, [x9], #16
    ldp x14, x15, [x9], #16
    stp x12, x13, [x10], #16
    stp x14, x15, [x10], #16
    subs x11, x11, #1
    b.ne 1b

    // 装填 Q0..Q7 (offset 80..208)
    ldp q0, q1, [x19, #80]
    ldp q2, q3, [x19, #112]
    ldp q4, q5, [x19, #144]
    ldp q6, q7, [x19, #176]

    // 装填 X0..X8 与目标函数指针 X16（不动 X18）
    ldr x16, [x19, #0]
    ldr x8,  [x19, #72]
    ldp x0, x1, [x19, #8]
    ldp x2, x3, [x19, #24]
    ldp x4, x5, [x19, #40]
    ldp x6, x7, [x19, #56]

    blr x16

    // 回写返回值 X0..X8、Q0..Q7、NZCV
    stp x0, x1, [x19, #8]
    stp x2, x3, [x19, #24]
    stp x4, x5, [x19, #40]
    stp x6, x7, [x19, #56]
    str x8, [x19, #72]
    stp q0, q1, [x19, #80]
    stp q2, q3, [x19, #112]
    stp q4, q5, [x19, #144]
    stp q6, q7, [x19, #176]
    mrs x9, nzcv
    str x9, [x19, #208]

    add sp, sp, #256
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

    .p2align 4
    .globl _runidbg_hook_common_trampoline
    .private_extern _runidbg_hook_common_trampoline
_runidbg_hook_common_trampoline:
    .inst 0xd50324df                  // bti jc (NOP on non-BTI)
    // 入口约定：X16 = hook_id，其余全部寄存器（X0..X15, X18..X30, SP, Q0..Q31, NZCV）均原样保持
    sub sp, sp, #816

    // 保存 X0..X30
    stp x0,  x1,  [sp, #0]
    stp x2,  x3,  [sp, #16]
    stp x4,  x5,  [sp, #32]
    stp x6,  x7,  [sp, #48]
    stp x8,  x9,  [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30,      [sp, #240]

    // 保存原始 SP、NZCV（并清零 _pad0）、hook_id、TLS
    add x9, sp, #816
    str x9,  [sp, #248]
    mrs x9, nzcv
    stp x9, xzr, [sp, #256]
    str x16, [sp, #784]
    str xzr, [sp, #792]
    mrs x9, tpidr_el0
    str x9,  [sp, #800]
    mrs x9, tpidrro_el0
    str x9,  [sp, #808]

    // 保存 Q0..Q31 (offset 272..784)
    stp q0,  q1,  [sp, #272]
    stp q2,  q3,  [sp, #304]
    stp q4,  q5,  [sp, #336]
    stp q6,  q7,  [sp, #368]
    stp q8,  q9,  [sp, #400]
    stp q10, q11, [sp, #432]
    stp q12, q13, [sp, #464]
    stp q14, q15, [sp, #496]
    stp q16, q17, [sp, #528]
    stp q18, q19, [sp, #560]
    stp q20, q21, [sp, #592]
    stp q22, q23, [sp, #624]
    stp q24, q25, [sp, #656]
    stp q26, q27, [sp, #688]
    stp q28, q29, [sp, #720]
    stp q30, q31, [sp, #752]

    // 调用 Rust 分发器：u64 runidbg_hook_dispatch(SavedNativeContext *ctx)
    mov x0, sp
    bl _runidbg_hook_dispatch
    cbnz x0, 2f

    // 路径 A：模拟已完成，恢复返回值与 callee-saved 寄存器并直接返回原调用方
    ldp q0,  q1,  [sp, #272]
    ldp q2,  q3,  [sp, #304]
    ldp q4,  q5,  [sp, #336]
    ldp q6,  q7,  [sp, #368]
    ldp q8,  q9,  [sp, #400]
    ldp q10, q11, [sp, #432]
    ldp q12, q13, [sp, #464]
    ldp q14, q15, [sp, #496]
    ldp q16, q17, [sp, #528]
    ldp q18, q19, [sp, #560]
    ldp q20, q21, [sp, #592]
    ldp q22, q23, [sp, #624]
    ldp q24, q25, [sp, #656]
    ldp q26, q27, [sp, #688]
    ldp q28, q29, [sp, #720]
    ldp q30, q31, [sp, #752]

    ldr x9, [sp, #256]
    msr nzcv, x9

    ldp x0,  x1,  [sp, #0]
    ldp x2,  x3,  [sp, #16]
    ldp x4,  x5,  [sp, #32]
    ldp x6,  x7,  [sp, #48]
    ldp x8,  x9,  [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30,      [sp, #240]

    add sp, sp, #816
    ret

2:
    // 路径 B：零栈帧尾跳转至重定位后的原始函数回退跳板（X0 = fallback_addr）
    mov x16, x0
    ldp q0,  q1,  [sp, #272]
    ldp q2,  q3,  [sp, #304]
    ldp q4,  q5,  [sp, #336]
    ldp q6,  q7,  [sp, #368]
    ldp q8,  q9,  [sp, #400]
    ldp q10, q11, [sp, #432]
    ldp q12, q13, [sp, #464]
    ldp q14, q15, [sp, #496]
    ldp q16, q17, [sp, #528]
    ldp q18, q19, [sp, #560]
    ldp q20, q21, [sp, #592]
    ldp q22, q23, [sp, #624]
    ldp q24, q25, [sp, #656]
    ldp q26, q27, [sp, #688]
    ldp q28, q29, [sp, #720]
    ldp q30, q31, [sp, #752]

    ldr x17, [sp, #256]
    msr nzcv, x17

    ldp x0,  x1,  [sp, #0]
    ldp x2,  x3,  [sp, #16]
    ldp x4,  x5,  [sp, #32]
    ldp x6,  x7,  [sp, #48]
    ldp x8,  x9,  [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30,      [sp, #240]

    add sp, sp, #816
    br x16
    "#
);

#[cfg(all(target_arch = "aarch64", not(target_os = "macos")))]
core::arch::global_asm!(
    r#"
    .section .text
    .p2align 4
    .globl runidbg_native_escape_call
    .hidden runidbg_native_escape_call
    .type runidbg_native_escape_call, %function
runidbg_native_escape_call:
    .inst 0xd503245f                  // bti c
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x29, sp

    mov x19, x0                       // x19 = NativeCallFrame*
    sub sp, sp, #256

    add x9, x19, #224
    mov x10, sp
    mov x11, #8
1:
    ldp x12, x13, [x9], #16
    ldp x14, x15, [x9], #16
    stp x12, x13, [x10], #16
    stp x14, x15, [x10], #16
    subs x11, x11, #1
    b.ne 1b

    ldp q0, q1, [x19, #80]
    ldp q2, q3, [x19, #112]
    ldp q4, q5, [x19, #144]
    ldp q6, q7, [x19, #176]

    ldr x16, [x19, #0]
    ldr x8,  [x19, #72]
    ldp x0, x1, [x19, #8]
    ldp x2, x3, [x19, #24]
    ldp x4, x5, [x19, #40]
    ldp x6, x7, [x19, #56]

    blr x16

    stp x0, x1, [x19, #8]
    stp x2, x3, [x19, #24]
    stp x4, x5, [x19, #40]
    stp x6, x7, [x19, #56]
    str x8, [x19, #72]
    stp q0, q1, [x19, #80]
    stp q2, q3, [x19, #112]
    stp q4, q5, [x19, #144]
    stp q6, q7, [x19, #176]
    mrs x9, nzcv
    str x9, [x19, #208]

    add sp, sp, #256
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
    .size runidbg_native_escape_call, .-runidbg_native_escape_call

    .p2align 4
    .globl runidbg_hook_common_trampoline
    .hidden runidbg_hook_common_trampoline
    .type runidbg_hook_common_trampoline, %function
runidbg_hook_common_trampoline:
    .inst 0xd50324df                  // bti jc
    sub sp, sp, #816

    stp x0,  x1,  [sp, #0]
    stp x2,  x3,  [sp, #16]
    stp x4,  x5,  [sp, #32]
    stp x6,  x7,  [sp, #48]
    stp x8,  x9,  [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30,      [sp, #240]

    add x9, sp, #816
    str x9,  [sp, #248]
    mrs x9, nzcv
    stp x9, xzr, [sp, #256]
    str x16, [sp, #784]
    str xzr, [sp, #792]
    mrs x9, tpidr_el0
    str x9,  [sp, #800]
    str xzr, [sp, #808]

    stp q0,  q1,  [sp, #272]
    stp q2,  q3,  [sp, #304]
    stp q4,  q5,  [sp, #336]
    stp q6,  q7,  [sp, #368]
    stp q8,  q9,  [sp, #400]
    stp q10, q11, [sp, #432]
    stp q12, q13, [sp, #464]
    stp q14, q15, [sp, #496]
    stp q16, q17, [sp, #528]
    stp q18, q19, [sp, #560]
    stp q20, q21, [sp, #592]
    stp q22, q23, [sp, #624]
    stp q24, q25, [sp, #656]
    stp q26, q27, [sp, #688]
    stp q28, q29, [sp, #720]
    stp q30, q31, [sp, #752]

    mov x0, sp
    bl runidbg_hook_dispatch
    cbnz x0, 2f

    ldp q0,  q1,  [sp, #272]
    ldp q2,  q3,  [sp, #304]
    ldp q4,  q5,  [sp, #336]
    ldp q6,  q7,  [sp, #368]
    ldp q8,  q9,  [sp, #400]
    ldp q10, q11, [sp, #432]
    ldp q12, q13, [sp, #464]
    ldp q14, q15, [sp, #496]
    ldp q16, q17, [sp, #528]
    ldp q18, q19, [sp, #560]
    ldp q20, q21, [sp, #592]
    ldp q22, q23, [sp, #624]
    ldp q24, q25, [sp, #656]
    ldp q26, q27, [sp, #688]
    ldp q28, q29, [sp, #720]
    ldp q30, q31, [sp, #752]

    ldr x9, [sp, #256]
    msr nzcv, x9

    ldp x0,  x1,  [sp, #0]
    ldp x2,  x3,  [sp, #16]
    ldp x4,  x5,  [sp, #32]
    ldp x6,  x7,  [sp, #48]
    ldp x8,  x9,  [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30,      [sp, #240]

    add sp, sp, #816
    ret

2:
    mov x16, x0
    ldp q0,  q1,  [sp, #272]
    ldp q2,  q3,  [sp, #304]
    ldp q4,  q5,  [sp, #336]
    ldp q6,  q7,  [sp, #368]
    ldp q8,  q9,  [sp, #400]
    ldp q10, q11, [sp, #432]
    ldp q12, q13, [sp, #464]
    ldp q14, q15, [sp, #496]
    ldp q16, q17, [sp, #528]
    ldp q18, q19, [sp, #560]
    ldp q20, q21, [sp, #592]
    ldp q22, q23, [sp, #624]
    ldp q24, q25, [sp, #656]
    ldp q26, q27, [sp, #688]
    ldp q28, q29, [sp, #720]
    ldp q30, q31, [sp, #752]

    ldr x17, [sp, #256]
    msr nzcv, x17

    ldp x0,  x1,  [sp, #0]
    ldp x2,  x3,  [sp, #16]
    ldp x4,  x5,  [sp, #32]
    ldp x6,  x7,  [sp, #48]
    ldp x8,  x9,  [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30,      [sp, #240]

    add sp, sp, #816
    br x16
    .size runidbg_hook_common_trampoline, .-runidbg_hook_common_trampoline
    "#
);

#[cfg(target_arch = "aarch64")]
extern "C" {
    /// 通过 ARM64 汇编桥在真实宿主 CPU 上执行外部函数
    pub fn runidbg_native_escape_call(frame: *mut NativeCallFrame);
    /// 通用 Inline Hook 汇编入口（仅取地址供 per-hook stub 跳转）
    pub fn runidbg_hook_common_trampoline();
}

/// 获取通用 Hook 汇编入口虚拟地址
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn common_trampoline_addr() -> u64 {
    runidbg_hook_common_trampoline as *const () as usize as u64
}

/// 非 AArch64 主机构建占位（仅保证文档与配置解析在 x86_64 上可通过 `cargo check`）
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn runidbg_native_escape_call(_frame: *mut NativeCallFrame) {
    panic!("runidbg_native_escape_call 仅支持 AArch64 架构");
}

#[cfg(not(target_arch = "aarch64"))]
pub fn common_trampoline_addr() -> u64 {
    0
}
