//! `runidbg-zygisk` — Android 进程内混合执行（Native + Unicorn 1:1 零拷贝）与 Zygisk 模块
//!
//! 架构分层：
//! - [`config`]：零外部依赖配置模型与 JSON 解析器；
//! - [`mem_map`]：1:1 零拷贝按需缺页路由、TBI 指针去标签与 Shadow Pristine Page；
//! - [`trampoline`]：纯 Rust ARM64 `global_asm!` Inline Hook 现场保存与原生逃逸桥；
//! - [`inline_hook`]：基于 `runidbg::good64` 的纯 Rust ARM64 Inline Hook 管理器（含 BTI 感知与重定位回退）；
//! - [`hybrid`]：线程本地重入池化 Unicorn 引擎、原生逃逸外层循环、自动 `dladdr` HLE 与直出 `.rtrace`。

pub mod android;
pub mod config;
pub mod hybrid;
pub mod inline_hook;
pub mod mem_map;
pub mod trampoline;
