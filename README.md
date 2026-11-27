<div align="center">

# runidbg

**纯 Rust 打造的高性能 Android ARM64 `.so` 仿真器、二进制 Tracer、污点分析与时间旅行逆向引擎**

`Rust + unidbg + ... = runidbg`

<p>
  <a href="https://github.com/tiwe0/runidbg/releases/latest"><img src="https://img.shields.io/badge/release-v0.4.6-FF6B2C?style=flat-square" alt="Release v0.4.6" /></a>
  <img src="https://img.shields.io/badge/Rust-2021-E6522C?style=flat-square&logo=rust&logoColor=white" alt="Rust 2021" />
  <img src="https://img.shields.io/badge/Target-Android%20ARM64-34D399?style=flat-square&logo=android&logoColor=white" alt="Android ARM64" />
  <img src="https://img.shields.io/badge/Tests-148%2F148%20passing-10B981?style=flat-square" alt="Tests 148/148" />
  <img src="https://img.shields.io/badge/License-MIT-64748B?style=flat-square" alt="MIT License" />
</p>

<p>
  <strong>简体中文</strong> &nbsp;·&nbsp;
  <a href="./README_EN.md">English</a> &nbsp;·&nbsp;
  <a href="./docs/GUIDE.md">完整使用指南</a> &nbsp;·&nbsp;
  <a href="./docs/SKILL.md">AI Agent Skill</a> &nbsp;·&nbsp;
  <a href="https://github.com/tiwe0/runidbg/releases">预编译下载</a>
</p>

<br />

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./docs/assets/runidbg-features-zh-dark.png" />
  <source media="(prefers-color-scheme: light)" srcset="./docs/assets/runidbg-features-zh-light.png" />
  <img src="./docs/assets/runidbg-features-zh-dark.png" alt="runidbg 核心特性全景图" width="100%" />
</picture>

</div>

<br />

## Highlights

- **纯 Rust 零 JVM 高性能** — `77 ms` 冷启动（`22.6×`）、`21.7 MB` 单实例内存（省 `82%`），单文件跨平台分发。
- **四引擎 ARM64 后端** — `Unicorn 2.1`（全功能 Trace / Hook / GDB）与 `Dynarmic JIT` / `Linux KVM` / `macOS Hypervisor`（纯算最高 `480×`）统一接口切换。
- **完整 Android 原生运行时** — ELF 动态链接、`110+` HLE、合并空闲链堆、JNI 1.6、APK 内存直载、`DeviceProfile` 真机画像、隔离双流 RNG 与离线护栏 Socket/epoll。
- **零拷贝 Tracer、单文件 `.rtrace`、轻量污点与 `decompile` v2** — `17.03M insns/s` 双流 `.idx/.ext`（统一记录 HLE 内存/熵源/时钟事件 + 缺失 `.ext` 显式告警），支持 **`pack`/`unpack` 打包单文件 Deflate 压缩 `.rtrace` 归档（全离线命令/UI/JS/MCP 透明免解包直读）**；纯 Rust 字节级前向/反向污点切片（`--from-seq` / `--stop-at-pc` / `--stop-mem` 手术刀截断与熵源标注）；**`decompile` v2 支持 1..64B 缓冲区多输出联合反编译（跨输出共享 CSE）、`LOAD16/32/64_LE` 可读折叠、NEON 128-bit 通道级提升与 ARMv8-CE 硬件 AES（`AESE`/`AESD`/`AESMC`/`AESIMC`）→ 自校验可编译伪 C & `QF_BV`/`QF_UFBV` SMT-LIB2**；SIMD 内存扫描（`22.95 GB/s`）、全知查询、内存重建（`mem`）与双跑差分污点联动（`diff --target-addr`）。
- **内置 `good64` 零依赖 ARM64 汇编器与重定位器** — 覆盖 99% Android ARM64 指令（含位域、LSE 原子、系统寄存器、PAC/BTI、标量 FP、128-bit NEON & AES），内置 4B/16B/20B Inline Hook 跳板与多遍 PC 相对指令重定位器，无缝替代 Keystone。
- **OLLVM / 字节码 VM 助手** — 自动识别 Dispatch Loop、4B/8B 跳转表、字节码 PC、Handler 分布与基址搬家差分（支持 `--seq-range` 窗口聚焦），配合在线 `watchRegfile` 与指令字解码。
- **`.rtape` 磁带与时间旅行** — 4KB 稀疏脏页增量与四引擎跨后端接力（Hyper/Dynarmic 极速初始化 → Unicorn 精录），支持 100% 比特级离线重放与 GDB 反向观察点。
- **QuickJS 脚本与内置多核 RPC** — 零配置 Frida 风格 Hook 与 `runidbg.d.ts`；开箱即用 `tokio + axum` 无锁多核 Worker 池（`1,141 QPS`）、热重载、`/metrics` 与暗黑 Web UI。
- **内置 MCP AI 逆向闭环** — 原生 stdio / Streamable HTTP 双模式 **39 个工具**（含 `emu_asm`、`trace_decompile`、`trace_mem` 与 `trace_diff` 污点联动）、`EnvDiag` 缺环境自动诊断与轻量 DEX 索引，无缝接入 Claude / Cursor / Codex。

---

## Quick Start

直接下载 [GitHub Releases](https://github.com/tiwe0/runidbg/releases/latest) 预编译二进制（`macOS arm64` / `Linux x86_64 & arm64` / `Windows x86_64`），或从源码构建 `cargo build --release --bin runidbg-cli`：

```javascript
// sign.js — 6 行跑通 Android ARM64 .so 仿真并导出零泄漏 RPC
const emu = Emu.create({ device: "pixel8pro", packageName: "com.example.app" });
const mod = emu.load("./libtarget.so");
emu.jniOnLoad(mod);

rpc.exports = {
  sign: (s) => emu.jni.withLocalFrame(() =>
    emu.jni.getString(emu.call(mod.base + 0x12340, emu.jni.envPtr, 0, emu.jni.newString(s)))
  ),
};
```

```bash
runidbg-cli run       sign.js                                      # 执行脚本
runidbg-cli serve     sign.js --workers auto --allow-reload        # 启动多核 RPC 服务
runidbg-cli asm       "paciasp; ubfx x0, x1, #4, #8; ret"          # 内置 good64 ARM64 汇编器
runidbg-cli taint     trace.idx --mode backward --addr 0x50006470 --from-seq 1000  # 离线污点 / diff / vm
runidbg-cli decompile trace.rtrace --addr 0x50006470 --len 16 --fold-rodata --smt2 # 16B 多输出/NEON/AES -> 自校验伪 C
runidbg-cli pack      trace.idx --base 0x40000000 --out trace.rtrace               # 裁剪零填充并压缩为单文件 .rtrace
runidbg-cli mem       trace.rtrace --addr 0x50006170 --len 576 --at 1820000        # 任意时刻内存快照重建
runidbg-cli ui        session.rtape --open                                         # 暗黑 Web UI 时间旅行驾驶舱
runidbg-cli mcp       --cwd .                                                      # 启动 MCP 服务端（39 工具）
```

---

## Benchmarks

> 前三项为 Apple Silicon（10 核 ARM64）同一 ~2 MB stripped `.so` 100% 等价输出实测；第四项为 `libzstd` 跨后端实测（含 Linux ARM64 嵌套 KVM，详见 [完整使用指南](./docs/GUIDE.md)）。

| 评测维度 | 基线 (`Java unidbg` / `Unicorn`) | Rust `runidbg` | 提升 |
| :--- | ---: | ---: | :---: |
| 冷启动耗时（加载 + `JNI_OnLoad`） | `unidbg` 1,738 ms | **77 ms** | **22.6×** |
| HTTP RPC（单核 / 10 核并发） | `unidbg` 255 QPS · 122 MB | **629 QPS · 21.7 MB** / **1,141 QPS** | **2.47×–4.48× · 单核省 82% 内存** |
| 全模块指令 Trace（`fast` mmap） | `unidbg` 0.15M insns/s | **17.03M insns/s** | **114×** |
| 多后端纯算（ZSTD 256KB × 20） | `runidbg` Unicorn 24.96 s | **Dynarmic 245 ms · KVM 105 ms · Hyper 52 ms** | **最高 480×** |

> `runidbg` 专注 **Android ARM64** 极速仿真、离线分析与工程化部署；如需 **ARM32** 或 **iOS Mach-O**，推荐使用久经考验的 [**unidbg**](https://github.com/zhkl0228/unidbg)。

---

## Documentation

| 文档 | 内容 |
| :--- | :--- |
| [**完整使用指南**](./docs/GUIDE.md) | 多后端选型与签名、QuickJS API 字典、`good64` 汇编与 Inline Hook、Trace / 污点 / 切片伪 C / Diff / VM、`.rtape` 时间旅行与 GDB RSP |
| [**AI Agent Skill**](./docs/SKILL.md) | 面向 Claude / Cursor / Codex 的 39 个 MCP 工具参考与自动化逆向工作流 |
| [**GitHub Releases**](https://github.com/tiwe0/runidbg/releases) | 全平台预编译二进制与 `SHA256SUMS.txt` |

---

## Contributing & Acknowledgements

欢迎通过 Issue / PR 提交脱敏后的不兼容 Android ARM64 `.so` 样本与最小复现脚本；本地校验请运行 `cargo test`（macOS ARM64 共 148 项测试，Linux/Windows 共 147 项）。

特别致谢 [**unidbg**](https://github.com/zhkl0228/unidbg) 及其作者 `zhkl0228`——在没有 AI 辅助的年代凭一己之力手写并持续维护横跨 Android 与 iOS 的仿真框架令人由衷钦佩；同时感谢 [Unicorn Engine](https://github.com/unicorn-engine/unicorn)、[Dynarmic](https://github.com/merryhime/dynarmic)、[QuickJS](https://bellard.org/quickjs/) / `rquickjs`、`goblin`、`bad64` 等优秀开源项目。

> **免责声明**：本项目仅用于二进制安全研究、逆向工程学习、性能评测及经授权的安全测试，严禁用于任何违反法律法规或未经授权的用途；使用者自行承担全部责任。
