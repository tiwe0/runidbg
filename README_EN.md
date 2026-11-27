<div align="center">

# runidbg

**High-Performance Android ARM64 `.so` Emulator, Binary Tracer, Taint Analyzer & Time-Travel Debugger in Pure Rust**

`Rust + unidbg + ... = runidbg`

<p>
  <a href="https://github.com/tiwe0/runidbg/releases/latest"><img src="https://img.shields.io/badge/release-v0.4.6-FF6B2C?style=flat-square" alt="Release v0.4.6" /></a>
  <img src="https://img.shields.io/badge/Rust-2021-E6522C?style=flat-square&logo=rust&logoColor=white" alt="Rust 2021" />
  <img src="https://img.shields.io/badge/Target-Android%20ARM64-34D399?style=flat-square&logo=android&logoColor=white" alt="Android ARM64" />
  <img src="https://img.shields.io/badge/Tests-148%2F148%20passing-10B981?style=flat-square" alt="Tests 148/148" />
  <img src="https://img.shields.io/badge/License-MIT-64748B?style=flat-square" alt="MIT License" />
</p>

<p>
  <a href="./README.md">简体中文</a> &nbsp;·&nbsp;
  <strong>English</strong> &nbsp;·&nbsp;
  <a href="./docs/GUIDE.md">Full Guide (中文)</a> &nbsp;·&nbsp;
  <a href="./docs/SKILL.md">AI Agent Skill</a> &nbsp;·&nbsp;
  <a href="https://github.com/tiwe0/runidbg/releases">Downloads</a>
</p>

<br />

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./docs/assets/runidbg-features-en-dark.png" />
  <source media="(prefers-color-scheme: light)" srcset="./docs/assets/runidbg-features-en-light.png" />
  <img src="./docs/assets/runidbg-features-en-dark.png" alt="runidbg Core Features Overview" width="100%" />
</picture>

</div>

<br />

## Highlights

- **Pure-Rust Zero-JVM Speed** — `77 ms` cold start (`22.6×`), `21.7 MB` single-worker RSS (`-82%` RAM), shipped as a single binary.
- **4 Pluggable ARM64 Backends** — Switch cleanly between `Unicorn 2.1` (full Trace / Hook / GDB) and `Dynarmic JIT` / `Linux KVM` / `macOS Hypervisor` (up to `480×` compute speedup).
- **Complete Android Native Runtime** — Full ELF dynamic linker, `110+` HLE stubs, coalescing free-list heap, JNI 1.6, in-memory APK loader, `DeviceProfile` presets, isolated dual-stream RNG & offline-safe Socket/epoll.
- **Zero-Copy Tracer, Single-File `.rtrace`, Lightweight Taint & `decompile` v2** — `17.03M insns/s` dual-stream `.idx/.ext` (unifying HLE memory/entropy/clock events with missing-`.ext` warnings) plus **`pack`/`unpack` single-file Deflate-compressed `.rtrace` archives transparently readable by every offline CLI/UI/JS/MCP command without unpacking**; pure-Rust byte-granular forward/backward taint slicing (`--from-seq` / `--stop-at-pc` / `--stop-mem` surgical cutoffs & `[ORIGIN: HLE rand()/gettimeofday()]` tagging); **`decompile` v2 with 1..64B multi-output joint buffer decompilation (cross-output shared CSE), readable `LOAD16/32/64_LE` folding, 128-bit NEON lane lifting & ARMv8-CE hardware AES (`AESE`/`AESD`/`AESMC`/`AESIMC`) → self-verified compilable pseudo-C & `QF_BV`/`QF_UFBV` SMT-LIB2**; SIMD scanning (`22.95 GB/s`), omniscient queries, `mem` reconstruction & dual-run diff-taint linkage (`diff --target-addr`).
- **Built-In `good64` Zero-Dep ARM64 Assembler & Relocator** — Covers 99% of practical Android ARM64 instructions (bitfields, LSE atomics, sysregs, PAC/BTI, scalar FP, 128-bit NEON & AES), with 4B/16B/20B Inline Hook trampolines and multi-pass PC-relative instruction relocation as a lightweight pure-Rust Keystone replacement.
- **OLLVM & Bytecode VM Assistant** — Auto-detects dispatch loops, 4B/8B jump tables, bytecode PCs, handler distributions & relocated regfile diffs (with `--seq-range` windowing), paired with live `watchRegfile` and word decoding.
- **`.rtape` Time-Travel Debugging** — Sparse 4KB dirty-page checkpoints & 4-backend relay (fast boot on Hyper/Dynarmic → record on Unicorn), bit-exact JS-free replay & reverse GDB watchpoints.
- **QuickJS Scripting & Built-In Multi-Core RPC** — Zero-config Frida-style hooks with `runidbg.d.ts`; out-of-the-box `tokio + axum` lock-free worker pool (`1,141 QPS`), hot reload, `/metrics` & embedded dark Web UI.
- **Built-In MCP AI Reversing Loop** — Native stdio & Streamable HTTP server with **39 tools** (including `emu_asm`, `trace_decompile`, `trace_mem` & `trace_diff` taint linkage), `EnvDiag` auto-patcher & lightweight DEX index for Claude / Cursor / Codex.

---

## Quick Start

Download prebuilt binaries from [GitHub Releases](https://github.com/tiwe0/runidbg/releases/latest) (`macOS arm64` / `Linux x86_64 & arm64` / `Windows x86_64`), or build from source with `cargo build --release --bin runidbg-cli`:

```javascript
// sign.js — emulate an Android ARM64 .so and expose a leak-free RPC endpoint
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
runidbg-cli run       sign.js                                      # Run script
runidbg-cli serve     sign.js --workers auto --allow-reload        # Start multi-core RPC server
runidbg-cli asm       "paciasp; ubfx x0, x1, #4, #8; ret"          # Built-in good64 ARM64 assembler
runidbg-cli taint     trace.idx --mode backward --addr 0x50006470 --from-seq 1000  # Offline taint / diff / vm
runidbg-cli decompile trace.rtrace --addr 0x50006470 --len 16 --fold-rodata --smt2 # 16B multi-out / NEON / AES -> pseudo-C
runidbg-cli pack      trace.idx --base 0x40000000 --out trace.rtrace               # Trim zero-pad & pack single-file .rtrace
runidbg-cli mem       trace.rtrace --addr 0x50006170 --len 576 --at 1820000        # Reconstruct memory at any seq
runidbg-cli ui        session.rtape --open                                         # Dark Web UI Time-Travel Cockpit
runidbg-cli mcp       --cwd .                                                      # Launch MCP server (39 tools)
```

---

## Benchmarks

> First three rows: Apple Silicon (10-core ARM64) apples-to-apples benchmark on the same ~2 MB stripped `.so` with 100% identical outputs. Fourth row: `libzstd` across `runidbg` backends (including nested Linux ARM64 KVM; see the [Full Guide (中文)](./docs/GUIDE.md)).

| Benchmark | Baseline (`Java unidbg` / `Unicorn`) | Rust `runidbg` | Improvement |
| :--- | ---: | ---: | :---: |
| Cold Start (ELF Load + `JNI_OnLoad`) | `unidbg` 1,738 ms | **77 ms** | **22.6×** |
| HTTP RPC (1 worker / 10 workers) | `unidbg` 255 QPS · 122 MB | **629 QPS · 21.7 MB** / **1,141 QPS** | **2.47×–4.48× · -82% RSS/worker** |
| Full-Module Trace (`fast` mmap) | `unidbg` 0.15M insns/s | **17.03M insns/s** | **114×** |
| Compute Backends (ZSTD 256KB × 20) | `runidbg` Unicorn 24.96 s | **Dynarmic 245 ms · KVM 105 ms · Hyper 52 ms** | **Up to 480×** |

> `runidbg` focuses on **Android ARM64** speed, offline analysis, and production serving. If you need **ARM32** or **iOS Mach-O**, consider the battle-tested [**unidbg**](https://github.com/zhkl0228/unidbg).

---

## Documentation

| Document | Covers |
| :--- | :--- |
| [**Full Guide (中文)**](./docs/GUIDE.md) | Backend builds & signing, QuickJS API, `good64` assembler & Inline Hook, Trace / Taint / Slice-to-C / Diff / VM, `.rtape` time-travel & GDB RSP |
| [**AI Agent Skill**](./docs/SKILL.md) | All 39 MCP tools and autonomous reversing workflows for Claude / Cursor / Codex |
| [**GitHub Releases**](https://github.com/tiwe0/runidbg/releases) | Prebuilt binaries for all platforms + `SHA256SUMS.txt` |

---

## Contributing & Acknowledgements

Incompatible Android ARM64 `.so` samples (with credentials redacted) and minimal reproduction scripts are warmly welcomed via Issues & PRs. Run `cargo test` to execute the full test suite (`148` tests on macOS ARM64; `147` on Linux/Windows).

Special thanks to [**unidbg**](https://github.com/zhkl0228/unidbg) (`zhkl0228`) for pioneering hand-crafted Android/iOS emulation in the pre-AI era, as well as [Unicorn Engine](https://github.com/unicorn-engine/unicorn), [Dynarmic](https://github.com/merryhime/dynarmic), [QuickJS](https://bellard.org/quickjs/) / `rquickjs`, `goblin`, and `bad64`.

> **Disclaimer**: This project is intended strictly for binary security research, reverse-engineering education, benchmarking, and authorized security testing. Any unlawful or unauthorized use is strictly prohibited; users assume full legal responsibility.
