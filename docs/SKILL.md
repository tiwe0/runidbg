---
name: runidbg
description: Use runidbg (runidbg-cli) to emulate Android ARM64 .so libraries across 4 backends (Unicorn/Dynarmic/KVM/Hypervisor), assemble/relocate ARM64 patches with built-in good64, write QuickJS JNI/Hook/VM/DEX scripts, diagnose missing Android environments with EnvDiag, capture high-speed binary instruction + HLE traces (and pack/unpack transparent single-file `.rtrace` archives), run offline byte-granular taint/slicing and decompile v2 (1..64B multi-output joint CSE, LOAD_LE folding, NEON 128-bit lanes & ARMv8-CE hardware AES, --from-seq/--stop-at-pc/--stop-mem/--fold-rodata, byte-reassembly & MBA simplification, UMULH/SMULH magic-div recovery & QF_BV/QF_UFBV SMT-LIB2), offline memory reconstruction (`mem`), omniscient query, dual-run diff-taint linkage, custom VM analysis, `.rtape` time-travel debugging, multi-core HTTP/JSON-RPC services, embedded Web UI, MCP (39 tools), or GDB RSP.
---

# runidbg Agent Skill

Use `runidbg` when reversing, emulating, tracing, time-travel debugging, or serving **Android ARM64 (`aarch64`) `.so` libraries** without an Android device or JVM.

## Prerequisites & Build

```bash
# macOS (requires pkgconf + cmake + ninja)
brew install pkgconf cmake ninja
cargo build --release
codesign --force --sign - --entitlements entitlements/hypervisor.plist target/release/runidbg-cli

# Binaries produced:
#   target/release/runidbg-cli
#   target/release/runidbg-arm64-emu-tracer
```

## Critical Semantics & Pitfalls to Remember

1. **64-bit register precision**: `ctx.reg("x8")` returns a JS `number` (loses precision above `2^53 - 1`). **Always use `ctx.reg64("x8")` or `emu.regs.get64("x8")`** (returns lossless `BigInt`) for 64-bit values, hashes, rotates, or high-bit pointers!
2. **Hook execution timing**:
   - `emu.hook.code` fires **BEFORE** the instruction executes (registers reflect state prior to the instruction).
   - `emu.hook.mem` / `emu.hook.watch` fires on memory access; `value` (and `value64` `BigInt`) carries the actual byte-width-masked value for both `MEM_READ` and `MEM_WRITE`. If the target range has no mapped pages yet, `handle.unmapped === true` and a warning is logged.
3. **Deterministic heap layout across probe scripts**: pass `--freeze-layout` (`runidbg-cli run --freeze-layout probe.js`) or `Emu.create({ freezeLayout: true })`. Host `emu.mem.alloc()` is isolated into `[host-scratch]` (`0x6400_0000`) so adding probe buffers never shifts guest `malloc` heap addresses! Inspect guest allocations anytime with `emu.heapLayout()`.
4. **Trace truncation & level**:
   - `fast`: PC + opcode only (no `.ext`).
   - `reg_delta` (default): PC + opcode + register deltas (no memory `.ext`).
   - `full`: registers + guest memory R/W + **HLE `memcpy`/`memmove`/`memset`/`bzero`/`malloc`/`calloc`/`realloc`/`free` + entropy/clock sources (`rand`/`getrandom`/`gettimeofday`/`clock_gettime`/`time`)** in `.ext` (required for `taint`, `decompile`, `mem`, `vm`, `find --addr/--bytes`, and `Trace.open().query()`; missing sibling `.ext` emits an explicit `WARN`).
   - Default `capacity` is `262144`. Always check `const st = emu.trace.stop(); if (st.truncated) ...` and raise `capacity` if truncated!
5. **`rand()` / `srand()` stub**: HLE `rand`/`random`/`srand`/`srandom` use a deterministic `xorshift64*` PRNG (not glibc TYPE_3), logging a one-time warning. Override via `emu.hook.importReplace("rand", ...)` if a target depends on a specific sequence.
6. **Backend choice**: `unicorn` is required for Trace, GDB RSP, and native code/mem/syscall hooks; use `dynarmic`, `hypervisor` (macOS), or `kvm` (Linux) for pure emulation acceleration, and relay via `.rtape` (`saveTape` -> `Emu.loadTape(..., { backend: "unicorn" })`) when fast-forwarding initialization.

## Standard Reverse-Engineering Workflow (Iterative Loop)

1. **Create a minimal QuickJS probe script** with `freezeLayout`, `emu.diag.enable()`, `device`, and `realClock`:
   ```javascript
   const emu = Emu.create({
     packageName: "com.example.app",
     searchPaths: ["./libs"],
     device: "pixel8pro", // pixel5 | pixel8pro | s24ultra | xiaomi14 | { ... }
     realClock: false,
     freezeLayout: true,  // keep guest heap addresses stable across probe scripts
   });
   emu.diag.enable();
   emu.setLimits({ timeoutMs: 30000, maxInstructions: 0 });

   emu.jni.onUnhandled((info) => {
     console.log(`[JNI] ${info.kind} ${info.className}.${info.name}${info.sig}`);
     return 0;
   });

   const mod = emu.load("./libs/libtarget.so");
   try {
     const ver = emu.jniOnLoad(mod);
     console.log("JNI_OnLoad =", ver ? "0x" + ver.toString(16) : null);
   } catch (e) {
     console.error(emu.lastCrash()?.formatted || e);
   }
   console.log("RegisteredNatives:", JSON.stringify(emu.jni.registeredNatives()));
   console.log("EnvDiag:", JSON.stringify(emu.diag.report(), null, 2));
   ```
2. **Run with structured logging**:
   ```bash
   ./target/release/runidbg-cli --log-level info run --freeze-layout probe.js
   ```
3. **Patch missing environment using `EnvDiag`**:
   - `missingFiles` -> `emu.vfs.writeFile(path, content)` or `emu.vfs.mountOverlay(guestDir, hostDir)`
   - `missingProperties` -> `emu.vfs.setProperty(key, val)` or `emu.vfs.setDevice(...)`
   - `missingSyscalls` -> `emu.hook.syscall(nr, (ctx, nr) => retVal)`
   - `missingJni` -> `emu.jni.hook("pkg/Class", { method(a, b) { ... } })`
   - Or call `emu.diag.generatePatchJs()` for an auto-generated patch template.

## Essential QuickJS Patterns

### Fast Guest Memory Watchpoints & Rust-Side Filtered Hooks
```javascript
// Watch guest writes to a buffer range (lossless 64-bit BigInt value64):
const wh = emu.hook.watch([buf, buf + 64], "w", (ctx, access, addr, size, val, val64) => {
  console.log(`pc=0x${ctx.pc.toString(16)} write [${addr.toString(16)}] = 0x${val64.toString(16)}`);
});

// Zero-JS-overhead Rust-side filtering (only enters JS when value, size, and PC match):
const mh = emu.hook.mem(
  [buf, buf + 64],
  { write: true, value: 0xdeadbeefn, size: 4, pcRange: [mod.base, mod.base + mod.size], bigInt: true },
  (ctx, access, addr, size, val, val64) => { ... }
);
if (mh.unmapped) console.warn("target range not mapped yet!");
```

### Online Custom-VM Regfile Watcher & Word Decoder
```javascript
const watcher = emu.vm.watchRegfile({
  baseReg: "x25",                  // auto-tracks stack-frame base relocations!
  count: 32,
  size: 8,
  dispatcherPc: mod.base + 0x12340,
  bcReg: "x23",                    // optional; set bcDeref: true if [x23] holds bytecode PC
  layout: { op: [6, 6], fields: [12, 17, 22, 27] },
});
emu.call(mod.base + 0x10000, ...);
console.log(watcher.format(100));  // step#0001 bc=0x...(+8B) op=49 f=[1,5,0,7] | R[3]: 0x10->0x42
watcher.detach();
```

### High-Speed Full Trace + Offline Taint, Omniscient Query, Diff & VM Analysis
```javascript
emu.trace.start({
  output: "run.idx",     // auto-creates run.ext in "full" mode (includes HLE memcpy/memset/malloc/free)
  level: "full",
  start: mod.base,
  end: mod.base + mod.size,
  capacity: 2000000,
});
emu.call(mod.base + 0x120be0, ...);
const st = emu.trace.stop();
if (st.truncated) console.warn("Trace truncated!", st);

// Pack single-file compressed .rtrace (all offline CLI/JS/MCP/UI commands read .rtrace transparently!):
Trace.pack("run.idx", "run.rtrace", { baseAddr: mod.base, note: "sign round" });
const arcInfo = Trace.inspectArchive("run.rtrace");

// Offline omniscient query, backward causal slicing, decompile v2 (1..64B, NEON/AES) & VM auto-analysis:
const tr = Trace.open("run.rtrace"); // or "run.idx"; check tr.isArchive / tr.missingExtWarning / tr.recordedLevel
const writes = tr.findWrites(0xdeadbeefn, { width: 4 }); // lossless BigInt hit.value64
const hist   = tr.findMem(0x50006470, { kind: "w", len: 8, minSeq: 1000, maxSeq: 50000, includeHle: false });
const snap   = tr.reconstructMem(0x50006470, 16); // snap.bytes is a Uint8Array
const slice  = tr.taintBackward({ addr: 0x50006470, len: 8, fromIdx: 1000, stopAtPcs: [0x40001200] });
const pseudo = tr.taintToC({ addr: 0x50006470, len: 16, fromIdx: 1000, foldRodata: true, emitSmt2: true });
const fwd    = tr.taintForward({ addr: 0x50001000, len: 16 });
const vmRep  = tr.vmAnalyze({ minIdx: 1821500, maxIdx: 1824500, baseReg: "x25", layout: { op: [6, 6], fields: [12, 17, 22, 27] } });
tr.close();

// Built-in good64 zero-dep ARM64 assembler, relocator & Inline Hook helpers:
const stub   = Emu.asm("paciasp; mov x0, #0x42; autiasp; ret", 0x40001000);
const reloc  = Emu.relocateAsm(stub, 0x40001000, 0x80001000);
emu.mem.patchAsm(mod.base + 0x1000, "mov x0, #1; ret");
emu.mem.inlineJump(mod.base + 0x2000, mod.base + 0x1000);

const diff      = Trace.diff("run_a.idx", "run_b.idx");
const diffTaint = Trace.diffTaint("run_a.idx", "run_b.idx", 0x50006850, 32);
```

Offline CLI equivalents:
```bash
runidbg-cli stats       run.idx --base 0x40000000 --top 20
runidbg-cli calltree    run.idx --base 0x40000000 --max-depth 4 --min-insns 1000
runidbg-cli crypto-scan run.idx --base 0x40000000
runidbg-cli dump        run.idx --base 0x40000000 --skip 0 --limit 50
runidbg-cli mem         run.idx --addr 0x50006170 --len 576 --at 1820000
runidbg-cli find        run.idx --base 0x40000000 --val 0x03000001
runidbg-cli find        run.idx --addr 0x50006470 --len 8 --seq-range 1000..50000 --only-writes --no-hle
runidbg-cli find        run.idx --base 0x40000000 --ascii "8404" --limit 10
runidbg-cli asm         "paciasp; ubfx x0, x1, #4, #8; ret" --pc 0x40001000
runidbg-cli taint       run.idx --mode backward --addr 0x50006470 --len 8 --from-seq 1922597 --base 0x40000000
runidbg-cli pack        run.idx --base 0x40000000 --out run.rtrace
runidbg-cli unpack      run.rtrace --info
runidbg-cli decompile   run.rtrace --addr 0x50006470 --len 16 --from-seq 1922597 --fold-rodata --fn round_fn --smt2
runidbg-cli diff        run_a.idx run_b.idx --target-addr 0x50006850 --len 32
runidbg-cli vm          run.idx --seq-range 1821500..1824500 --base 0x40000000 --base-reg x25 --layout 6:6,12,17,22,27
runidbg-cli export-ida  run.idx --base 0x40000000 --out ida_cov.py
runidbg-cli export-bn   run.idx --base 0x40000000 --out bn_cov.py
```

### `.rtape` Snapshots & Deterministic Time-Travel Debugging
```javascript
// Fast-forward init on Dynarmic -> save tape -> relay to Unicorn for time-travel recording:
fastEmu.saveTape("./init.rtape", "after_init");
const uc = Emu.loadTape("./init.rtape", { backend: "unicorn", checkpoint: "after_init" });
uc.record.start({ keyframeInterval: 100000, captureJni: true });
uc.module("libtarget.so").call("sign_func", dst, src, len);
uc.record.bookmark("done");
uc.record.stop("./sign_tt.rtape");

const tt = Emu.openTimeTravel("./sign_tt.rtape");
tt.seekBookmark("done");
const writer = tt.findPrevWrite(dst, 8);
tt.close();
```

### Using MCP Tools (39 Tools for Direct AI Agent Control)
Start MCP server via stdio (`runidbg-cli mcp --cwd .`) or Streamable HTTP (`runidbg-cli mcp --http 127.0.0.1:8090 --cwd .`):
- **Lifecycle & Execution**: `emu_create` (supports `backend`, `freezeLayout`), `emu_load`, `emu_jni_onload`, `emu_exports`, `emu_call`, `emu_eval_js`
- **DEX & JNI**: `emu_load_dex`, `emu_dex_class_info`, `emu_jni_set_field`, `emu_jni_call_native`
- **Inspection, Memory & Assembler**: `emu_regs`, `emu_mem_read`, `emu_mem_scan`, `emu_disasm`, `emu_asm`
- **Tracing, Taint, Slice-to-C, Mem, Diff, VM & Hooks**: `emu_trace_call`, `trace_inspect`, `trace_calltree`, `trace_crypto_scan`, `trace_taint`, `trace_decompile`, `trace_mem`, `trace_query`, `trace_diff`, `trace_vm_analyze`, `emu_hook_capture`
- **`.rtape` & Time-Travel**: `emu_save_tape`, `emu_load_tape`, `emu_seek_tape`, `tape_info`, `tt_record_start`, `tt_record_stop`, `tt_open`, `tt_seek`, `tt_reverse_watch`, `tt_mem_read`, `tt_close`
- **Diagnostics**: `emu_diag_missing`, `emu_last_crash`

## Guardrails & Best Practices
- Only targets **Android ARM64 (`aarch64`)** ELF shared libraries.
- Never hardcode or commit real cookies, session tokens, or private keys into scripts or tests.
- Scope `trace.start({ start, end })` to `[mod.base, mod.base + mod.size]` to keep `.idx`/`.ext` compact while still capturing HLE `memcpy`/`memset`/`malloc`/`free` calls attributed to module call sites.
- For full API details, read [docs/GUIDE.md](./GUIDE.md) and [src/script/runidbg.d.ts](../src/script/runidbg.d.ts).
