// runidbg (runidbg-arm64-emu-tracer) QuickJS Scripting Type Definitions (V1 + V2)
// Export via: runidbg-cli init-types

declare const args: string[];

declare function hex(bytes: Uint8Array): string;
declare function require(specifier: string): any;

declare namespace console {
  function log(...values: unknown[]): void;
  function warn(...values: unknown[]): void;
  function error(...values: unknown[]): void;
}

declare namespace fs {
  function readBytes(path: string): Uint8Array;
  function readText(path: string): string;
  function writeBytes(path: string, bytes: Uint8Array): void;
  function writeText(path: string, text: string): void;
  function exists(path: string): boolean;
}

declare namespace rpc {
  let exports: Record<string, (...args: any[]) => any>;
}

type DevicePresetName = "pixel5" | "pixel8pro" | "s24ultra" | "xiaomi14";

interface DeviceProfileConfig {
  preset?: DevicePresetName;
  brand?: string;
  manufacturer?: string;
  model?: string;
  device?: string;
  product?: string;
  board?: string;
  hardware?: string;
  socPlatform?: string;
  fingerprint?: string;
  buildId?: string;
  buildDisplay?: string;
  incremental?: string;
  securityPatch?: string;
  androidRelease?: string;
  sdkInt?: number;
  abi?: string;
  abiList?: string;
  cpuCores?: number;
  ramTotalKb?: number;
  kernelRelease?: string;
  kernelVersion?: string;
  screenWidth?: number;
  screenHeight?: number;
  screenDpi?: number;
  locale?: string;
  timezone?: string;
  carrierName?: string;
  carrierMccMnc?: string;
  serialNo?: string;
  androidId?: string;
}

type EmuBackendKind = "unicorn" | "dynarmic" | "kvm" | "hypervisor" | "hyper";

interface EmuOptions {
  /**
   * 底层 CPU 执行后端（默认 `"unicorn"`）：
   * - `"unicorn"`: 支持完整仿真 + Trace + GDB + 原生 Hook
   * - `"dynarmic"` / `"kvm"`（Linux 默认编译） / `"hypervisor"`（`"hyper"`，macOS 默认编译）: 仅限仿真模式
   */
  backend?: EmuBackendKind;
  packageName?: string;
  searchPaths?: string[];
  hleAccel?: boolean;
  heapSize?: number;
  device?: DevicePresetName | DeviceProfileConfig;
  realClock?: boolean;
  net?: boolean | NetOptions;
  /**
   * 冻结 guest 堆布局（等同于 CLI `runidbg-cli run --freeze-layout`）：
   * 开启后，`emu.mem.alloc()` 会自动改用独立的 `[host-scratch]` 区（0x6400_0000+），
   * 不再占用 guest `malloc/calloc/realloc` 所在的 0x5000_0000 堆空间，
   * 确保“先跑找地址、再挂 Hook 重跑”的两遍法 guest 堆地址 100% 稳定。
   */
  freezeLayout?: boolean;
}

interface TraceOptions {
  output?: string;
  /**
   * Trace 采集级别（默认 `"reg_delta"`）：
   * - `"fast"`: 仅记录 PC 与指令码（不产出 `.ext`）
   * - `"reg_delta"`: 记录指令 + 寄存器增量（默认，不记录访存）
   * - `"full"`: 记录指令 + 寄存器增量 + 全量内存 R/W + HLE `memcpy/memset/malloc/free`（**仅 `"full"` 产出 `.ext` 供离线 `taint` / `query` / `reconstructMem` 使用**）
   */
  level?: "fast" | "reg_delta" | "full";
  start?: number | bigint;
  end?: number | bigint;
  /** 最大指令记录容量（默认 `262144`；若耗尽截断，`trace.stop()` 会输出告警且 `stats.truncated === true`） */
  capacity?: number;
}

interface TraceStats {
  records: number;
  extRecords: number;
  totalInsns: number;
  droppedInsns: number;
  droppedExt: number;
  /** 若指令或扩展流发生缓冲区截断则为 `true` */
  truncated: boolean;
}

interface RegisteredNativeInfo {
  className: string;
  name: string;
  sig: string;
  fnPtr: number;
}

interface UnhandledJniInfo {
  kind: string;
  className: string;
  name: string;
  sig: string;
  isStatic: boolean;
  args: unknown[];
}

interface HookHandle {
  readonly id: number;
  /** 仅 `emu.hook.mem` 返回：若注册区间当前完全未映射，值为 `true`（Hook 仍已挂入，未来映射后生效；同时会输出 warn 日志） */
  readonly unmapped?: boolean;
  detach(): boolean;
}

interface CodeHookOptions {
  once?: boolean;
  maxHits?: number;
}

interface MemHookOptions {
  read?: boolean;
  write?: boolean;
  /**
   * Rust 侧值过滤：仅当读写值（按本次访问宽度截断后）等于 `value` 时才跨入 QuickJS 回调，
   * 可大幅减少高频访存 Hook 的 JS 桥接开销。
   */
  value?: number | bigint;
  /** Rust 侧访问宽度过滤（仅匹配指定字节宽度的访存，如 1 / 2 / 4 / 8） */
  size?: number;
  /** Rust 侧 PC 范围过滤 `[startPc, endPc]`（闭区间），仅当触发访存的指令 PC 落在该区间内才回调 */
  pcRange?: [number | bigint, number | bigint];
  /**
   * 开启后，回调的第 3 个参数 `addr` 与第 5 个参数 `value` 直接以 `bigint` 传入（避免超过 2^53 的 64 位值精度丢失）。
   * 无论是否开启，回调的第 6 个参数 `value64` 始终以 `bigint` 传入。
   */
  bigInt?: boolean;
}

interface CpuContext {
  x0: number; x1: number; x2: number; x3: number; x4: number; x5: number; x6: number; x7: number;
  x8: number; x9: number; x10: number; x11: number; x12: number; x13: number; x14: number; x15: number;
  x16: number; x17: number; x18: number; x19: number; x20: number; x21: number; x22: number; x23: number;
  x24: number; x25: number; x26: number; x27: number; x28: number; x29: number; x30: number;
  sp: number;
  pc: number;
  lr: number;
  fp: number;
  nzcv: number;
  retval: number;
  readonly mem: MemNamespace;
  /** 读取寄存器为 JS number（注意：超过 2^53 的 64 位值会丢失低位精度，涉及大整数/哈希/位运算请改用 `reg64`） */
  reg(name: string): number;
  /** 精确无损读取 64 位寄存器为 `bigint`（`regBigInt` 的简写别名） */
  reg64(name: string): bigint;
  regBigInt(name: string): bigint;
  setReg(name: string, value: number | bigint): void;
  args(count?: number): number[];
  stop(): void;
}

interface AttachCallbacks {
  onEnter?: (this: Record<string, any>, ctx: CpuContext) => void;
  onLeave?: (this: Record<string, any>, ctx: CpuContext) => void;
}

interface RegsNamespace {
  get(name: string): number;
  /** 精确无损读取 64 位寄存器为 `bigint`（`getBigInt` 的简写别名） */
  get64(name: string): bigint;
  getBigInt(name: string): bigint;
  set(name: string, value: number | bigint): void;
  dump(): Record<string, number>;
}

interface HookNamespace {
  /** 在已映射指令地址挂入 onEnter/onLeave Hook（若地址未映射会立即抛错） */
  attach(addr: number | bigint, callbacks: AttachCallbacks): HookHandle;
  replace(addr: number | bigint, fn: (ctx: CpuContext) => number | bigint | boolean | void): HookHandle;
  /** 按外部导入符号名（如 `"fopen"`, `"getauxval"`）挂 Hook；支持在 `emu.load` 之前或之后调用 */
  import(
    symbolName: string,
    callbacks: AttachCallbacks | ((ctx: CpuContext) => number | bigint | boolean | void)
  ): HookHandle;
  /** 按外部导入符号名直接替换其实现（无需反汇编找 PLT 偏移） */
  importReplace(
    symbolName: string,
    fn: (ctx: CpuContext) => number | bigint | boolean | void
  ): HookHandle;
  /**
   * 指令级 Hook（**指令执行前**触发回调；在回调内调用 `ctx.setReg` / 改写 `ctx.x0` 会立即作用于当前即将执行的这条指令）。
   * 若要改写某次 `BL` 调用后的返回值，请把地址挂在 `BL` 的**下一条指令**（`blAddr + 4`），例如：
   * ```js
   * emu.hook.code(mod.base + 0x93664 + 4, (ctx) => { ctx.x0 = 1; });
   * ```
   */
  code(
    addrOrRange: number | bigint | [number | bigint, number | bigint],
    fn: (ctx: CpuContext, pc: number, size: number) => void,
    options?: CodeHookOptions
  ): HookHandle;
  /**
   * 内存读写 Hook（**访存提交前**触发回调：
   * - `read`: 在内存读返回给目标指令之前触发，`value` 尚未写入目标寄存器，如需读原始字节可用 `ctx.mem.readBytes(addr, size)`；
   * - `write`: 在新值真正写入目标内存之前触发，`value` / `value64` 为**即将写入的新值**，`ctx.mem.readBytes(addr, size)` 读到的是**旧值**）。
   * - 若注册地址区间当前尚未映射，不会静默丢弃：Hook 仍挂入（后续映射后自动触发），同时输出 warn 日志且返回的 `handle.unmapped === true`。
   * - 回调第 6 参数 `value64` 始终为无损 64 位 `bigint`；传入 `options.bigInt = true` 时 `addr` 与 `value` 也会直接以 `bigint` 传入。
   */
  mem(
    range: [number | bigint, number | bigint],
    options: MemHookOptions,
    fn: (
      ctx: CpuContext,
      access: "read" | "write" | "other",
      addr: number | bigint,
      size: number,
      value: number | bigint,
      value64: bigint
    ) => void
  ): HookHandle;
  mem(
    range: [number | bigint, number | bigint],
    fn: (
      ctx: CpuContext,
      access: "read" | "write" | "other",
      addr: number,
      size: number,
      value: number,
      value64: bigint
    ) => void
  ): HookHandle;
  /**
   * Guest 侧地址区间读写监视（`emu.hook.mem` 的便捷别名，覆盖 guest `STR`/`STP`/`LDR`/`LDP` 指令）。
   * - `mode`: `"w"`（默认，仅监视写入）| `"r"`（仅监视读取）| `"rw"`（读写均监视），或传 `MemHookOptions` 对象。
   */
  watch(
    range: [number | bigint, number | bigint],
    modeOrOpts: "w" | "r" | "rw" | (MemHookOptions & { mode?: "w" | "r" | "rw" }),
    fn: (
      ctx: CpuContext,
      access: "read" | "write" | "other",
      addr: number | bigint,
      size: number,
      value: number | bigint,
      value64: bigint
    ) => void
  ): HookHandle;
  watch(
    range: [number | bigint, number | bigint],
    fn: (
      ctx: CpuContext,
      access: "read" | "write" | "other",
      addr: number,
      size: number,
      value: number,
      value64: bigint
    ) => void
  ): HookHandle;
  syscall(
    nrOrWildcard: number | "*",
    fn: (ctx: CpuContext, nr: number) => number | bigint | void | undefined
  ): HookHandle;
}

interface LoadOptions {
  /** 是否在加载后立即执行 DT_INIT / .init_array 构造器（默认 true；设为 false 可先挂 Hook 再手动调用 mod.runInit()） */
  runInit?: boolean;
}

interface ModuleHandle {
  readonly name: string;
  readonly base: number;
  readonly size: number;
  symbol(name: string): number | null;
  exports(): string[];
  call(symOrAddr: string | number | bigint, ...args: Array<number | bigint>): number;
  /** 手动执行该模块的 DT_INIT / .init_array 构造器（配合 `load(path, { runInit: false })` 使用） */
  runInit(): void;
}

interface JniFieldInfo {
  readonly id: number;
  readonly className: string;
  readonly name: string;
  readonly sig: string;
  readonly isStatic: boolean;
}

interface JniMethodInfo {
  readonly id: number;
  readonly className: string;
  readonly name: string;
  readonly sig: string;
  readonly isStatic: boolean;
}

interface JniObjectInfo {
  readonly ref: number;
  readonly className: string;
  readonly kind: string;
}

interface JniTraceEvent {
  readonly seq: number;
  readonly op: string;
  readonly className: string;
  readonly targetRef: number;
  readonly member: string;
  readonly sig: string;
  readonly args: string[];
  readonly ret: string;
  readonly isNull: boolean;
  /** 本次调用是否命中了用户通过 `hook`/`hookField`/`hookMethod` 注册的 JS Hook */
  readonly handled: boolean;
  /** 命中的 Hook 唯一 ID（对应 `listHooks()[i].id`）；未命中 Hook 时为 `null` */
  readonly hookId: number | null;
}

interface JniTraceNamespace {
  /** 开启全量 JNI 调用事件采集（默认关闭，关闭时零开销） */
  start(opts?: { maxStrLen?: number; maxEvents?: number }): void;
  stop(): void;
  clear(): void;
  /** 导出完整 JNI 调用序列（不受 32 条面包屑环形缓冲截断） */
  events(): JniTraceEvent[];
  /** 实时订阅每一次 JNI 调用事件（无需硬编码虚表/槽位地址；传 null 取消订阅） */
  onEvent(cb: ((ev: JniTraceEvent) => void) | null): void;
}

interface JniRegisteredHookInfo {
  readonly id: number;
  readonly kind: "field" | "method" | "any";
  readonly className: string;
  readonly name: string;
  readonly sig: string | null;
  readonly hits: number;
}

interface JniNamespace {
  readonly envPtr: number;
  /**
   * 拦截指定类（或接口/父类）的 JNI 方法或字段读取（支持运行时子类自动回退到声明接口/父类）。
   * - 带 `(` 的键（如 `"g()Lcas/c0;"`）自动注册为**方法专属 + 精确签名**；
   * - 带 `:` 的键（如 `"g:Ljava/lang/String;"` / `"field:g"`）自动注册为**字段专属**；
   * - 纯名称键注册到兼容通用表（建议存在字段/方法同名冲突时直接使用 `hookField` / `hookMethod`）。
   * - 优先级：精确签名专属 Hook > 无签名专属 Hook > 声明类专属 Hook > 通用 Hook > 内置模型 > `onUnhandled`。
   */
  hook(className: string, methods: Record<string, (...args: any[]) => any>): void;
  /** 显式注册**字段专属** Hook（支持 `"g"` 或 `"g:[C"`，绝不劫持同名方法） */
  hookField(className: string, fields: Record<string, (...args: any[]) => any>): void;
  /** 显式注册**方法专属** Hook（支持 `"g"` 或 `"g()Lcas/c0;"` 精确重载签名，绝不劫持同名字段） */
  hookMethod(className: string, methods: Record<string, (...args: any[]) => any>): void;
  /** 列出全部已注册的 JNI Hook（含类别 `field`/`method`/`any` 与签名，便于排查命中问题） */
  listHooks(): JniRegisteredHookInfo[];
  onUnhandled(callback: (info: UnhandledJniInfo) => any): void;
  registeredNatives(): RegisteredNativeInfo[];
  /**
   * 调用通过 `RegisterNatives` 动态注册的 JNI 方法。
   * - 静态方法：不传 `opts.this`，`X1` 自动传 `jclass`；
   * - 实例方法：传 `{ this: objRef }`，`X1` 传入该实例 `jobject`（使 `GetObjectField(this, ...)` 正常读取实例字段）。
   */
  callNative(
    className: string,
    methodName: string,
    args?: Array<number | bigint>,
    opts?: { this?: number | bigint }
  ): number;
  /** 以指定实例 `objRef` 作为 `this` 调用已注册的 JNI 实例方法 */
  callNativeOn(
    objRef: number | bigint,
    className: string,
    methodName: string,
    args?: Array<number | bigint>
  ): number;
  findClass(className: string): number;
  newString(value: string): number;
  newByteArray(bytes: Uint8Array | number[]): number;
  /** 创建 `[C` (`jcharArray`, UTF-16) 对象 */
  newCharArray(input: string | Uint16Array | number[]): number;
  /** 创建 `[I` (`jintArray`) 对象 */
  newIntArray(input: Int32Array | number[]): number;
  /** 创建 `[J` (`jlongArray`) 对象 */
  newLongArray(input: BigInt64Array | Array<number | bigint>): number;
  newObject(className: string, fields?: Record<string, unknown>): number;
  newStringArray(items: string[]): number;
  getStringArray(ref: number | bigint): Array<string | null> | null;
  newObjectArray(refs: Array<number | bigint>): number;
  getObjectArray(ref: number | bigint): number[] | null;
  getString(ref: number | bigint): string | null;
  getBytes(ref: number | bigint): Uint8Array | null;
  /** 读取 `[C` (`jcharArray`, UTF-16) 内容（TypedArray 视图，支持在 Hook 回调内重入） */
  getChars(ref: number | bigint): Uint16Array | null;
  /** 读取 `[I` (`jintArray`) 内容（TypedArray 视图，支持在 Hook 回调内重入） */
  getInts(ref: number | bigint): Int32Array | null;
  /** 读取 `[J` (`jlongArray`) 内容（TypedArray 视图，支持在 Hook 回调内重入） */
  getLongs(ref: number | bigint): BigInt64Array | null;
  /** 读取 `[B` (`jbyteArray`) 为普通 `number[]`（无效/非数组句柄返回 `[]`，支持在 Hook 回调内重入） */
  getByteArray(ref: number | bigint): number[];
  /** 读取 `[I` (`jintArray`) 为普通 `number[]`（无效/非数组句柄返回 `[]`，支持在 Hook 回调内重入） */
  getIntArray(ref: number | bigint): number[];
  /** 读取 `[J` (`jlongArray`) 为普通 `number[]`（无效/非数组句柄返回 `[]`，支持在 Hook 回调内重入） */
  getLongArray(ref: number | bigint): number[];
  /** 读取 `[C` (`jcharArray`, UTF-16) 为 JS 字符串（无效/非数组句柄返回 `""`，支持在 Hook 回调内重入） */
  getCharArray(ref: number | bigint): string;
  /** 设置实例对象字段（支持基本类型、string、TypedArray、jobject 句柄及可选 JNI 签名 `sig`；支持在 Hook 回调内重入） */
  setField(objRef: number | bigint, fieldName: string, value: unknown, sig?: string): void;
  /** 查询实例对象字段：基本类型返回原值，对象/数组字段返回 `jobject` 句柄，未设置返回 `null`；支持在 Hook 回调内重入 */
  getField(objRef: number | bigint, fieldName: string): unknown;
  /** 设置类静态字段（支持基本类型、string、Uint8Array(`[B`)、Uint16Array(`[C`)、Int32Array(`[I`)、BigInt64Array(`[J`)、jobject 句柄及可选 JNI 签名 `sig`） */
  setStaticField(className: string, fieldName: string, value: unknown, sig?: string): void;
  /** 查询已设置的类静态字段：基本类型返回原值，对象/数组字段返回 `jobject` 句柄（配合 `getString`/`getBytes`/`getChars`/`getInts` 读取内容），未设置返回 `null` */
  getStaticField(className: string, fieldName: string): unknown;
  /** 开启/关闭 FindClass 严格存在性校验（开启且已加载 DEX 时，非系统类不存在返回 NULL 并抛出 ClassNotFoundException） */
  setStrictFindClass(enabled: boolean): void;
  /** 按 FieldID 反查所属类名、字段名、签名与是否静态（ID 仅在当前进程内有效；未知返回 `null`；支持在 Hook 回调内调用） */
  describeField(fieldId: number | bigint): JniFieldInfo | null;
  /** 列出本次运行内已 intern 的全部字段（含实例与静态字段） */
  listFields(): JniFieldInfo[];
  /** 按 MethodID 反查所属类名、方法名、签名与是否静态（ID 仅在当前进程内有效；未知返回 `null`；支持在 Hook 回调内调用） */
  describeMethod(methodId: number | bigint): JniMethodInfo | null;
  /** 列出本次运行内已 intern 的全部方法 */
  listMethods(): JniMethodInfo[];
  /** 按 `jobject` / `jclass` 句柄反查真实类名与对象类型（支持在 Hook 回调内调用；未知返回 `null`） */
  describeObject(ref: number | bigint): JniObjectInfo | null;
  /** 结构化 JNI 事件追踪与实时订阅（默认关闭，零开销，无需硬编码虚表槽位） */
  readonly trace: JniTraceNamespace;
  pushLocalFrame(): void;
  popLocalFrame(keepRef?: number | bigint): number;
  withLocalFrame<T>(fn: () => T): T;
  objectCount(): number;
}

interface HeapAllocInfo {
  readonly seq: number;
  readonly op: string;
  readonly ptr: number;
  readonly ptrHex: string;
  readonly size: number;
  readonly callerPc: number;
  readonly callerPcHex: string;
  readonly freed: boolean;
}

interface HeapLayoutInfo {
  readonly frozen: boolean;
  readonly heapBaseHex: string;
  readonly heapUsed: number;
  readonly heapHighWater: number;
  readonly totalAllocs: number;
  readonly allocations: HeapAllocInfo[];
}

interface MemNamespace {
  /** 分配内存（当 `freezeLayout` 开启时自动分配在独立 `[host-scratch]` 区，不扰动 guest 堆布局） */
  alloc(size: number): number;
  /** 强制在独立 `[host-scratch]` 区（0x6400_0000+）分配宿主临时缓冲，绝不影响 guest `malloc` 地址布局 */
  allocScratch(size: number): number;
  /** 动态切换是否将 `emu.mem.alloc()` 隔离到 `[host-scratch]` */
  setFreezeLayout(freeze: boolean): void;
  /** 查询当前堆布局指纹与关键 guest 分配点列表 */
  heapLayout(limit?: number): HeapLayoutInfo;
  free(addr: number | bigint): boolean;
  heapUsed(): number;
  readBytes(addr: number | bigint, len: number): Uint8Array;
  writeBytes(addr: number | bigint, bytes: Uint8Array): void;
  readCString(addr: number | bigint, maxLen?: number): string;
  writeCString(addr: number | bigint, str: string): number;
  readU32(addr: number | bigint): number;
  writeU32(addr: number | bigint, value: number): void;
  readU64(addr: number | bigint): bigint;
  writeU64(addr: number | bigint, value: number | bigint): void;
  scan(start: number | bigint, len: number, pattern: string): number[];
  patch(addr: number | bigint, bytes: Uint8Array): number;
  nop(addr: number | bigint, count?: number): number;
  ret(addr: number | bigint, retval?: number | bigint): number;
  /** 使用内置轻量 ARM64 汇编器 `good64` 将汇编文本编译为小端字节码（支持本地标签与 `;`/换行多指令） */
  asm(source: string, pc?: number | bigint | string): Uint8Array;
  /** Inline Hook PC 相对指令重定位：将 `oldPc` 处的机器码搬运到 `newPc`（自动重写 `B`/`BL`/`B.cond`/`CBZ`/`TBZ`/`ADR`/`ADRP`/`LDR literal` 与块内短分支） */
  relocateAsm(
    bytes: Uint8Array,
    oldPc: number | bigint | string,
    newPc: number | bigint | string
  ): Uint8Array;
  /** 在 `addr` 处使用 `good64` 现场汇编并写入 Guest 内存（自动刷新后端指令缓存），返回写入字节数 */
  patchAsm(addr: number | bigint | string, source: string): number;
  /** Inline Hook 跳转辅助：在 `fromAddr` 写入 4B 短跳 `B`（±128MB 内）或 16B 绝对跳板 `LDR X16, #8; BR X16; .quad target` */
  inlineJump(fromAddr: number | bigint | string, targetAddr: number | bigint | string): number;
}

interface VirtualNicConfig {
  name?: string;
  ipv4?: string;
  netmask?: string;
  gateway?: string;
  mac?: string;
  ipv6?: string;
}

interface NetOptions {
  enabled?: boolean;
  capture?: boolean;
  allowHosts?: string[];
  nic?: VirtualNicConfig;
}

interface CapturedPacket {
  fd: number;
  dir: "send" | "recv";
  peer: string;
  len: number;
  hex: string;
  text: string;
}

interface PacketHookEvent {
  fd: number;
  peer: string;
  data: Uint8Array;
  text: string;
}

interface NetNamespace {
  enable(options?: boolean | NetOptions): void;
  disable(): void;
  setNic(nic: VirtualNicConfig): void;
  nic(): Required<Omit<VirtualNicConfig, "netmask">>;
  packets(): CapturedPacket[];
  clearPackets(): void;
  onSend(callback: ((pkt: PacketHookEvent) => Uint8Array | string | void) | null): void;
  onRecv(callback: ((pkt: PacketHookEvent) => Uint8Array | string | void) | null): void;
}

interface VfsNamespace {
  setProperty(key: string, value: string): void;
  writeFile(guestPath: string, data: string | Uint8Array): void;
  readFile(guestPath: string): Uint8Array | null;
  mountOverlay(guestDir: string, hostDir: string): void;
  setTime(unixSecs: number): void;
  useRealClock(enabled?: boolean): void;
  setDevice(presetOrConfig: DevicePresetName | DeviceProfileConfig): void;
  deviceProfile(): Required<Omit<DeviceProfileConfig, "preset">>;
}

interface TraceNamespace {
  start(options?: TraceOptions): void;
  stop(): TraceStats;
}

interface DiagReport {
  missingFiles: Record<string, number>;
  missingProperties: Record<string, number>;
  missingSyscalls: Record<string, number>;
  missingJni: Record<string, number>;
  missingHle: Record<string, number>;
  missingJniFields: Record<string, number>;
  missingAuxv: Record<string, number>;
}

interface DiagNamespace {
  enable(): void;
  disable(): void;
  clear(): void;
  report(): DiagReport;
  generatePatchJs(): string;
}

interface ApkHandle {
  readonly packageName: string | null;
  readonly abi: string;
  readonly libs: string[];
  readonly assets: string[];
  readonly signatureSize: number;
  loadLib(libName: string, opts?: LoadOptions): ModuleHandle;
}

interface CrashReport {
  readonly reason: string;
  readonly pc: number;
  readonly pcHex: string;
  readonly pcLocation: string;
  readonly lr: number;
  readonly lrLocation: string;
  readonly sp: number;
  readonly fp: number;
  readonly disasm: Array<{ addr: string; word: string; asm: string; isPc: boolean }>;
  readonly backtrace: Array<{ index: number; addr: string; location: string }>;
  readonly breadcrumbs: string[];
  readonly formatted: string;
}

interface DexClassInfo {
  readonly name: string;
  readonly superClass: string | null;
  readonly interfaces: string[];
  readonly fields: Array<{ name: string; sig: string; isStatic: boolean }>;
  readonly methods: Array<{ name: string; sig: string; isDirect: boolean }>;
  readonly staticValues: Record<string, unknown>;
}

interface DexNamespace {
  classes(prefix?: string): string[];
  classInfo(className: string): DexClassInfo | null;
}

interface TapeCheckpointInfo {
  readonly index: number;
  readonly label: string;
  readonly timestampMs: number;
  readonly sourceBackend: string;
  readonly insnCount: number;
  readonly isDelta: boolean;
  readonly storedPages: number;
  readonly zeroedPages: number;
  readonly removedPages: number;
  readonly compressedBytes: number;
  readonly uncompressedBytes: number;
  readonly modules: string[];
}

interface TapeTimelineInfo {
  readonly startInsn: number;
  readonly endInsn: number;
  readonly keyframeInterval: number;
  readonly eventCount: number;
  readonly clockEvents: number;
  readonly jniEvents: number;
  readonly hookEvents: number;
  readonly hostFileCount: number;
  readonly bookmarks: Array<{ insn: number; label: string }>;
}

interface TapeSummary {
  readonly version: number;
  readonly fileSize: number;
  readonly checkpoints: TapeCheckpointInfo[];
  readonly timeline: TapeTimelineInfo | null;
}

interface RecordOptions {
  /** 自动插入增量关键帧的指令间隔（默认 100000） */
  keyframeInterval?: number;
  /** 最大录制指令数（0 表示不限） */
  maxInsns?: number;
  /** 是否捕获外部 JNI 回调实现离线脱离 JS 重放（默认 true） */
  captureJni?: boolean;
}

interface RecordNamespace {
  start(opts?: RecordOptions): void;
  bookmark(label: string): number;
  insns(): number;
  isRecording(): boolean;
  stop(path: string): TapeSummary;
}

interface TimeTravelStopInfo {
  readonly reason: "step" | "breakpoint" | "watchpoint" | "log_begin" | "log_end";
  readonly insn: number;
  readonly pc: number;
  readonly pcHex: string;
  readonly location: string;
  readonly watchAddr?: number;
  readonly watchAddrHex?: string;
  readonly watchAccessAddr?: number;
  readonly watchAccessAddrHex?: string;
  readonly watchSize?: number;
  readonly watchKind?: "write" | "read" | "access";
  readonly watchActualKind?: "write" | "read";
  readonly watchValue?: number;
  readonly watchValueHex?: string;
}

interface WatchHitInfo {
  readonly insn: number;
  readonly pc: number;
  readonly pcHex: string;
  readonly location: string;
  readonly addr: number;
  readonly addrHex: string;
  readonly size: number;
  readonly kind: "write" | "read" | "access";
  readonly actualKind: "write" | "read";
  readonly value: number;
  readonly valueHex: string;
}

interface TimeTravelHandle {
  readonly startInsn: number;
  readonly totalInsns: number;
  readonly keyframes: number;
  readonly bookmarks: Array<{ insn: number; label: string }>;
  readonly modules: Array<{ name: string; base: number; baseHex: string; size: number }>;
  currentInsn(): number;
  isLiveForked(): boolean;
  close(): boolean;
  seekInsn(insn: number): TimeTravelStopInfo;
  seekBookmark(label: string): TimeTravelStopInfo;
  stepForward(n?: number): TimeTravelStopInfo;
  stepBack(n?: number): TimeTravelStopInfo;
  findPrevWrite(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  findPrevRead(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  findPrevAccess(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  findNextWrite(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  findNextRead(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  findNextAccess(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  regs(): Record<string, number>;
  readonly mem: {
    readBytes(addr: number | bigint | string, len: number): Uint8Array;
    readU32(addr: number | bigint | string): number;
    readU64(addr: number | bigint | string): bigint;
    readCString(addr: number | bigint | string, maxLen?: number): string;
  };
  verifyDeterminism(): { verifiedKeyframes: number };
}

interface LoadTapeOptions {
  /** 恢复到哪个目标后端（支持跨后端接力，如从 Dynarmic/Hyper/KVM 磁带切入 `"unicorn"` 做 Trace/GDB） */
  backend?: EmuBackendKind;
  /** 指定检查点序号、书签名或 `"latest"`（默认最新检查点） */
  checkpoint?: number | string;
  /** 额外追加的依赖库搜索路径（会保留并与磁带原路径合并） */
  searchPaths?: string[];
  device?: DevicePresetName | DeviceProfileConfig;
  realClock?: boolean;
  net?: boolean | NetOptions;
  /** 可选覆盖磁带恢复后的 `freezeLayout` 状态 */
  freezeLayout?: boolean;
}

interface EmuHandle {
  /** 当前实例使用的规范化 CPU 执行后端名 */
  readonly backend: "unicorn" | "dynarmic" | "kvm" | "hypervisor";
  /** 是否支持 Trace 模式（仅 `"unicorn"` 为 true） */
  readonly supportsTrace: boolean;
  /** 是否支持 GDB 调试模式（仅 `"unicorn"` 为 true） */
  readonly supportsGdb: boolean;
  /** 若由 `Emu.loadTape()` 恢复，记录所加载的检查点摘要 */
  readonly tapeCheckpoint: TapeCheckpointInfo | null;
  load(path: string, opts?: LoadOptions): ModuleHandle;
  /** 列出当前已加载的全部 ELF 模块（含从 `.rtape` 磁带恢复的模块） */
  modules(): ModuleHandle[];
  /** 按模块名查找已加载模块（适用于从 `.rtape` 磁带恢复后直接取回符号表） */
  module(name: string): ModuleHandle | null;
  /** 加载单个 `.dex`、路径数组或包含 `classes*.dex` 的目录到轻量元数据索引并挂载到 VFS */
  loadDex(pathOrPaths: string | string[]): {
    classes: number;
    addedClasses: number;
    totalClasses: number;
    dexCount: number;
  };
  readonly dex: DexNamespace;
  loadApk(path: string): ApkHandle;
  jniOnLoad(mod: ModuleHandle): number | null;
  call(addr: number | bigint, ...args: Array<number | bigint>): number;
  stop(): void;
  lastCrash(): CrashReport | null;
  setLimits(limits?: { timeoutMs?: number; maxInstructions?: number }): void;
  readonly diag: DiagNamespace;
  readonly regs: RegsNamespace;
  readonly hook: HookNamespace;
  readonly jni: JniNamespace;
  readonly mem: MemNamespace;
  readonly vfs: VfsNamespace;
  readonly net: NetNamespace;
  readonly trace: TraceNamespace;
  snapshot(): number;
  restore(snapshotId: number): void;
  /** 将当前完整状态保存为 `.rtape` 磁盘磁带（首个全量稀疏基线检查点） */
  saveTape(path: string, label?: string): TapeSummary;
  /** 向已有 `.rtape` 磁带追加 4KB 脏页增量检查点（书签） */
  checkpointTape(path: string, label?: string): TapeCheckpointInfo;
  /** 将当前实例快进或倒带至 `.rtape` 磁带中的指定检查点（序号 / 书签名 / `"latest"`） */
  seekTape(path: string, checkpoint?: number | string): TapeCheckpointInfo;
  /** 二期指令级时间旅行录制控制器（仅 Unicorn 后端可用） */
  readonly record: RecordNamespace;
  /** 打印/查询当前 guest 堆布局指纹与关键分配点（`emu.mem.heapLayout()` 的便捷别名） */
  heapLayout(limit?: number): HeapLayoutInfo;
  /** 针对 OLLVM / 自定义字节码 VM 的在线实时辅助命名空间（寄存器堆跟踪 + 指令字解码） */
  readonly vm: VmNamespace;
}

interface VmWordLayout {
  /** opcode 位域 `[lsb, width]`（如 `[6, 6]` 表示 bits `[11:6]`） */
  op: [number, number];
  /** 操作数字段列表：传 `lsb` 自动按相邻间距推算位宽（末段默认 5 bit），或显式传 `[lsb, width]` */
  fields?: Array<number | [number, number]>;
}

interface VmDecodedWord {
  readonly raw: bigint;
  readonly rawHex: string;
  readonly op: number;
  readonly opBigInt: bigint;
  readonly opHex: string;
  readonly fields: number[];
  readonly fieldsBigInt: bigint[];
  readonly fieldsHex: string[];
  readonly text: string;
}

interface VmWatchRegfileOptions {
  /** VM 寄存器堆基址寄存器名（如 `"x25"`），自动追踪栈帧迁移导致的基址搬家 */
  baseReg: string;
  /** 虚拟寄存器数量（默认 32，范围 1..256） */
  count?: number;
  /** 每个虚拟寄存器字节宽（`4` 或 `8`，默认 `8`） */
  size?: 4 | 8;
  /** VM 调度点 PC 或 `[start, end]` 区间 */
  dispatcherPc?: number | bigint | [number | bigint, number | bigint];
  /** `dispatcherPc` 的简写别名 */
  pc?: number | bigint | [number | bigint, number | bigint];
  /** `dispatcherPc` 的区间别名 `[start, end]` */
  range?: [number | bigint, number | bigint];
  /** 可选：字节码指针寄存器名（如 `"x23"`，与 `bcPtrAddr` 互斥） */
  bcReg?: string;
  /** 若为 `true`，表示 `[bcReg]` 内存中存放字节码指针（须配合 `bcReg`） */
  bcDeref?: boolean;
  /** 可选：存放字节码指针的固定内存地址（与 `bcReg` 互斥） */
  bcPtrAddr?: number | bigint;
  /** 从字节码指针读取指令字的宽度（`1` / `2` / `4` / `8`，默认 `4`） */
  wordSize?: 1 | 2 | 4 | 8;
  /** 可选：字节码指令字位域解码器 */
  layout?: VmWordLayout;
  /** 内存中最多保留的事件步数（默认 10000，>= 1） */
  maxSteps?: number;
  /** 可选：每步实时回调（注意：回调触发时尚未进入下一步，因此 `ev.bcStep` 在回调内为 `null`，下一步执行后回填） */
  onStep?: (ev: VmWatchStepEvent) => void;
}

interface VmWatchRegDiff {
  readonly reg: number;
  readonly name: string;
  readonly oldVal: bigint;
  readonly newVal: bigint;
  readonly oldHex: string;
  readonly newHex: string;
}

interface VmWatchStepEvent {
  readonly step: number;
  readonly pc: number;
  readonly pcHex: string;
  readonly base: bigint;
  readonly baseHex: string;
  readonly prevBase: bigint | null;
  readonly baseRelocated: boolean;
  readonly bcPc: bigint | null;
  readonly bcPcHex: string | null;
  bcStep: number | null;
  readonly rawWord: bigint | null;
  readonly rawWordHex: string | null;
  readonly op: number | null;
  readonly opHex: string | null;
  readonly fields: number[] | null;
  readonly fieldsHex: string[] | null;
  readonly decodedText: string | null;
  readonly diffs: VmWatchRegDiff[];
}

interface VmWatchHandle extends HookHandle {
  events(): VmWatchStepEvent[];
  stats(): Array<{ readonly op: number; readonly opHex: string; readonly hits: number; readonly stepHist: Record<string, number> }>;
  format(limit?: number): string;
}

interface VmNamespace {
  /** 按位域布局解码单条字节码指令字，返回 `{ op, fields, text }`（如 `"op=49 f=[1,5,0,7]"`） */
  decodeWord(word: number | bigint, layout: VmWordLayout): VmDecodedWord;
  /** 挂载在线 VM 寄存器堆跟踪器，自动输出 `R[n]: old->new` 符号差分、字节码消费步长与基址搬家事件 */
  watchRegfile(opts: VmWatchRegfileOptions): VmWatchHandle;
}

interface VmAnalyzeOptions {
  /** 手动指定调度点 PC（省略时自动检测最高分热 `BR`/`BLR` 调度循环） */
  dispatcherPc?: number | bigint;
  /** 手动指定字节码指针寄存器（如 `"x23"`；省略时自动推断） */
  bcReg?: string;
  /** 若为 `true`，表示 `[bcReg]` 内存中存放字节码指针 */
  bcDeref?: boolean;
  /** 可选：直接指定存放字节码指针的内存地址 */
  bcPtrAddr?: number | bigint;
  /** 可选：虚拟寄存器堆基址寄存器名（如 `"x25"`），开启离线 `R[n]` 符号差分与基址搬家追踪 */
  baseReg?: string;
  /** 虚拟寄存器数量（默认 32，范围 1..256） */
  regCount?: number;
  /** 单个虚拟寄存器字节宽（`4` 或 `8`，默认 `8`） */
  regSize?: 4 | 8;
  /** 字节码指令字位域布局（对象或字符串如 `"6:6,12:5,17:5,22:5,27:5"`） */
  layout?: VmWordLayout | string;
  /** 自动识别调度点所需最少唯一 Handler 数（默认 3） */
  minHandlers?: number;
  /** 自动识别调度点所需最少分发次数（默认 4） */
  minDispatches?: number;
  /** 可选：起始指令下标（含；等价 `--seq-range <start>..<end>`） */
  minIdx?: number;
  /** 可选：结束指令下标（含；等价 `--seq-range <start>..<end>`） */
  maxIdx?: number;
  /** 最大扫描原生指令数（0 = 全部） */
  maxInsns?: number;
  /** 返回轨迹最多保留的 VM 步数（默认 256，`0` 表示不限） */
  maxSteps?: number;
  /** 模块基址（用于 `summaryText` 中输出 `+0x...` 相对偏移） */
  baseAddr?: number | bigint;
}

interface VmAnalysisReport {
  readonly scannedInsns: number;
  readonly totalVmSteps: number;
  readonly selectedDispatcher: number | null;
  readonly selectedDispatcherHex: string | null;
  readonly detectedBcReg: string | null;
  readonly detectedBcMemAddr: number | null;
  readonly detectedBcMemAddrHex: string | null;
  readonly dispatchers: Array<{
    readonly pc: number;
    readonly pcHex: string;
    readonly kind: "br" | "blr";
    readonly targetReg: string;
    readonly totalDispatches: number;
    readonly uniqueHandlers: number;
    readonly score: number;
    readonly jumpTableBase?: number;
    readonly jumpTableBaseHex?: string;
    readonly jumpTableEntrySize?: number;
    readonly detectedBcReg?: string;
    readonly detectedBcMemAddrHex?: string;
  }>;
  readonly handlers: Array<{
    readonly handlerPc: number;
    readonly handlerPcHex: string;
    readonly opcodes: number[];
    readonly opcodeHexes: string[];
    readonly hitCount: number;
    readonly minArm64Insns: number;
    readonly maxArm64Insns: number;
    readonly avgArm64Insns: number;
    readonly firstStep: number;
    readonly firstTraceIdx: number;
    readonly bcStepHist: Record<string, number>;
  }>;
  readonly steps: Array<{
    readonly step: number;
    readonly traceIdx: number;
    readonly seq: number;
    readonly dispatcherPcHex: string;
    readonly handlerPc: number;
    readonly handlerPcHex: string;
    readonly arm64Insns: number;
    readonly bcPc?: number;
    readonly bcPcHex?: string;
    readonly bcStep?: number;
    readonly rawWord?: number;
    readonly rawWordHex?: string;
    readonly op?: number;
    readonly opHex?: string;
    readonly fields?: number[];
    readonly fieldsHex?: string[];
    readonly decodedText?: string;
    readonly regfileBaseHex?: string;
    readonly baseRelocated: boolean;
    readonly regDiffs: Array<{
      readonly reg: number;
      readonly name: string;
      readonly oldHex: string | null;
      readonly newHex: string;
      readonly text: string;
    }>;
  }>;
  readonly summaryText: string;
}

interface TraceQueryOptions {
  /** 按写入值查询（配合 `width` 1..8 字节） */
  value?: number | bigint | string;
  /** 值匹配字节宽度（默认 `value > 0xFFFFFFFF` 时为 8，否则为 4；范围 1..8） */
  width?: number;
  /** `width` 的别名 */
  align?: number;
  /** 按目标内存地址查询读写及 HLE 访问历史 */
  addr?: number | bigint | string;
  /** 按地址查询时的字节长度（默认 1） */
  len?: number;
  /** 按地址查询时是否仅返回写事件与 HLE 变更事件（默认 false） */
  writesOnly?: boolean;
  /** 按地址查询时的事件类型过滤：`"r"` 仅读、`"w"` 仅写、`"rw"` 读写全部（默认 `"rw"`） */
  kind?: "r" | "w" | "rw";
  /** 按地址查询时是否包含 HLE 事件（默认 true） */
  includeHle?: boolean;
  /** 仅返回序号 >= `minSeq` 的事件 */
  minSeq?: number;
  /** 仅返回序号 <= `maxSeq` 的事件 */
  maxSeq?: number;
  /** 仅返回序号 <= `at` 的事件（等同于 `maxSeq`） */
  at?: number;
  /** 返回最大条数（默认 200） */
  limit?: number;
}

interface TraceQueryHit {
  readonly seq: number;
  readonly pc: number;
  readonly pcHex: string;
  readonly addr: number;
  readonly addrHex: string;
  readonly size: number;
  readonly kind: string;
  readonly value: number;
  /** 64 位无损 BigInt 值（与 `ctx.reg64` 精度一致） */
  readonly value64: bigint;
  readonly valueHex: string;
  /** 仅 `hle_memcpy` / `hle_memmove` / `hle_realloc_copy` 事件存在源地址 */
  readonly src?: number;
  readonly srcHex?: string;
}

interface TraceHleEvent {
  readonly seq: number;
  readonly op: string;
  readonly pc: number;
  readonly pcHex: string;
  readonly dst: number;
  readonly dstHex: string;
  readonly src: number;
  readonly srcHex: string;
  readonly len: number;
}

interface TraceDiffEntry {
  readonly idx: number;
  readonly kind: "control" | "reg" | "mem" | "hle" | "length";
  readonly pcA: number;
  readonly pcAHex: string;
  readonly pcB: number;
  readonly pcBHex: string;
  readonly detail: string;
}

interface TraceDiffSummary {
  readonly totalA: number;
  readonly totalB: number;
  readonly commonPrefixInsns: number;
  readonly firstControlDivergenceIdx: number | null;
  readonly firstDataDivergenceIdx: number | null;
  readonly diffs: TraceDiffEntry[];
}

interface TraceReconstructResult {
  readonly addrHex: string;
  readonly atSeq: number;
  readonly knownBytes: number;
  readonly hex: string;
  readonly bytes: Uint8Array;
}

interface TraceTaintOptions {
  /** 内存种子/目标起始地址（与 `reg` 二选一） */
  addr?: number | bigint;
  /** 内存种子/目标字节长度（默认 8） */
  len?: number;
  /** 寄存器种子/目标名（如 `"x0"`, `"w8"`, `"v0"`, `"q1"`；与 `addr` 二选一） */
  reg?: string;
  /** Forward 模式：起始指令下标（默认 0）；Backward 模式：目标观测点指令下标（默认末条指令） */
  atIdx?: number;
  /** `atIdx` 的前向语义别名 */
  startIdx?: number;
  /** Backward 模式下切片起点下界（含该指令；精准截断到单轮循环或子阶段） */
  fromIdx?: number;
  /** Backward 模式下命中这些 PC 时停止回溯，把边界状态提升为输入起源 */
  stopAtPcs?: Array<number | bigint | string>;
  /** Backward 模式下遇到读取这些内存区间时直接钉死为输入起源 */
  stopMem?: Array<{ addr: number | bigint | string; len?: number }>;
  /** 最大扫描指令数（0 表示扫描全部） */
  maxInsns?: number;
  /** 返回报告最多保留的步骤条数（默认 512） */
  maxSteps?: number;
  /** 是否追踪变址寄存器（如 S-Box 查表 `LDRB Wd, [Xtable, Xidx]` 中的 `Xidx`，默认 true） */
  trackMemIndex?: boolean;
  /** 是否追踪栈指针 `SP` 本身（默认 false） */
  trackSp?: boolean;
}

interface TraceTaintStep {
  readonly idx: number;
  readonly seq: number;
  readonly pc: number;
  readonly pcHex: string;
  readonly asm: string;
  readonly kind: "load" | "store" | "alu" | "rmw" | "const" | "hle_copy" | "hle_clear" | "hle_ret" | "hle_origin";
  readonly sources: string[];
  readonly dests: string[];
  readonly tagMaskHex: string;
  readonly value?: number;
  readonly valueHex?: string;
}

interface TraceTaintReport {
  readonly mode: "forward" | "backward";
  readonly seed: string;
  readonly anchorIdx: number;
  readonly stopIdx: number;
  readonly scannedInsns: number;
  readonly totalMatchingSteps: number;
  readonly originAnnotations: string[];
  readonly steps: TraceTaintStep[];
  readonly taintedRegs: Array<{ readonly name: string; readonly tagMaskHex: string }>;
  readonly taintedMemRanges: Array<{
    readonly addr: number;
    readonly addrHex: string;
    readonly len: number;
    readonly tagMaskHex: string;
  }>;
}

interface TraceDecompileOptions {
  /** 目标观测内存地址（与 `reg` 二选一） */
  addr?: number | bigint | string;
  /** 目标内存宽度（1..=64 字节，1..=8 返回标量，9..=64 联合反编译为 `void fn(..., uint8_t *out)`；默认 4） */
  len?: number;
  /** 目标观测寄存器名（如 `"x0"`, `"w0"`；与 `addr` 二选一） */
  reg?: string;
  /** 观测点指令下标（默认末条指令） */
  atIdx?: number;
  /** 切片起点下界（含该指令；将单轮循环/子阶段入口状态直接提升为符号参数） */
  fromIdx?: number;
  /** 命中这些 PC 时停止回溯并提升边界寄存器/内存为输入参数 */
  stopAtPcs?: Array<number | bigint | string>;
  /** 遇到读取这些内存区间时直接钉死为输入参数 */
  stopMem?: Array<{ addr: number | bigint | string; len?: number }>;
  /** 将整个 Trace 中从未被写过的只读内存（如 `.rodata` / VM 字节码）折叠为常量（默认 false） */
  foldRodata?: boolean;
  /** 最大扫描指令数（0 表示全部） */
  maxInsns?: number;
  /** 最大切片步数（默认 4096） */
  maxSteps?: number;
  /** 是否追踪访存变址/S-Box 查表（默认 true） */
  trackMemIndex?: boolean;
  /** 是否追踪 SP（默认 false） */
  trackSp?: boolean;
  /** 生成的 C 函数名称（默认 `"decompiled_slice"`） */
  functionName?: string;
  /** 是否启用代数/旋转/MBA/字节重装化简（默认 true） */
  simplify?: boolean;
  /** 是否额外导出标准 `QF_BV` / `QF_UFBV` SMT-LIB2 文本（默认 false） */
  emitSmt2?: boolean;
  /** 可选初始寄存器具体值映射（如 `{ x0: 0x1234, x1: 0x5678 }`），用于启用寄存器参数的数值自校验 */
  initialRegs?: Record<string, number | bigint | string>;
}

interface TraceDecompileReport {
  readonly seed: string;
  readonly anchorIdx: number;
  readonly stopIdx: number;
  readonly scannedInsns: number;
  readonly sliceInsns: number;
  readonly rawNodes: number;
  readonly simplifiedNodes: number;
  readonly originAnnotations: string[];
  readonly outputLen: number;
  readonly expectedOutputHex?: string;
  readonly evaluatedOutputHex?: string;
  readonly expectedOutputBytesHex?: string;
  readonly evaluatedOutputBytesHex?: string;
  readonly verified: boolean | null;
  readonly cCode: string;
  readonly smt2: string | null;
  readonly inputs: Array<{
    readonly name: string;
    readonly kind: "reg" | "mem" | "hle_source";
    readonly addrHex?: string;
    readonly widthBytes: number;
    readonly sampleHex?: string;
  }>;
  readonly tables: Array<{
    readonly name: string;
    readonly baseAddrHex: string;
    readonly elemBytes: number;
    readonly observedCount: number;
  }>;
}

interface TraceDiffTaintSpan {
  readonly offset: number;
  readonly addrHex: string;
  readonly len: number;
  readonly bytesAHex: string;
  readonly bytesBHex: string;
  readonly originsARegs: string[];
  readonly originsAMem: string[];
  readonly originsAHle: string[];
  readonly originsBRegs: string[];
  readonly originsBMem: string[];
  readonly originsBHle: string[];
}

interface TraceDiffTaintReport {
  readonly targetAddrHex: string;
  readonly len: number;
  readonly identicalBytes: number;
  readonly differingBytes: number;
  readonly spans: TraceDiffTaintSpan[];
  readonly summaryText: string;
}

interface TraceArchivePackOptions {
  /** 显式指定伴生 `.ext` 路径（省略则自动探测同级 `.ext`；与 `noExt: true` 互斥） */
  extPath?: string;
  /** 仅打包 `.idx` 忽略同级 `.ext`（默认 false） */
  noExt?: boolean;
  /** 可选模块加载基址（写入文件头供离线分析自动复用） */
  baseAddr?: number | bigint | string;
  /** 可选 UTF-8 备注文本 */
  note?: string;
  /** 压缩等级 `0..=9`（`0` 不压缩直接存储，默认 `6`） */
  level?: number;
}

interface TraceArchiveInfo {
  readonly version: number;
  readonly hasExt: boolean;
  readonly compressed: boolean;
  readonly baseAddr: number;
  readonly baseAddrHex: string;
  readonly idxInsns: number;
  readonly idxRawLen: number;
  readonly idxCompLen: number;
  readonly idxCrc32Hex: string;
  readonly extEvents: number;
  readonly extRawLen: number;
  readonly extCompLen: number;
  readonly extCrc32Hex: string;
  readonly archiveFileLen: number;
  readonly ratioPercent: number;
  readonly recordedLevel: "fast" | "reg_delta" | "full" | null;
  readonly note: string | null;
  readonly summaryText: string;
  readonly outPath?: string;
}

interface TraceArchiveUnpackOptions {
  /** 可选输出文件名前缀（默认取 `.rtrace` 文件名主干） */
  stem?: string;
  /** 目标 `.idx`/`.ext` 已存在时是否允许覆盖（默认 false） */
  overwrite?: boolean;
}

interface TraceArchiveUnpackResult {
  readonly idxPath: string;
  readonly extPath: string | null;
  readonly info: TraceArchiveInfo;
}

interface TraceReaderHandle {
  readonly totalInsns: number;
  readonly totalExt: number;
  /** 若 `.idx` 录制于 `full` 级别但缺失同级 `.ext` 文件则为 `true` */
  readonly missingExtWarning: boolean;
  /** 录制级别（`"fast"` | `"reg_delta"` | `"full"` | `null`） */
  readonly recordedLevel: "fast" | "reg_delta" | "full" | null;
  /** 是否打开自单文件压缩 `.rtrace` 归档 */
  readonly isArchive: boolean;
  /** 若 `.rtrace` 归档内记录了模块基址则给出十六进制地址，否则 `null` */
  readonly archiveBaseAddrHex: string | null;
  /** 离线全知内存/值查询（内置替代手写 numpy 扫描 `.idx`/`.ext`） */
  query(opts: TraceQueryOptions): TraceQueryHit[];
  /** 值溯源便捷别名：查找所有写入过 `value` 的 guest 指令与 HLE 拷贝事件 */
  findWrites(
    value: number | bigint | string,
    opts?: Omit<TraceQueryOptions, "value" | "addr" | "len" | "writesOnly" | "kind" | "includeHle">
  ): TraceQueryHit[];
  /** 地址溯源便捷别名：查找访问 `addr` 的读写及 HLE 历史事件（默认 `writesOnly: false`） */
  findReads(
    addr: number | bigint | string,
    opts?: Omit<TraceQueryOptions, "value" | "addr" | "width" | "align">
  ): TraceQueryHit[];
  /** 通用内存访存查询（支持 `kind: "r" | "w" | "rw"`, `len`, `minSeq`, `maxSeq`, `includeHle`） */
  findMem(
    addr: number | bigint | string,
    opts?: Omit<TraceQueryOptions, "value" | "addr" | "width" | "align">
  ): TraceQueryHit[];
  /** 读取 trace.ext 中的全部 HLE 事件（memcpy / memmove / memset / malloc / calloc / realloc / free / rand / gettimeofday 等） */
  hleEvents(limit?: number): TraceHleEvent[];
  /** 基于 trace.ext 写历史 + HLE 拷贝/填充事件重建指定 `atSeq`（省略则重建至末尾）时刻的内存区间内容 */
  reconstructMem(addr: number | bigint | string, len: number, atSeq?: number): TraceReconstructResult;
  /** 离线前向污点传播：从输入内存/寄存器出发，沿 ARM64 指令与 HLE memcpy 追踪污点流向（自动清除被覆写旧地址，免疫栈/VM 地址复用） */
  taintForward(opts: TraceTaintOptions): TraceTaintReport;
  /** 离线反向因果切片：从输出字节/寄存器倒推精确的指令与 HLE 计算链，直达输入起源 */
  taintBackward(opts: TraceTaintOptions): TraceTaintReport;
  /** 动态污点切片 → 单路径符号提升 → 代数/MBA/字节重装化简 → 自校验精简伪 C（及可选 SMT-LIB2） */
  decompileSlice(opts: TraceDecompileOptions): TraceDecompileReport;
  /** `decompileSlice` 的便捷别名 */
  taintToC(opts: TraceDecompileOptions): TraceDecompileReport;
  /** 离线 VM 专项分析：自动识别调度循环与跳转表、统计 Handler 分布与字节码消费步长、按位域解码指令字并输出虚拟寄存器堆符号差分 */
  vmAnalyze(opts?: VmAnalyzeOptions): VmAnalysisReport;
  close(): boolean;
}

declare namespace Trace {
  /** 打开离线 `trace.idx`（自动关联同目录同名 `.ext`，或手动传 `extPath`）或单文件压缩 `.rtrace` 归档 */
  function open(idxPath: string, extPath?: string | null): TraceReaderHandle;
  /** 双跑 Trace 差分（支持 `.idx` 与 `.rtrace`）：定位首次控制流分歧与首次寄存器/内存/HLE 数据分歧 */
  function diff(idxA: string, idxB: string, maxDiffs?: number): TraceDiffSummary;
  /** 双跑差分 + 自动反向污点联动（支持 `.idx` 与 `.rtrace`）：比对目标缓冲区差异字节段并分别反向溯源 */
  function diffTaint(
    idxA: string,
    idxB: string,
    addr: number | bigint | string,
    len?: number,
    maxInsns?: number
  ): TraceDiffTaintReport;
  /** 将 `trace.idx`（及伴生 `.ext`）裁剪零填充并压缩打包为单文件 `.rtrace` 归档 */
  function pack(
    idxPath: string,
    outPath?: string | null,
    opts?: TraceArchivePackOptions
  ): TraceArchiveInfo;
  /** 快速查看 `.rtrace` 文件头与元信息（不解压指令载荷） */
  function inspectArchive(rtracePath: string): TraceArchiveInfo;
  /** 将 `.rtrace` 归档校验 CRC32 后解包还原为 `.idx`（及 `.ext`） */
  function unpack(
    rtracePath: string,
    outDir?: string | null,
    opts?: TraceArchiveUnpackOptions
  ): TraceArchiveUnpackResult;
}

declare namespace Emu {
  /** 返回当前构建在当前操作系统上默认编译启用的执行后端列表 */
  function backends(): Array<"unicorn" | "dynarmic" | "kvm" | "hypervisor">;
  /** 使用内置轻量 ARM64 汇编器 `good64` 将汇编文本编译为小端字节码（不依赖仿真实例） */
  function asm(source: string, pc?: number | bigint | string): Uint8Array;
  /** 使用 `good64` 重定位器将 `oldPc` 处的 ARM64 机器码搬运到 `newPc`（超距自动展开为安全跳板/地址加载，支持块内分支重映射） */
  function relocateAsm(
    bytes: Uint8Array,
    oldPc: number | bigint | string,
    newPc: number | bigint | string
  ): Uint8Array;
  function create(options?: EmuOptions): EmuHandle;
  /** 从 `.rtape` 磁盘磁带直接拉起实例（支持跨进程秒启与跨后端接力） */
  function loadTape(path: string, options?: LoadTapeOptions): EmuHandle;
  /** 读取 `.rtape` 磁带文件摘要与全部检查点时间线 */
  function inspectTape(path: string): TapeSummary;
  /** 打开含二期时间旅行事件日志的 `.rtape` 磁带，进行指令级 seek / 单步回退 / 反向内存观察点追踪 */
  function openTimeTravel(path: string): TimeTravelHandle;
}
