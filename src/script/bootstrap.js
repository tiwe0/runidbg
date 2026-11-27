// runidbg QuickJS V1 + V2 Bootstrap — wraps Rust `__native` bridge into ergonomic JS APIs

(function (global) {
  function toAddr(v) {
    if (typeof v === "bigint") return Number(v);
    if (typeof v === "number") return v;
    throw new TypeError("Expected number or bigint address/argument, got " + typeof v);
  }

  function formatArg(v) {
    if (v instanceof Uint8Array) {
      return "Uint8Array(" + v.length + ") [" + hex(v.slice(0, 16)) + (v.length > 16 ? "..." : "") + "]";
    }
    if (typeof v === "bigint") return v.toString() + "n";
    if (typeof v === "object" && v !== null) {
      try {
        return JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() + "n" : x));
      } catch (_) {
        return String(v);
      }
    }
    return String(v);
  }

  global.hex = function hex(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError("hex() expects a Uint8Array");
    }
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      out += (b < 16 ? "0" : "") + b.toString(16);
    }
    return out;
  };

  global.console = {
    log(...vals) {
      __native.print("log", vals.map(formatArg).join(" "));
    },
    warn(...vals) {
      __native.print("warn", vals.map(formatArg).join(" "));
    },
    error(...vals) {
      __native.print("error", vals.map(formatArg).join(" "));
    },
  };

  // V2: Host filesystem helpers
  global.fs = {
    readBytes(path) {
      return __native.fsReadBytes(String(path));
    },
    readText(path) {
      return __native.fsReadText(String(path));
    },
    writeBytes(path, bytes) {
      if (!(bytes instanceof Uint8Array)) {
        throw new TypeError("fs.writeBytes expects a Uint8Array");
      }
      __native.fsWriteBytes(String(path), bytes);
    },
    writeText(path, text) {
      __native.fsWriteText(String(path), String(text));
    },
    exists(path) {
      return __native.fsExists(String(path));
    },
  };

  // V2: CommonJS require()
  global.require = function require(specifier) {
    return __native.requireModule(String(specifier));
  };

  // RPC: Frida-style rpc.exports registry & JSON bridge helpers
  global.rpc = { exports: {} };

  function toJsonSafe(val) {
    if (val instanceof Uint8Array) {
      return { __type: "bytes", hex: hex(val), length: val.length };
    }
    if (typeof val === "bigint") {
      return val.toString();
    }
    return val;
  }

  function safeStringify(val) {
    if (val === undefined) return "null";
    return JSON.stringify(val, (_, v) => toJsonSafe(v));
  }

  global.__rpcList = function __rpcList() {
    const exp = global.rpc && global.rpc.exports;
    if (!exp || typeof exp !== "object") return "[]";
    const names = Object.keys(exp).filter((k) => typeof exp[k] === "function");
    names.sort();
    return JSON.stringify(names);
  };

  global.__asyncSlot = { state: "idle", json: "null", err: null };

  function settleOrWrap(ret) {
    if (ret && typeof ret.then === "function") {
      global.__asyncSlot = { state: "pending", json: "null", err: null };
      ret.then(
        (v) => {
          try {
            global.__asyncSlot = { state: "ok", json: safeStringify(v), err: null };
          } catch (e) {
            global.__asyncSlot = { state: "err", json: "null", err: String(e) };
          }
        },
        (e) => {
          global.__asyncSlot = {
            state: "err",
            json: "null",
            err: e && e.stack ? String(e.message || e) + "\n" + e.stack : String(e),
          };
        }
      );
      return "__PENDING__";
    }
    return safeStringify(ret);
  }

  global.__rpcCall = function __rpcCall(method, paramsJson) {
    const exp = global.rpc && global.rpc.exports;
    if (!exp || typeof exp[method] !== "function") {
      throw new Error("RPC method not found: " + method);
    }
    const parsed = paramsJson ? JSON.parse(paramsJson) : [];
    const callArgs = Array.isArray(parsed) ? parsed : [parsed];
    return settleOrWrap(exp[method](...callArgs));
  };

  global.__evalToJson = function __evalToJson(code) {
    return settleOrWrap((0, eval)(code));
  };

  // Per-emu MemNamespace registry so CpuContext.mem can reuse it with zero allocation
  const emuMemMap = new Map();

  // Build shared prototype for V2 CpuContext (x0..x30, sp, pc, lr, fp, nzcv, retval)
  const cpuCtxProto = {
    reg(name) {
      return __native.regGet(this._emuId, String(name));
    },
    regBigInt(name) {
      return __native.regGetBigInt(this._emuId, String(name));
    },
    reg64(name) {
      return __native.regGetBigInt(this._emuId, String(name));
    },
    setReg(name, val) {
      __native.regSet(this._emuId, String(name), val);
    },
    args(n = 8) {
      const count = Math.min(Math.max(Number(n) | 0, 0), 8);
      const out = new Array(count);
      for (let i = 0; i < count; i++) {
        out[i] = __native.regGet(this._emuId, "x" + i);
      }
      return out;
    },
    stop() {
      __native.emuStop(this._emuId);
    },
    get mem() {
      return emuMemMap.get(this._emuId);
    },
    get retval() {
      return __native.regGet(this._emuId, "x0");
    },
    set retval(val) {
      __native.regSet(this._emuId, "x0", val);
    },
  };

  const regProps = ["sp", "pc", "lr", "fp", "nzcv"];
  for (let i = 0; i <= 30; i++) regProps.push("x" + i);
  for (const name of regProps) {
    Object.defineProperty(cpuCtxProto, name, {
      enumerable: true,
      get() {
        return __native.regGet(this._emuId, name);
      },
      set(val) {
        __native.regSet(this._emuId, name, val);
      },
    });
  }

  global.__makeCpuCtx = function __makeCpuCtx(emuId) {
    const ctx = Object.create(cpuCtxProto);
    ctx._emuId = emuId;
    return ctx;
  };

  function makeHookHandle(emuId, hookId) {
    let detached = false;
    return {
      id: hookId,
      detach() {
        if (detached) return false;
        detached = true;
        return __native.hookDetach(emuId, hookId);
      },
    };
  }

  function makeModule(emuId, info) {
    const modId = info.id;
    return {
      name: info.name,
      base: info.base,
      size: info.size,
      symbol(name) {
        const addr = __native.modSymbol(emuId, modId, String(name));
        return addr === 0 ? null : addr;
      },
      exports() {
        return __native.modExports(emuId, modId);
      },
      call(symOrAddr, ...callArgs) {
        const rawArgs = callArgs.map(toAddr);
        if (typeof symOrAddr === "string") {
          return __native.modCallSymbol(emuId, modId, symOrAddr, rawArgs);
        }
        return __native.emuCallAddr(emuId, toAddr(symOrAddr), rawArgs);
      },
      runInit() {
        __native.modRunInit(emuId, modId);
      },
      _id: modId,
    };
  }

  function normalizeTapeCheckpoint(cp) {
    if (cp === undefined || cp === null) return null;
    if (typeof cp === "number") {
      if (!Number.isInteger(cp) || cp < 0) {
        throw new RangeError(`无效的磁带检查点索引: ${cp}（必须为非负整数）`);
      }
      return `idx:${cp}`;
    }
    if (typeof cp === "string") {
      if (cp.length === 0) {
        throw new RangeError("磁带检查点书签名不能为空字符串（如需最新检查点请省略参数或传 'latest'）");
      }
      if (cp.toLowerCase() === "latest") return "latest";
      return `label:${cp}`;
    }
    throw new TypeError(`无效的磁带检查点类型: ${typeof cp}（期望 number 或 string）`);
  }

  function buildEmuHandle(emuId, opts = {}, tapeCheckpoint = null) {
      const backend = __native.emuBackend(emuId);
      const supportsTrace = backend === "unicorn";
      const supportsGdb = backend === "unicorn";
      let currentTapeCheckpoint = tapeCheckpoint;

      const memNs = {
        alloc(size) {
          return __native.memAlloc(emuId, Number(size));
        },
        allocScratch(size) {
          return __native.memAllocScratch(emuId, Number(size));
        },
        setFreezeLayout(enabled) {
          __native.memSetFreezeLayout(emuId, Boolean(enabled));
        },
        heapLayout(limit = 512) {
          return __native.memHeapLayout(emuId, Number(limit));
        },
        readBytes(addr, len) {
          return __native.memReadBytes(emuId, addr, Number(len));
        },
        writeBytes(addr, bytes) {
          if (!(bytes instanceof Uint8Array)) {
            throw new TypeError("mem.writeBytes expects a Uint8Array");
          }
          __native.memWriteBytes(emuId, toAddr(addr), bytes);
        },
        readCString(addr, maxLen = 4096) {
          return __native.memReadCString(emuId, toAddr(addr), Number(maxLen));
        },
        writeCString(addr, str) {
          return __native.memWriteCString(emuId, toAddr(addr), String(str));
        },
        readU32(addr) {
          return __native.memReadU32(emuId, toAddr(addr));
        },
        writeU32(addr, val) {
          __native.memWriteU32(emuId, toAddr(addr), Number(val) >>> 0);
        },
        readU64(addr) {
          return __native.memReadU64(emuId, toAddr(addr));
        },
        writeU64(addr, val) {
          __native.memWriteU64(emuId, toAddr(addr), BigInt(val));
        },
        // V2: scan & patch
        scan(start, len, pattern) {
          return __native.memScan(emuId, toAddr(start), Number(len), String(pattern));
        },
        patch(addr, bytes) {
          if (!(bytes instanceof Uint8Array)) {
            throw new TypeError("mem.patch expects a Uint8Array");
          }
          return __native.memPatch(emuId, toAddr(addr), bytes);
        },
        nop(addr, count = 1) {
          return __native.memNop(emuId, toAddr(addr), Number(count));
        },
        ret(addr, retval) {
          const hasVal = retval !== undefined;
          return __native.memRet(emuId, toAddr(addr), hasVal, hasVal ? retval : 0);
        },
        asm(source, pc = 0) {
          return __native.asmEncode(String(source), pc);
        },
        relocateAsm(bytes, oldPc, newPc) {
          if (!(bytes instanceof Uint8Array)) {
            throw new TypeError("mem.relocateAsm expects a Uint8Array");
          }
          return __native.asmRelocate(bytes, oldPc, newPc);
        },
        patchAsm(addr, source) {
          return __native.memPatchAsm(emuId, addr, String(source));
        },
        inlineJump(fromAddr, targetAddr) {
          return __native.memInlineJump(emuId, fromAddr, targetAddr);
        },
        free(addr) {
          return __native.memFree(emuId, toAddr(addr));
        },
        heapUsed() {
          return __native.memHeapUsed(emuId);
        },
      };
      emuMemMap.set(emuId, memNs);
      if (opts.device !== undefined) {
        __native.vfsSetDevice(emuId, opts.device);
      }
      if (opts.freezeLayout !== undefined) {
        __native.memSetFreezeLayout(emuId, Boolean(opts.freezeLayout));
      } else if (__native.isDefaultFreezeLayout()) {
        __native.memSetFreezeLayout(emuId, true);
      }
      if (opts.realClock !== undefined) {
        __native.vfsUseRealClock(emuId, Boolean(opts.realClock));
      }
      if (opts.net !== undefined) {
        __native.netConfigure(emuId, opts.net);
      }

      return {
        backend,
        supportsTrace,
        supportsGdb,
        get tapeCheckpoint() {
          return currentTapeCheckpoint;
        },
        load(path, loadOpts = {}) {
          const runInit = loadOpts && loadOpts.runInit === false ? false : true;
          const info = __native.emuLoad(emuId, String(path), runInit);
          return makeModule(emuId, info);
        },
        modules() {
          return __native.emuModules(emuId).map((info) => makeModule(emuId, info));
        },
        module(name) {
          const target = String(name);
          const list = __native.emuModules(emuId);
          const hit = list.find(
            (m) =>
              m.name === target ||
              m.name.endsWith("/" + target) ||
              target.endsWith("/" + m.name)
          );
          return hit ? makeModule(emuId, hit) : null;
        },
        loadDex(pathOrPaths) {
          const list = Array.isArray(pathOrPaths)
            ? pathOrPaths.map(String)
            : [String(pathOrPaths)];
          return __native.emuLoadDex(emuId, list);
        },
        dex: {
          classes(prefix) {
            return __native.dexClasses(
              emuId,
              prefix !== undefined ? String(prefix) : undefined
            );
          },
          classInfo(className) {
            return __native.dexClassInfo(emuId, String(className));
          },
        },
        loadApk(path) {
          const info = __native.emuLoadApk(emuId, String(path));
          return {
            packageName: info.packageName,
            abi: info.abi,
            libs: info.libs,
            assets: info.assets,
            signatureSize: info.signatureSize,
            loadLib(libName, loadOpts = {}) {
              const runInit = loadOpts && loadOpts.runInit === false ? false : true;
              const modInfo = __native.emuLoadApkLib(emuId, String(libName), runInit);
              return makeModule(emuId, modInfo);
            },
          };
        },
        diag: {
          enable() {
            __native.diagSetEnabled(emuId, true);
          },
          disable() {
            __native.diagSetEnabled(emuId, false);
          },
          clear() {
            __native.diagClear(emuId);
          },
          report() {
            return __native.diagReport(emuId);
          },
          generatePatchJs() {
            return __native.diagGeneratePatchJs(emuId);
          },
        },
        jniOnLoad(mod) {
          const ver = __native.emuJniOnLoad(emuId, mod._id);
          return ver < 0 ? null : ver;
        },
        call(addr, ...callArgs) {
          return __native.emuCallAddr(emuId, toAddr(addr), callArgs.map(toAddr));
        },
        stop() {
          __native.emuStop(emuId);
        },
        lastCrash() {
          return __native.emuLastCrash(emuId) ?? null;
        },
        setLimits(limits = {}) {
          const timeoutMs = limits && limits.timeoutMs !== undefined ? Number(limits.timeoutMs) : 0;
          const maxInsns =
            limits && limits.maxInstructions !== undefined ? Number(limits.maxInstructions) : 0;
          __native.emuSetLimits(emuId, timeoutMs, maxInsns);
        },
        regs: {
          get(name) {
            return __native.regGet(emuId, String(name));
          },
          getBigInt(name) {
            return __native.regGetBigInt(emuId, String(name));
          },
          get64(name) {
            return __native.regGetBigInt(emuId, String(name));
          },
          set(name, val) {
            __native.regSet(emuId, String(name), val);
          },
          dump() {
            return __native.regDump(emuId);
          },
        },
        hook: {
          attach(addr, callbacks) {
            if (!callbacks || typeof callbacks !== "object") {
              throw new TypeError("hook.attach(addr, { onEnter?, onLeave? }) expects an object");
            }
            const onEnter = typeof callbacks.onEnter === "function" ? callbacks.onEnter : null;
            const onLeave = typeof callbacks.onLeave === "function" ? callbacks.onLeave : null;
            if (!onEnter && !onLeave) {
              throw new TypeError("hook.attach requires at least onEnter or onLeave");
            }
            const id = __native.hookAttach(emuId, toAddr(addr), onEnter, onLeave);
            return makeHookHandle(emuId, id);
          },
          replace(addr, fn) {
            if (typeof fn !== "function") {
              throw new TypeError("hook.replace(addr, fn) expects a function");
            }
            const id = __native.hookReplace(emuId, toAddr(addr), fn);
            return makeHookHandle(emuId, id);
          },
          import(symName, callbacks) {
            const addr = __native.hookImportResolve(emuId, String(symName));
            if (typeof callbacks === "function") {
              const id = __native.hookReplace(emuId, addr, callbacks);
              return makeHookHandle(emuId, id);
            }
            if (!callbacks || typeof callbacks !== "object") {
              throw new TypeError("hook.import(symName, { onEnter?, onLeave? } | fn) expects callbacks or a replace function");
            }
            const onEnter = typeof callbacks.onEnter === "function" ? callbacks.onEnter : null;
            const onLeave = typeof callbacks.onLeave === "function" ? callbacks.onLeave : null;
            if (!onEnter && !onLeave) {
              throw new TypeError("hook.import requires at least onEnter or onLeave");
            }
            const id = __native.hookAttach(emuId, addr, onEnter, onLeave);
            return makeHookHandle(emuId, id);
          },
          importReplace(symName, fn) {
            if (typeof fn !== "function") {
              throw new TypeError("hook.importReplace(symName, fn) expects a function");
            }
            const addr = __native.hookImportResolve(emuId, String(symName));
            const id = __native.hookReplace(emuId, addr, fn);
            return makeHookHandle(emuId, id);
          },
          code(addrOrRange, fn, opts = {}) {
            if (typeof fn !== "function") {
              throw new TypeError("hook.code(addrOrRange, fn, opts?) expects a function");
            }
            let begin, end;
            if (Array.isArray(addrOrRange)) {
              if (addrOrRange.length !== 2) {
                throw new RangeError("hook.code([begin, end], ...) expects a 2-element range");
              }
              begin = addrOrRange[0];
              end = addrOrRange[1];
            } else {
              begin = addrOrRange;
              end = addrOrRange;
            }
            let maxHits = -1;
            if (opts && opts.once) {
              maxHits = 1;
            } else if (opts && opts.maxHits !== undefined) {
              maxHits = Number(opts.maxHits);
            }
            const id = __native.hookCode(emuId, begin, end, maxHits, fn);
            return makeHookHandle(emuId, id);
          },
          mem(range, optsOrFn, maybeFn) {
            if (!Array.isArray(range) || range.length < 2) {
              throw new TypeError("hook.mem([begin, end], opts?, fn) expects a [begin, end] range");
            }
            let opts, fn;
            if (typeof optsOrFn === "function") {
              opts = { read: true, write: true };
              fn = optsOrFn;
            } else if (optsOrFn === undefined || optsOrFn === null) {
              opts = { read: true, write: true };
              fn = maybeFn;
            } else if (typeof optsOrFn === "object" && !Array.isArray(optsOrFn)) {
              opts = optsOrFn;
              fn = maybeFn;
            } else {
              throw new TypeError("hook.mem options must be an object or callback function");
            }
            if (typeof fn !== "function") {
              throw new TypeError("hook.mem expects a callback function");
            }
            const bothOmitted = opts.read === undefined && opts.write === undefined;
            const r = bothOmitted ? true : Boolean(opts.read);
            const w = bothOmitted ? true : Boolean(opts.write);
            const res = __native.hookMem(
              emuId,
              range[0],
              range[1],
              {
                read: r,
                write: w,
                value: opts.value,
                size: opts.size,
                pcRange: opts.pcRange,
                bigInt: Boolean(opts.bigInt),
              },
              fn
            );
            const handle = makeHookHandle(emuId, res.id);
            handle.unmapped = Boolean(res.unmapped);
            return handle;
          },
          watch(range, modeOrOpts, fn) {
            const parseWatchMode = (mode) => {
              if (typeof mode !== "string") {
                throw new TypeError("hook.watch mode must be 'w' | 'r' | 'rw', got " + typeof mode);
              }
              const m = mode.trim().toLowerCase();
              if (m === "w" || m === "write") return { read: false, write: true };
              if (m === "r" || m === "read") return { read: true, write: false };
              if (m === "rw" || m === "wr" || m === "access" || m === "a") {
                return { read: true, write: true };
              }
              throw new TypeError("hook.watch mode must be 'w' | 'r' | 'rw', got " + mode);
            };
            let opts;
            let cb = fn;
            if (typeof modeOrOpts === "function") {
              opts = { read: false, write: true };
              cb = modeOrOpts;
            } else if (modeOrOpts === undefined || modeOrOpts === null) {
              opts = { read: false, write: true };
            } else if (typeof modeOrOpts === "string") {
              opts = parseWatchMode(modeOrOpts);
            } else if (typeof modeOrOpts === "object" && !Array.isArray(modeOrOpts)) {
              opts = Object.assign({}, modeOrOpts);
              if (modeOrOpts.mode !== undefined) {
                const parsed = parseWatchMode(modeOrOpts.mode);
                opts.read = parsed.read;
                opts.write = parsed.write;
              } else if (opts.read === undefined && opts.write === undefined) {
                opts.read = false;
                opts.write = true;
              } else {
                opts.read = Boolean(opts.read);
                opts.write = Boolean(opts.write);
              }
            } else {
              throw new TypeError("hook.watch expects mode string, options object, or callback");
            }
            return this.mem(range, opts, cb);
          },
          syscall(nrOrWildcard, fn) {
            if (typeof fn !== "function") {
              throw new TypeError("hook.syscall(nr | '*', fn) expects a function");
            }
            const nr = nrOrWildcard === "*" ? -1 : Number(nrOrWildcard);
            const id = __native.hookSyscall(emuId, nr, fn);
            return makeHookHandle(emuId, id);
          },
        },
        jni: {
          envPtr: 0x18001000,
          hook(className, methods) {
            if (!methods || typeof methods !== "object") {
              throw new TypeError("jni.hook(className, methods) expects an object of functions");
            }
            for (const [methodName, fn] of Object.entries(methods)) {
              if (typeof fn !== "function") {
                throw new TypeError(`jni.hook: ${className}.${methodName} must be a function`);
              }
              __native.jniHook(emuId, String(className), methodName, fn);
            }
          },
          hookField(className, fields) {
            if (!fields || typeof fields !== "object") {
              throw new TypeError("jni.hookField(className, fields) expects an object of functions");
            }
            for (const [fieldKey, fn] of Object.entries(fields)) {
              if (typeof fn !== "function") {
                throw new TypeError(`jni.hookField: ${className}.${fieldKey} must be a function`);
              }
              __native.jniHookField(emuId, String(className), fieldKey, fn);
            }
          },
          hookMethod(className, methods) {
            if (!methods || typeof methods !== "object") {
              throw new TypeError("jni.hookMethod(className, methods) expects an object of functions");
            }
            for (const [methodKey, fn] of Object.entries(methods)) {
              if (typeof fn !== "function") {
                throw new TypeError(`jni.hookMethod: ${className}.${methodKey} must be a function`);
              }
              __native.jniHookMethod(emuId, String(className), methodKey, fn);
            }
          },
          listHooks() {
            return __native.jniListHooks(emuId);
          },
          onUnhandled(fn) {
            if (typeof fn !== "function") {
              throw new TypeError("jni.onUnhandled expects a function");
            }
            __native.jniOnUnhandled(emuId, fn);
          },
          registeredNatives() {
            return __native.jniRegisteredNatives(emuId);
          },
          callNative(className, methodName, callArgs = [], opts = {}) {
            const thisRef =
              opts && opts.this !== undefined && opts.this !== null
                ? toAddr(opts.this)
                : 0;
            return __native.jniCallNative(
              emuId,
              String(className),
              String(methodName),
              callArgs.map(toAddr),
              thisRef
            );
          },
          callNativeOn(objRef, className, methodName, callArgs = []) {
            return __native.jniCallNative(
              emuId,
              String(className),
              String(methodName),
              callArgs.map(toAddr),
              toAddr(objRef)
            );
          },
          newString(s) {
            return __native.jniNewString(emuId, String(s));
          },
          newByteArray(bytes) {
            if (Array.isArray(bytes)) {
              bytes = new Uint8Array(bytes);
            }
            if (!(bytes instanceof Uint8Array)) {
              throw new TypeError("jni.newByteArray expects a Uint8Array or number[]");
            }
            return __native.jniNewByteArray(emuId, bytes);
          },
          newCharArray(input) {
            return __native.jniNewCharArray(emuId, input);
          },
          newIntArray(input) {
            return __native.jniNewIntArray(emuId, input);
          },
          newLongArray(input) {
            return __native.jniNewLongArray(emuId, input);
          },
          newObject(className, fields) {
            return __native.jniNewObject(emuId, String(className), fields || null);
          },
          findClass(className) {
            return __native.jniFindClass(emuId, String(className));
          },
          newStringArray(items) {
            if (!Array.isArray(items)) {
              throw new TypeError("jni.newStringArray expects a string array");
            }
            return __native.jniNewStringArray(emuId, items.map(String));
          },
          getStringArray(ref) {
            return __native.jniGetStringArray(emuId, toAddr(ref)) ?? null;
          },
          newObjectArray(refs) {
            if (!Array.isArray(refs)) {
              throw new TypeError("jni.newObjectArray expects a ref array");
            }
            return __native.jniNewObjectArray(emuId, refs.map(toAddr));
          },
          getObjectArray(ref) {
            return __native.jniGetObjectArray(emuId, toAddr(ref)) ?? null;
          },
          getString(ref) {
            return __native.jniGetString(emuId, toAddr(ref)) ?? null;
          },
          getBytes(ref) {
            return __native.jniGetBytes(emuId, toAddr(ref)) ?? null;
          },
          getChars(ref) {
            return __native.jniGetChars(emuId, toAddr(ref)) ?? null;
          },
          getInts(ref) {
            return __native.jniGetInts(emuId, toAddr(ref)) ?? null;
          },
          getLongs(ref) {
            return __native.jniGetLongs(emuId, toAddr(ref)) ?? null;
          },
          getByteArray(ref) {
            const ta = __native.jniGetBytes(emuId, toAddr(ref));
            return ta ? Array.from(ta) : [];
          },
          getIntArray(ref) {
            const ta = __native.jniGetInts(emuId, toAddr(ref));
            return ta ? Array.from(ta) : [];
          },
          getLongArray(ref) {
            const ta = __native.jniGetLongs(emuId, toAddr(ref));
            return ta ? Array.from(ta, Number) : [];
          },
          getCharArray(ref) {
            const ta = __native.jniGetChars(emuId, toAddr(ref));
            if (!ta || ta.length === 0) return "";
            let out = "";
            for (let i = 0; i < ta.length; i += 4096) {
              out += String.fromCharCode(...ta.subarray(i, Math.min(i + 4096, ta.length)));
            }
            return out;
          },
          setField(objRef, fieldName, value, sig) {
            __native.jniSetField(
              emuId,
              toAddr(objRef),
              String(fieldName),
              value,
              sig !== undefined ? String(sig) : undefined
            );
          },
          getField(objRef, fieldName) {
            return __native.jniGetField(emuId, toAddr(objRef), String(fieldName));
          },
          setStaticField(className, fieldName, value, sig) {
            __native.jniSetStaticField(
              emuId,
              String(className),
              String(fieldName),
              value,
              sig !== undefined ? String(sig) : undefined
            );
          },
          getStaticField(className, fieldName) {
            return __native.jniGetStaticField(emuId, String(className), String(fieldName));
          },
          setStrictFindClass(enabled) {
            __native.jniSetStrictFindClass(emuId, Boolean(enabled));
          },
          describeField(fieldId) {
            return __native.jniDescribeField(emuId, toAddr(fieldId));
          },
          listFields() {
            return __native.jniListFields(emuId);
          },
          describeMethod(methodId) {
            return __native.jniDescribeMethod(emuId, toAddr(methodId));
          },
          listMethods() {
            return __native.jniListMethods(emuId);
          },
          describeObject(ref) {
            return __native.jniDescribeObject(emuId, toAddr(ref));
          },
          trace: {
            start(opts = {}) {
              const maxStrLen = opts && opts.maxStrLen !== undefined ? Number(opts.maxStrLen) : 64;
              const maxEvents = opts && opts.maxEvents !== undefined ? Number(opts.maxEvents) : 0;
              __native.jniTraceStart(emuId, maxStrLen, maxEvents);
            },
            stop() {
              __native.jniTraceStop(emuId);
            },
            clear() {
              __native.jniTraceClear(emuId);
            },
            events() {
              return __native.jniTraceEvents(emuId);
            },
            onEvent(fn) {
              __native.jniTraceOnEvent(emuId, fn || null);
            },
          },
          pushLocalFrame() {
            __native.jniPushLocalFrame(emuId);
          },
          popLocalFrame(keepRef = 0) {
            return __native.jniPopLocalFrame(emuId, toAddr(keepRef));
          },
          withLocalFrame(fn) {
            if (typeof fn !== "function") {
              throw new TypeError("jni.withLocalFrame expects a function");
            }
            __native.jniPushLocalFrame(emuId);
            try {
              return fn();
            } finally {
              __native.jniPopLocalFrame(emuId, 0);
            }
          },
          objectCount() {
            return __native.jniObjectCount(emuId);
          },
        },
        mem: memNs,
        vfs: {
          setProperty(key, val) {
            __native.vfsSetProperty(emuId, String(key), String(val));
          },
          writeFile(guestPath, data) {
            if (typeof data === "string") {
              __native.vfsWriteText(emuId, String(guestPath), data);
            } else if (data instanceof Uint8Array) {
              __native.vfsWriteBytes(emuId, String(guestPath), data);
            } else {
              throw new TypeError("vfs.writeFile expects string or Uint8Array");
            }
          },
          readFile(guestPath) {
            return __native.vfsReadFile(emuId, String(guestPath)) ?? null;
          },
          mountOverlay(guestDir, hostDir) {
            __native.vfsMountOverlay(emuId, String(guestDir), String(hostDir));
          },
          setTime(unixSecs) {
            __native.vfsSetTime(emuId, Number(unixSecs));
          },
          useRealClock(enabled = true) {
            __native.vfsUseRealClock(emuId, Boolean(enabled));
          },
          setDevice(presetOrObj) {
            __native.vfsSetDevice(emuId, presetOrObj);
          },
          deviceProfile() {
            return __native.vfsDeviceProfile(emuId);
          },
        },
        net: {
          enable(netOpts = true) {
            if (typeof netOpts === "boolean") {
              __native.netConfigure(emuId, netOpts);
            } else {
              __native.netConfigure(emuId, Object.assign({ enabled: true }, netOpts || {}));
            }
          },
          disable() {
            __native.netConfigure(emuId, false);
          },
          setNic(nicObj) {
            __native.netSetNic(emuId, nicObj || {});
          },
          nic() {
            return __native.netNic(emuId);
          },
          packets() {
            return __native.netPackets(emuId);
          },
          clearPackets() {
            __native.netClearPackets(emuId);
          },
          onSend(fn) {
            __native.netSetInterceptor(emuId, true, fn || null);
          },
          onRecv(fn) {
            __native.netSetInterceptor(emuId, false, fn || null);
          },
        },
        trace: {
          start(traceOpts = {}) {
            const output = traceOpts.output ? String(traceOpts.output) : "";
            const level = traceOpts.level ? String(traceOpts.level) : "reg_delta";
            const start = traceOpts.start !== undefined ? toAddr(traceOpts.start) : 0;
            const end = traceOpts.end !== undefined ? toAddr(traceOpts.end) : -1;
            const capacity = traceOpts.capacity !== undefined ? Number(traceOpts.capacity) : 262144;
            __native.traceStart(emuId, output, level, start, end, capacity);
          },
          stop() {
            const stats = __native.traceStop(emuId);
            stats.truncated = Boolean(stats.droppedInsns > 0 || stats.droppedExt > 0);
            if (stats.truncated) {
              console.warn(
                `[runidbg::trace] Trace 发生截断: recorded=${stats.records}, droppedInsns=${stats.droppedInsns}, droppedExt=${stats.droppedExt}（请调大 trace.start({ capacity })）`
              );
            }
            return stats;
          },
        },
        snapshot() {
          return __native.emuSnapshot(emuId);
        },
        restore(snapId) {
          __native.emuRestore(emuId, Number(snapId));
        },
        saveTape(path, label) {
          return __native.emuSaveTape(
            emuId,
            String(path),
            label !== undefined && label !== null ? String(label) : null
          );
        },
        checkpointTape(path, label) {
          return __native.emuCheckpointTape(
            emuId,
            String(path),
            label !== undefined && label !== null ? String(label) : null
          );
        },
        seekTape(path, checkpoint) {
          const info = __native.emuSeekTape(
            emuId,
            String(path),
            normalizeTapeCheckpoint(checkpoint)
          );
          currentTapeCheckpoint = info;
          return info;
        },
        heapLayout(limit = 512) {
          return __native.memHeapLayout(emuId, Number(limit));
        },
        vm: {
          decodeWord(word, layout) {
            if (!layout || typeof layout !== "object" || Array.isArray(layout) || !Array.isArray(layout.op) || layout.op.length !== 2) {
              throw new TypeError("vm.decodeWord(word, { op: [lsb, width], fields?: [...] }) expects a valid layout");
            }
            let w;
            if (typeof word === "bigint") {
              if (word < 0n || word > 0xFFFFFFFFFFFFFFFFn) {
                throw new RangeError("vm.decodeWord bigint word must be in [0n, 0xffffffffffffffffn]");
              }
              w = word;
            } else if (typeof word === "number") {
              if (!Number.isSafeInteger(word) || word < 0) {
                throw new RangeError("vm.decodeWord number word must be a non-negative safe integer (use BigInt for > 2^53-1)");
              }
              w = BigInt(word);
            } else {
              throw new TypeError("vm.decodeWord word must be a non-negative safe integer or BigInt");
            }

            const parseBitField = (lsb, width, label) => {
              if (typeof lsb !== "number" || !Number.isInteger(lsb) || typeof width !== "number" || !Number.isInteger(width)) {
                throw new TypeError(`${label} lsb/width must be integers`);
              }
              if (lsb < 0 || lsb >= 64 || width <= 0 || lsb + width > 64) {
                throw new RangeError(`${label} bitfield out of range: lsb=${lsb}, width=${width}`);
              }
              return [BigInt(lsb), width];
            };

            const extractBig = (lsbBig, width) => {
              const mask = width >= 64 ? 0xFFFFFFFFFFFFFFFFn : ((1n << BigInt(width)) - 1n);
              return (w >> lsbBig) & mask;
            };

            const [opLsb, opW] = parseBitField(layout.op[0], layout.op[1], "layout.op");
            const opBig = extractBig(opLsb, opW);

            if (layout.fields !== undefined && !Array.isArray(layout.fields)) {
              throw new TypeError("layout.fields must be an array");
            }
            const rawFields = layout.fields || [];
            const fieldsBig = rawFields.map((item, idx) => {
              if (Array.isArray(item)) {
                if (item.length !== 2) {
                  throw new TypeError("layout.fields tuple must be [lsb, width]");
                }
                const [fLsb, fW] = parseBitField(item[0], item[1], `layout.fields[${idx}]`);
                return extractBig(fLsb, fW);
              }
              if (typeof item !== "number" || !Number.isInteger(item)) {
                throw new TypeError(`layout.fields[${idx}] must be an integer or [lsb, width]`);
              }
              const lsb = item;
              const next = rawFields[idx + 1];
              const nextLsb = Array.isArray(next) ? next[0] : next;
              const width =
                typeof nextLsb === "number" && Number.isInteger(nextLsb) && nextLsb > lsb && (nextLsb - lsb) <= 16
                  ? (nextLsb - lsb)
                  : Math.min(5, Math.max(0, 64 - lsb));
              const [fLsb, fW] = parseBitField(lsb, width, `layout.fields[${idx}]`);
              return extractBig(fLsb, fW);
            });

            const text =
              fieldsBig.length > 0
                ? `op=${opBig.toString()} f=[${fieldsBig.map((x) => x.toString()).join(",")}]`
                : `op=${opBig.toString()}`;
            return {
              raw: w,
              rawHex: "0x" + w.toString(16),
              op: Number(opBig),
              opBigInt: opBig,
              opHex: "0x" + opBig.toString(16),
              fields: fieldsBig.map((x) => Number(x)),
              fieldsBigInt: fieldsBig,
              fieldsHex: fieldsBig.map((x) => "0x" + x.toString(16)),
              text,
            };
          },
          watchRegfile(watchOpts) {
            if (!watchOpts || typeof watchOpts !== "object" || Array.isArray(watchOpts)) {
              throw new TypeError("emu.vm.watchRegfile(opts) expects an options object");
            }
            if (typeof watchOpts.baseReg !== "string" || !watchOpts.baseReg.trim()) {
              throw new TypeError("emu.vm.watchRegfile requires baseReg (e.g. 'x25')");
            }
            const baseReg = watchOpts.baseReg.trim();
            // 提前校验寄存器名有效性，避免延迟到 hook 回调时报错
            __native.regGetBigInt(emuId, baseReg);

            const count = watchOpts.count === undefined ? 32 : watchOpts.count;
            if (typeof count !== "number" || !Number.isInteger(count) || count < 1 || count > 256) {
              throw new RangeError("emu.vm.watchRegfile count must be an integer in [1, 256]");
            }
            const size = watchOpts.size === undefined ? 8 : watchOpts.size;
            if (size !== 4 && size !== 8) {
              throw new RangeError("emu.vm.watchRegfile size must be 4 or 8");
            }
            const wordSize = watchOpts.wordSize === undefined ? 4 : watchOpts.wordSize;
            if (wordSize !== 1 && wordSize !== 2 && wordSize !== 4 && wordSize !== 8) {
              throw new RangeError("emu.vm.watchRegfile wordSize must be 1, 2, 4, or 8");
            }
            const maxSteps = watchOpts.maxSteps === undefined ? 10000 : watchOpts.maxSteps;
            if (typeof maxSteps !== "number" || !Number.isInteger(maxSteps) || maxSteps < 1) {
              throw new RangeError("emu.vm.watchRegfile maxSteps must be an integer >= 1");
            }

            const pcOrRange =
              watchOpts.dispatcherPc !== undefined
                ? watchOpts.dispatcherPc
                : watchOpts.pc !== undefined
                  ? watchOpts.pc
                  : watchOpts.range;
            if (pcOrRange === undefined || pcOrRange === null) {
              throw new TypeError("emu.vm.watchRegfile requires dispatcherPc (or pc / range)");
            }
            let range;
            if (Array.isArray(pcOrRange)) {
              if (pcOrRange.length !== 2) {
                throw new RangeError("emu.vm.watchRegfile range must be [begin, end]");
              }
              range = [pcOrRange[0], pcOrRange[1]];
            } else {
              range = [pcOrRange, pcOrRange];
            }

            const bcReg =
              watchOpts.bcReg !== undefined && watchOpts.bcReg !== null
                ? String(watchOpts.bcReg).trim()
                : null;
            if (bcReg !== null) {
              if (!bcReg) throw new TypeError("emu.vm.watchRegfile bcReg cannot be empty");
              __native.regGetBigInt(emuId, bcReg);
            }
            const bcDeref = Boolean(watchOpts.bcDeref);
            const bcPtrAddr =
              watchOpts.bcPtrAddr !== undefined && watchOpts.bcPtrAddr !== null
                ? watchOpts.bcPtrAddr
                : null;
            if (bcReg !== null && bcPtrAddr !== null) {
              throw new TypeError("emu.vm.watchRegfile bcReg and bcPtrAddr are mutually exclusive");
            }
            if (bcDeref && bcReg === null) {
              throw new TypeError("emu.vm.watchRegfile bcDeref: true requires bcReg");
            }

            const layout = watchOpts.layout !== undefined && watchOpts.layout !== null ? watchOpts.layout : null;
            if (layout !== null) {
              // 提前校验 layout 合法性
              this.decodeWord(0n, layout);
            }
            if (watchOpts.onStep !== undefined && typeof watchOpts.onStep !== "function") {
              throw new TypeError("emu.vm.watchRegfile onStep must be a function");
            }
            const onStep = watchOpts.onStep || null;
            const selfVm = this;

            let prevBase = null;
            let prevVals = null;
            let prevBcPc = null;
            let prevEv = null;
            let stepNo = 0;
            const events = [];
            const opStats = new Map();

            const readSlotBytes = (memNs, addr, nBytes) => {
              try {
                return memNs.readBytes(addr, nBytes);
              } catch (_) {
                return null;
              }
            };

            const hookId = __native.hookCode(emuId, range[0], range[1], -1, (ctx, pc) => {
              const base = ctx.reg64(baseReg);
              const baseRelocated = prevBase !== null && base !== prevBase;
              const byteLen = count * size;
              const rawBytes = readSlotBytes(ctx.mem, base, byteLen);
              const diffs = [];
              let curVals = null;

              if (rawBytes && rawBytes.length === byteLen) {
                curVals = new Array(count);
                const dv = new DataView(rawBytes.buffer, rawBytes.byteOffset, rawBytes.byteLength);
                for (let i = 0; i < count; i++) {
                  const val =
                    size === 8
                      ? dv.getBigUint64(i * 8, true)
                      : BigInt(dv.getUint32(i * 4, true));
                  curVals[i] = val;
                  if (prevVals !== null && !baseRelocated && prevVals[i] !== val) {
                    diffs.push({
                      reg: i,
                      name: `R[${i}]`,
                      oldVal: prevVals[i],
                      newVal: val,
                      oldHex: "0x" + prevVals[i].toString(16),
                      newHex: "0x" + val.toString(16),
                    });
                  }
                }
              }

              let bcPc = null;
              if (bcPtrAddr !== null) {
                const b = readSlotBytes(ctx.mem, bcPtrAddr, 8);
                if (b && b.length === 8) {
                  bcPc = new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, true);
                }
              } else if (bcReg) {
                const rVal = ctx.reg64(bcReg);
                if (bcDeref) {
                  const b = readSlotBytes(ctx.mem, rVal, 8);
                  if (b && b.length === 8) {
                    bcPc = new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, true);
                  }
                } else {
                  bcPc = rVal;
                }
              }

              // 使用独立 prevEv 回填上一步 bcStep 与 opStats，避免超 maxSteps 后反复覆写 events 末项！
              if (bcPc !== null && prevBcPc !== null && prevEv !== null) {
                const delta = Number(bcPc - prevBcPc);
                prevEv.bcStep = delta;
                if (prevEv.opHex !== null && prevEv.opHex !== undefined) {
                  const st = opStats.get(prevEv.opHex);
                  if (st) {
                    st.stepHist[delta] = (st.stepHist[delta] || 0) + 1;
                  }
                }
              }

              let rawWord = null;
              let decoded = null;
              if (bcPc !== null) {
                const wb = readSlotBytes(ctx.mem, bcPc, wordSize);
                if (wb && wb.length === wordSize) {
                  const wdv = new DataView(wb.buffer, wb.byteOffset, wb.byteLength);
                  if (wordSize === 8) rawWord = wdv.getBigUint64(0, true);
                  else if (wordSize === 4) rawWord = BigInt(wdv.getUint32(0, true));
                  else if (wordSize === 2) rawWord = BigInt(wdv.getUint16(0, true));
                  else rawWord = BigInt(wb[0]);
                  if (layout) {
                    decoded = selfVm.decodeWord(rawWord, layout);
                  }
                }
              }

              const ev = {
                step: stepNo++,
                pc,
                pcHex: "0x" + pc.toString(16),
                base,
                baseHex: "0x" + base.toString(16),
                prevBase: baseRelocated ? prevBase : null,
                baseRelocated,
                bcPc,
                bcPcHex: bcPc !== null ? "0x" + bcPc.toString(16) : null,
                bcStep: null,
                rawWord,
                rawWordHex: rawWord !== null ? "0x" + rawWord.toString(16) : null,
                op: decoded ? decoded.op : null,
                opHex: decoded ? decoded.opHex : null,
                fields: decoded ? decoded.fields : null,
                fieldsHex: decoded ? decoded.fieldsHex : null,
                decodedText: decoded ? decoded.text : null,
                diffs,
              };

              if (decoded) {
                let st = opStats.get(decoded.opHex);
                if (!st) {
                  st = { op: decoded.op, opHex: decoded.opHex, hits: 0, stepHist: {} };
                  opStats.set(decoded.opHex, st);
                }
                st.hits++;
              }

              if (events.length < maxSteps) {
                events.push(ev);
              }
              prevBase = base;
              prevVals = curVals; // 若本次读取失败则为 null，绝不会留下全 undefined 数组！
              prevBcPc = bcPc;
              prevEv = ev;
              if (onStep) {
                onStep(ev);
              }
            });

            const baseHandle = makeHookHandle(emuId, hookId);
            return {
              id: baseHandle.id,
              detach: baseHandle.detach,
              events() {
                return events;
              },
              stats() {
                return Array.from(opStats.values()).sort((a, b) => b.hits - a.hits);
              },
              format(limit = 200) {
                if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 0) {
                  throw new RangeError("watcher.format(limit) expects a non-negative integer");
                }
                return events
                  .slice(0, limit)
                  .map((e) => {
                    const bc = e.bcPcHex
                      ? e.bcStep !== null
                        ? ` bc=${e.bcPcHex}(${e.bcStep >= 0 ? "+" : ""}${e.bcStep}B)`
                        : ` bc=${e.bcPcHex}`
                      : "";
                    const dec = e.decodedText
                      ? ` ${e.decodedText}`
                      : e.rawWordHex
                        ? ` word=${e.rawWordHex}`
                        : "";
                    const reloc = e.baseRelocated ? ` [REGFILE->${e.baseHex}]` : "";
                    const ds =
                      e.diffs.length > 0
                        ? " | " + e.diffs.map((d) => `${d.name}: ${d.oldHex}->${d.newHex}`).join(", ")
                        : "";
                    return `step#${String(e.step).padStart(4, "0")}${bc}${dec}${reloc}${ds}`;
                  })
                  .join("\n");
              },
            };
          },
        },
        record: {
          start(opts = {}) {
            const o = opts || {};
            const kfInterval =
              o.keyframeInterval != null ? Number(o.keyframeInterval) : 100000;
            const maxInsns = o.maxInsns != null ? Number(o.maxInsns) : 0;
            const captureJni = o.captureJni != null ? Boolean(o.captureJni) : true;
            __native.emuRecordStart(emuId, kfInterval, maxInsns, captureJni);
          },
          bookmark(label) {
            return __native.emuRecordBookmark(emuId, String(label));
          },
          insns() {
            return __native.emuRecordInsns(emuId);
          },
          isRecording() {
            return __native.emuRecordIsRecording(emuId);
          },
          stop(path) {
            return __native.emuRecordStop(emuId, String(path));
          },
        },
      };
  }

  function validateStepCount(n, fnName) {
    const num = Number(n);
    if (!Number.isInteger(num) || num < 0) {
      throw new RangeError(fnName + ": step count must be a non-negative integer, got " + n);
    }
    return num;
  }

  function buildTimeTravelHandle(openInfo) {
    const ttId = openInfo.ttId;
    const mem = {
      readBytes(addr, len) {
        return __native.ttMemReadBytes(ttId, addr, Number(len));
      },
      readU32(addr) {
        const b = __native.ttMemReadBytes(ttId, addr, 4);
        return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
      },
      readU64(addr) {
        const b = __native.ttMemReadBytes(ttId, addr, 8);
        let lo = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
        let hi = (b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)) >>> 0;
        return (BigInt(hi) << 32n) | BigInt(lo);
      },
      readCString(addr, maxLen = 4096) {
        const cap = Math.max(1, Number(maxLen) || 4096);
        let base = typeof addr === "bigint" ? addr : BigInt(addr);
        const bytes = [];
        const chunk = 64;
        while (bytes.length < cap) {
          const toRead = Math.min(chunk, cap - bytes.length);
          let slice;
          try {
            slice = __native.ttMemReadBytes(ttId, base + BigInt(bytes.length), toRead);
          } catch (_) {
            if (bytes.length === 0) throw _;
            break;
          }
          for (let i = 0; i < slice.length; i++) {
            if (slice[i] === 0) {
              return __native.utf8Decode(new Uint8Array(bytes));
            }
            bytes.push(slice[i]);
          }
        }
        return __native.utf8Decode(new Uint8Array(bytes));
      },
    };
    return {
      startInsn: openInfo.startInsn,
      totalInsns: openInfo.totalInsns,
      keyframes: openInfo.keyframes,
      bookmarks: openInfo.bookmarks,
      modules: openInfo.modules,
      currentInsn() {
        return __native.ttCurrentInsn(ttId);
      },
      isLiveForked() {
        return __native.ttIsLiveForked(ttId);
      },
      close() {
        return __native.ttClose(ttId);
      },
      seekInsn(insn) {
        return __native.ttSeekInsn(ttId, Number(insn));
      },
      seekBookmark(label) {
        return __native.ttSeekBookmark(ttId, String(label));
      },
      stepForward(n = 1) {
        return __native.ttStep(ttId, validateStepCount(n, "stepForward"));
      },
      stepBack(n = 1) {
        return __native.ttStep(ttId, -validateStepCount(n, "stepBack"));
      },
      findPrevWrite(addr, len = 1) {
        return __native.ttFindMemAccess(ttId, addr, Number(len), "write", true);
      },
      findPrevRead(addr, len = 1) {
        return __native.ttFindMemAccess(ttId, addr, Number(len), "read", true);
      },
      findPrevAccess(addr, len = 1) {
        return __native.ttFindMemAccess(ttId, addr, Number(len), "access", true);
      },
      findNextWrite(addr, len = 1) {
        return __native.ttFindMemAccess(ttId, addr, Number(len), "write", false);
      },
      findNextRead(addr, len = 1) {
        return __native.ttFindMemAccess(ttId, addr, Number(len), "read", false);
      },
      findNextAccess(addr, len = 1) {
        return __native.ttFindMemAccess(ttId, addr, Number(len), "access", false);
      },
      regs() {
        return __native.ttRegs(ttId);
      },
      mem,
      verifyDeterminism() {
        return __native.ttVerifyDeterminism(ttId);
      },
    };
  }

  global.Emu = {
    backends() {
      return __native.emuCompiledBackends();
    },
    asm(source, pc = 0) {
      return __native.asmEncode(String(source), pc);
    },
    relocateAsm(bytes, oldPc, newPc) {
      if (!(bytes instanceof Uint8Array)) {
        throw new TypeError("Emu.relocateAsm expects a Uint8Array");
      }
      return __native.asmRelocate(bytes, oldPc, newPc);
    },
    create(opts = {}) {
      const packageName = opts.packageName || "com.example.app";
      const searchPaths = Array.isArray(opts.searchPaths) ? opts.searchPaths.map(String) : [];
      const hleAccel = opts.hleAccel !== undefined ? Boolean(opts.hleAccel) : true;
      const heapSize = opts.heapSize !== undefined ? Number(opts.heapSize) : 32 * 1024 * 1024;
      const requestedBackend =
        opts.backend !== undefined && opts.backend !== null ? String(opts.backend) : "unicorn";
      const emuId = __native.emuCreate(packageName, searchPaths, hleAccel, heapSize, requestedBackend);
      return buildEmuHandle(emuId, opts, null);
    },
    loadTape(path, opts = {}) {
      const safeOpts = opts || {};
      const backend =
        safeOpts.backend !== undefined && safeOpts.backend !== null
          ? String(safeOpts.backend)
          : "unicorn";
      const checkpoint = normalizeTapeCheckpoint(safeOpts.checkpoint);
      const searchPaths = Array.isArray(safeOpts.searchPaths)
        ? safeOpts.searchPaths.map(String)
        : null;
      const res = __native.emuLoadTape(String(path), checkpoint, backend, searchPaths);
      return buildEmuHandle(res.emuId, safeOpts, res.checkpoint);
    },
    inspectTape(path) {
      return __native.emuInspectTape(String(path));
    },
    openTimeTravel(path) {
      const info = __native.ttOpen(String(path));
      return buildTimeTravelHandle(info);
    },
  };

  function requireNonEmptyPath(val, label) {
    if (typeof val !== "string" || val.trim().length === 0) {
      throw new TypeError(label + " 必须为非空字符串路径");
    }
    return val;
  }

  function optionalPathArg(val, label) {
    if (val === undefined || val === null) return null;
    if (typeof val !== "string" || val.trim().length === 0) {
      throw new TypeError(label + " 必须为非空字符串路径或 null/undefined");
    }
    return val;
  }

  function requirePlainOpts(val, label) {
    if (val === undefined || val === null) return {};
    if (typeof val !== "object" || Array.isArray(val)) {
      throw new TypeError(label + " 必须为普通配置对象");
    }
    return val;
  }

  global.Trace = {
    open(idxPath, extPath) {
      const info = __native.traceOpen(
        requireNonEmptyPath(idxPath, "Trace.open(idxPath)"),
        optionalPathArg(extPath, "Trace.open(extPath)")
      );
      const traceId = info.traceId;
      return {
        totalInsns: info.totalInsns,
        totalExt: info.totalExt,
        missingExtWarning: Boolean(info.missingExtWarning),
        recordedLevel: info.recordedLevel || null,
        isArchive: Boolean(info.isArchive),
        archiveBaseAddrHex: info.archiveBaseAddrHex || null,
        query(opts) {
          return __native.traceQuery(traceId, opts || {});
        },
        findWrites(value, opts = {}) {
          return __native.traceQuery(traceId, Object.assign({}, opts || {}, { value }));
        },
        findReads(addr, opts = {}) {
          return __native.traceQuery(
            traceId,
            Object.assign({ writesOnly: false }, opts || {}, { addr })
          );
        },
        findMem(addr, opts = {}) {
          return __native.traceQuery(
            traceId,
            Object.assign({}, opts || {}, { addr })
          );
        },
        hleEvents(limit = 500) {
          return __native.traceHleEvents(traceId, Number(limit));
        },
        reconstructMem(addr, len, atSeq) {
          if (typeof len !== "number") {
            throw new TypeError("reconstructMem 参数 len 必须为非负整数");
          }
          return __native.traceReconstructMem(
            traceId,
            addr,
            len,
            atSeq !== undefined && atSeq !== null ? atSeq : null
          );
        },
        taintForward(opts) {
          return __native.traceTaint(traceId, "forward", opts || {});
        },
        taintBackward(opts) {
          return __native.traceTaint(traceId, "backward", opts || {});
        },
        decompileSlice(opts) {
          return __native.traceDecompileSlice(traceId, opts || {});
        },
        taintToC(opts) {
          return __native.traceDecompileSlice(traceId, opts || {});
        },
        vmAnalyze(opts) {
          return __native.traceVmAnalyze(traceId, opts || {});
        },
        close() {
          return __native.traceClose(traceId);
        },
      };
    },
    diff(idxA, idxB, maxDiffs = 100) {
      return __native.traceDiff(String(idxA), String(idxB), Number(maxDiffs));
    },
    diffTaint(idxA, idxB, addr, len = 16, maxInsns = 0) {
      if (typeof len !== "number") {
        throw new TypeError("Trace.diffTaint 参数 len 必须为整数 (1..=4096)");
      }
      if (typeof maxInsns !== "number") {
        throw new TypeError("Trace.diffTaint 参数 maxInsns 必须为非负整数");
      }
      return __native.traceDiffTaint(
        String(idxA),
        String(idxB),
        addr,
        len,
        maxInsns
      );
    },
    pack(idxPath, outPath, opts) {
      return __native.tracePack(
        requireNonEmptyPath(idxPath, "Trace.pack(idxPath)"),
        optionalPathArg(outPath, "Trace.pack(outPath)"),
        requirePlainOpts(opts, "Trace.pack(opts)")
      );
    },
    inspectArchive(rtracePath) {
      return __native.traceInspectArchive(
        requireNonEmptyPath(rtracePath, "Trace.inspectArchive(rtracePath)")
      );
    },
    unpack(rtracePath, outDir, opts) {
      return __native.traceUnpack(
        requireNonEmptyPath(rtracePath, "Trace.unpack(rtracePath)"),
        optionalPathArg(outDir, "Trace.unpack(outDir)"),
        requirePlainOpts(opts, "Trace.unpack(opts)")
      );
    },
  };
})(globalThis);
