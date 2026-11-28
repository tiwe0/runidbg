#!/usr/bin/env bash
set -euo pipefail

# 一键交叉编译 Android ARM64 `librunidbg_zygisk.so` 并打包为标准 Magisk / KernelSU / APatch Zygisk 模块 Zip
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# 先将输出路径解析为绝对路径，避免 cd "$STAGE_DIR" 后相对路径失效！
RAW_OUT_ZIP="${1:-$ROOT_DIR/dist/runidbg-zygisk-v0.5.0.zip}"
mkdir -p "$(dirname "$RAW_OUT_ZIP")"
OUT_ZIP="$(cd "$(dirname "$RAW_OUT_ZIP")" && pwd)/$(basename "$RAW_OUT_ZIP")"

cd "$ROOT_DIR"

API_LEVEL="${ANDROID_API_LEVEL:-29}"
MODULE_VERSION="${MODULE_VERSION:-v0.5.0}"
MODULE_VERSION_CODE="${MODULE_VERSION_CODE:-500}"

detect_ndk() {
  for cand in \
    "${ANDROID_NDK_HOME:-}" \
    "${ANDROID_NDK_LATEST_HOME:-}" \
    "${ANDROID_NDK_ROOT:-}"; do
    if [ -n "$cand" ] && [ -d "$cand/toolchains/llvm/prebuilt" ]; then
      echo "$cand"
      return 0
    fi
  done
  # 通配搜索时按版本号倒序优先选择最新 NDK
  local latest=""
  for base in \
    /opt/homebrew/share/android-commandlinetools/ndk \
    "$HOME/Library/Android/sdk/ndk" \
    "$HOME/Android/Sdk/ndk"; do
    if [ -d "$base" ]; then
      local pick
      pick="$(ls -1 "$base" 2>/dev/null | sort -V | tail -n 1 || true)"
      if [ -n "$pick" ] && [ -d "$base/$pick/toolchains/llvm/prebuilt" ]; then
        latest="$base/$pick"
        break
      fi
    fi
  done
  if [ -n "$latest" ]; then
    echo "$latest"
    return 0
  fi
  return 1
}

NDK_DIR="$(detect_ndk)" || {
  echo "ERROR: Android NDK not found. Set ANDROID_NDK_HOME or install NDK via sdkmanager." >&2
  exit 1
}

HOST_TAG=""
for tag in darwin-x86_64 darwin-arm64 linux-x86_64; do
  if [ -d "$NDK_DIR/toolchains/llvm/prebuilt/$tag/bin" ]; then
    HOST_TAG="$tag"
    break
  fi
done
if [ -z "$HOST_TAG" ]; then
  echo "ERROR: Could not locate LLVM prebuilt toolchain inside $NDK_DIR" >&2
  exit 1
fi

TOOLCHAIN_ROOT="$NDK_DIR/toolchains/llvm/prebuilt/$HOST_TAG"
TOOLCHAIN_BIN="$TOOLCHAIN_ROOT/bin"
TOOLCHAIN_SYSROOT="$TOOLCHAIN_ROOT/sysroot"
CLANG_CC="$TOOLCHAIN_BIN/aarch64-linux-android${API_LEVEL}-clang"
CLANG_CXX="$TOOLCHAIN_BIN/aarch64-linux-android${API_LEVEL}-clang++"
LLVM_AR="$TOOLCHAIN_BIN/llvm-ar"
LLVM_STRIP="$TOOLCHAIN_BIN/llvm-strip"
LLVM_NM="$TOOLCHAIN_BIN/llvm-nm"
LLVM_READELF="$TOOLCHAIN_BIN/llvm-readelf"

echo "==> Using NDK: $NDK_DIR ($HOST_TAG, API $API_LEVEL)"

mkdir -p "$ROOT_DIR/target"
TOOLCHAIN_WRAPPER="$ROOT_DIR/target/android-arm64-toolchain.cmake"
cat > "$TOOLCHAIN_WRAPPER" << EOF
set(ANDROID_ABI "arm64-v8a" CACHE STRING "" FORCE)
set(ANDROID_PLATFORM "android-${API_LEVEL}" CACHE STRING "" FORCE)
include("${NDK_DIR}/build/cmake/android.toolchain.cmake")
EOF

export CC_aarch64_linux_android="$CLANG_CC"
export CXX_aarch64_linux_android="$CLANG_CXX"
export AR_aarch64_linux_android="$LLVM_AR"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG_CC"
export CMAKE_TOOLCHAIN_FILE_aarch64_linux_android="$TOOLCHAIN_WRAPPER"
export CFLAGS_aarch64_linux_android="-fPIC"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--sysroot=$TOOLCHAIN_SYSROOT -target aarch64-linux-android${API_LEVEL}"

cargo build \
  -p runidbg-zygisk \
  --target aarch64-linux-android \
  --release

SO_PATH="$ROOT_DIR/target/aarch64-linux-android/release/librunidbg_zygisk.so"
if [ ! -f "$SO_PATH" ]; then
  echo "ERROR: Expected built library at $SO_PATH" >&2
  exit 1
fi

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

mkdir -p "$STAGE_DIR/zygisk" "$STAGE_DIR/META-INF/com/google/android"
cp "$SO_PATH" "$STAGE_DIR/zygisk/arm64-v8a.so"
"$LLVM_STRIP" --strip-unneeded "$STAGE_DIR/zygisk/arm64-v8a.so"

sed \
  -e "s/^version=.*/version=${MODULE_VERSION}/" \
  -e "s/^versionCode=.*/versionCode=${MODULE_VERSION_CODE}/" \
  "$ROOT_DIR/crates/runidbg-zygisk/module/module.prop" > "$STAGE_DIR/module.prop"
cp "$ROOT_DIR/crates/runidbg-zygisk/module/customize.sh" "$STAGE_DIR/"
cp "$ROOT_DIR/crates/runidbg-zygisk/module/config.example.json" "$STAGE_DIR/"

# 标准 Magisk module_installer.sh 兼容壳（Magisk App / KernelSU / APatch / TWRP 通用）
cat > "$STAGE_DIR/META-INF/com/google/android/update-binary" << 'EOF'
#!/sbin/sh
umask 022
ui_print() { echo "$1"; }
require_new_magisk() {
  ui_print "*******************************"
  ui_print " Please install Magisk v20.4+! "
  ui_print "*******************************"
  exit 1
}
OUTFD=$2
ZIPFILE=$3
mount /data 2>/dev/null || true
[ -f /data/adb/magisk/util_functions.sh ] || require_new_magisk
. /data/adb/magisk/util_functions.sh
[ "$MAGISK_VER_CODE" -lt 20400 ] && require_new_magisk
install_module
exit 0
EOF
chmod +x "$STAGE_DIR/META-INF/com/google/android/update-binary"
echo "#MAGISK" > "$STAGE_DIR/META-INF/com/google/android/updater-script"

TARGET_SO="$STAGE_DIR/zygisk/arm64-v8a.so"

echo "==> Verifying exported Zygisk API v4 symbols (exact .dynsym check):"
DEFINED_SYMS="$("$LLVM_NM" -D --defined-only "$TARGET_SO")"
echo "$DEFINED_SYMS"
echo "$DEFINED_SYMS" | grep -Eq ' T zygisk_module_entry$' || { echo "ERROR: missing zygisk_module_entry" >&2; exit 1; }
echo "$DEFINED_SYMS" | grep -Eq ' T zygisk_companion_entry$' || { echo "ERROR: missing zygisk_companion_entry" >&2; exit 1; }
EXTRA_SYMS="$(echo "$DEFINED_SYMS" | awk '{print $3}' | grep -Ev '^(zygisk_module_entry|zygisk_companion_entry)$' || true)"
if [ -n "$EXTRA_SYMS" ]; then
  echo "ERROR: unexpected exported symbols in .dynsym: $EXTRA_SYMS" >&2
  exit 1
fi

echo "==> Verifying DT_NEEDED dependencies (strict allowlist):"
"$LLVM_READELF" -d "$TARGET_SO" | grep NEEDED || true
BAD_NEEDED="$("$LLVM_READELF" -d "$TARGET_SO" | awk '/\(NEEDED\)/{print $NF}' | tr -d '[]' | grep -Ev '^(libc|libdl|liblog|libm)\.so$' || true)"
if [ -n "$BAD_NEEDED" ]; then
  echo "ERROR: unexpected DT_NEEDED libraries: $BAD_NEEDED" >&2
  exit 1
fi

echo "==> Verifying 16KB ELF PT_LOAD alignment (Android 15 16KB page compatibility):"
LOAD_LINES="$("$LLVM_READELF" -lW "$TARGET_SO" | awk '$1 == "LOAD"')"
echo "$LOAD_LINES"
while IFS= read -r line; do
  [ -z "$line" ] && continue
  align_hex="$(echo "$line" | awk '{print $NF}')"
  if [ "$((align_hex))" -lt 16384 ]; then
    echo "ERROR: PT_LOAD alignment $align_hex < 16384 (0x4000)!" >&2
    exit 1
  fi
done <<< "$LOAD_LINES"

rm -f "$OUT_ZIP"
(cd "$STAGE_DIR" && zip -qr "$OUT_ZIP" .)

echo "==> Packaged Zygisk module: $OUT_ZIP ($(du -h "$OUT_ZIP" | awk '{print $1}'))"
