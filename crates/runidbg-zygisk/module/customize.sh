#!/system/bin/sh
# runidbg-zygisk Magisk / KernelSU / APatch 模块安装脚本
SKIPUNZIP=0

ui_print "***********************************************"
ui_print "  runidbg Zygisk Hybrid Tracer (v0.5.0)"
ui_print "  1:1 Zero-Copy ARM64 Unicorn In-Process Trace"
ui_print "***********************************************"

ARCH_ABI="$(getprop ro.product.cpu.abi)"
case "$ARCH_ABI" in
  arm64-v8a*) ;;
  *)
    abort "! runidbg-zygisk only supports arm64-v8a devices (detected: $ARCH_ABI)"
    ;;
esac

mkdir -p /data/adb/runidbg
mkdir -p /data/local/tmp/runidbg
chmod 0755 /data/local/tmp/runidbg

if [ ! -f /data/adb/runidbg/config.json ]; then
  cp "$MODPATH/config.example.json" /data/adb/runidbg/config.json
  chmod 0600 /data/adb/runidbg/config.json
  ui_print "- Created template /data/adb/runidbg/config.json"
  ui_print "  Edit package_name, target_libs, and hooks before launching target app."
else
  ui_print "- Preserved existing /data/adb/runidbg/config.json"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/zygisk/arm64-v8a.so" 0 0 0644
chcon -R u:object_r:system_file:s0 "$MODPATH" 2>/dev/null || true
chcon u:object_r:system_lib_file:s0 "$MODPATH/zygisk/arm64-v8a.so" 2>/dev/null || true
ui_print "- Installation complete. Traces will be saved to /data/local/tmp/runidbg/*.rtrace"
