#!/usr/bin/env bash
# Builds the standalone arm64 su (daemon + client) and regenerates su_blob.h.
# Run from git-bash. The .cmd clang wrappers produce nothing when invoked from
# git-bash, so the extension-less wrappers are used; the MSYS include/library
# paths have to be cleared or clang picks up D:\msys64\ucrt64\include and dies
# with "__declspec attributes are not enabled".
set -euo pipefail
unset C_INCLUDE_PATH CPATH CPLUS_INCLUDE_PATH LIBRARY_PATH INCLUDE || true

NDK="${NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -n "$NDK" ] || {
  echo "Set NDK, ANDROID_NDK_HOME, or ANDROID_NDK_ROOT to Android NDK 28.2.13676358." >&2
  exit 1
}

CC="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android24-clang"
OUT="$HERE/su_aarch64_pie"

[ -x "$CC" ] || { echo "clang wrapper not found: $CC" >&2; exit 1; }

"$CC" -fPIE -pie -O2 -g0 -o "$OUT" "$HERE/su_daemon.c" "$HERE/su_entry.c"
ls -l "$OUT"
python "$HERE/gen_blob.py" "$OUT" "$HERE/../include/su_blob.h"
sha256sum "$OUT"
