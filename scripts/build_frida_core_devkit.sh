#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_FRIDA_CORE_DIR="$SCRIPT_DIR/../vendor/frida-core"

FRIDA_CORE_DIR="${1:-$DEFAULT_FRIDA_CORE_DIR}"
BUILD_DIR="${2:-$FRIDA_CORE_DIR/build-hook-inject}"

if [[ ! -d "$FRIDA_CORE_DIR" ]]; then
  echo "frida-core not found at: $FRIDA_CORE_DIR" >&2
  exit 1
fi

if [[ ! -x "$FRIDA_CORE_DIR/configure" ]]; then
  echo "missing $FRIDA_CORE_DIR/configure; clone frida-core or init submodules" >&2
  exit 1
fi

mkdir -p "$BUILD_DIR"

if [[ ! -f "$BUILD_DIR/build.ninja" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]] && [[ -z "${MACOS_CERTID:-}" ]]; then
    export MACOS_CERTID=-
  fi

  (
    cd "$FRIDA_CORE_DIR"
    MESON_BUILD_ROOT="$BUILD_DIR" ./configure \
      --with-devkits=core \
      --with-assets=embedded \
      --with-compat=disabled \
      --enable-local-backend \
      --disable-simmy-backend \
      --disable-fruity-backend \
      --disable-droidy-backend \
      --disable-socket-backend \
      --disable-barebone-backend \
      --disable-compiler-backend \
      --disable-gadget \
      --disable-server \
      --disable-portal \
      --disable-tests \
      --disable-connectivity
  )
fi

(
  cd "$FRIDA_CORE_DIR"
  MESON_BUILD_ROOT="$BUILD_DIR" make
)

DEVKIT_DIR="$BUILD_DIR/src/devkit"
if [[ ! -f "$DEVKIT_DIR/frida-core.h" ]]; then
  echo "devkit header not found in $DEVKIT_DIR" >&2
  exit 1
fi

echo "Devkit ready: $DEVKIT_DIR"
echo "Use: FRIDA_CORE_DEVKIT_DIR=\"$DEVKIT_DIR\" cargo build"
