#!/bin/sh
# Build the Linux x64 std.video bridge. GStreamer is resolved at runtime, so
# development headers are deliberately not required.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUTPUT=${1:-"$ROOT/../../../build/native/video/linux-x64"}
case "$OUTPUT" in
  /*) ;;
  *) OUTPUT="$ROOT/$OUTPUT" ;;
esac
mkdir -p -- "$OUTPUT"

cc -std=c11 -O2 -fPIC -fvisibility=hidden -Wall -Wextra -Werror \
  -I"$ROOT/../include" \
  "$ROOT/minilang_video.c" \
  -shared -Wl,-z,relro,-z,now -Wl,-soname,libminilang_video.so \
  -pthread -ldl -o "$OUTPUT/libminilang_video.so"

printf 'Wrote: %s\n' "$OUTPUT/libminilang_video.so"
