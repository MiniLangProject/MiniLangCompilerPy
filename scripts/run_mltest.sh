#!/usr/bin/env bash
# Build mltest, discover tagged tests, compile the generated runner, and execute it.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python="${PYTHON:-python3}"
compiler="${MINILANG_COMPILER:-$root/mlc_win64.py}"
test_root="${1:-$root/tests/mltest_fixture}"
if [[ $# -gt 0 ]]; then shift; fi
artifacts="${MLTEST_ARTIFACTS:-$root/build/mltest-linux}"
mkdir -p "$artifacts"

"$python" "$compiler" "$root/tools/mltest.ml" "$artifacts/mltest" -I "$root" --target linux-x64
chmod +x "$artifacts/mltest"
"$artifacts/mltest" generate "$test_root" "$artifacts/runner.ml"
"$python" "$compiler" "$artifacts/runner.ml" "$artifacts/tests" -I "$root" --target linux-x64
chmod +x "$artifacts/tests"
"$artifacts/tests" "$@"
