#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Regenerate Python protobuf bindings from proto/*.proto into
# src/pywhats/proto/. Run this whenever a .proto file changes.
#
# Requires grpcio-tools (installed with the [dev] extra):
#   pip install -e ".[dev]"
#
# Generated files are committed to the repo; downstream consumers do
# not need protoc.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proto_dir="$repo_root/proto"
out_dir="$repo_root/src/pywhats/proto"

mkdir -p "$out_dir"

# Pick a python interpreter — prefer the project venv if it exists.
if [[ -x "$repo_root/.venv/bin/python" ]]; then
  python="$repo_root/.venv/bin/python"
else
  python="${PYTHON:-python3}"
fi

echo "Generating protobuf bindings with $python"

shopt -s nullglob
proto_files=("$proto_dir"/*.proto)
if [[ ${#proto_files[@]} -eq 0 ]]; then
  echo "no .proto files found in $proto_dir" >&2
  exit 1
fi

"$python" -m grpc_tools.protoc \
  --proto_path="$proto_dir" \
  --python_out="$out_dir" \
  "${proto_files[@]}"

# grpcio-tools emits absolute-style imports that would need
# src/pywhats/proto to be on sys.path. Rewrite them to relative
# imports so the package works as-installed.
"$python" - "$out_dir" <<'PY'
import pathlib, re, sys
out = pathlib.Path(sys.argv[1])
pattern = re.compile(r'^import (\w+_pb2) as (\w+)$', re.MULTILINE)
for f in out.glob("*_pb2.py"):
    text = f.read_text()
    new = pattern.sub(r'from . import \1 as \2', text)
    if new != text:
        f.write_text(new)
        print(f"rewrote imports in {f.name}")
PY

echo "done; generated files in $out_dir"
ls -1 "$out_dir"/*_pb2.py
