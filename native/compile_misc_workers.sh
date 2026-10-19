#!/bin/sh
set -eu

zig=${1:?pass the Zig 0.14.1 executable}
headers=${2:?pass the private generated headers directory}
output_dir=${3:?pass a new output directory}
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir "$output_dir"

"$zig" cc -target aarch64-linux-gnu -O2 -fPIC -shared -s \
    -Wl,-soname,libcodex_update_code_hold200.so \
    -o "$output_dir/update_hold.so" "$base/source/update_code_hold_200.c"
"$zig" cc -target aarch64-linux-gnu -O2 -fPIC -shared -s \
    -I "$headers" -Wl,-soname,libcodex_cp_fl23_bk4_files_200.so \
    -o "$output_dir/bk4_full.so" "$base/source/bk4_commit_200.c"
"$zig" cc -target aarch64-linux-gnu -O2 -fPIC -shared \
    -o "$output_dir/cp_read.so" "$base/source/cp_color_read_200.c"
"$zig" cc -target aarch64-linux-gnu -O2 -fPIC -shared -DRESTORE=0 \
    -I "$headers" -o "$output_dir/cp_apply_full.so" \
    "$base/source/cp_color_apply_200.c"
