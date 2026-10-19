#!/bin/sh
set -eu

zig=${1:?pass the Zig 0.14.1 executable}
headers=${2:?pass the private generated headers directory}
output_dir=${3:?pass a new output directory}
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir "$output_dir"

for stage in dual triple; do
    source="$base/source/p1_${stage}_gate_200.c"
    for mode in verify_orig apply verify_patch restore; do
        output="libcodex_p1_${stage}_gate_${mode}_template_200.so"
        case "$mode" in
            verify_orig) set -- -DP1_VERIFY_ONLY ;;
            apply) set -- ;;
            verify_patch) set -- -DP1_VERIFY_ONLY -DP1_RESTORE_ORIGINAL ;;
            restore) set -- -DP1_RESTORE_ORIGINAL ;;
        esac
        "$zig" cc -target aarch64-linux-gnu -O2 -fPIC -ffreestanding \
            -fno-stack-protector -fno-builtin -nostdlib -shared -s \
            -I "$headers" "$@" "-Wl,-soname,$output" \
            -o "$output_dir/$output" "$source"
    done
done
