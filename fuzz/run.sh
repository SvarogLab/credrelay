#!/bin/sh
# Builds a fuzz target and runs it for a while, keeping everything it builds and finds under the
# workspace's build directory: cargo fuzz itself would write its corpus, crashes and lockfile into
# fuzz/.
#
#   fuzz/run.sh <target> [seconds]    (default 60)
set -eu

target=${1:?usage: fuzz/run.sh <target> [seconds]}
seconds=${2:-60}
fuzz_dir=$(cd "$(dirname "$0")" && pwd)
out=${CARGO_TARGET_DIR:-$fuzz_dir/../target}/fuzz
host=$(rustc +nightly -vV | sed -n 's/^host: //p')

CARGO_RESOLVER_LOCKFILE_PATH=$out/Cargo.lock \
    cargo +nightly fuzz build --fuzz-dir "$fuzz_dir" --target-dir "$out" "$target"
mkdir -p "$out/corpus/$target" "$out/artifacts/$target"
"$out/$host/release/$target" -max_total_time="$seconds" \
    -artifact_prefix="$out/artifacts/$target/" "$out/corpus/$target"
