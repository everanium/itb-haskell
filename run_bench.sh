#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the Haskell binding.
# Builds libitb3.so + the cabal package via build.sh, then runs the
# itb-bench harness: Single Message encrypt and incremental Streaming
# encrypt throughput at 1 MiB / 16 MiB / 64 MiB.
#
# Usage:
#   ./run_bench.sh                       # canonical 5 s per case
#   ITB_BENCH_MIN_SEC=1 ./run_bench.sh   # quick smoke

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export LD_LIBRARY_PATH="$DIST_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# Bench-hostile Go runtime defaults are capped at libitb3 load time via
# env vars so a bench crash before the harness's own setMemoryLimit /
# setGcPercent calls still runs under a bounded heap. The harness
# reasserts these via the API for self-contained reproducibility.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-4GiB}"
export ITB_GOGC="${ITB_GOGC:-100}"

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# baseline. Override any of these before calling the script to change
# the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

# ITB_WITH_MAC=true derives MAC/AEAD profile counterparts. When
# ITB_PROFILE is set explicitly by the caller, it wins over the
# derivation and applies to both shapes (expert override).
: "${ITB_WITH_MAC:=false}"
if [ -n "${ITB_PROFILE:-}" ]; then
    ITB_MSG_PROFILE_DEFAULT="${ITB_PROFILE}"
    ITB_STREAM_PROFILE_DEFAULT="${ITB_PROFILE}"
elif [ "${ITB_WITH_MAC}" = "true" ]; then
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-mac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-aead-triple-mac-v1"
else
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-nomac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-noaead-triple-v1"
fi

BENCH_BIN="$(cabal list-bin itb-bench)"

# itb-bench reads ITB_MSG_PROFILE for the Message shape and
# ITB_STREAM_PROFILE for the Stream shape independently, so both
# shapes run in a single process regardless of whether they share a
# profile. Any caller-supplied ITB_MSG_PROFILE / ITB_STREAM_PROFILE
# wins over the per-shape defaults derived above.
export ITB_MSG_PROFILE="${ITB_MSG_PROFILE:-$ITB_MSG_PROFILE_DEFAULT}"
export ITB_STREAM_PROFILE="${ITB_STREAM_PROFILE:-$ITB_STREAM_PROFILE_DEFAULT}"
exec "$BENCH_BIN"
