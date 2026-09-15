#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Haskell binding.
# Builds libitb3.so + the cabal package via build.sh, points the
# dynamic loader at the freshly-built shared library, then invokes
# `cabal test`. Positional arguments are forwarded to cabal.

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export LD_LIBRARY_PATH="$DIST_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

exec cabal test --test-show-details=direct "$@"
