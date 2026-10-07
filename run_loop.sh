#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Haskell binding:
# builds the utility's cabal target on first use (or after a clean) and
# execs it with every argument passed through. libitb3.so and the
# binding library are assumed built by build.sh, which also pins the
# link and run-time search paths, so the binary finds the shared
# library through its own rpath and the launcher sets no environment.
#
# The build output is captured rather than discarded: cabal reports its
# progress on stdout and its warnings on stderr, and a redirect of one
# stream alone would let the other join the utility's own output.
# Nothing is printed unless the build fails, in which case everything
# it said is.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

BIN="$(cabal list-bin itb-loop 2>/dev/null || true)"
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    if ! build_log="$(cabal build itb-loop 2>&1)"; then
        printf '%s\n' "$build_log" >&2
        exit 1
    fi
    BIN="$(cabal list-bin itb-loop)"
fi

exec "$BIN" "$@"
