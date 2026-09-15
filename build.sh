#!/usr/bin/env bash
#
# build.sh -- one-step build for the Haskell binding: libitb3.so
# (only when absent — set ITB_REBUILD_LIBITB3=1 to force a Go rebuild)
# plus the cabal package (library, tests, bench, eitb executable).
# Prerequisites (Go, ghc, cabal-install) must be installed separately;
# see README.md "Prerequisites".
#
# The build starts by removing every artefact this binding owns, so no
# output of an earlier build can survive into this one and mask a
# breakage. ITB_SKIP_CLEAN=1 keeps the tree for fast iteration.
#
# Usage:
#   ./build.sh                       # default build (full asm stack)
#   ./build.sh --noitbasm            # opt out of ITB's SIMD asm kernels
#   ITB_SKIP_CLEAN=1 ./build.sh      # incremental build, no wipe

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

# ---------------------------------------------------------------------
# Artefact wipe.
#
# ARTEFACTS names what this binding generates. Inside a git work tree
# the list is supplemented from `git ls-files --others --ignored`, which
# enumerates exactly the paths .gitignore covers and by construction can
# never name a tracked one. Every candidate is canonicalised and refused
# unless it resolves inside this binding's own directory -- `dist` below
# is this binding's own cabal output, never the repo's shared
# dist/linux-amd64.
#
# The Hackage dependency store lives outside the repository and is left
# alone; only this package's own build products are removed.
# ---------------------------------------------------------------------
ARTEFACTS=(
    dist-newstyle
    dist
    .stack-work
    cabal.project.local
    'cabal.project.local~'
    '.ghc.environment.*'
    '*.hi'
    '*.o'
)

# Containment is checked against the physical path, so the candidate
# and the root are canonicalised the same way even when the checkout is
# reached through a symlinked directory.
CLEAN_ROOT="$(readlink -m -- "$SCRIPT_DIR")"

rm_artefact() {
    local rel="$1" abs
    abs="$(readlink -m -- "$CLEAN_ROOT/$rel")"
    case "$abs" in
        "$CLEAN_ROOT"/?*) ;;
        *) echo "clean: '$rel' resolves outside $CLEAN_ROOT ($abs)" >&2
           exit 1 ;;
    esac
    [ -e "$abs" ] || return 0
    echo "[clean] rm -rf $abs"
    rm -rf -- "$abs"
}

clean_artefacts() {
    local entry match
    shopt -s nullglob
    for entry in "${ARTEFACTS[@]}"; do
        for match in "$CLEAN_ROOT"/$entry; do
            rm_artefact "${match#"$CLEAN_ROOT"/}"
        done
    done
    shopt -u nullglob
    # The work-tree probe silences stderr because a source tarball
    # carries no git metadata; there the ARTEFACTS list stands alone.
    if git -C "$CLEAN_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1
    then
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            # A dot-prefixed .md is a private note kept out of the index
            # by the global ignore file, not build output.
            case "${entry##*/}" in .*.md) continue;; esac
            rm_artefact "$entry"
        done < <(git -C "$CLEAN_ROOT" ls-files --others --ignored \
                     --exclude-standard --directory)
    fi
}

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

if [ "${ITB_SKIP_CLEAN:-0}" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 -- keeping existing build artefacts"
else
    echo "==> removing build artefacts"
    clean_artefacts
fi

if [[ ! -f "$DIST_DIR/libitb3.so" || "${ITB_REBUILD_LIBITB3:-0}" == "1" || ${#TAGS[@]} -gt 0 ]]; then
    echo "==> building libitb3.so${TAGS:+ (with ${TAGS[*]})}"
    (cd "$REPO_ROOT" && go build -trimpath ${TAGS[@]+"${TAGS[@]}"} \
        -buildmode=c-shared -o dist/linux-amd64/libitb3.so ./cmd/cshared)
fi

# Pin the link and run-time search paths to the freshly-built dist
# directory. cabal.project.local is generated (gitignored) so the
# absolute path never lands in a committed file.
cat > cabal.project.local <<EOF
package libitb3
    extra-lib-dirs: $DIST_DIR
    ghc-options: -optl-Wl,-rpath,$DIST_DIR
EOF

export LD_LIBRARY_PATH="$DIST_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

echo "==> building Haskell binding (cabal build)"
cabal build all --enable-tests --enable-benchmarks

# `cabal build all` covers every component, the itb-eitb executable
# included. The binary is invoked here through cabal list-bin rather
# than through eitb/eitb, because that launcher re-enters this script
# when the binary is missing.
echo "==> eitb"
"$(cabal list-bin itb-eitb)" version

echo "==> ready: ./run_tests.sh"
