## ITB Haskell Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb3 shared library's `ITB_Triple_*` surface
(`cmd/cshared`), packaged as a cabal library binding `libitb3.so`
through `foreign import ccall`. Every hash-name / MAC-name /
cipher-name / profile-name is an opaque string passed through to Go
for validation — the binding carries no ITB construction logic. The
public surface is a `Pipeline` (init / load / save / rekey /
setMaxWorkers / close, Single Message encrypt / decrypt, whole-buffer
and incremental stream sessions), an opts query-string builder for
init overrides, the profile-record entries `register` /
`lookupProfile` / `profiles` / `inspect`, and the Go runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go ghc cabal-install
cabal update
```

`cabal update` fetches the Hackage index; the test suite pulls
`hspec` from Hackage on first build (the library itself depends only
on `base` and `bytestring`). Generic Linux: any GHC 9.x plus
cabal-install 3.x works. On distributions whose GHC ships static
boot-library archives the `shared:` / `library-vanilla:` knobs in
`cabal.project` are harmless.

## Build

The convenience driver builds `libitb3.so` (only when absent — set
`ITB_REBUILD_LIBITB3=1` to force a Go rebuild) and the cabal package
in one step:

```bash
./bindings/haskell/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared
cd bindings/haskell && cabal build all
```

## Library lookup order

`build.sh` generates a `cabal.project.local` (gitignored) carrying
the absolute `extra-lib-dirs` and an rpath to the repository's
`dist/linux-amd64` directory, so `libitb3.so` resolves at link and
run time; the run scripts additionally export `LD_LIBRARY_PATH` for
robustness. A manual `cabal build` without that file fails at link
time — run `build.sh` first (or write an equivalent
`cabal.project.local`).

## Usage example

```haskell
import ITB3
import qualified Data.ByteString.Char8 as BC

main :: IO ()
main = do
  sender   <- newPipeline "singlemsg-triple-mac-v1"
  blobHere <- save sender
  receiver <- loadPipeline blobHere Nothing

  wire  <- encryptMessage sender (BC.pack "any text or binary data")
  plain <- decryptMessage receiver wire
  print (plain == BC.pack "any text or binary data")

  freePipeline receiver
  freePipeline sender
```

`ITB3.Opts` overrides the profile default at init (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette, worker
cap); an `Opts` is a `Monoid`, so setters compose with `<>`. The
resolved shape travels inside the blob, so the receiver needs no
options of its own:

```haskell
import ITB3.Opts

let opts = chunkSize 65536 <> withWrapper False <> maxWorkers 4
sender   <- initPipeline "singlemsg-triple-mac-v1" opts
b        <- save sender
receiver <- loadPipeline b Nothing
```

`rekey` rotates the parallax + wrapper masters mid-session (the
eight ITB seeds and MAC key are fixed for the session lifetime by
design) and returns the fresh blob; the receiver picks up the new
masters by loading it:

```haskell
rotated  <- rekey sender (BS.replicate 32 0x11) (BS.replicate 32 0x22)
receiver <- loadPipeline rotated Nothing
```

The same rotation is available on the receiver side as a master
override pair on load: `loadPipeline b (Just (perm, wrap))` reopens
the blob with fresh masters folded in.

## Persisting sessions

The blob returned by `save` is a self-describing session bundle: it
carries the resolved profile record, the inner key material, and the
parallax / wrapper masters. `loadPipeline` reconstructs a Pipeline
from it without naming a profile.

```haskell
b         <- save sender                          -- current blob bytes
receiver  <- loadPipeline b Nothing               -- reopen from bytes
saveF sender "session.blob"                       -- write to a file (mode 0600)
receiver2 <- loadPipelineF "session.blob" Nothing -- reopen from a file
profile   <- inspect b                            -- profile record, no Pipeline
-- profile: {"name":"singlemsg-triple-mac-v1","mode":"singlemsg-mac",...}
```

`inspect` decodes the embedded profile record (a JSON object) without
constructing a Pipeline. `saveF` / `loadPipelineF` perform the file
access inside libitb3.

Load works for blobs generated with shipped primitives (every entry in
the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to load such a blob through this
binding throws `ITBError` with `statusRecipePrimitiveUnknown`.

**Runtime tuning.** The worker cap is per-machine and never travels
in the blob; the receiver may pick its own after load (`setMaxWorkers`
— the Init-time opts setter is `maxWorkers` on the `Opts` record):

```haskell
setMaxWorkers receiver 4   -- clamped by libitb3; <= 0 selects auto
```

## Profile registry

`register` installs a user-defined profile under a new name from a
profile JSON record; `lookupProfile` reads a registered record back
(named so because `lookup` is a Prelude function); `profiles` lists
every registered name. The record's field rules are enforced by
libitb3; the binding treats the JSON as an opaque string.

```haskell
register "my-nomac-plain"
  "{\"mode\":\"singlemsg-nomac\",\"width\":512,\"hash\":\"areion512\",\"keybits\":1024,\"wrapper\":false,\"parallax\":false}"
record <- lookupProfile "my-nomac-plain"   -- record with "name" filled in
names  <- profiles                          -- ["blob-triple-mac-v1", ...]
```

A `Pipeline` owns its Go-side handle through a `ForeignPtr`, so an
unreachable Pipeline is released by the Haskell GC; `freePipeline`
releases it deterministically. `Data.ByteString.ByteString` is the
byte-buffer type throughout.

Incremental streaming:

```haskell
pipe <- newPipeline "streaming-noaead-triple-v1"
sess <- encryptStream pipe
writeStream sess part1
writeStream sess part2
wire <- drainAll sess          -- endStream + drain in one call
freeStream sess
```

The explicit loop form is `writeStream` / `endStream` / `readStream`;
`readStream sess maxBytes` returns `(chunk, finished)` and never
blocks before `endStream`. A stream session record carries its parent
`Pipeline` (and the session's finalizer references the Pipeline's
`ForeignPtr`), so the GC cannot free the Pipeline handle while a
session on it is live.

Errors are thrown as `ITBError { statusCode, lastError }` (an
`Exception` instance); callers branch on `statusCode` against the
constants exported by `ITB3.Errors`:

```haskell
r <- try (newPipeline "no-such-profile" Nothing)
case r of
  Left e | statusCode e == statusBadInput -> putStrLn "rejected"
  _ -> pure ()
```

Options are URL-query strings composed monoidally from the typed
setters in `ITB3.Opts` (unknown keys pass through verbatim via the
`opt` escape hatch and are validated by libitb3):

```haskell
pipe <- initPipeline "streaming-aead-triple-mac-v1"
                     (nonceBits 512 <> keyBits 1024 <> chunkSize 65536)
```

`profiles` returns the registered profile name list.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb3 load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass a negative value to
query without changing. Long-running or allocation-heavy workloads
(benchmarks, bulk encryption) should set both — without a soft cap +
aggressive GC the Go scratch heap grows unboundedly under allocation
churn:

```haskell
setMemoryLimit (4 * 1024 * 1024 * 1024) -- 4 GiB soft cap
setGcPercent 100                         -- balanced GC
```

## Testing

```bash
./bindings/haskell/run_tests.sh
```

hspec suite: version and profile-list checks, Single Message and
incremental Streaming round trips, a whole-buffer stream round trip,
a > 1 MiB payload through the pre-allocate/retry path, error mapping
(unknown profile, unknown opts key, tampered wire, closed Pipeline,
duplicate profile registration), rekey blob refresh, save / load
persistence, inspect, the GC parent-pin, and the opts builder
rendering.

## Benchmarking

```bash
./bindings/haskell/run_bench.sh                       # canonical 5 s per case
ITB_BENCH_MIN_SEC=1 ./bindings/haskell/run_bench.sh   # quick smoke
```

Single Message encrypt and incremental Streaming encrypt (No MAC
profiles) at 1 MiB / 16 MiB / 64 MiB, configured through the fleet's
canonical env vars (`ITB_INNER_HASH`, `ITB_KEY_BITS`,
`ITB_NONCE_BITS`, `ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`,
`ITB_PROFILE`, `ITB_BENCH_MIN_SEC`); the harness caps the Go runtime
via `setMemoryLimit (4 * 1024 * 1024 * 1024)` and `setGcPercent 100`. See
`bindings/BENCH.md` for the fleet-wide configuration authority and
comparison tables.

## itb3 CLI

The Go core ships an openssl-style CLI utility
[`itb3`](https://github.com/everanium/itb/tree/main/cmd/itb3/) that generates session blobs on disk
(`itb3 genblob <mode> <hash> -o blob.json`); this binding reopens
such blobs via `loadPipelineF`. `itb3` also encrypts / decrypts
payloads directly on disk (`-i` / `-o`) or through stdin / stdout,
rotates outer masters, and inspects stored blobs. See
[`cmd/itb3/README.md`](https://github.com/everanium/itb/blob/main/cmd/itb3/README.md) for the full
subcommand reference.

## eitb utility

```bash
./bindings/haskell/eitb/eitb version
./bindings/haskell/eitb/eitb profiles
./bindings/haskell/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.itb  2> blob.hex
./bindings/haskell/eitb/eitb decrypt singlemsg-triple-mac-v1 "$(cat blob.hex)" out.itb back.bin
```

`encrypt` prints the session blob to stderr as hex; feed that hex back
to `decrypt` on the receiving side. `decrypt` reopens the session with
`loadPipeline` from the blob hex; the profile argument only selects
the Single Message or streaming cipher pair.

## Limitations

- **Safe FFI calls throughout.** libitb3 hosts a full Go runtime and a
  cipher call can run for a long time, so every import is a `safe`
  ccall — the GHC capability stays free for other Haskell threads and
  GC during a call. The per-call overhead this adds is negligible
  against the buffer copy that each FFI crossing already performs.
- **ByteStrings as buffers.** Inputs cross zero-copy (pinned
  ByteString memory); every output is a freshly allocated ByteString.
  Allocation-sensitive callers should size `readStream` to their
  chunk cadence — a few MiB per drain keeps the FFI call count and
  the allocation churn low on the streaming shape.
- **GC finalizers are a backstop, not a resource plan.** The Haskell
  GC runs finalizers at its own pace; long-lived processes should
  call `freePipeline` / `freeStream` (or `closePipeline`)
  deterministically rather than relying on collection to release
  Go-side sessions.
- **Streaming decrypt caveat.** Chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The binding exposes the Triple Pipeline surface only; the Low-Level
  Go-native configuration surface is not exported.

## License

Apache-2.0 — see [LICENSE](https://github.com/everanium/itb/blob/main/LICENSE).
