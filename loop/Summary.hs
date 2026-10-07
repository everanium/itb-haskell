{-# LANGUAGE ScopedTypeVariables #-}

-- | The final summary in both renderings, and the two measurements it
-- folds in that are not per-worker counters: the process resident set
-- and the shared library's pool counters.
module Summary
  ( readRss
  , poolSnapshot
  , SummaryInput (..)
  , finalSummary
  ) where

import Control.Exception (SomeException, try)
import Data.Char (isDigit, ord)
import Data.IORef
import Data.Int (Int64)
import Data.List (intercalate, isPrefixOf)
import System.Environment (lookupEnv)
import Text.Printf (printf)

import qualified ITB3

import Size
import State

-- | The process's current resident set and its high-water mark in
-- bytes, from @\/proc\/self\/status@ (VmRSS and VmHWM, reported in
-- kB). Both are zero on a platform without that file; the figures are
-- informational and never enter the verdict.
readRss :: IO (Int64, Int64)
readRss = do
  res <- try (readFile "/proc/self/status")
  case res of
    Left (_ :: SomeException) -> pure (0, 0)
    Right text ->
      let ls = lines text
          field name = case [l | l <- ls, (name ++ ":") `isPrefixOf` l] of
            (l : _) -> statusKb l
            []      -> 0
      in pure (field "VmRSS", field "VmHWM")

-- | Parses one @Vm...:   1234 kB@ line into bytes; zero on any parse
-- failure.
statusKb :: String -> Int64
statusKb line = case dropWhile (not . isDigit) line of
  "" -> 0
  rest -> case span isDigit rest of
    (digits, _) -> read digits * 1024

-- | Pool counters. The shared library keeps process-wide monotonic
-- totals at every pool checkout of its cipher core: per hash-array
-- tier the starter width, checkouts, constructor misses, regrow
-- replacements and bytes allocated; for the scratch byte pool and the
-- parallax chunk pool the checkouts, constructor misses, regrows and
-- regrow bytes. Two snapshots bracketing the main loop are differenced
-- into per-run hit \/ miss figures that tell whether a pool keeps its
-- items warm between calls or evicts them across GC cycles. The slot
-- layout is read from the library: slot 0 carries the tier count T,
-- tier i occupies the five slots at @1 + 5*i@, and the two byte pools
-- occupy the eight slots at @1 + 5*T@; the buffer is sized from the
-- binding's length query, never from a constant.
poolSnapshot :: IO [Int64]
poolSnapshot = do
  res <- try ITB3.poolStats
  case res of
    Left (_ :: SomeException) -> pure []
    Right v                   -> pure v

-- | One hash-array tier's differenced figures.
data PoolTier = PoolTier
  { ptTier     :: !Int
  , ptStarter  :: !Int64
  , ptGet      :: !Int64
  , ptFresh    :: !Int64
  , ptRegrow   :: !Int64
  , ptNewBytes :: !Int64
  }

-- | One byte pool's differenced figures.
data BytePool = BytePool
  { bpGet         :: !Int64
  , bpFresh       :: !Int64
  , bpRegrow      :: !Int64
  , bpRegrowBytes :: !Int64
  }

emptyPool :: BytePool
emptyPool = BytePool 0 0 0 0

missPercent :: Int64 -> Int64 -> Double
missPercent miss get
  | get <= 0  = 0
  | otherwise = 100 * fromIntegral miss / fromIntegral get

poolDiff :: [Int64] -> [Int64] -> ([PoolTier], BytePool, BytePool)
poolDiff warmup steady
  | length warmup < 9 || length steady < 9 = ([], emptyPool, emptyPool)
  | tiers < 0 || 1 + 5 * fromIntegral tiers + 8 > length steady = ([], emptyPool, emptyPool)
  | otherwise = (reported, buf, chunk)
  where
    tiers = head steady
    t = fromIntegral tiers :: Int
    at xs i = xs !! i
    reported =
      [ PoolTier i (at steady base)
          (at steady (base + 1) - at warmup (base + 1))
          (at steady (base + 2) - at warmup (base + 2))
          (at steady (base + 3) - at warmup (base + 3))
          (at steady (base + 4) - at warmup (base + 4))
      | i <- [0 .. t - 1]
      , let base = 1 + 5 * i
      , at steady base /= 0
      ]
    tail' = 1 + 5 * t
    delta i = at steady (tail' + i) - at warmup (tail' + i)
    buf = BytePool (delta 0) (delta 1) (delta 2) (delta 3)
    chunk = BytePool (delta 4) (delta 5) (delta 6) (delta 7)

-- | The measurements the launcher hands the summary beside the run
-- state.
data SummaryInput = SummaryInput
  { siRun           :: !RunState
  , siStreamProfile :: !String
  , siMsgProfile    :: !String
  , siRssWarmup     :: !Int64
  , siRssPeak       :: !Int64
  , siRssFinal      :: !Int64
  , siPoolWarmup    :: ![Int64]
  , siPoolSteady    :: ![Int64]
  , siGomaxprocs    :: !Int
  , siElapsedNs     :: !Int64
  }

-- | The effective GC percentage as the runtime reports it: the query
-- form of the setter (a set-and-restore round trip inside the library)
-- so the field is the same whether the value came from the flag, the
-- environment, or the runtime default.
effectiveGogc :: Int -> IO Int
effectiveGogc flag
  | flag > 0  = pure flag
  | otherwise = ITB3.setGcPercent (-1)

-- | Renders a string as a JSON string literal with the escapes JSON
-- requires.
jsonString :: String -> String
jsonString s = '"' : concatMap esc s ++ "\""
  where
    esc '"' = "\\\""
    esc '\\' = "\\\\"
    esc '\n' = "\\n"
    esc '\r' = "\\r"
    esc '\t' = "\\t"
    esc c
      | ord c < 0x20 = printf "\\u%04x" (ord c)
      | otherwise = [c]

-- | Output contract. Both renderings are shared with the Go harness
-- and every other binding's loop utility field for field: the same
-- lines in the same order, the same keys in the same order, floats
-- with a fixed number of decimals so the JSON is byte-identical across
-- implementations. The Go harness alone adds its runtime-internal
-- lines after @rss:@ and its runtime-internal keys after
-- @parallax_chunk_pool@; nothing here reproduces them because nothing
-- they read is reachable through the C ABI.
finalSummary :: SummaryInput -> IO Int
finalSummary si = do
  let r = siRun si
      cfg = rsConfig r
      ws = rsWorkers r
  perWorker <- mapM (readIORef . wIters) ws
  encs <- mapM (readIORef . wBytesEnc) ws
  decs <- mapM (readIORef . wBytesDec) ws
  nanosEncs <- mapM (readIORef . wNanosEnc) ws
  nanosDecs <- mapM (readIORef . wNanosDec) ws
  errs <- mapM (readIORef . wError) ws
  rekeys <- readIORef (rsRekeys r)
  cycles <- readIORef (rsBlobCycles r)
  gogc <- effectiveGogc (cfgGogc cfg)
  microbatch <- policyLabel <$> lookupEnv "ITB_MICROBATCH_TIERS"
  starters <- policyLabel <$> lookupEnv "ITB_HASHPOOL_STARTERS"
  autoTier <- either (\(_ :: SomeException) -> "") id <$> try ITB3.drbgAutoTier

  let totalIters = sum perWorker
      totalEnc = sum encs
      totalDec = sum decs
      nanosEnc = sum nanosEncs
      nanosDec = sum nanosDecs
      workers = fromIntegral (cfgWorkers cfg) :: Int64
      -- Throughput. Per-direction throughput divides the sum of every
      -- worker's wall time in that direction by the worker count — the
      -- equivalent single-stream wall time under N-way concurrency —
      -- so each direction reports the aggregate rate it sustained
      -- rather than collapsing to combined/2 (every iteration moves
      -- equal encrypt and decrypt bytes, so a total-elapsed
      -- denominator would give both directions the same figure). The
      -- combined rate keeps total elapsed as the one-glance overall
      -- figure.
      avgEnc = if nanosEnc > 0 then nanosEnc `div` workers else 0
      avgDec = if nanosDec > 0 then nanosDec `div` workers else 0
      failures = [e | Just e <- errs]
      errorCount = length failures
      ok = errorCount == 0
      rssDelta = siRssFinal si - siRssWarmup si
      rssGrowth =
        if siRssWarmup si > 0
          then 100 * fromIntegral rssDelta / fromIntegral (siRssWarmup si)
          else 0 :: Double
      (tiers, buf, chunk) = poolDiff (siPoolWarmup si) (siPoolSteady si)
      elapsed = siElapsedNs si

  if cfgJsonOutput cfg
    then do
      outRaw $ concat
        [ "{", kv "duration_seconds" (printf "%.3f" (fromIntegral elapsed / 1e9 :: Double))
        , ",", kv "iterations" (show totalIters)
        , ",", kv "per_worker_iterations"
                 ("[" ++ intercalate "," (map show perWorker) ++ "]")
        , ",", kv "bytes_encrypted" (show totalEnc)
        , ",", kv "bytes_decrypted" (show totalDec)
        , ",", kv "encrypt_mb_per_sec" (printf "%.1f" (mbPerSec totalEnc avgEnc))
        , ",", kv "decrypt_mb_per_sec" (printf "%.1f" (mbPerSec totalDec avgDec))
        , ",", kv "combined_mb_per_sec"
                 (printf "%.1f" (mbPerSec (totalEnc + totalDec) elapsed))
        , ",", kv "rekeys" (show rekeys)
        , ",", kv "blob_cycles" (show cycles)
        , ",", kv "worker_errors"
                 ("[" ++ intercalate "," (map jsonString failures) ++ "]")
        , ",", kv "verdict" (jsonString (if ok then "PASS" else "FAIL"))
        , ",", kv "shape" (jsonString (shapeName (cfgShape cfg)))
        , ",", kv "stream_profile" (jsonString (siStreamProfile si))
        , ",", kv "message_profile" (jsonString (siMsgProfile si))
        , ",", kv "hash" (jsonString (cfgHash cfg))
        , ",", kv "mac" (jsonString (cfgMac cfg))
        , ",", kv "payload_bytes" (show (cfgPayload cfg))
        , ",", kv "payload_mode" (jsonString (payloadModeName (cfgPayloadMode cfg)))
        , ",", kv "seed" (show (cfgSeed cfg))
        , ",", kv "key_bits" (show (cfgKeyBits cfg))
        , ",", kv "nonce_bits" (show (cfgNonceBits cfg))
        , ",", kv "blob_mode" (show (cfgBlobMode cfg))
        , ",", kv "drbg" (jsonString (cfgDrbg cfg))
        , ",", kv "drbg_auto_tier" (jsonString autoTier)
        , ",", kv "chunk_size_bytes" (show (cfgChunkSize cfg))
        , ",", kv "barrier_fill" (show (cfgBarrierFill cfg))
        , ",", kv "parallax" (jsonString (onOff (cfgParallax cfg)))
        , ",", kv "wrapper" (jsonString (onOff (cfgWrapper cfg)))
        , ",", kv "goroutines_requested" (show (cfgWorkersAsked cfg))
        , ",", kv "goroutines" (show (cfgWorkers cfg))
        , ",", kv "concurrency" (jsonString concurrency)
        , ",", kv "gogc" (jsonString (show gogc))
        , ",", kv "memlimit_bytes" (show (cfgMemlimit cfg))
        , ",", kv "gomaxprocs" (show (siGomaxprocs si))
        , ",", kv "microbatch_tiers" (jsonString microbatch)
        , ",", kv "hashpool_starters" (jsonString starters)
        , ",", kv "rss_warmup_bytes" (show (siRssWarmup si))
        , ",", kv "rss_peak_bytes" (show (siRssPeak si))
        , ",", kv "rss_final_bytes" (show (siRssFinal si))
        , ",", kv "rss_growth_percent" (printf "%.2f" rssGrowth)
        , ",", kv "hash_pool_tiers"
                 ("[" ++ intercalate "," (map tierJson tiers) ++ "]")
        , ",", kv "buf_pool" (poolJson buf)
        , ",", kv "parallax_chunk_pool" (poolJson chunk)
        , "}\n"
        ]
      pure (if ok then 0 else 1)
    else do
      logLine "=== FINAL ==="
      logLine $ "  duration: " ++ humanDuration (roundNs elapsed 1000000)
      logLine $ "  iterations: " ++ intercalate " + " (map show perWorker)
        ++ " = " ++ show totalIters ++ " total"
      logLine $ "  throughput: encrypt " ++ humanRate totalEnc avgEnc
        ++ ", decrypt " ++ humanRate totalDec avgDec
        ++ ", combined " ++ humanRate (totalEnc + totalDec) elapsed
      logLine $ "  bytes: " ++ humanBytes totalEnc ++ " encrypted, "
        ++ humanBytes totalDec ++ " decrypted"
      logLine $ "  data integrity: " ++ show totalIters ++ "/"
        ++ show totalIters ++ " PASS"
      logLine $ "  concurrency: " ++ concurrency ++ ", workers "
        ++ show (cfgWorkers cfg) ++ " (requested "
        ++ show (cfgWorkersAsked cfg) ++ ")"
      logLine $ "  rss: warmup " ++ humanBytes (siRssWarmup si)
        ++ ", peak " ++ humanBytes (siRssPeak si)
        ++ ", final " ++ humanBytes (siRssFinal si)
        ++ " (delta " ++ humanBytesSigned rssDelta ++ ", "
        ++ printf "%.1f" rssGrowth ++ "% growth)"
      mapM_ (logLine . tierLine) tiers
      logLine $ "  buf pool: get " ++ show (bpGet buf) ++ ", regrow "
        ++ show (bpRegrow buf) ++ " (of which fresh " ++ show (bpFresh buf)
        ++ "), miss " ++ printf "%.2f" (missPercent (bpRegrow buf) (bpGet buf))
        ++ "%, " ++ humanBytes (bpRegrowBytes buf) ++ " regrown"
      logLine $ "  parallax chunk pool: get " ++ show (bpGet chunk)
        ++ ", regrow " ++ show (bpRegrow chunk) ++ " (of which fresh "
        ++ show (bpFresh chunk) ++ "), miss "
        ++ printf "%.2f" (missPercent (bpRegrow chunk) (bpGet chunk))
        ++ "%, " ++ humanBytes (bpRegrowBytes chunk) ++ " regrown"
      if rekeys > 0 then logLine ("  rekeys: " ++ show rekeys) else pure ()
      if cycles > 0 then logLine ("  blob cycles: " ++ show cycles) else pure ()
      mapM_ (\e -> logLine ("  ERROR: " ++ e)) failures
      if ok
        then logLine "  verdict: PASS" >> pure 0
        else logLine ("  verdict: FAIL (errors=" ++ show errorCount ++ ")") >> pure 1
  where
    kv k v = jsonString k ++ ":" ++ v
    tierJson t = concat
      [ "{", kv "tier" (show (ptTier t))
      , ",", kv "starter" (show (ptStarter t))
      , ",", kv "get" (show (ptGet t))
      , ",", kv "new" (show (ptFresh t))
      , ",", kv "regrow" (show (ptRegrow t))
      , ",", kv "new_bytes" (show (ptNewBytes t))
      , ",", kv "miss_percent"
               (printf "%.2f" (missPercent (ptFresh t + ptRegrow t) (ptGet t)))
      , "}"
      ]
    poolJson p = concat
      [ "{", kv "get" (show (bpGet p))
      , ",", kv "new" (show (bpFresh p))
      , ",", kv "regrow" (show (bpRegrow p))
      , ",", kv "regrow_bytes" (show (bpRegrowBytes p))
      , ",", kv "miss_percent" (printf "%.2f" (missPercent (bpRegrow p) (bpGet p)))
      , "}"
      ]
    tierLine t = "  hash pool tier " ++ show (ptTier t) ++ " (starter "
      ++ show (ptStarter t) ++ "): get " ++ show (ptGet t) ++ ", miss "
      ++ show (ptFresh t + ptRegrow t) ++ " (new " ++ show (ptFresh t)
      ++ " + regrow " ++ show (ptRegrow t) ++ "), miss "
      ++ printf "%.2f" (missPercent (ptFresh t + ptRegrow t) (ptGet t))
      ++ "%, " ++ humanBytes (ptNewBytes t) ++ " allocated"
