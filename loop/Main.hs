{-# LANGUAGE ScopedTypeVariables #-}

-- | Long-run stress harness. The loop utility holds one Pipeline
-- handle per exercised cipher surface for minutes, hammers it with
-- concurrent encrypt → decrypt → compare round-trips from N worker
-- threads, rotates the outer masters and reopens the handle from its
-- session blob on a schedule, and reports whether the process survived
-- with every byte intact. It is the Haskell binding's counterpart of
-- the Go harness under @tools\/loop@: the same flags, the same round
-- structure, the same summary in both renderings.
--
-- The default shape is full production: the Streaming AEAD profile
-- with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner
-- hash, 1024-bit keys and the profile's 512-bit nonce width, driven
-- through a stream session by three workers for five minutes on 16 MiB
-- plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
-- held for the whole run, so any cross-call state leakage inside the
-- Pipeline surfaces as a data mismatch between workers rather than
-- cancelling out.
--
-- A failure is one of two things. A cipher, rekey or load call that
-- returns a non-OK status is a worker error: the run stops, the summary
-- lists it, the verdict is FAIL and the exit code 1. A round-trip that
-- returns without error but with different bytes is a data mismatch:
-- the process terminates on the spot with exit code 3, printing the
-- worker, the iteration and the first differing offset, and no summary
-- — the state that produced the wrong bytes is the evidence. A crash
-- inside the shared library or the host runtime has no exit code of its
-- own here; surfacing it is what the utility is for.
--
-- Usage:
--
-- >   ./run_loop.sh --duration 5m --goroutines 3 --shape stream \
-- >                 --hash areion512 --mac hmac-blake3 \
-- >                 --payload-size 16MB --memlimit auto \
-- >                 --parallax on --wrapper on
--
-- Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
-- then the partial summary prints.
module Main (main) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar
import Control.Exception (SomeException, finally, try)
import Control.Monad (forM_, unless, when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.IORef
import Data.Int (Int64)
import Data.List (isPrefixOf)
import Data.Maybe (fromMaybe)
import Data.Word (Word64)
import System.Environment (getArgs, lookupEnv)
import System.Exit (ExitCode (ExitFailure, ExitSuccess), exitWith)
import System.Posix.Signals (Handler (Catch), installHandler, sigINT, sigTERM)
import Text.Read (readMaybe)

import qualified ITB3
import ITB3 (Opts, Pipeline)

import Payload (openEntropy)
import Size
import State
import Summary
import Worker (workerMain)

-- | Profiles the shape-based pair is built against when @--profile@ is
-- empty.
defaultStreamProfile, defaultMessageProfile :: String
defaultStreamProfile = "streaming-aead-triple-mac-v1"
defaultMessageProfile = "singlemsg-triple-mac-v1"

-- | The primitive supplied for the parallax palette and the outer
-- cipher when a profile leaves them unnamed. AES-CMAC is PRF-grade, so
-- it is sound outside the Interlocked Barrier, and it is the closest
-- relative of the AES-based inner primitive whose profiles need this
-- fill.
keystreamFillCipher :: String
keystreamFillCipher = "aescmac"

-- ── Flags ───────────────────────────────────────────────────────────

-- | How a flag's value parses, which also decides whether the usage
-- prints a default for it.
data Kind = KInt | KInt64 | KWord64 | KString | KBool
  deriving (Eq)

-- | One command-line flag: its name, the type label the usage prints,
-- the kind that decides how its value parses, its help text, and its
-- default. Values are validated after the whole line is parsed.
data Flag = Flag
  { flName  :: String
  , flLabel :: String
  , flKind  :: Kind
  , flHelp  :: String
  , flDef   :: String
  }

-- | The flag table, in alphabetical order (the order the usage prints).
flags :: [Flag]
flags =
  [ Flag "barrier-fill" "int" KInt
      "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)" "0"
  , Flag "blob-cycle-every" "int" KInt64
      "reopen each pipeline from its session blob every N iterations per worker; 0 = never" "0"
  , Flag "blob-mode" "int" KInt
      "container floor sizing mode: 1 (per-region, default) | 2 (per-container)" "1"
  , Flag "chunk-size" "string" KString
      "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape" "0"
  , Flag "drbg" "string" KString
      "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)" ""
  , Flag "duration" "duration" KString
      "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0" "5m"
  , Flag "gogc" "int" KInt
      "GC trigger percentage; 0 = leave the runtime default" "0"
  , Flag "gomaxprocs" "int" KInt
      "Go runtime GOMAXPROCS override; 0 = inherit from the environment" "0"
  , Flag "goroutines" "int" KInt
      "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1" "3"
  , Flag "hash" "string" KString "inner ITB hash primitive name" "areion512"
  , Flag "iterations" "int" KInt64
      "fixed per-worker iteration count; 0 = duration-based" "0"
  , Flag "json-output" "" KBool
      "print the final summary as one compact JSON object instead of log lines" "false"
  , Flag "key-bits" "int" KInt
      "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)" "0"
  , Flag "mac" "string" KString "MAC primitive name" "hmac-blake3"
  , Flag "memlimit" "string" KString
      "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)" "auto"
  , Flag "memprofile" "string" KString
      "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none" ""
  , Flag "nonce-bits" "int" KInt
      "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)" "0"
  , Flag "parallax" "string" KString "parallax layer: on | off" "on"
  , Flag "payload-mode" "string" KString
      "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii" "fixed"
  , Flag "payload-size" "string" KString
      "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)" "16MB"
  , Flag "profile" "string" KString
      "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair" ""
  , Flag "rekey-every" "int" KInt64
      "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never" "0"
  , Flag "seed" "uint" KWord64
      "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts" "0"
  , Flag "shape" "string" KString
      "cipher surface to exercise: stream | message | stream_one_shot | both" "stream"
  , Flag "wrapper" "string" KString "wrapper layer: on | off" "on"
  ]

usage :: IO ()
usage = errRaw $ "Usage of loop:\n" ++ concatMap one flags
  where
    one f = "  -" ++ flName f ++ label f ++ "\n    \t" ++ flHelp f
      ++ defaultSuffix f ++ "\n"
    label f = if null (flLabel f) then "" else ' ' : flLabel f
    -- Haskell-specific. The default-value suffix is composed by hand;
    -- a flag library that appends its own renders it itself.
    defaultSuffix f
      | flKind f == KInt && flDef f /= "0" = " (default " ++ flDef f ++ ")"
      | flKind f == KString && not (null (flDef f)) =
          " (default \"" ++ flDef f ++ "\")"
      | otherwise = ""

-- | Whether the raw value parses under the flag's kind.
valid :: Kind -> String -> Bool
valid KInt v = maybe False inRange (readMaybe v :: Maybe Integer)
  where inRange n = n <= 2147483647 && n >= -2147483647
-- Haskell-specific. The Read instance of a sized integer wraps a value
-- that does not fit instead of failing, so the range is checked on an
-- unbounded parse rather than inferred from a successful one.
valid KInt64 v = maybe False inRange (readMaybe v :: Maybe Integer)
  where
    inRange n = n <= fromIntegral (maxBound :: Int64)
      && n >= fromIntegral (minBound :: Int64)
valid KWord64 v =
  not ("-" `isPrefixOf` v)
    && maybe False (\n -> n >= 0 && n <= 18446744073709551615)
         (readMaybe v :: Maybe Integer)
valid KString _ = True
valid KBool v = v == "true" || v == "false"

-- | What the command line resolved to: the help path, a rejection with
-- the exit code already reported, or the raw name-to-value pairs.
data Parsed = ParsedHelp | ParsedError Int | ParsedOk [(String, String)]

-- | Parses argv into the raw flag values. Accepts @-name value@,
-- @--name value@, @-name=value@ and @--name=value@; a boolean flag
-- takes no value unless given as @-name=true@ \/ @-name=false@.
parseArgv :: [String] -> IO Parsed
parseArgv = go []
  where
    go acc [] = pure (ParsedOk acc)
    go acc (arg : rest)
      | not ("-" `isPrefixOf` arg) || arg == "-" = do
          errLine $ "unexpected positional arguments: [" ++ arg ++ "]"
          pure (ParsedError 2)
      | name == "h" || name == "help" = usage >> pure ParsedHelp
      | otherwise = case [f | f <- flags, flName f == key] of
          [] -> do
            errLine $ "flag provided but not defined: -" ++ key
            usage
            pure (ParsedError 2)
          (f : _) -> case value f of
            Nothing -> do
              errLine $ "flag needs an argument: -" ++ flName f
              pure (ParsedError 2)
            Just (v, rest')
              | valid (flKind f) v -> go ((flName f, v) : acc) rest'
              | otherwise -> do
                  errLine $ "invalid value \"" ++ v ++ "\" for flag -" ++ flName f
                  pure (ParsedError 2)
      where
        name = if "--" `isPrefixOf` arg then drop 2 arg else drop 1 arg
        (key, eqTail) = break (== '=') name
        value f = case eqTail of
          ('=' : v) -> Just (v, rest)
          _ | flKind f == KBool -> Just ("true", rest)
            | otherwise -> case rest of
                (v : more) -> Just (v, more)
                []         -> Nothing

-- | Rejects the value with the contract's message unless the rule
-- holds.
need :: Bool -> String -> Either String ()
need True _ = Right ()
need False msg = Left msg

-- | The validation stages, in the order the contract fixes. The two
-- that read the library (the hash registry and the profile record)
-- sit between them, so each pure stage ends where an IO question
-- begins.
stageA :: (String -> String) -> Either String (Int64, Int64, Int, Shape)
stageA raw = do
  let durationRaw = raw "duration"
  durationNs <- case parseDuration durationRaw of
    Just d | d > 0 -> Right d
    _ -> Left ("--duration must be positive, got " ++ durationRaw)
  let iterations = int64Of raw "iterations"
  need (iterations >= 0) ("--iterations must be >= 0, got " ++ show iterations)
  let goroutines = intOf raw "goroutines"
  need (goroutines >= 1 && goroutines <= maxWorkers)
    ("--goroutines must be in 1.." ++ show maxWorkers ++ ", got " ++ show goroutines)
  shape <- case parseShape (raw "shape") of
    Just s -> Right s
    Nothing -> Left ("--shape must be stream | message | stream_one_shot | both, got \""
      ++ raw "shape" ++ "\"")
  pure (durationNs, iterations, goroutines, shape)

stageB :: (String -> String) -> Int -> Either String (Int64, Int64, Bool, Int, Bool, Bool)
stageB raw goroutines = do
  let payloadRaw = raw "payload-size"
  payload <- case parseSize payloadRaw of
    Just p -> Right p
    Nothing -> Left ("--payload-size: invalid size \"" ++ payloadRaw ++ "\"")
  need (payload >= 1) "--payload-size must be at least 1 byte"
  let memRaw = raw "memlimit"
      memAuto = memRaw == "auto"
      autoLimit = if goroutines <= 3 then 1073741824 else 268435456
  memlimit <-
    if memAuto
      then Right autoLimit
      else case parseSize memRaw of
        Just m -> Right m
        Nothing -> Left ("--memlimit: invalid size \"" ++ memRaw ++ "\"")
  let gogc = intOf raw "gogc"
  need (gogc >= 0) ("--gogc must be >= 0, got " ++ show gogc)
  parallax <- layer "parallax"
  wrapper <- layer "wrapper"
  pure (payload, memlimit, memAuto, gogc, parallax, wrapper)
  where
    layer name = case raw name of
      "on" -> Right True
      "off" -> Right False
      v -> Left ("--" ++ name ++ " must be on | off, got \"" ++ v ++ "\"")

stageC :: (String -> String) -> Either String (Int, Int, Int, Int, Int64, Int, Int64, Int64, PayloadMode)
stageC raw = do
  let keyBits = intOf raw "key-bits"
  need (keyBits `elem` [0, 512, 1024, 2048])
    ("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got " ++ show keyBits)
  let nonceBits = intOf raw "nonce-bits"
  need (nonceBits `elem` [0, 128, 256, 512])
    ("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got " ++ show nonceBits)
  let blobMode = intOf raw "blob-mode"
  need (blobMode `elem` [1, 2])
    ("--blob-mode must be 1 (per-region) | 2 (per-container), got " ++ show blobMode)
  let barrierFill = intOf raw "barrier-fill"
  need (barrierFill `elem` [0, 1, 2, 4, 8, 16, 32])
    ("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got "
      ++ show barrierFill)
  let chunkRaw = raw "chunk-size"
  chunkSize <- case parseSize chunkRaw of
    Just c -> Right c
    Nothing -> Left ("--chunk-size: invalid size \"" ++ chunkRaw ++ "\"")
  let gomaxprocs = intOf raw "gomaxprocs"
  need (gomaxprocs >= 0)
    ("--gomaxprocs must be > 0 when specified, got " ++ show gomaxprocs)
  let rekeyEvery = int64Of raw "rekey-every"
  need (rekeyEvery >= 0) ("--rekey-every must be >= 0, got " ++ show rekeyEvery)
  let blobEvery = int64Of raw "blob-cycle-every"
  need (blobEvery >= 0) ("--blob-cycle-every must be >= 0, got " ++ show blobEvery)
  pmode <- case parsePayloadMode (raw "payload-mode") of
    Just m -> Right m
    Nothing -> Left ("--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \""
      ++ raw "payload-mode" ++ "\"")
  pure (keyBits, nonceBits, blobMode, barrierFill, chunkSize, gomaxprocs, rekeyEvery, blobEvery, pmode)

intOf :: (String -> String) -> String -> Int
intOf raw n = fromMaybe 0 (readMaybe (raw n))

int64Of :: (String -> String) -> String -> Int64
int64Of raw n = fromMaybe 0 (readMaybe (raw n))

word64Of :: (String -> String) -> String -> Word64
word64Of raw n = fromMaybe 0 (readMaybe (raw n))

-- | Builds the resolved config from argv. @Left@ carries the exit code
-- after the first failing rule has printed @loop: \<message\>@;
-- @Right Nothing@ is the help path.
parseFlags :: [String] -> IO (Either Int (Maybe Config))
parseFlags argv = do
  parsed <- parseArgv argv
  case parsed of
    ParsedHelp -> pure (Right Nothing)
    ParsedError code -> pure (Left code)
    ParsedOk given -> do
      let raw n = fromMaybe (defOf n) (lookup n given)
      case stageA raw of
        Left msg -> reject msg
        Right (durationNs, iterations, goroutines, shape) -> do
          hashOk <- hashRegistered (raw "hash")
          if not hashOk
            then reject ("--hash \"" ++ raw "hash" ++ "\" is not a registered hash primitive")
            else case stageB raw goroutines of
              Left msg -> reject msg
              Right (payload, memlimit, memAuto, gogc, parallax, wrapper) -> do
                narrowed <-
                  if null (raw "profile")
                    then pure (Just shape)
                    else fmap (fmap (narrowShape shape)) (profileSurface (raw "profile"))
                case narrowed of
                  Nothing -> pure (Left 2)
                  Just shape' -> case stageC raw of
                    Left msg -> reject msg
                    Right (keyBits, nonceBits, blobMode, barrierFill, chunkSize, gomaxprocs, rekeyEvery, blobEvery, pmode) ->
                      pure (Right (Just defaultConfig
                        { cfgDurationNs = durationNs
                        , cfgIterations = iterations
                        -- Concurrency mode. This binding runs
                        -- shared-handle, so --goroutines is the thread
                        -- count verbatim, never clamped.
                        , cfgWorkersAsked = goroutines
                        , cfgWorkers = goroutines
                        , cfgShape = shape'
                        , cfgHash = raw "hash"
                        -- Validated by Init: the C ABI enumerates no
                        -- MAC names.
                        , cfgMac = raw "mac"
                        , cfgPayload = fromIntegral payload
                        , cfgMemlimit = memlimit
                        , cfgMemlimitAuto = memAuto
                        , cfgGogc = gogc
                        , cfgParallax = parallax
                        , cfgWrapper = wrapper
                        , cfgProfile = raw "profile"
                        , cfgKeyBits = keyBits
                        , cfgNonceBits = nonceBits
                        , cfgBlobMode = blobMode
                        , cfgChunkSize = chunkSize
                        , cfgBarrierFill = barrierFill
                        -- Validated by Init: the C ABI enumerates no
                        -- DRBG names.
                        , cfgDrbg = raw "drbg"
                        , cfgGomaxprocs = gomaxprocs
                        , cfgRekeyEvery = rekeyEvery
                        , cfgBlobCycleEvery = blobEvery
                        , cfgPayloadMode = pmode
                        , cfgSeed = word64Of raw "seed"
                        , cfgJsonOutput = raw "json-output" == "true"
                        , cfgMemprofile = raw "memprofile"
                        }))
  where
    defOf n = head [flDef f | f <- flags, flName f == n]
    reject msg = errLine msg >> pure (Left 2)

-- | Whether the name is one the shipped hash registry carries, read
-- from the binding's own registry enumeration.
hashRegistered :: String -> IO Bool
hashRegistered name = do
  res <- try ITB3.hashNames
  case res of
    Left (_ :: SomeException) -> pure False
    Right names               -> pure (name `elem` names)

-- | Resolves a registered profile to the shape family its record's
-- mode exposes: a mode beginning with @streaming@ exposes the stream
-- surfaces, one beginning with @singlemsg@ the message surface,
-- @blob-only@ none. Prints the validation message and returns
-- 'Nothing' on rejection.
profileSurface :: String -> IO (Maybe Shape)
profileSurface name = do
  res <- try (ITB3.lookupProfile name)
  case res of
    Left (_ :: SomeException) -> do
      errLine $ "--profile \"" ++ name ++ "\" is not a registered triple profile"
      pure Nothing
    Right json -> do
      let mode = fieldAfter "\"mode\":\"" json
      if "streaming" `isPrefixOf` mode
        then pure (Just ShapeStream)
        else if "singlemsg" `isPrefixOf` mode
          then pure (Just ShapeMessage)
          else do
            errLine $ "--profile \"" ++ name
              ++ "\" carries no cipher surface (blob-only mode)"
            pure Nothing

-- | Applies a @--profile@'s surface to the requested shape: a
-- message-surface profile forces message; a stream-surface profile
-- keeps stream or stream_one_shot as requested and turns message or
-- both into stream.
narrowShape :: Shape -> Shape -> Shape
narrowShape _ ShapeMessage = ShapeMessage
narrowShape ShapeStreamOneShot _ = ShapeStreamOneShot
narrowShape _ _ = ShapeStream

-- ── Profile records ─────────────────────────────────────────────────

-- | The quoted run that follows the needle, or the empty string when
-- the needle is absent.
fieldAfter :: String -> String -> String
fieldAfter needle json = maybe "" (takeWhile (/= '"')) (breakOn needle json)

-- | What follows the needle's first occurrence, or 'Nothing'.
breakOn :: String -> String -> Maybe String
breakOn needle hay
  | needle `isPrefixOf` hay = Just (drop (length needle) hay)
  | null hay = Nothing
  | otherwise = breakOn needle (tail hay)

-- | String value of a key in a profile JSON record, or @-@ when absent
-- or empty. Profile record strings are restricted to @[a-z0-9-]@, so a
-- quoted run is one complete value.
recordStr :: String -> String -> String
recordStr json key = case fieldAfter ("\"" ++ key ++ "\":\"") json of
  "" -> "-"
  v  -> v

-- | Integer value of a key in a profile JSON record; @0@ when absent.
recordInt :: String -> String -> String
recordInt json key = case breakOn ("\"" ++ key ++ "\":") json of
  Nothing -> "0"
  Just rest -> case takeWhile (`elem` "-0123456789") rest of
    "" -> "0"
    v  -> v

-- | Boolean value of a key in a profile JSON record; False when absent.
recordBool :: String -> String -> Bool
recordBool json key =
  maybe False (const True) (breakOn ("\"" ++ key ++ "\":true") json)

-- ── Pipelines ───────────────────────────────────────────────────────

-- | Folds a keystream primitive into opts for any layer the named
-- profile leaves unfilled but the operator asked for.
--
-- A profile built around a primitive that is safe only inside the
-- Interlocked Barrier ships with no parallax palette and no outer
-- cipher: both layers run outside the barrier, where that primitive
-- would stand bare, so the recipe leaves them unnamed rather than
-- naming a primitive that must not key them. Engaging either layer
-- therefore needs a keystream-capable primitive supplied from outside
-- the recipe; without it construction fails on a palette below its
-- minimum or an unnamed outer cipher, and the primitive that most
-- deserves stressing becomes the one that cannot be stressed with
-- those layers engaged.
--
-- Overrides fold into the resolved record the blob carries, so the
-- receiver rebuilds the same shape from the blob alone.
--
-- Haskell-specific. The record is read as JSON text and the two keys
-- are probed by substring: an absent @palette@ or @outer@ key is the
-- unfilled state, since the encoder omits both when unset.
fillKeystreamLayers :: String -> Bool -> Bool -> IO (Maybe (Opts, Bool))
fillKeystreamLayers name wantParallax wantWrapper = do
  res <- try (ITB3.lookupProfile name)
  case res of
    Left (_ :: SomeException) -> do
      errLine $ "--profile \"" ++ name ++ "\" is not a registered triple profile"
      pure Nothing
    Right json -> do
      let hasKey k = maybe False (const True) (breakOn k json)
          palette = wantParallax && not (hasKey "\"palette\":")
          outer = wantWrapper && not (hasKey "\"outer\":")
          segment = palette && not (hasKey "\"segment\":")
          optsPalette
            | palette = ITB3.parallaxPalette
                [keystreamFillCipher, keystreamFillCipher, keystreamFillCipher]
            | otherwise = mempty
          -- A recipe that never carried a palette never carried a
          -- segment size either, and the schedule rejects zero.
          optsSegment = if segment then ITB3.parallaxSegmentSize 4093 else mempty
          optsOuter = if outer then ITB3.outerCipher keystreamFillCipher else mempty
      pure (Just (optsPalette <> optsSegment <> optsOuter, palette || outer))

-- | Prints the construction line with the recipe read back from the
-- blob the Pipeline handed out, not echoed from the flags: every
-- construction override is proven to have reached the library by the
-- value the receiver would see. Record values that are empty (a No MAC
-- profile's MAC, a mixed profile's single hash) print as @-@.
logPipelineInitialised :: String -> BS.ByteString -> IO ()
logPipelineInitialised profile blob = do
  res <- try (ITB3.inspect blob)
  case res of
    Left (e :: SomeException) ->
      logLine $ head' ++ " (inspect: " ++ errorSentence e ++ ")"
    Right json ->
      logLine $ head' ++ " hash=" ++ recordStr json "hash"
        ++ " key-bits=" ++ recordInt json "keybits"
        ++ " nonce-bits=" ++ recordInt json "nonce_bits"
        ++ " barrier-fill=" ++ recordInt json "barrier_fill"
        ++ " chunk-size=" ++ recordInt json "chunk"
        ++ " mac=" ++ recordStr json "mac"
        ++ " parallax=" ++ onOff (recordBool json "parallax")
        ++ " wrapper=" ++ onOff (recordBool json "wrapper")
        ++ (if recordInt json "container_mode" == "2" then " container-mode=2" else "")
        ++ (case recordStr json "drbg" of
              "-" -> ""
              d -> " drbg=" ++ d)
  where
    head' = "pipeline initialised: profile=" ++ profile ++ " blob="
      ++ show (BS.length blob) ++ " bytes"

-- | Constructs one Pipeline against the profile with every
-- flag-carried override in the opts string (zero values included — the
-- shared library treats zero as "profile default"), then obtains the
-- Init blob once through save: the binding's init entry does not hand
-- the blob back, and the bytes are the ones Init produced. Later blob
-- reopens use the retained blob; save is never called again.
buildPipeline :: Config -> String -> IO (Maybe (Pipeline, BS.ByteString))
buildPipeline cfg profile = do
  let base = ITB3.innerHash (cfgHash cfg)
        <> ITB3.macName (cfgMac cfg)
        <> ITB3.withParallax (cfgParallax cfg)
        <> ITB3.withWrapper (cfgWrapper cfg)
        <> ITB3.keyBits (cfgKeyBits cfg)
        <> ITB3.nonceBits (cfgNonceBits cfg)
        <> ITB3.barrierFill (cfgBarrierFill cfg)
        <> ITB3.drbg (cfgDrbg cfg)
        <> ITB3.chunkSize (fromIntegral (cfgChunkSize cfg))
  extra <-
    if null (cfgProfile cfg)
      then pure (Just (mempty, False))
      else fillKeystreamLayers (cfgProfile cfg) (cfgParallax cfg) (cfgWrapper cfg)
  case extra of
    Nothing -> pure Nothing
    Just (fill, filled) -> do
      when filled $
        errLine $ cfgProfile cfg
          ++ " leaves the requested keystream layers unnamed; "
          ++ keystreamFillCipher ++ " supplied for them"
      res <- try (ITB3.initPipeline profile (base <> fill))
      case res of
        Left (e :: SomeException) -> do
          errLine $ "Init(" ++ profile ++ "): " ++ statusDetail e
          pure Nothing
        Right pipe -> do
          saved <- try (ITB3.save pipe)
          case saved of
            Left (e :: SomeException) -> do
              errLine $ "Save(" ++ profile ++ "): " ++ statusDetail e
              ITB3.freePipeline pipe
              pure Nothing
            Right blob
              | cfgBlobMode cfg /= 2 -> do
                  logPipelineInitialised profile blob
                  pure (Just (pipe, blob))
              | otherwise -> do
                  -- The sizing mode is not an Opts knob: the Init blob
                  -- is edited and the pipeline reopened from it, so the
                  -- retained blob (the one blob-cycle reopens from)
                  -- carries the edited mode.
                  ITB3.freePipeline pipe
                  case editInnerBlobMode blob 2 of
                    Nothing -> do
                      errLine "rewrite blob mode: inner blob mode field not found"
                      pure Nothing
                    Just edited -> do
                      reloaded <- try (ITB3.loadPipeline edited Nothing)
                      case reloaded of
                        Left (e :: SomeException) -> do
                          errLine $ "reload Mode 2 blob: " ++ statusDetail e
                          pure Nothing
                        Right pipe' -> do
                          logPipelineInitialised profile edited
                          pure (Just (pipe', edited))

-- | Sets the inner blob's @mode@ field of a wrap-layer session blob to
-- the target mode (1 = per-region, 2 = per-container). The wrap
-- layer's profile record carries its own @mode@ (a string), so the
-- search starts at the inner blob (@ib@); both shipped modes are one
-- digit wide, so the blob length does not change. 'Nothing' when the
-- inner blob or its mode field is not found.
--
-- Haskell-specific. The binding carries no JSON library and reads
-- profile records by targeted string handling, so the edit replaces
-- the single digit in place rather than re-serialising the blob.
editInnerBlobMode :: BS.ByteString -> Int -> Maybe BS.ByteString
editInnerBlobMode blob target = do
  let (pre, fromIb) = BC.breakSubstring (BC.pack "\"ib\":{") blob
  if BS.null fromIb then Nothing else Just ()
  let ibLen = BS.length pre + 6
      (preMode, fromMode) = BC.breakSubstring (BC.pack "\"mode\":") (BS.drop ibLen blob)
  if BS.null fromMode then Nothing else Just ()
  let at = ibLen + BS.length preMode + 7
      isDigit c = c >= '0' && c <= '9'
  if at + 1 < BS.length blob
       && BC.index blob at >= '1' && BC.index blob at <= '2'
       && not (isDigit (BC.index blob (at + 1)))
    then Just (BS.concat [BS.take at blob, BC.singleton (head (show target)), BS.drop (at + 1) blob])
    else Nothing

-- | Builds the Pipeline for a surface the shape exercises. The outer
-- 'Nothing' is a construction failure; the inner one is a surface this
-- shape does not build.
buildFor :: Bool -> Config -> String -> IO (Maybe (Maybe (Pipeline, BS.ByteString)))
buildFor False _ _ = pure (Just Nothing)
buildFor True cfg name = fmap Just <$> buildPipeline cfg name

-- ── Run ─────────────────────────────────────────────────────────────

run :: [String] -> IO Int
run argv = do
  parsed <- parseFlags argv
  case parsed of
    Left code -> pure code
    Right Nothing -> pure 0
    Right (Just cfg0) -> do
      -- Runtime shaping. A long run under allocation churn grows the Go
      -- heap inside the shared library without bound unless a soft
      -- limit paces the collector, so a limit is always in force: an
      -- explicit --memlimit is set as given, and auto caps the heap
      -- only when the runtime reports no limit at all (a limit already
      -- installed from the environment is left standing). The GC
      -- percentage and GOMAXPROCS are set only when their flag is
      -- non-zero — a zero flag skips the setter rather than calling it
      -- with zero, because zero is a real value to the GC-percent
      -- setter, and a call would clobber whatever the environment
      -- installed. All of it lands before any Pipeline exists so the
      -- baselines are taken under the shaped runtime, in the order heap
      -- limit, GC percent, GOMAXPROCS.
      if cfgMemlimitAuto cfg0
        then do
          inForce <- ITB3.setMemoryLimit (-1)
          when (inForce == maxBound) (() <$ ITB3.setMemoryLimit (cfgMemlimit cfg0))
        else () <$ ITB3.setMemoryLimit (cfgMemlimit cfg0)
      effective <- ITB3.setMemoryLimit (-1)
      when (cfgGogc cfg0 > 0) (() <$ ITB3.setGcPercent (cfgGogc cfg0))
      when (cfgGomaxprocs cfg0 > 0) (() <$ ITB3.setGomaxprocs (cfgGomaxprocs cfg0))
      let cfg = cfg0 { cfgMemlimit = effective }

      microbatch <- policyLabel <$> lookupEnv "ITB_MICROBATCH_TIERS"
      starters <- policyLabel <$> lookupEnv "ITB_HASHPOOL_STARTERS"
      logLine $ "start: duration=" ++ humanDuration (cfgDurationNs cfg)
        ++ " iterations=" ++ show (cfgIterations cfg)
        ++ " goroutines=" ++ show (cfgWorkersAsked cfg)
        ++ " workers=" ++ show (cfgWorkers cfg)
        ++ " concurrency=" ++ concurrency
        ++ " shape=" ++ shapeName (cfgShape cfg)
        ++ " hash=" ++ cfgHash cfg ++ " mac=" ++ cfgMac cfg
        ++ " payload=" ++ humanBytes (fromIntegral (cfgPayload cfg))
        ++ " memlimit=" ++ humanBytes (cfgMemlimit cfg)
        ++ " parallax=" ++ onOff (cfgParallax cfg)
        ++ " wrapper=" ++ onOff (cfgWrapper cfg)
      logLine $ "overrides: profile=\"" ++ cfgProfile cfg ++ "\""
        ++ " key-bits=" ++ show (cfgKeyBits cfg)
        ++ " nonce-bits=" ++ show (cfgNonceBits cfg)
        ++ " chunk-size=" ++ humanBytes (cfgChunkSize cfg)
        ++ " barrier-fill=" ++ show (cfgBarrierFill cfg)
        ++ " gomaxprocs=" ++ show (cfgGomaxprocs cfg)
        ++ " rekey-every=" ++ show (cfgRekeyEvery cfg)
        ++ " blob-cycle-every=" ++ show (cfgBlobCycleEvery cfg)
        ++ " payload-mode=" ++ payloadModeName (cfgPayloadMode cfg)
        ++ " seed=" ++ show (cfgSeed cfg)
        ++ " json-output=" ++ (if cfgJsonOutput cfg then "true" else "false")
        ++ (if cfgBlobMode cfg /= 1 then " blob-mode=" ++ show (cfgBlobMode cfg) else "")
        ++ (if null (cfgDrbg cfg) then "" else " drbg=" ++ cfgDrbg cfg)
      logLine $ "policy: microbatch-tiers=" ++ microbatch
        ++ " hashpool-starters=" ++ starters

      -- Pipeline construction — one shared handle per exercised shape.
      -- stream and stream_one_shot share the streaming handle.
      let streamName = if null (cfgProfile cfg) then defaultStreamProfile else cfgProfile cfg
          msgName = if null (cfgProfile cfg) then defaultMessageProfile else cfgProfile cfg
          wantStream = cfgShape cfg `elem` [ShapeStream, ShapeStreamOneShot, ShapeBoth]
          wantMsg = cfgShape cfg `elem` [ShapeMessage, ShapeBoth]
      streamBuilt <- buildFor wantStream cfg streamName
      case streamBuilt of
        Nothing -> pure 1
        Just mStream -> do
          msgBuilt <- buildFor wantMsg cfg msgName
          case msgBuilt of
            Nothing -> pure 1
            Just mMsg -> do
              r <- newRunState cfg streamName msgName
              forM_ mStream $ \(p, b) -> do
                writeIORef (rsStreamPipe r) (Just p)
                writeIORef (rsStreamBlob r) b
              forM_ mMsg $ \(p, b) -> do
                writeIORef (rsMsgPipe r) (Just p)
                writeIORef (rsMsgBlob r) b
              probe <- poolSnapshot
              if null probe
                then errLine "pool snapshot alloc failed" >> pure 1
                else driveRun r
                  (if wantStream then streamName else "")
                  (if wantMsg then msgName else "")

-- | The four phases after construction: warmup barrier, main loop,
-- shutdown, summary.
driveRun :: RunState -> String -> String -> IO Int
driveRun r streamLabel msgLabel = do
  let cfg = rsConfig r
      n = cfgWorkers cfg

  -- Graceful stop. SIGINT / SIGTERM set the run's stop request, which
  -- every worker checks before starting an iteration, so a signal
  -- interrupts nothing mid-call — the in-flight encrypt / decrypt /
  -- compare completes, the worker returns, and the partial summary
  -- prints with the verdict the completed iterations earned.
  _ <- installHandler sigINT (Catch (requestStop r)) Nothing
  _ <- installHandler sigTERM (Catch (requestStop r)) Nothing

  arrived <- newIORef (0 :: Int)
  returned <- newIORef (0 :: Int)
  gate <- newEmptyMVar

  -- Warmup barrier. Every worker runs one iteration and arrives; the
  -- clock starts only once all of them have paid their first-call costs
  -- (pool warm-up, lazy kernel dispatch, page faults on the payload
  -- buffers), and the RSS and pool baselines taken here describe a
  -- process that has already run the whole cipher path once per worker.
  -- A worker that gives up still arrives, from the handler below, so
  -- the launcher never waits on a rendezvous that can no longer happen.
  warmupStart <- nowNs
  forM_ (rsWorkers r) $ \w -> do
    seen <- newIORef False
    let arrive = do
          already <- atomicModifyIORef' seen (\v -> (True, v))
          unless already (atomicModifyIORef' arrived (\v -> (v + 1, ())))
    _ <- forkIO $
      (do res <- try (workerMain r w arrive (readMVar gate))
          case res of
            Left (e :: SomeException) ->
              workerFail r w ("g" ++ show (wId w) ++ ": worker thread: "
                ++ errorSentence e)
            Right () -> pure ())
      `finally` do
        arrive
        now <- nowNs
        atomicModifyIORef' (rsFinishNs r) (\v -> (max v now, ()))
        atomicModifyIORef' returned (\v -> (v + 1, ()))
    pure ()
  waitFor arrived n
  (rssWarmup, rssPeak0) <- readRss
  poolWarmup <- poolSnapshot
  warmupNs <- (\now -> now - warmupStart) <$> nowNs
  logLine $ "warmup: " ++ show n ++ " workers x 1 iter completed in "
    ++ humanDuration (roundNs warmupNs 100000000)
    ++ " (baseline rss=" ++ humanBytes rssWarmup ++ ")"

  -- Open the gate; the deadline below asks the workers to stop in
  -- duration mode.
  startNs <- nowNs
  atomicModifyIORef' (rsFinishNs r) (\_ -> (startNs, ()))
  putMVar gate ()
  waitLoop r returned n startNs
  finishNs <- readIORef (rsFinishNs r)
  let elapsedNs = max 0 (finishNs - startNs)

  (rssFinal, peak) <- readRss
  poolSteady <- poolSnapshot

  unless (null (cfgMemprofile cfg)) $ do
    res <- try (ITB3.writeHeapProfile (cfgMemprofile cfg))
    case res of
      Left (e :: SomeException) -> errLine $ "memprofile: " ++ errorSentence e
      Right () -> logLine $ "memprofile: heap profile written to "
        ++ cfgMemprofile cfg

  gomaxprocs <- ITB3.setGomaxprocs 0
  finalSummary SummaryInput
    { siRun = r
    , siStreamProfile = streamLabel
    , siMsgProfile = msgLabel
    , siRssWarmup = rssWarmup
    , siRssPeak = max rssPeak0 peak
    , siRssFinal = rssFinal
    , siPoolWarmup = poolWarmup
    , siPoolSteady = poolSteady
    , siGomaxprocs = gomaxprocs
    , siElapsedNs = elapsedNs
    }

-- | Waits until the counter reaches the target.
waitFor :: IORef Int -> Int -> IO ()
waitFor ref target = go
  where
    go = do
      v <- readIORef ref
      unless (v >= target) (threadDelay 2000 >> go)

-- | Waits for every worker, polling every 100 ms so the deadline and a
-- signal are both noticed promptly.
waitLoop :: RunState -> IORef Int -> Int -> Int64 -> IO ()
waitLoop r returned n startNs = go
  where
    cfg = rsConfig r
    go = do
      done <- readIORef returned
      unless (done >= n) $ do
        now <- nowNs
        when (cfgIterations cfg == 0 && now - startNs >= cfgDurationNs cfg)
          (requestStop r)
        threadDelay 100000
        go

main :: IO ()
main = do
  restoreSigpipe
  openEntropy
  argv <- getArgs
  code <- run argv
  exitWith (if code == 0 then ExitSuccess else ExitFailure code)
