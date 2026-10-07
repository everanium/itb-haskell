{-# LANGUAGE ScopedTypeVariables #-}

-- | Shared declarations of the loop stress harness: the
-- cipher-surface selectors, the concurrency mode this binding runs,
-- the resolved configuration, the run state every worker shares, the
-- reader \/ writer lock that keeps iterations clear of handle
-- mutation, and the output helpers every unit writes through.
--
-- Haskell-specific. A module cannot import a module that imports it,
-- and the worker, the maintenance operations and the summary all need
-- the same run state; a declarations unit holding what they share is
-- the same answer the C reference reaches with its header.
module State
  ( -- * Vocabulary
    Shape (..)
  , shapeName
  , parseShape
  , PayloadMode (..)
  , payloadModeName
  , parsePayloadMode
  , maxWorkers
  , concurrency
  , pumpSlice
    -- * Configuration
  , Config (..)
  , defaultConfig
    -- * Run state
  , RunState (..)
  , Worker (..)
  , newRunState
  , newWorker
  , workerFail
  , requestStop
    -- * Reader \/ writer lock
  , RWLock
  , newRWLock
  , withReadLock
  , withWriteLock
    -- * Output
  , logLine
  , errLine
  , errRaw
  , outRaw
  , restoreSigpipe
  , onOff
  , policyLabel
  , errorSentence
  , statusDetail
  ) where

import Control.Concurrent (yield, threadDelay)
import Control.Concurrent.MVar
import Control.Exception (bracket_, SomeException, displayException, fromException)
import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Unsafe as BU
import Data.IORef
import Data.Int (Int64)
import Data.Word (Word64)
import Data.Word (Word8)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import System.IO.Unsafe (unsafePerformIO)
import System.Posix.IO (fdWriteBuf)
import System.Posix.Signals (Handler (Default), installHandler, sigPIPE)
import System.Posix.Types (Fd (..))

import ITB3 (ITBError (..), Pipeline)

-- ── Vocabulary ──────────────────────────────────────────────────────

-- | Cipher surfaces the @--shape@ flag selects.
data Shape
  = ShapeStream          -- ^ session pump: begin \/ write \/ read \/ end
  | ShapeMessage         -- ^ Single Message: one whole-buffer call
  | ShapeStreamOneShot   -- ^ stream surface, one whole-buffer call
  | ShapeBoth            -- ^ all three, rotating by iteration number
  deriving (Eq, Show)

shapeNames :: [(String, Shape)]
shapeNames =
  [ ("stream", ShapeStream)
  , ("message", ShapeMessage)
  , ("stream_one_shot", ShapeStreamOneShot)
  , ("both", ShapeBoth)
  ]

shapeName :: Shape -> String
shapeName s = head [n | (n, v) <- shapeNames, v == s]

parseShape :: String -> Maybe Shape
parseShape s = lookup s shapeNames

-- | Plaintext content policies the @--payload-mode@ flag selects.
--
--   * @fixed@: one CSPRNG-generated buffer per worker, held unchanged
--     for the whole run (the default).
--   * @rotating@: the buffer is regenerated before every iteration, so
--     no two encrypt calls see the same plaintext.
--   * @pattern-zero@ \/ @pattern-ff@: degenerate constant fills (all
--     @0x00@ \/ all @0xFF@) probing minimum-entropy plaintext handling.
--   * @pattern-ascii@: a repeating @\'A\'..\'Z\'@ ramp probing
--     low-entropy structured text.
data PayloadMode
  = PayloadFixed
  | PayloadRotating
  | PayloadPatternZero
  | PayloadPatternFf
  | PayloadPatternAscii
  deriving (Eq, Show)

payloadModeNames :: [(String, PayloadMode)]
payloadModeNames =
  [ ("fixed", PayloadFixed)
  , ("rotating", PayloadRotating)
  , ("pattern-zero", PayloadPatternZero)
  , ("pattern-ff", PayloadPatternFf)
  , ("pattern-ascii", PayloadPatternAscii)
  ]

payloadModeName :: PayloadMode -> String
payloadModeName m = head [n | (n, v) <- payloadModeNames, v == m]

parsePayloadMode :: String -> Maybe PayloadMode
parsePayloadMode s = lookup s payloadModeNames

-- | @--goroutines@ ceiling; the harness targets modest hosts and each
-- worker pins payload-sized buffers for the whole run.
maxWorkers :: Int
maxWorkers = 10

-- | Concurrency mode. This binding runs shared-handle: every foreign
-- import in the binding is @safe@, so the capability is released for
-- the duration of a call and the runtime knows the thread has left
-- Haskell code; @forkIO@ threads on the capabilities @-N@ provides
-- therefore call into one Pipeline handle at the same time, which is
-- what the shared library permits after construction.
concurrency :: String
concurrency = "shared-handle"

-- | Largest slice fed to a stream session per write; the drain after
-- every write uses the same bound.
pumpSlice :: Int
pumpSlice = 1024 * 1024

-- ── Configuration ───────────────────────────────────────────────────

-- | The resolved command line.
data Config = Config
  { cfgDurationNs     :: !Int64        -- ^ ignored when 'cfgIterations' > 0
  , cfgIterations     :: !Int64        -- ^ per-worker count incl. warmup; 0 = duration-based
  , cfgWorkersAsked   :: !Int          -- ^ the @--goroutines@ value as given
  , cfgWorkers        :: !Int          -- ^ the effective worker count
  , cfgShape          :: !Shape
  , cfgHash           :: !String
  , cfgMac            :: !String
  , cfgPayload        :: !Int          -- ^ plaintext bytes per iteration
  , cfgMemlimit       :: !Int64        -- ^ the effective limit once shaped
  , cfgMemlimitAuto   :: !Bool         -- ^ cap only when the runtime has none
  , cfgGogc           :: !Int          -- ^ 0 = leave the runtime default
  , cfgParallax       :: !Bool
  , cfgWrapper        :: !Bool
  , cfgProfile        :: !String       -- ^ empty = shape-based profile pair
  , cfgKeyBits        :: !Int          -- ^ 0 = profile default
  , cfgNonceBits      :: !Int          -- ^ 0 = profile default
  , cfgBlobMode       :: !Int          -- ^ container floor sizing mode: 1 (per-region, default) | 2 (per-container)
  , cfgChunkSize      :: !Int64        -- ^ 0 = profile default
  , cfgBarrierFill    :: !Int          -- ^ 0 = profile default
  , cfgDrbg           :: !String       -- ^ DRBG fill primitive; empty = profile default (auto tier)
  , cfgGomaxprocs     :: !Int          -- ^ 0 = inherit from the environment
  , cfgRekeyEvery     :: !Int64        -- ^ 0 = never
  , cfgBlobCycleEvery :: !Int64        -- ^ 0 = never
  , cfgPayloadMode    :: !PayloadMode
  , cfgSeed           :: !Word64       -- ^ 0 = OS CSPRNG plaintexts
  , cfgJsonOutput     :: !Bool
  , cfgMemprofile     :: !String       -- ^ empty = none
  }

defaultConfig :: Config
defaultConfig = Config
  { cfgDurationNs = 0
  , cfgIterations = 0
  , cfgWorkersAsked = 0
  , cfgWorkers = 0
  , cfgShape = ShapeStream
  , cfgHash = ""
  , cfgMac = ""
  , cfgPayload = 0
  , cfgMemlimit = 0
  , cfgMemlimitAuto = False
  , cfgGogc = 0
  , cfgParallax = True
  , cfgWrapper = True
  , cfgProfile = ""
  , cfgKeyBits = 0
  , cfgNonceBits = 0
  , cfgBlobMode = 1
  , cfgChunkSize = 0
  , cfgBarrierFill = 0
  , cfgDrbg = ""
  , cfgGomaxprocs = 0
  , cfgRekeyEvery = 0
  , cfgBlobCycleEvery = 0
  , cfgPayloadMode = PayloadFixed
  , cfgSeed = 0
  , cfgJsonOutput = False
  , cfgMemprofile = ""
  }

-- ── Reader / writer lock ────────────────────────────────────────────

-- | Handle mutation. Iterations hold the read side for their whole
-- encrypt → decrypt → compare; rekey and blob reopen take the write
-- side, so no cipher call is in flight while a handle's keying changes
-- or the handle itself is swapped, and no encrypt is separated from
-- its decrypt by either.
--
-- Haskell-specific. The standard library offers no reader \/ writer
-- lock, so the semantics are built from the mutual exclusion it does
-- offer: a reader count and a writer flag inside one 'MVar', with a
-- waiting-writer count closing the door to arriving readers so a
-- writer cannot starve, and a yield-then-sleep rather than a spin
-- while waiting.
newtype RWLock = RWLock (MVar LockState)

data LockState = LockState
  { lsReaders :: !Int
  , lsWriting :: !Bool
  , lsWaiting :: !Int
  }

newRWLock :: IO RWLock
newRWLock = RWLock <$> newMVar (LockState 0 False 0)

acquireRead :: RWLock -> IO ()
acquireRead l@(RWLock v) = do
  ok <- modifyMVar v $ \s ->
    if lsWriting s || lsWaiting s > 0
      then pure (s, False)
      else pure (s { lsReaders = lsReaders s + 1 }, True)
  unless ok (yield >> threadDelay 100 >> acquireRead l)

releaseRead :: RWLock -> IO ()
releaseRead (RWLock v) =
  modifyMVar_ v $ \s -> pure s { lsReaders = lsReaders s - 1 }

acquireWrite :: RWLock -> IO ()
acquireWrite (RWLock v) = do
  modifyMVar_ v $ \s -> pure s { lsWaiting = lsWaiting s + 1 }
  go
  where
    go = do
      ok <- modifyMVar v $ \s ->
        if lsWriting s || lsReaders s > 0
          then pure (s, False)
          else pure (s { lsWriting = True, lsWaiting = lsWaiting s - 1 }, True)
      unless ok (yield >> threadDelay 100 >> go)

releaseWrite :: RWLock -> IO ()
releaseWrite (RWLock v) = modifyMVar_ v $ \s -> pure s { lsWriting = False }

-- | Runs the action with the read side held, releasing it however the
-- action leaves.
withReadLock :: RWLock -> IO a -> IO a
withReadLock l = bracket_ (acquireRead l) (releaseRead l)

-- | Runs the action with the write side held.
withWriteLock :: RWLock -> IO a -> IO a
withWriteLock l = bracket_ (acquireWrite l) (releaseWrite l)

-- ── Run state ───────────────────────────────────────────────────────

-- | One worker's private state: its plaintext, its generator, its
-- counters, and the error it stopped on.
data Worker = Worker
  { wId        :: !Int
  , wPlaintext :: !(IORef BS.ByteString)
  , wRng       :: !(IORef Word64)       -- ^ splitmix64 state when seeded
  , wIters     :: !(IORef Int64)
  , wBytesEnc  :: !(IORef Int64)
  , wBytesDec  :: !(IORef Int64)
  , wNanosEnc  :: !(IORef Int64)
  , wNanosDec  :: !(IORef Int64)
  , wError     :: !(IORef (Maybe String))
  }

newWorker :: Int -> IO Worker
newWorker i =
  Worker i <$> newIORef BS.empty <*> newIORef 0 <*> newIORef 0
           <*> newIORef 0 <*> newIORef 0 <*> newIORef 0 <*> newIORef 0
           <*> newIORef Nothing

-- | The state every worker shares: the Pipeline handles, the retained
-- blobs, the lock that keeps iterations clear of handle mutation, the
-- stop request, and the maintenance counts.
data RunState = RunState
  { rsConfig       :: !Config
  , rsStreamPipe   :: !(IORef (Maybe Pipeline))
  , rsMsgPipe      :: !(IORef (Maybe Pipeline))
  , rsStreamName   :: !String
  , rsMsgName      :: !String
    -- | The blob Init handed out, replaced by every rekey; the input
    -- of the next blob reopen. Guarded by 'rsLock'.
  , rsStreamBlob   :: !(IORef BS.ByteString)
  , rsMsgBlob      :: !(IORef BS.ByteString)
  , rsLock         :: !RWLock
  , rsStop         :: !(IORef Bool)
  , rsRekeys       :: !(IORef Int64)
  , rsBlobCycles   :: !(IORef Int64)
  , rsWorkers      :: ![Worker]
    -- | The instant the last worker returned, so elapsed excludes the
    -- wake-up latency of the waiter.
  , rsFinishNs     :: !(IORef Int64)
  }

newRunState :: Config -> String -> String -> IO RunState
newRunState cfg streamName msgName = do
  ws <- mapM newWorker [0 .. cfgWorkers cfg - 1]
  RunState cfg
    <$> newIORef Nothing <*> newIORef Nothing
    <*> pure streamName <*> pure msgName
    <*> newIORef BS.empty <*> newIORef BS.empty
    <*> newRWLock <*> newIORef False
    <*> newIORef 0 <*> newIORef 0
    <*> pure ws <*> newIORef 0

-- | Asks every worker to stop before its next iteration.
requestStop :: RunState -> IO ()
requestStop r = atomicWriteIORef (rsStop r) True

-- | Records the worker's error text (first error wins) and requests a
-- stop of the whole run.
workerFail :: RunState -> Worker -> String -> IO ()
workerFail r w text = do
  atomicModifyIORef' (wError w) $ \old ->
    (maybe (Just text) Just old, ())
  requestStop r

-- ── Output ──────────────────────────────────────────────────────────

-- | Serialises the one write each line takes, so two workers logging
-- maintenance lines at once cannot interleave.
outLock :: MVar ()
outLock = unsafePerformIO (newMVar ())
{-# NOINLINE outLock #-}

-- | Writes the whole buffer to a descriptor in as few write calls as
-- the descriptor allows.
--
-- Haskell-specific. The standard handles buffer and flush on their own
-- schedule, which neither keeps a line and its newline in one write
-- nor lets the failing write happen on the thread that is about to die
-- of it; the descriptor is written directly instead.
writeAll :: Fd -> BS.ByteString -> IO ()
writeAll fd bs = withMVar outLock $ \_ ->
  BU.unsafeUseAsCStringLen bs $ \(p, n) -> go (castPtr p) n
  where
    go :: Ptr Word8 -> Int -> IO ()
    go _ 0 = pure ()
    go p n = do
      wrote <- fromIntegral <$> fdWriteBuf fd p (fromIntegral n)
      if wrote <= 0 then pure () else go (p `plusPtr` wrote) (n - wrote)

-- | Prints one prefixed status line to stdout. The line is assembled
-- with its newline and handed to one write call, so a worker logging a
-- maintenance line from another thread cannot land between a text and
-- the newline that terminates it.
logLine :: String -> IO ()
logLine text = writeAll (Fd 1) (BC.pack ("[loop] " ++ text ++ "\n"))

-- | Prints one prefixed diagnostic to stderr.
errLine :: String -> IO ()
errLine text = writeAll (Fd 2) (BC.pack ("loop: " ++ text ++ "\n"))

-- | Prints an already-composed block to stderr.
errRaw :: String -> IO ()
errRaw = writeAll (Fd 2) . BC.pack

-- | Prints an already-composed line to stdout.
outRaw :: String -> IO ()
outRaw = writeAll (Fd 1) . BC.pack

-- | A consumer that stops reading ends the run. The default
-- disposition for SIGPIPE is restored so the process dies from the
-- signal with status 141 and prints nothing — the reference behaviour,
-- and what anyone piping into head or less expects. The runtime
-- installs its own disposition before any user code runs and the
-- failed write surfaces as an IO exception instead, so restoring the
-- default is an explicit step here rather than something inherited.
restoreSigpipe :: IO ()
restoreSigpipe = do
  _ <- installHandler sigPIPE Default Nothing
  pure ()

onOff :: Bool -> String
onOff b = if b then "on" else "off"

-- | Renders an encoder policy env value for the summary: the raw
-- string when set, "default" when the shipped ladder applies.
policyLabel :: Maybe String -> String
policyLabel Nothing = "default"
policyLabel (Just env) =
  let trimmed = dropWhile (`elem` " \t") env
  in if null trimmed then "default" else trimmed

-- | The sentence a failing call left behind. Nothing is composed here:
-- the library hands over the class of failure and, where there is one,
-- the instance, and that text is printed as it arrived.
errorSentence :: SomeException -> String
errorSentence e = case fromException e of
  Just (ITBError _ msg) -> msg
  Nothing               -> displayException e

-- | The failure detail a log line carries: the numeric status the
-- binding's own surface exposes and the finished sentence the library
-- left behind.
statusDetail :: SomeException -> String
statusDetail e = case fromException e of
  Just (ITBError code msg) -> "status " ++ show code ++ ": " ++ msg
  Nothing                  -> displayException e
