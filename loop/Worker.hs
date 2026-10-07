{-# LANGUAGE ScopedTypeVariables #-}

-- | The worker: its thread body (one warmup iteration, the warmup
-- barrier, the main loop), one iteration, the session pump loop the
-- stream shape drives, and the round-trip comparison that decides
-- between a worker error and a data mismatch.
module Worker
  ( workerMain
  ) where

import Control.Exception (SomeException, try)
import Control.Monad (unless, when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as BL
import Data.IORef
import Data.Int (Int64)
import Numeric (showHex)
import System.Exit (ExitCode (ExitFailure))
import System.Posix.Process (exitImmediately)

import qualified ITB3
import ITB3 (Pipeline)

import Ops (workerMaintenance)
import Payload (fillPayload, seedWorker)
import Size (nowNs)
import State

-- | Pump loop. The Go harness hands ITB an @io.Reader@ \/ @io.Writer@
-- pair and ITB drives the chunk loop internally; the C ABI has no
-- reader \/ writer entry, so the caller drives it: open a session,
-- feed slices of at most 1 MiB, drain whatever the session has
-- produced after every write (a read before end never blocks), end,
-- then drain until the session reports finished (after end, a read on
-- an empty spool blocks until the terminal bytes arrive). The loop is
-- written here rather than delegated to the binding's drain
-- convenience so it stands in the utility, at the same place, in every
-- language.
pump :: Pipeline -> Bool -> BS.ByteString -> IO BS.ByteString
pump pipe encrypt src
  | encrypt = ITB3.encryptStream pipe >>= drive
  | otherwise = ITB3.decryptStream pipe >>= drive
  where
    drive :: ITB3.StreamSession s => s -> IO BS.ByteString
    drive session = do
      out <- newIORef mempty
      feed session out src
      ITB3.endStream session
      final session out
      ITB3.freeStream session
      BL.toStrict . BB.toLazyByteString <$> readIORef out
    feed session out rest
      | BS.null rest = pure ()
      | otherwise = do
          let (slice, more) = BS.splitAt pumpSlice rest
          ITB3.writeStream session slice
          drain session out
          feed session out more
    drain session out = do
      (chunk, _) <- ITB3.readStream session pumpSlice
      unless (BS.null chunk) $ do
        modifyIORef' out (<> BB.byteString chunk)
        drain session out
    final session out = do
      (chunk, finished) <- ITB3.readStream session pumpSlice
      unless (BS.null chunk) (modifyIORef' out (<> BB.byteString chunk))
      unless finished (final session out)

-- | First offset at which the two differ; the shorter length when one
-- is a prefix of the other.
firstDifference :: BS.ByteString -> BS.ByteString -> Int
firstDifference a b = go 0
  where
    n = min (BS.length a) (BS.length b)
    go i
      | i >= n = n
      | BS.index a i /= BS.index b i = i
      | otherwise = go (i + 1)

-- | Up to 16 bytes of the buffer from the offset as lowercase hex, or
-- @-@ when the buffer has no bytes there.
hexWindow :: BS.ByteString -> Int -> String
hexWindow buf off
  | off >= BS.length buf = "-"
  | otherwise = concatMap byteHex (BS.unpack (BS.take 16 (BS.drop off buf)))
  where
    byteHex v = let h = showHex v "" in if length h < 2 then '0' : h else h

-- | Records a worker error for a failed cipher call.
cipherFail :: RunState -> Worker -> Int64 -> Shape -> String -> SomeException -> IO ()
cipherFail r w iter shape direction e =
  workerFail r w $ "g" ++ show (wId w) ++ " iter " ++ show iter
    ++ " shape=" ++ shapeName shape ++ ": " ++ direction ++ ": "
    ++ statusDetail e

-- | Shape dispatch. @message@ is one whole-buffer call on the Single
-- Message Pipeline; @stream_one_shot@ is one whole-buffer call on the
-- streaming Pipeline (the C ABI's @ITB_Triple_EncryptStream@, which
-- routes to the same one-shot stream entry the Go harness calls by
-- name); @stream@ opens a session on the same streaming Pipeline and
-- drives the chunk loop from here. Under @both@ the three rotate by
-- iteration number so the session path and the whole-buffer path
-- alternate on one handle inside every worker — the cross-path
-- state-reuse hazard this harness exists to catch.
surfaceFor :: Shape -> Int64 -> Shape
surfaceFor ShapeBoth iter = case iter `mod` 3 of
  0 -> ShapeStream
  1 -> ShapeMessage
  _ -> ShapeStreamOneShot
surfaceFor shape _ = shape

-- | One iteration. In order: refill the plaintext under rotating mode;
-- take the read lock; pick the surface; encrypt (timed); decrypt
-- (timed); compare the round-trip with the plaintext; bump the
-- counters; release the lock. The whole round-trip runs under the read
-- lock so handle-mutating maintenance (rekey, blob reopen) never lands
-- between an encrypt and its matching decrypt — maintenance runs after
-- this returns, from the worker loop. Returns False after recording
-- the worker error.
iterate1 :: RunState -> Worker -> Int64 -> IO Bool
iterate1 r w iter = do
  let cfg = rsConfig r
  when (cfgPayloadMode cfg == PayloadRotating) $ do
    fresh <- fillPayload PayloadRotating (cfgSeed cfg /= 0) (wRng w) (cfgPayload cfg)
    writeIORef (wPlaintext w) fresh
  plain <- readIORef (wPlaintext w)
  let shape = surfaceFor (cfgShape cfg) iter
  withReadLock (rsLock r) $ do
    held <- handleFor r shape
    case held of
      Nothing -> do
        workerFail r w $ "g" ++ show (wId w) ++ " iter " ++ show iter
          ++ " shape=" ++ shapeName shape ++ ": no pipeline for this surface"
        pure False
      Just pipe -> do
        t0 <- nowNs
        encResult <- try (encryptWith shape pipe plain)
        case encResult of
          Left (e :: SomeException) -> cipherFail r w iter shape "encrypt" e >> pure False
          Right wire -> do
            t1 <- nowNs
            atomicModifyIORef' (wNanosEnc w) (\v -> (v + (t1 - t0), ()))
            decResult <- try (decryptWith shape pipe wire)
            case decResult of
              Left (e :: SomeException) -> cipherFail r w iter shape "decrypt" e >> pure False
              Right got -> do
                t2 <- nowNs
                atomicModifyIORef' (wNanosDec w) (\v -> (v + (t2 - t1), ()))
                checkRoundTrip w iter shape plain got
                atomicModifyIORef' (wIters w) (\v -> (v + 1, ()))
                atomicModifyIORef' (wBytesEnc w) (\v -> (v + fromIntegral (BS.length plain), ()))
                atomicModifyIORef' (wBytesDec w) (\v -> (v + fromIntegral (BS.length got), ()))
                pure True
  where
    encryptWith ShapeStream pipe plain = pump pipe True plain
    encryptWith ShapeStreamOneShot pipe plain = ITB3.encryptStreamOneShot pipe plain
    encryptWith _ pipe plain = ITB3.encryptMessage pipe plain
    decryptWith ShapeStream pipe wire = pump pipe False wire
    decryptWith ShapeStreamOneShot pipe wire = ITB3.decryptStreamOneShot pipe wire
    decryptWith _ pipe wire = ITB3.decryptMessage pipe wire

handleFor :: RunState -> Shape -> IO (Maybe Pipeline)
handleFor r ShapeMessage = readIORef (rsMsgPipe r)
handleFor r _ = readIORef (rsStreamPipe r)

-- | Failure model. A cipher call that returns a non-OK status is a
-- worker error: it is recorded, the run is asked to stop, the other
-- workers finish their in-flight iteration, and the error is listed in
-- the summary with the FAIL verdict. A round-trip that returns OK with
-- different bytes is a data mismatch: the process terminates here,
-- without summary or cleanup, because the Pipeline state that produced
-- the wrong bytes is the evidence and nothing that runs afterwards may
-- touch it.
--
-- Haskell-specific. Leaving a forked thread with the ordinary exit
-- throws in that thread alone and the process would carry on, so the
-- immediate process exit is the one used here; it also skips every
-- handler and finalizer, which is what the no-cleanup rule asks for.
checkRoundTrip :: Worker -> Int64 -> Shape -> BS.ByteString -> BS.ByteString -> IO ()
checkRoundTrip w iter shape plain got =
  when (BS.length got /= BS.length plain || plain /= got) $ do
    let off = firstDifference plain got
    errRaw $ "loop: DATA MISMATCH g" ++ show (wId w) ++ " iter " ++ show iter
      ++ " shape=" ++ shapeName shape
      ++ ": want " ++ show (BS.length plain) ++ " bytes, got "
      ++ show (BS.length got) ++ " bytes, first difference at offset "
      ++ show off ++ ": want " ++ hexWindow plain off
      ++ " got " ++ hexWindow got off ++ "\n"
    exitImmediately (ExitFailure 3)

-- | The worker thread body: one warmup iteration, the warmup barrier,
-- then the main loop until a stop is requested or the fixed per-worker
-- iteration budget (warmup included) is spent. A failing warmup still
-- passes both barriers so the launcher never waits on a worker that
-- has already given up.
--
-- Concurrency mode. This binding runs shared-handle: every foreign
-- import is @safe@, so the capability is released for the whole of a
-- call and the runtime knows the thread has left Haskell code, which
-- lets the @--goroutines@ threads call into one Pipeline handle at the
-- same time on the capabilities @-N@ provides. The flag is the thread
-- count verbatim, never clamped.
workerMain :: RunState -> Worker -> IO () -> IO () -> IO ()
workerMain r w arriveWarmup waitGate = do
  writeIORef (wRng w) (seedWorker (cfgSeed cfg) (wId w))
  -- Allocation posture. The plaintext is allocated once per worker and
  -- held for the whole run (rotating mode replaces it per iteration);
  -- the wire and round-trip buffers are the ones the binding returns
  -- per call and the runtime reclaims them when the iteration drops
  -- them, and the pump accumulates through a builder that is emptied
  -- per direction. Under the default fixed CSPRNG mode every worker's
  -- buffer is distinct, so cross-worker data crossover is detectable;
  -- pattern modes trade that property for content edge-case coverage.
  allocOk <- try $ do
    plain <- fillPayload (cfgPayloadMode cfg) (cfgSeed cfg /= 0) (wRng w) (cfgPayload cfg)
    writeIORef (wPlaintext w) plain
  ok0 <- case allocOk of
    Left (e :: SomeException) -> do
      workerFail r w $ "g" ++ show (wId w) ++ " iter 0: payload alloc: " ++ errorSentence e
      pure False
    Right () -> do
      -- Warmup iteration — counted in the totals; its completion feeds
      -- the post-warmup baselines. Anything that escapes an iteration
      -- other than a library status becomes a worker error rather than
      -- a lost thread: the launcher waits for one arrival per worker,
      -- so a worker that unwound past it would leave the launcher
      -- waiting for a rendezvous that can no longer happen.
      res <- try (iterate1 r w 0)
      case res of
        Left (e :: SomeException) -> do
          workerFail r w $ "g" ++ show (wId w) ++ " iter 0: " ++ errorSentence e
          pure False
        Right v -> pure v
  arriveWarmup
  waitGate
  when ok0 (mainLoop 1)
  where
    cfg = rsConfig r
    mainLoop iter
      | cfgIterations cfg > 0 && iter >= cfgIterations cfg = pure ()
      | otherwise = do
          stop <- readIORef (rsStop r)
          unless stop $ do
            res <- try (iterate1 r w iter)
            cont <- case res of
              Left (e :: SomeException) -> do
                workerFail r w $ "g" ++ show (wId w) ++ " iter " ++ show iter
                  ++ ": " ++ errorSentence e
                pure False
              Right v -> pure v
            when cont $ do
              maint <- try (workerMaintenance r w iter)
              case maint of
                Left (e :: SomeException) -> workerFail r w $
                  "g" ++ show (wId w) ++ " iter " ++ show iter ++ ": "
                    ++ errorSentence e
                Right False -> pure ()
                Right True -> mainLoop (iter + 1)
