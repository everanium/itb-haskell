{-# LANGUAGE ScopedTypeVariables #-}

-- | The maintenance operations that mutate a live Pipeline handle
-- between iterations: master rotation (@--rekey-every@) and blob
-- reopen (@--blob-cycle-every@).
module Ops
  ( workerMaintenance
  ) where

import Control.Exception (SomeException, try)
import qualified Data.ByteString as BS
import Data.IORef
import Data.Int (Int64)

import qualified ITB3

import Payload (fillRandom)
import State

-- | Byte length of each fresh master drawn for a rotation. Matches the
-- size Init auto-generates for both the parallax and the wrapper
-- master.
rekeyMasterSize :: Int
rekeyMasterSize = 32

-- | Master rotation. Rotates the parallax + wrapper masters on every
-- active Pipeline under the write lock and retains the refreshed blob
-- for subsequent blob reopens. Masters are drawn fresh from the OS
-- CSPRNG on every rotation regardless of @--seed@ (master rotation is
-- pipeline keying, not plaintext content); a disabled layer passes no
-- bytes, which Rekey ignores. The eight inner seeds and the MAC key
-- are untouched by design — Rekey targets only the two outer-layer
-- master secrets.
rekeyPipes :: RunState -> Worker -> Int64 -> IO Bool
rekeyPipes r w iter = do
  perm <- if cfgParallax (rsConfig r) then fillRandom rekeyMasterSize else pure BS.empty
  wrap <- if cfgWrapper (rsConfig r) then fillRandom rekeyMasterSize else pure BS.empty
  withWriteLock (rsLock r) $ do
    okStream <- rotate (rsStreamPipe r) (rsStreamBlob r) (rsStreamName r) perm wrap
    if not okStream
      then pure False
      else do
        okMsg <- rotate (rsMsgPipe r) (rsMsgBlob r) (rsMsgName r) perm wrap
        if not okMsg
          then pure False
          else do
            n <- atomicModifyIORef' (rsRekeys r) (\v -> (v + 1, v + 1))
            logLine $ "rekey: g" ++ show (wId w) ++ " iter " ++ show iter
              ++ " rotated parallax + wrapper masters (rekey #" ++ show n ++ ")"
            pure True
  where
    rotate pipeRef blobRef name perm wrap = do
      held <- readIORef pipeRef
      case held of
        Nothing -> pure True
        Just p -> do
          res <- try (ITB3.rekey p perm wrap)
          case res of
            Left (e :: SomeException) -> do
              workerFail r w $ "g" ++ show (wId w) ++ " iter " ++ show iter
                ++ ": Rekey(" ++ name ++ "): " ++ statusDetail e
              pure False
            Right blob -> do
              writeIORef blobRef blob
              pure True

-- | Blob reopen. Reopens every active Pipeline from its retained blob
-- under the write lock: a fresh handle is loaded from the blob, the
-- running handle is freed, and the fresh one is swapped in, so every
-- later iteration round-trips through seeds and masters that survived
-- a blob crossing. The input is the blob Init or the latest Rekey
-- handed out, not a fresh Save: that is what a receiver holds, and
-- reopening from it proves the handed-out bytes rather than the live
-- state. The blob carries the Pipeline's full shape, so no override
-- reaches the reopen. On a Load failure the running handle stays and
-- the failure aborts the run.
blobCyclePipes :: RunState -> Worker -> Int64 -> IO Bool
blobCyclePipes r w iter = withWriteLock (rsLock r) $ do
  okStream <- reopen (rsStreamPipe r) (rsStreamBlob r) (rsStreamName r)
  if not okStream
    then pure False
    else do
      okMsg <- reopen (rsMsgPipe r) (rsMsgBlob r) (rsMsgName r)
      if not okMsg
        then pure False
        else do
          n <- atomicModifyIORef' (rsBlobCycles r) (\v -> (v + 1, v + 1))
          logLine $ "blob-cycle: g" ++ show (wId w) ++ " iter " ++ show iter
            ++ " reopened from session blob (cycle #" ++ show n ++ ")"
          pure True
  where
    reopen pipeRef blobRef name = do
      held <- readIORef pipeRef
      case held of
        Nothing -> pure True
        Just old -> do
          blob <- readIORef blobRef
          res <- try (ITB3.loadPipeline blob Nothing)
          case res of
            Left (e :: SomeException) -> do
              workerFail r w $ "g" ++ show (wId w) ++ " iter " ++ show iter
                ++ ": Load(" ++ name ++ "): " ++ statusDetail e
              pure False
            Right fresh -> do
              writeIORef pipeRef (Just fresh)
              ITB3.freePipeline old
              pure True

-- | Handle mutation. Runs the periodic Pipeline-mutating operations
-- after a completed iteration: master rotation (@--rekey-every@) and
-- blob reopen (@--blob-cycle-every@). Both intervals count per-worker
-- iterations; the warmup iteration (iter 0) never triggers because the
-- worker loop calls this for iter >= 1 only. Rekey rewrites the
-- outer-layer keying of a live handle and a blob reopen replaces the
-- handle outright; each takes the write lock, so in-flight cipher
-- calls on other workers drain before anything changes and no encrypt
-- is separated from its decrypt by either. Returns False after
-- recording the worker error.
workerMaintenance :: RunState -> Worker -> Int64 -> IO Bool
workerMaintenance r w iter = do
  let cfg = rsConfig r
  okRekey <-
    if cfgRekeyEvery cfg > 0 && iter `mod` cfgRekeyEvery cfg == 0
      then rekeyPipes r w iter
      else pure True
  if not okRekey
    then pure False
    else if cfgBlobCycleEvery cfg > 0 && iter `mod` cfgBlobCycleEvery cfg == 0
      then blobCyclePipes r w iter
      else pure True
