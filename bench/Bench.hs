{-# LANGUAGE BangPatterns #-}

-- | Throughput micro-benchmarks: Single Message encrypt and
-- incremental Streaming encrypt at 1 MiB \/ 16 MiB \/ 64 MiB.
--
-- Bench configuration is driven by the fleet's canonical environment
-- variables so a side-by-side comparison with the root Go bench
-- harness is straightforward:
--
-- > ITB_INNER_HASH      (default areion512)
-- > ITB_KEY_BITS        (default 1024)
-- > ITB_NONCE_BITS      (default 512)
-- > ITB_WITH_PARALLAX   (default false)
-- > ITB_WITH_WRAPPER    (default false)
-- > ITB_MSG_PROFILE     (fallback ITB_PROFILE, then singlemsg-triple-nomac-v1)
-- > ITB_STREAM_PROFILE  (fallback ITB_PROFILE, then streaming-noaead-triple-v1)
-- > ITB_BENCH_MIN_SEC   (default 5)
module Main (main) where

import Control.Monad (forM_, void)
import qualified Data.ByteString as BS
import Data.IORef (modifyIORef', newIORef, readIORef)
import Data.Maybe (fromMaybe)
import GHC.Clock (getMonotonicTimeNSec)
import System.Environment (lookupEnv)
import System.IO (IOMode (ReadMode), withBinaryFile)
import Text.Printf (printf)
import Text.Read (readMaybe)

import ITB3

benchMinIters :: Int
benchMinIters = 3

sizes :: [Int]
sizes = [1 * 1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024]

main :: IO ()
main = do
  -- Bench-scale allocation churn grows the Go scratch heap
  -- unboundedly without a soft memory cap + aggressive GC; the
  -- return values report the previous settings, not an error.
  void (setMemoryLimit (4 * 1024 * 1024 * 1024))
  void (setGcPercent 100)

  opts <- benchOpts
  minSec <- envDouble "ITB_BENCH_MIN_SEC" 5.0

  printf "%-17s %-8s %s\n" "bench" "size" "mb_per_sec"

  msgProfile <- profileEnv "ITB_MSG_PROFILE" "singlemsg-triple-nomac-v1"
  msgPipe <- initPipeline msgProfile opts
  forM_ sizes $ \size -> do
    plain <- csprngBytes size
    benchCase "message" size minSec (void (encryptMessage msgPipe plain))
    -- Pre-encrypt one wire outside the decrypt timing loop.
    decWire <- encryptMessage msgPipe plain
    benchCase "message-dec" size minSec (void (decryptMessage msgPipe decWire))
  freePipeline msgPipe

  streamProfile <- profileEnv "ITB_STREAM_PROFILE" "streaming-noaead-triple-v1"
  streamPipe <- initPipeline streamProfile opts
  forM_ sizes $ \size -> do
    plain <- csprngBytes size
    benchCase "stream" size minSec (streamOnce streamPipe plain)
    -- Pre-encrypt one wire outside the decrypt timing loop.
    decWire <- streamEncryptAll streamPipe plain
    benchCase "stream-dec" size minSec (streamDecryptOnce streamPipe decWire)
  freePipeline streamPipe

  -- Whole-buffer stream: one FFI round trip through
  -- encryptStreamOneShot / decryptStreamOneShot per iteration.
  oneShotPipe <- initPipeline streamProfile opts
  forM_ sizes $ \size -> do
    plain <- csprngBytes size
    benchCase "stream_one_shot" size minSec
      (void (encryptStreamOneShot oneShotPipe plain))
    -- Pre-encrypt one wire outside the decrypt timing loop.
    decWire <- encryptStreamOneShot oneShotPipe plain
    benchCase "stream_one_shot-dec" size minSec
      (void (decryptStreamOneShot oneShotPipe decWire))
  freePipeline oneShotPipe

-- | One incremental stream encrypt pass: Begin \/ Write (4 MiB
-- slices, draining opportunistically) \/ End \/ final drain \/ Free.
streamOnce :: Pipeline -> BS.ByteString -> IO ()
streamOnce pipe plain = do
  sess <- encryptStream pipe
  sink <- newIORef (0 :: Int)
  forM_ (chunksOf (4 * 1024 * 1024) plain) $ \piece -> do
    writeStream sess piece
    drainAvailable sess sink
  endStream sess
  let finalDrain = do
        (chunk, fin) <- readStream sess (4 * 1024 * 1024)
        modifyIORef' sink (+ BS.length chunk)
        if fin then pure () else finalDrain
  finalDrain
  void (readIORef sink)
  freeStream sess
  where
    -- Before endStream a read never blocks; drain whatever the chain
    -- has produced so far to keep the session spool bounded.
    drainAvailable sess sink = do
      (chunk, _) <- readStream sess (4 * 1024 * 1024)
      if BS.null chunk
        then pure ()
        else do
          modifyIORef' sink (+ BS.length chunk)
          drainAvailable sess sink

-- | Encrypt one plaintext and collect all wire bytes.
streamEncryptAll :: Pipeline -> BS.ByteString -> IO BS.ByteString
streamEncryptAll pipe plain = do
  sess <- encryptStream pipe
  parts <- newIORef ([] :: [BS.ByteString])
  forM_ (chunksOf (4 * 1024 * 1024) plain) $ \piece -> do
    writeStream sess piece
    let drain = do
          (chunk, _) <- readStream sess (4 * 1024 * 1024)
          if BS.null chunk then pure ()
            else do modifyIORef' parts (chunk :); drain
    drain
  endStream sess
  let finalDrain = do
        (chunk, fin) <- readStream sess (4 * 1024 * 1024)
        modifyIORef' parts (chunk :)
        if fin then pure () else finalDrain
  finalDrain
  xs <- readIORef parts
  freeStream sess
  pure (BS.concat (reverse xs))

-- | One incremental stream decrypt pass over pre-encrypted wire.
streamDecryptOnce :: Pipeline -> BS.ByteString -> IO ()
streamDecryptOnce pipe wire = do
  sess <- decryptStream pipe
  sink <- newIORef (0 :: Int)
  forM_ (chunksOf (4 * 1024 * 1024) wire) $ \piece -> do
    writeStream sess piece
    drainAvailable sess sink
  endStream sess
  let finalDrain = do
        (chunk, fin) <- readStream sess (4 * 1024 * 1024)
        modifyIORef' sink (+ BS.length chunk)
        if fin then pure () else finalDrain
  finalDrain
  void (readIORef sink)
  freeStream sess
  where
    drainAvailable sess sink = do
      (chunk, _) <- readStream sess (4 * 1024 * 1024)
      if BS.null chunk
        then pure ()
        else do
          modifyIORef' sink (+ BS.length chunk)
          drainAvailable sess sink

-- | Runs the action until the wall-clock budget is spent (with an
-- iteration floor + one untimed warm-up), then prints one table row.
benchCase :: String -> Int -> Double -> IO () -> IO ()
benchCase name size minSec action = do
  action -- warm-up
  t0 <- getMonotonicTimeNSec
  let loop !iters = do
        action
        t <- getMonotonicTimeNSec
        let elapsed = fromIntegral (t - t0) / 1e9 :: Double
        if elapsed < minSec || iters + 1 < benchMinIters
          then loop (iters + 1)
          else pure (iters + 1, elapsed)
  (iters, elapsed) <- loop (0 :: Int)
  let mib = fromIntegral size * fromIntegral iters / (1024 * 1024) :: Double
  printf "%-17s %-8s %.1f\n" name (sizeLabel size) (mib / elapsed)

sizeLabel :: Int -> String
sizeLabel size
  | size >= 1024 * 1024 = show (size `div` (1024 * 1024)) <> " MiB"
  | otherwise = show (size `div` 1024) <> " KiB"

-- | CSPRNG-filled plaintext (kernel CSPRNG via \/dev\/urandom) so the
-- COBS path handles the same byte-content distribution as the root Go
-- bench (crypto\/rand). Not in the timing loop.
csprngBytes :: Int -> IO BS.ByteString
csprngBytes n = withBinaryFile "/dev/urandom" ReadMode (`BS.hGet` n)

benchOpts :: IO Opts
benchOpts = do
  nb <- envInt "ITB_NONCE_BITS" 512
  kb <- envInt "ITB_KEY_BITS" 1024
  wp <- envBool "ITB_WITH_PARALLAX" False
  ww <- envBool "ITB_WITH_WRAPPER" False
  ih <- envStr "ITB_INNER_HASH" ""
  mn <- envStr "ITB_MAC_NAME" ""
  pure $ mconcat
    [ nonceBits nb
    , keyBits kb
    , withParallax wp
    , withWrapper ww
    , if null ih then mempty else innerHash ih
    , if null mn then mempty else macName mn
    ]

envStr :: String -> String -> IO String
envStr key def = do
  v <- lookupEnv key
  pure $ case v of
    Just s | not (null s) -> s
    _ -> def

-- | Reads the per-shape profile env var, falling back to ITB_PROFILE,
-- then to the shape's own default.
profileEnv :: String -> String -> IO String
profileEnv shapeKey fallback = do
  s <- envStr shapeKey ""
  if not (null s) then pure s else envStr "ITB_PROFILE" fallback

envInt :: String -> Int -> IO Int
envInt key def = do
  v <- envStr key ""
  pure (fromMaybe def (readMaybe v))

envDouble :: String -> Double -> IO Double
envDouble key def = do
  v <- envStr key ""
  pure (fromMaybe def (readMaybe v))

envBool :: String -> Bool -> IO Bool
envBool key def = do
  v <- envStr key ""
  pure $ case v of
    "" -> def
    s  -> s == "true" || s == "1"

chunksOf :: Int -> BS.ByteString -> [BS.ByteString]
chunksOf n bs
  | BS.null bs = []
  | otherwise = BS.take n bs : chunksOf n (BS.drop n bs)
