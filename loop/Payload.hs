-- | Plaintext content: the payload modes, the seeded per-worker
-- generator, and the buffer fill from the operating-system CSPRNG.
module Payload
  ( seedWorker
  , openEntropy
  , fillRandom
  , fillPayload
  ) where

import Control.Exception (evaluate)
import Control.Monad (when)
import Data.Bits (shiftR, xor, (.&.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Data.IORef
import Data.Word (Word64, Word8)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (poke)
import System.IO.Unsafe (unsafePerformIO)
import System.Posix.IO
  (OpenMode (ReadOnly), defaultFileFlags, fdReadBuf, openFd)
import System.Posix.Types (Fd)

import State (PayloadMode (..))

-- | Seeded plaintext. The seed makes plaintext content reproducible so
-- a failing iteration can be replayed with the same bytes; it governs
-- nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
-- so a seeded run is a reproduction aid and never a security test.
-- Each worker's stream is domain-separated by its id so seeded workers
-- still hold pairwise-distinct buffers under the fixed and rotating
-- modes. The generator is splitmix64: a few lines in any language,
-- which is why it is the one every binding uses.
seedWorker :: Word64 -> Int -> Word64
seedWorker seed workerId = seed + fromIntegral workerId + 1

splitmix64 :: Word64 -> (Word64, Word64)
splitmix64 state = (s, z2 `xor` (z2 `shiftR` 31))
  where
    s = state + 0x9E3779B97F4A7C15
    z1 = (s `xor` (s `shiftR` 30)) * 0xBF58476D1CE4E5B9
    z2 = (z1 `xor` (z1 `shiftR` 27)) * 0x94D049BB133111EB

-- | The platform entropy source, opened once for the process and held
-- for its lifetime.
--
-- Haskell-specific. The standard library carries no CSPRNG, so the
-- source the platform offers for bulk draws is read directly. The
-- descriptor is a raw one rather than a buffered handle for two
-- reasons: several workers draw at once and a handle is not safe to
-- share between them, and a descriptor opened per draw would be closed
-- again before anything watching the process could say which file the
-- read belonged to.
urandomFd :: Fd
urandomFd = unsafePerformIO (openFd "/dev/urandom" ReadOnly defaultFileFlags)
{-# NOINLINE urandomFd #-}

-- | Opens the entropy source before any worker starts, so the one-time
-- open cannot race between them.
openEntropy :: IO ()
openEntropy = () <$ evaluate urandomFd

-- | Fills a fresh buffer of @n@ bytes from the operating-system
-- CSPRNG. The read loops because a large read may come back short.
fillRandom :: Int -> IO BS.ByteString
fillRandom n = BSI.create n $ \p -> go p n
  where
    go :: Ptr Word8 -> Int -> IO ()
    go _ 0 = pure ()
    go p k = do
      got <- fromIntegral <$> fdReadBuf urandomFd p (fromIntegral k)
      when (got <= 0) (ioError (userError "/dev/urandom: short read"))
      go (p `plusPtr` got) (k - got)

-- | Writes one plaintext buffer according to the payload mode,
-- advancing the worker's generator state in place. The fixed and
-- rotating modes draw from the seeded generator when the run is seeded
-- and from the OS CSPRNG otherwise; the pattern modes are
-- deterministic regardless of the seed.
fillPayload :: PayloadMode -> Bool -> IORef Word64 -> Int -> IO BS.ByteString
fillPayload mode seeded rngRef n = case mode of
  PayloadFixed        -> randomOrSeeded
  PayloadRotating     -> randomOrSeeded
  PayloadPatternZero  -> pure (BS.replicate n 0x00)
  PayloadPatternFf    -> pure (BS.replicate n 0xFF)
  PayloadPatternAscii -> BSI.create n (ramp 0)
  where
    ramp :: Int -> Ptr Word8 -> IO ()
    ramp i p
      | i >= n = pure ()
      | otherwise = do
          poke (p `plusPtr` i) (0x41 + fromIntegral (i `mod` 26) :: Word8)
          ramp (i + 1) p
    randomOrSeeded
      | not seeded = fillRandom n
      | otherwise = do
          start <- readIORef rngRef
          stRef <- newIORef start
          bs <- BSI.create n (seededFill stRef 0)
          readIORef stRef >>= writeIORef rngRef
          pure bs
    seededFill :: IORef Word64 -> Int -> Ptr Word8 -> IO ()
    seededFill stRef i p
      | i >= n = pure ()
      | otherwise = do
          st <- readIORef stRef
          let (st', v) = splitmix64 st
              takeN = min 8 (n - i)
          writeIORef stRef st'
          mapM_ (\k -> poke (p `plusPtr` (i + k)) (byteOf v k)) [0 .. takeN - 1]
          seededFill stRef (i + 8) p
    byteOf :: Word64 -> Int -> Word8
    byteOf v k = fromIntegral ((v `shiftR` (8 * k)) .&. 0xFF)
