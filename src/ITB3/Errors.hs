-- | Error type thrown by every fallible call in the binding, plus the
-- stable libitb3 status-code constants
-- (@cmd\/cshared\/internal\/capi\/errors.go@).
module ITB3.Errors
  ( ITBError (..)
  , check
  , readLastError
    -- * Status-code constants
  , statusOk
  , statusBadHash
  , statusBadKeyBits
  , statusBadHandle
  , statusBadInput
  , statusBufferTooSmall
  , statusEncryptFailed
  , statusDecryptFailed
  , statusSeedWidthMix
  , statusBadMac
  , statusMacFailure
  , statusBlobMalformedRecipe
  , statusRecipePrimitiveUnknown
  , statusUnknownProfile
  , statusBlobModeMismatch
  , statusBlobMalformed
  , statusBlobVersionTooNew
  , statusBlobTooManyOpts
  , statusStreamTruncated
  , statusStreamAfterFinal
  , statusTripleClosed
  , statusProfileExists
  , statusInternal
  ) where

import Control.Exception (Exception (..), throwIO)
import Control.Monad (when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Internal as BSI
import Foreign.C.Types (CInt)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (castPtr, nullPtr)
import Foreign.Storable (peek, poke)

import ITB3.FFI (c_ITB_LastError)

-- | A non-OK libitb3 status. 'lastError' carries the @ITB_LastError@
-- diagnostic captured immediately after the failing call
-- (process-global last-write-wins — under concurrent FFI use the
-- message may belong to a different call; the status code is always
-- attributable).
data ITBError = ITBError
  { statusCode :: Int
  , lastError  :: String
  }
  deriving (Show, Eq)

instance Exception ITBError where
  displayException (ITBError code msg) =
    "itb: status=" <> show code <> ": " <> msg

-- ── status-code constants (stable across releases) ──────────────────

statusOk, statusBadHash, statusBadKeyBits, statusBadHandle,
  statusBadInput, statusBufferTooSmall, statusEncryptFailed,
  statusDecryptFailed, statusSeedWidthMix, statusBadMac,
  statusMacFailure, statusBlobMalformedRecipe, statusRecipePrimitiveUnknown,
  statusUnknownProfile, statusBlobModeMismatch, statusBlobMalformed,
  statusBlobVersionTooNew, statusBlobTooManyOpts,
  statusStreamTruncated, statusStreamAfterFinal, statusTripleClosed,
  statusProfileExists, statusInternal :: Int
statusOk                = 0
statusBadHash           = 1
statusBadKeyBits        = 2
statusBadHandle         = 3
statusBadInput          = 4
statusBufferTooSmall    = 5
statusEncryptFailed     = 6
statusDecryptFailed     = 7
statusSeedWidthMix      = 8
statusBadMac            = 9
statusMacFailure        = 10
statusBlobMalformedRecipe    = 11
statusRecipePrimitiveUnknown = 12
statusUnknownProfile         = 13
statusBlobModeMismatch  = 19
statusBlobMalformed     = 20
statusBlobVersionTooNew = 21
statusBlobTooManyOpts   = 22
statusStreamTruncated   = 23
statusStreamAfterFinal  = 24
statusTripleClosed      = 25
statusProfileExists     = 26
statusInternal          = 99

-- | Throws 'ITBError' (with the @ITB_LastError@ diagnostic attached)
-- when the return code is non-OK.
check :: CInt -> IO ()
check rc =
  when (fromIntegral rc /= statusOk) $ do
    msg <- readLastError
    throwIO (ITBError (fromIntegral rc) msg)

-- | Reads the @ITB_LastError@ diagnostic (NUL-stripped). Returns the
-- empty string when no diagnostic is recorded.
readLastError :: IO String
readLastError = do
  need <- alloca $ \lenP -> do
    poke lenP 0
    rc <- c_ITB_LastError nullPtr 0 lenP
    if fromIntegral rc == statusOk || fromIntegral rc == statusBufferTooSmall
      then fromIntegral <$> peek lenP
      else pure (0 :: Int)
  if need <= 1
    then pure ""
    else do
      fp <- BSI.mallocByteString need
      written <- alloca $ \lenP -> do
        poke lenP 0
        rc <- withForeignPtr fp $ \p ->
          c_ITB_LastError (castPtr p) (fromIntegral need) lenP
        if fromIntegral rc == statusOk
          then fromIntegral <$> peek lenP
          else pure (0 :: Int)
      -- The reported length includes the trailing NUL; strip it.
      pure . BC.unpack . BS.take (max 0 (written - 1)) $
        BSI.fromForeignPtr fp 0 (min written need)
