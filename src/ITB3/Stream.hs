-- | Incremental stream sessions over an open 'Pipeline'.
--
-- A session is a dumb byte pump: 'StreamEncryptor' takes plaintext in
-- through 'writeStream' and yields wire through 'readStream' \/
-- 'drainAll'; 'StreamDecryptor' is the mirror (wire in, plaintext
-- out). All chunking, MAC, envelope, and wire-format decisions stay
-- inside libitb3.
--
-- Each session record carries its parent 'Pipeline', and the
-- session's GC finalizer also references the Pipeline's 'ForeignPtr',
-- so the Haskell GC cannot free the Pipeline handle while a session
-- on it is still reachable or pending finalization (session-parent
-- pin). 'freeStream' cancels a session deterministically.
module ITB3.Stream
  ( StreamEncryptor
  , StreamDecryptor
  , StreamSession
  , encryptStream
  , decryptStream
  , writeStream
  , endStream
  , readStream
  , drainAll
  , freeStream
  ) where

import Control.Monad (unless, void)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BU
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Foreign.C.Types (CInt)
import Foreign.Concurrent (newForeignPtr)
import Foreign.ForeignPtr
  (ForeignPtr, finalizeForeignPtr, touchForeignPtr, withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, intPtrToPtr, ptrToIntPtr)
import Foreign.Storable (peek, poke)

import ITB3.Errors (check)
import ITB3.FFI
import ITB3.Pipeline (Pipeline, pipelineForeignPtr, withPipelineHandle)

-- | Default drain slice used by 'drainAll'.
drainSlice :: Int
drainSlice = 1024 * 1024

data Session = Session
  { sessFP     :: !(ForeignPtr ())
  , sessParent :: !Pipeline      -- ^ Session-parent pin: keeps the
                                 -- Pipeline reachable while the
                                 -- session is referenced.
  , sessEnded  :: !(IORef Bool)
  }

-- | Incremental encrypt session: plaintext in, wire out.
newtype StreamEncryptor = StreamEncryptor Session

-- | Incremental decrypt session: wire in, plaintext out.
newtype StreamDecryptor = StreamDecryptor Session

-- | Shared session accessor for the two stream directions.
class StreamSession s where
  sessionOf :: s -> Session

instance StreamSession StreamEncryptor where
  sessionOf (StreamEncryptor s) = s

instance StreamSession StreamDecryptor where
  sessionOf (StreamDecryptor s) = s

beginSession
  :: (ITBHandle -> Ptr ITBHandle -> IO CInt)
  -> Pipeline
  -> IO Session
beginSession beginFn pipe = do
  h <- withPipelineHandle pipe $ \ph ->
    alloca $ \outP -> do
      poke outP 0
      rc <- beginFn ph outP
      check rc
      peek outP
  ended <- newIORef False
  let parentFP = pipelineForeignPtr pipe
  -- The finalizer closure references the parent's ForeignPtr and
  -- touches it after the session is freed, so the parent's finalizer
  -- cannot run before this one completes.
  fp <- newForeignPtr (intPtrToPtr (fromIntegral h)) $ do
    void (c_ITB_Triple_StreamFree h)
    touchForeignPtr parentFP
  pure (Session fp pipe ended)

withSessionHandle :: Session -> (ITBHandle -> IO a) -> IO a
withSessionHandle s f = withForeignPtr (sessFP s) $ \p -> do
  r <- f (fromIntegral (ptrToIntPtr p))
  -- Keep the parent Pipeline pinned across the FFI call as well.
  touchForeignPtr (pipelineForeignPtr (sessParent s))
  pure r

-- | Opens an incremental encrypt session (plaintext in, wire out).
encryptStream :: Pipeline -> IO StreamEncryptor
encryptStream = fmap StreamEncryptor . beginSession c_ITB_Triple_EncryptStreamBegin

-- | Opens an incremental decrypt session (wire in, plaintext out).
decryptStream :: Pipeline -> IO StreamDecryptor
decryptStream = fmap StreamDecryptor . beginSession c_ITB_Triple_DecryptStreamBegin

-- | Feeds bytes into the session. Blocks until the cipher chain
-- accepts them; errors are sticky.
writeStream :: StreamSession s => s -> BS.ByteString -> IO ()
writeStream s src =
  withSessionHandle (sessionOf s) $ \h ->
    BU.unsafeUseAsCStringLen src $ \(p, n) ->
      c_ITB_Triple_StreamWrite h (castPtr p) (fromIntegral n) >>= check

-- | Signals end-of-input. Idempotent; a 'writeStream' after
-- 'endStream' fails with 'ITB3.Errors.statusBadInput'.
endStream :: StreamSession s => s -> IO ()
endStream s = do
  withSessionHandle (sessionOf s) $ \h ->
    c_ITB_Triple_StreamEnd h >>= check
  writeIORef (sessEnded (sessionOf s)) True

-- | Drains up to @maxBytes@ produced bytes; returns
-- @(bytes, finished)@. Partial drains are normal; before 'endStream'
-- an empty result means no output is available yet, and after
-- 'endStream' an empty-spool read blocks until the terminal bytes
-- arrive or the session errors.
readStream :: StreamSession s => s -> Int -> IO (BS.ByteString, Bool)
readStream s maxBytes = do
  let n = max 1 maxBytes
  fp <- BSI.mallocByteString n
  (got, fin) <- withSessionHandle (sessionOf s) $ \h ->
    alloca $ \lenP -> alloca $ \finP -> do
      poke lenP 0
      poke finP 0
      rc <- withForeignPtr fp $ \p ->
        c_ITB_Triple_StreamRead h p (fromIntegral n) lenP finP
      check rc
      got <- fromIntegral <$> peek lenP
      fin <- peek finP
      pure (got, fin /= (0 :: CInt))
  pure (BSI.fromForeignPtr fp 0 (min got n), fin)

-- | Calls 'endStream' (when not yet called) and concatenates every
-- remaining output byte.
drainAll :: StreamSession s => s -> IO BS.ByteString
drainAll s = do
  ended <- readIORef (sessEnded (sessionOf s))
  unless ended (endStream s)
  let go acc = do
        (chunk, fin) <- readStream s drainSlice
        let acc' = chunk : acc
        if fin then pure (BS.concat (reverse acc')) else go acc'
  go []

-- | Cancels the session and frees the Go-side state now instead of
-- waiting for GC. Safe to call more than once.
freeStream :: StreamSession s => s -> IO ()
freeStream = finalizeForeignPtr . sessFP . sessionOf
