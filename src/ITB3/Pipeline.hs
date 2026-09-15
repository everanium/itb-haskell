{-# LANGUAGE BangPatterns #-}

-- | Managed wrapper around the Triple Pipeline handle.
--
-- A 'Pipeline' owns its libitb3 handle through a 'ForeignPtr' whose
-- finalizer calls @ITB_Triple_Free@, so an unreachable Pipeline is
-- released by the Haskell GC (libitb3 zeroes key material internally).
-- 'freePipeline' forces the release deterministically.
module ITB3.Pipeline
  ( Pipeline
  , newPipeline
  , initPipeline
  , loadPipeline
  , loadPipelineF
  , save
  , saveF
  , setMaxWorkers
  , rekey
  , closePipeline
  , freePipeline
  , encryptMessage
  , decryptMessage
  , encryptStreamOneShot
  , decryptStreamOneShot
  , inspect
  , register
  , lookupProfile
  , profiles
    -- * Internal (used by "ITB3.Stream")
  , withPipelineHandle
  , pipelineForeignPtr
  , retryOnce
  , outCap
  ) where

import Control.Monad (void)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BU
import Foreign.C.Types (CInt, CSize)
import Foreign.Concurrent (newForeignPtr)
import Foreign.ForeignPtr (ForeignPtr, finalizeForeignPtr, withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, intPtrToPtr, ptrToIntPtr)
import Foreign.Storable (peek, poke)
import Data.Word (Word8)

import ITB3.Errors
import ITB3.FFI
import ITB3.Opts (Opts, emptyOpts, renderOpts)

-- | Floor capacity for blob \/ JSON output buffers (Init \/ Rekey \/
-- Save \/ Inspect \/ Lookup \/ Profiles).
blobCap :: Int
blobCap = 64 * 1024

-- | Pre-allocation formula for Message \/ one-shot stream outputs:
-- @payload * 5\/4 + 65536@.
outCap :: Int -> Int
outCap payload = payload + payload `div` 4 + 65536

-- | A Triple Pipeline session. 'save' exports the session bundle the
-- receiver feeds to 'loadPipeline'; 'rekey' refreshes it.
--
-- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
-- chunk, so plaintext of verified chunks is released before a later
-- chunk can fail authentication.
newtype Pipeline = Pipeline
  { pipeFP :: ForeignPtr ()
  }

-- | The Pipeline's 'ForeignPtr'. Internal — 'ITB3.Stream' references it
-- from a stream session's finalizer so the Pipeline handle outlives
-- every session opened on it.
pipelineForeignPtr :: Pipeline -> ForeignPtr ()
pipelineForeignPtr = pipeFP

-- | Runs an action with the raw libitb3 handle, keeping the Pipeline
-- alive for the duration of the call. Internal.
withPipelineHandle :: Pipeline -> (ITBHandle -> IO a) -> IO a
withPipelineHandle p f =
  withForeignPtr (pipeFP p) (f . fromIntegral . ptrToIntPtr)

mkPipeline :: ITBHandle -> IO Pipeline
mkPipeline h = do
  fp <- newForeignPtr (intPtrToPtr (fromIntegral h))
                      (void (c_ITB_Triple_Free h))
  pure (Pipeline fp)

-- ── retry-once buffer discipline ─────────────────────────────────────

-- | Single dispatch site for every variable-size output buffer:
-- pre-allocate @cap@ bytes, and on @statusBufferTooSmall@ retry once
-- with the exact size the FFI reported — gated on the reported length
-- strictly exceeding the current capacity.
retryOnce :: Int -> (Ptr Word8 -> CSize -> Ptr CSize -> IO CInt) -> IO BS.ByteString
retryOnce cap call = do
  (rc, need, bs) <- attempt cap
  if fromIntegral rc == statusBufferTooSmall && need > cap
    then do
      (rc2, need2, bs2) <- attempt need
      check rc2
      pure (BS.take need2 bs2)
    else do
      check rc
      pure bs
  where
    attempt !n = do
      fp <- BSI.mallocByteString n
      alloca $ \lenP -> do
        poke lenP 0
        rc <- withForeignPtr fp $ \p -> call p (fromIntegral n) lenP
        need <- fromIntegral <$> peek lenP
        pure (rc, need, BSI.fromForeignPtr fp 0 (min need n))

-- | Passes a ByteString as a NUL-terminated C string (copied).
withCStr :: String -> (Ptr Word8 -> IO a) -> IO a
withCStr s f = BS.useAsCString (BC.pack s) (f . castPtr)

withOpts :: Opts -> (Ptr Word8 -> IO a) -> IO a
withOpts o f = BS.useAsCString (renderOpts o) (f . castPtr)

withBytes :: BS.ByteString -> (Ptr Word8 -> CSize -> IO a) -> IO a
withBytes bs f =
  BU.unsafeUseAsCStringLen bs $ \(p, n) -> f (castPtr p) (fromIntegral n)

-- ── construction ─────────────────────────────────────────────────────

-- | Convenience constructor with profile defaults ('initPipeline'
-- with 'emptyOpts').
newPipeline :: String -> IO Pipeline
newPipeline profile = initPipeline profile emptyOpts

-- | Constructs a fresh Pipeline against the named profile; the session
-- bundle is available through 'save'. On a blob-buffer retry the Init
-- re-runs and yields a fresh session (the undersized attempt is closed
-- by libitb3 before returning). An unregistered name fails with
-- 'statusUnknownProfile'.
initPipeline :: String -> Opts -> IO Pipeline
initPipeline profile opts =
  withCStr profile $ \profileC ->
    withOpts opts $ \optsC ->
      alloca $ \handleP -> do
        poke handleP 0
        _ <- retryOnce blobCap $ \buf cap lenP -> do
          -- Go closes the undersized attempt; the retry re-runs Init
          -- and yields a fresh session.
          poke handleP 0
          c_ITB_Triple_Init (castPtr profileC) (castPtr optsC)
                            buf cap lenP handleP
        h <- peek handleP
        mkPipeline h

-- | The masters pair crosses as @(perm, wrap, count)@: @Nothing@
-- yields 0, otherwise 2 — libitb3 validates the pair.
mastersArgs :: Maybe (BS.ByteString, BS.ByteString) -> (BS.ByteString, BS.ByteString, CSize)
mastersArgs Nothing         = (BS.empty, BS.empty, 0)
mastersArgs (Just (p', w')) = (p', w', 2)

-- | Reconstructs a Pipeline from a blob produced by 'save' or 'rekey'.
-- The masters argument is @Nothing@ to use the blob-embedded masters,
-- or @Just (perm, wrap)@ to override them. The profile shape travels
-- inside the blob — no profile name, no opts. A blob whose record
-- names a primitive absent from the local build fails with
-- 'statusRecipePrimitiveUnknown'; a record failing the profile field
-- rules with 'statusBlobMalformedRecipe'.
loadPipeline :: BS.ByteString -> Maybe (BS.ByteString, BS.ByteString) -> IO Pipeline
loadPipeline blobBytes masters = do
  let (pm, wm, count) = mastersArgs masters
  withBytes blobBytes $ \blobP blobLen ->
    withBytes pm $ \pmP pmLen ->
      withBytes wm $ \wmP wmLen ->
        alloca $ \handleP -> do
          poke handleP 0
          rc <- c_ITB_Triple_Load blobP blobLen pmP pmLen wmP wmLen count handleP
          check rc
          h <- peek handleP
          mkPipeline h

-- | 'loadPipeline' for a blob stored at the given path; the file is
-- read inside libitb3 (a missing or unreadable file fails with
-- 'statusBadInput' and the diagnostic attached).
loadPipelineF :: FilePath -> Maybe (BS.ByteString, BS.ByteString) -> IO Pipeline
loadPipelineF path masters = do
  let (pm, wm, count) = mastersArgs masters
  withCStr path $ \pathC ->
    withBytes pm $ \pmP pmLen ->
      withBytes wm $ \wmP wmLen ->
        alloca $ \handleP -> do
          poke handleP 0
          rc <- c_ITB_Triple_LoadF (castPtr pathC) pmP pmLen wmP wmLen count handleP
          check rc
          h <- peek handleP
          mkPipeline h

-- ── session management ───────────────────────────────────────────────

-- | The current session bundle bytes for the receiver side (the Init
-- blob, or the bytes of the latest 'rekey'). A closed Pipeline fails
-- with 'statusTripleClosed'.
save :: Pipeline -> IO BS.ByteString
save p =
  withPipelineHandle p $ \h ->
    retryOnce blobCap $ \buf cap lenP -> c_ITB_Triple_Save h buf cap lenP

-- | Writes the current blob to the given path inside libitb3 (mode
-- 0600; the containing directory must exist).
saveF :: Pipeline -> FilePath -> IO ()
saveF p path =
  withPipelineHandle p $ \h ->
    withCStr path $ \pathC -> c_ITB_Triple_SaveF h (castPtr pathC) >>= check

-- | Sets the worker cap for every subsequent cipher call. The value is
-- clamped by libitb3 (@<= 0@ selects auto, @> 256@ becomes 256); only
-- the handle state is reported. The cap is per-machine and never
-- travels in the blob. (Named 'setMaxWorkers' because 'ITB3.Opts.maxWorkers'
-- is the Init-time opts setter.)
setMaxWorkers :: Pipeline -> Int -> IO ()
setMaxWorkers p n =
  withPipelineHandle p $ \h -> c_ITB_Triple_MaxWorkers h (fromIntegral n) >>= check

-- | Rotates the parallax + wrapper masters and returns the fresh blob
-- (also available through 'save'). Must not run concurrently with
-- cipher calls or open stream sessions on the same Pipeline.
rekey :: Pipeline -> BS.ByteString -> BS.ByteString -> IO BS.ByteString
rekey p perm wrap =
  withPipelineHandle p $ \h ->
    withBytes perm $ \pmP pmLen ->
      withBytes wrap $ \wmP wmLen ->
        retryOnce blobCap $ \buf cap lenP ->
          c_ITB_Triple_Rekey h pmP pmLen wmP wmLen buf cap lenP

-- | Zeroes the Pipeline's key material and marks it closed.
-- Idempotent; subsequent cipher calls fail with 'statusTripleClosed'.
closePipeline :: Pipeline -> IO ()
closePipeline p = withPipelineHandle p $ \h -> c_ITB_Triple_Close h >>= check

-- | Releases the Go-side handle now instead of waiting for GC.
-- Safe to call more than once.
freePipeline :: Pipeline -> IO ()
freePipeline = finalizeForeignPtr . pipeFP

-- ── cipher entries ───────────────────────────────────────────────────

-- | Single Message encrypt: one call, one self-contained wire.
encryptMessage :: Pipeline -> BS.ByteString -> IO BS.ByteString
encryptMessage = cipher c_ITB_Triple_EncryptMessage

-- | Receive-side counterpart of 'encryptMessage'.
decryptMessage :: Pipeline -> BS.ByteString -> IO BS.ByteString
decryptMessage = cipher c_ITB_Triple_DecryptMessage

-- | One-shot stream encrypt for callers holding the whole plaintext
-- in memory. For bounded-memory streaming use
-- 'ITB3.Stream.encryptStream'.
encryptStreamOneShot :: Pipeline -> BS.ByteString -> IO BS.ByteString
encryptStreamOneShot = cipher c_ITB_Triple_EncryptStream

-- | Receive-side counterpart of 'encryptStreamOneShot'.
decryptStreamOneShot :: Pipeline -> BS.ByteString -> IO BS.ByteString
decryptStreamOneShot = cipher c_ITB_Triple_DecryptStream

-- | Shared body for the four buffer-in \/ buffer-out cipher entries.
cipher
  :: (ITBHandle -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr CSize -> IO CInt)
  -> Pipeline -> BS.ByteString -> IO BS.ByteString
cipher f p src =
  withPipelineHandle p $ \h ->
    withBytes src $ \srcP srcLen ->
      retryOnce (outCap (BS.length src)) $ \buf cap lenP ->
        f h srcP srcLen buf cap lenP

-- ── profile records ──────────────────────────────────────────────────
--
-- A profile record is the JSON object libitb3 accepts in 'register',
-- returns from 'lookupProfile' \/ 'inspect', and embeds in every
-- blob. Optional keys are omitted when empty \/ zero. The binding
-- treats the record as an opaque string; every field rule is
-- enforced by libitb3.

-- | Decodes the profile record embedded in the blob without
-- constructing a Pipeline. No registry read, no primitive probe.
inspect :: BS.ByteString -> IO String
inspect blobBytes =
  withBytes blobBytes $ \blobP blobLen ->
    BC.unpack <$> retryOnce blobCap (\buf cap lenP ->
      c_ITB_Triple_Inspect blobP blobLen buf cap lenP)

-- | Registers a user-defined Triple profile under the given name from
-- a profile JSON record (a non-empty @name@ key inside the record
-- must equal the argument) so subsequent 'initPipeline' calls resolve
-- it. A duplicate name fails with 'statusProfileExists'.
register :: String -> String -> IO ()
register name profileJSON =
  withCStr name $ \nameC ->
    withCStr profileJSON $ \jsonC -> do
      rc <- c_ITB_Triple_Register (castPtr nameC) (castPtr jsonC)
      check rc

-- | The profile registered under the given name — a shipped catalogue
-- entry or a prior 'register' — as its JSON record. An unregistered
-- name fails with 'statusUnknownProfile'. (Named 'lookupProfile'
-- because 'lookup' is a Prelude function.)
lookupProfile :: String -> IO String
lookupProfile name =
  withCStr name $ \nameC ->
    BC.unpack <$> retryOnce blobCap (\buf cap lenP ->
      c_ITB_Triple_Lookup (castPtr nameC) buf cap lenP)

-- | The sorted list of every registered profile name — the shipped
-- catalogue plus prior 'register' calls. libitb3 returns a JSON array
-- of strings; names match @^[a-z][a-z0-9-]+$@, so the array splits
-- on the quote characters alone.
profiles :: IO [String]
profiles = do
  json <- BC.unpack <$> retryOnce blobCap (\buf cap lenP ->
    c_ITB_Triple_Profiles buf cap lenP)
  pure (odds (splitOn '"' json))
  where
    splitOn c str = case break (== c) str of
      (a, [])     -> [a]
      (a, _:rest) -> a : splitOn c rest
    odds (_:x:xs) = x : odds xs
    odds _        = []
