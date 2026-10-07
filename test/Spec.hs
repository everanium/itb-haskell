{-# LANGUAGE BangPatterns #-}

-- | hspec suite for the ITB Haskell binding: roster checks, Single
-- Message and incremental streaming round trips, error mapping, the
-- large-plaintext pre-allocate\/retry path, rekey, profile
-- registration, and the stream session's GC parent-pin.
module Main (main) where

import Control.Concurrent (threadDelay)
import Control.Monad (forM_)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.Bits (shiftL, shiftR, xor)
import Data.List (isInfixOf, sort)
import Data.Word (Word8, Word64)
import System.Directory (getTemporaryDirectory, removeFile)
import System.Mem (performGC)
import Test.Hspec

import ITB3

-- | Deterministic non-trivial payload (xorshift64 fill).
payload :: Int -> Word64 -> BS.ByteString
payload n seed = fst (BS.unfoldrN n step (seed * 2 + 1))
  where
    step :: Word64 -> Maybe (Word8, Word64)
    step !x =
      let a = x `xor` (x `shiftL` 13)
          b = a `xor` (a `shiftR` 7)
          c = b `xor` (b `shiftL` 17)
      in Just (fromIntegral c, c)

-- | Expects the action to throw an 'ITBError' whose status is one of
-- the given codes.
shouldFailWithStatus :: IO a -> [Int] -> IO ()
shouldFailWithStatus action codes =
  (action >> pure ()) `shouldThrow` \e -> statusCode e `elem` codes

main :: IO ()
main = hspec $ do
  describe "roster" $ do
    it "version is non-empty" $ do
      v <- version
      v `shouldNotBe` ""

    it "drbg auto tier is one of the two fill ciphers" $ do
      t <- drbgAutoTier
      t `shouldSatisfy` (`elem` ["aes-256-ctr", "chacha20"])

    it "profiles list carries the shipped names" $ do
      forM_ [ "singlemsg-triple-mac-v1"
            , "singlemsg-triple-nomac-v1"
            , "streaming-aead-triple-mac-v1"
            , "streaming-noaead-triple-v1"
            ] $ \name -> profiles >>= (`shouldSatisfy` elem name)

    it "runtime knobs answer queries" $ do
      -- Negative values query without changing.
      _ <- setMemoryLimit (-1)
      prev <- setGcPercent (-1)
      prev `shouldSatisfy` (/= minBound)

  describe "Single Message" $ do
    it "round-trips through blob hand-off (singlemsg-triple-mac-v1)" $ do
      sender <- newPipeline "singlemsg-triple-mac-v1"
      blobBytes <- save sender
      receiver <- loadPipeline blobBytes Nothing
      forM_ [1, 4096, 256 * 1024] $ \size -> do
        let plain = payload size (fromIntegral size)
        wire <- encryptMessage sender plain
        wire `shouldNotBe` plain
        back <- decryptMessage receiver wire
        back `shouldBe` plain
      freePipeline receiver
      freePipeline sender

    it "round-trips a large plaintext (pattern P1, > 1 MiB)" $ do
      sender <- newPipeline "singlemsg-triple-nomac-v1"
      blobBytes <- save sender
      receiver <- loadPipeline blobBytes Nothing
      let plain = payload (2 * 1024 * 1024 + 17) 3
      wire <- encryptMessage sender plain
      back <- decryptMessage receiver wire
      back `shouldBe` plain
      freePipeline receiver
      freePipeline sender

  describe "Streaming" $ do
    it "round-trips incrementally (streaming-noaead-triple-v1)" $ do
      sender <- newPipeline "streaming-noaead-triple-v1"
      blobBytes <- save sender
      receiver <- loadPipeline blobBytes Nothing
      let plain = payload (96 * 1024) 7

      -- Encrypt incrementally: 8 KiB writes, then end + drain.
      enc <- encryptStream sender
      forM_ (chunksOf 8192 plain) (writeStream enc)
      wire <- drainAll enc
      BS.length wire `shouldSatisfy` (> 0)
      freeStream enc

      -- Decrypt with pathological batch sizes (17-byte feed, 23-byte
      -- drain) across chunk boundaries.
      dec <- decryptStream receiver
      forM_ (chunksOf 17 wire) (writeStream dec)
      endStream dec
      let drainLoop acc = do
            (chunk, fin) <- readStream dec 23
            let acc' = chunk : acc
            if fin then pure (BS.concat (reverse acc')) else drainLoop acc'
      back <- drainLoop []
      back `shouldBe` plain
      freeStream dec
      freePipeline receiver
      freePipeline sender

    it "one-shot stream matches the incremental wire format" $ do
      sender <- newPipeline "streaming-noaead-triple-v1"
      blobBytes <- save sender
      receiver <- loadPipeline blobBytes Nothing
      let plain = payload (64 * 1024 + 3) 11
      wire <- encryptStreamOneShot sender plain
      back <- decryptStreamOneShot receiver wire
      back `shouldBe` plain
      freePipeline receiver
      freePipeline sender

    it "pins its parent Pipeline against GC (session-parent pin)" $ do
      -- The Pipeline local goes out of scope with no other reference;
      -- the session record (and its finalizer) must keep the Go-side
      -- Pipeline handle alive.
      sess <- do
        pipe <- newPipeline "streaming-noaead-triple-v1"
        encryptStream pipe
      performGC
      threadDelay 50000
      performGC
      threadDelay 50000
      writeStream sess (BC.pack "still alive after parent went out of scope")
      wire <- drainAll sess
      BS.length wire `shouldSatisfy` (> 0)
      freeStream sess

  describe "error mapping" $ do
    it "unknown profile maps to statusBadInput" $
      newPipeline "no-such-profile"
        `shouldFailWithStatus` [statusUnknownProfile]

    it "unknown opts key maps to statusBadInput" $
      -- Typoed key (lowercase s) — Go rejects unknown keys; the
      -- binding performs no validation of its own.
      initPipeline "singlemsg-triple-mac-v1" (opt "chunksize" "4096")
        `shouldFailWithStatus` [statusBadInput]

    it "tampered wire fails authentication" $ do
      sender <- newPipeline "singlemsg-triple-mac-v1"
      blobBytes <- save sender
      receiver <- loadPipeline blobBytes Nothing
      wire <- encryptMessage sender (payload 4096 21)
      let i = BS.length wire `div` 2
          tampered = BS.concat
            [ BS.take i wire
            , BS.singleton (BS.index wire i `xor` 0xFF)
            , BS.drop (i + 1) wire
            ]
      decryptMessage receiver tampered
        `shouldFailWithStatus` [statusMacFailure, statusDecryptFailed]
      freePipeline receiver
      freePipeline sender

    it "closed Pipeline maps to statusTripleClosed" $ do
      pipe <- newPipeline "singlemsg-triple-mac-v1"
      closePipeline pipe
      closePipeline pipe -- idempotent
      encryptMessage pipe (BC.pack "payload")
        `shouldFailWithStatus` [statusTripleClosed]
      freePipeline pipe

  describe "session management" $ do
    it "rekey refreshes the blob and the refreshed blob loads" $ do
      sender <- newPipeline "singlemsg-triple-mac-v1"
      blobBefore <- save sender
      rotated <- rekey sender (payload 32 5) (payload 32 6)
      rotated `shouldNotBe` blobBefore
      blobAfter <- save sender
      blobAfter `shouldBe` rotated
      receiver <- loadPipeline rotated Nothing
      wire <- encryptMessage sender (BC.pack "post-rekey payload")
      back <- decryptMessage receiver wire
      back `shouldBe` BC.pack "post-rekey payload"
      freePipeline receiver
      freePipeline sender

    it "register round-trips, reads back, and rejects a duplicate" $ do
      -- 8-entry width-256 hashes constellation, layers off; the
      -- record is a profile JSON object.
      let prof = concat
            [ "{\"mode\":\"singlemsg-nomac\",\"width\":256,"
            , "\"hashes\":[\"blake3\",\"blake2s\",\"areion256\",\"blake2b256\","
            , "\"chacha20\",\"blake3\",\"blake2s\",\"areion256\"],"
            , "\"keybits\":1024,\"wrapper\":false,\"parallax\":false}"
            ]
      register "haskell-binding-test-mixed" prof
      sender <- newPipeline "haskell-binding-test-mixed"
      blobBytes <- save sender
      receiver <- loadPipeline blobBytes Nothing
      wire <- encryptMessage sender (BC.pack "custom profile")
      back <- decryptMessage receiver wire
      back `shouldBe` BC.pack "custom profile"
      looked <- lookupProfile "haskell-binding-test-mixed"
      looked `shouldSatisfy` isInfixOf "\"name\":\"haskell-binding-test-mixed\""
      looked `shouldSatisfy` isInfixOf "\"hashes\":[\"blake3\",\"blake2s\""
      register "haskell-binding-test-mixed" prof
        `shouldFailWithStatus` [statusProfileExists]
      -- A non-empty name inside the record must equal the argument.
      register "haskell-binding-test-mismatch"
        "{\"name\":\"other\",\"mode\":\"singlemsg-nomac\",\"width\":512,\"hash\":\"areion512\",\"keybits\":1024,\"wrapper\":false,\"parallax\":false}"
        `shouldFailWithStatus` [statusBadInput]
      freePipeline receiver
      freePipeline sender

    it "unknown profile maps to statusUnknownProfile on lookup" $
      lookupProfile "no-such-profile" `shouldFailWithStatus` [statusUnknownProfile]

    it "negative maxWorkers opts value is clamped" $ do
      pipe <- initPipeline "singlemsg-triple-mac-v1" (maxWorkers (-1))
      b <- save pipe
      BS.null b `shouldBe` False
      freePipeline pipe

  describe "persistence" $ do
    it "save then load round-trips; save is stable; load retains the bytes" $ do
      sender <- newPipeline "singlemsg-triple-mac-v1"
      b <- save sender
      b2 <- save sender
      b2 `shouldBe` b
      receiver <- loadPipeline b Nothing
      wire <- encryptMessage sender (BC.pack "in-memory")
      back <- decryptMessage receiver wire
      back `shouldBe` BC.pack "in-memory"
      retained <- save receiver
      retained `shouldBe` b
      freePipeline receiver
      freePipeline sender

    it "load with master overrides equals a sender rekey" $ do
      sender <- newPipeline "singlemsg-triple-mac-v1"
      b <- save sender
      let perm = BS.replicate 32 0x31
          wrap = BS.replicate 32 0x32
      receiver <- loadPipeline b (Just (perm, wrap))
      rotated <- save receiver
      rotated `shouldNotBe` b
      _ <- rekey sender perm wrap
      wire <- encryptMessage sender (BC.pack "overrides")
      back <- decryptMessage receiver wire
      back `shouldBe` BC.pack "overrides"
      freePipeline receiver
      freePipeline sender

    it "inspect carries the recipe plus inspection-only fields; garbage is statusBadInput" $ do
      sender <- newPipeline "singlemsg-triple-mac-v1"
      b <- save sender
      inspected <- inspect b
      looked <- lookupProfile "singlemsg-triple-mac-v1"
      -- inspect carries the registry recipe plus the blob-only
      -- nonce_bits / barrier_fill inspection fields; lookup returns
      -- just the recipe.
      inspected `shouldSatisfy` isInfixOf "\"name\":\"singlemsg-triple-mac-v1\""
      inspected `shouldSatisfy` isInfixOf "\"mode\":\"singlemsg-mac\""
      inspected `shouldSatisfy` isInfixOf "\"nonce_bits\":"
      inspected `shouldSatisfy` isInfixOf "\"barrier_fill\":"
      looked `shouldSatisfy` isInfixOf "\"name\":\"singlemsg-triple-mac-v1\""
      looked `shouldSatisfy` (not . isInfixOf "\"nonce_bits\":")
      looked `shouldSatisfy` (not . isInfixOf "\"barrier_fill\":")
      inspect (BC.pack "not a blob") `shouldFailWithStatus` [statusBadInput]
      freePipeline sender

    it "profiles lists the catalogue sorted and each name resolves" $ do
      names <- profiles
      names `shouldSatisfy` elem "singlemsg-triple-mac-v1"
      names `shouldBe` sort names
      forM_ names $ \n -> do
        looked <- lookupProfile n
        looked `shouldSatisfy` isInfixOf ("\"name\":\"" ++ n ++ "\"")

    it "saveF then loadPipelineF round-trips; missing file is statusBadInput" $ do
      tmp <- getTemporaryDirectory
      let path = tmp ++ "/itb-haskell-persist.blob"
      sender <- newPipeline "streaming-aead-triple-mac-v1"
      saveF sender path
      onDisk <- BS.readFile path
      b <- save sender
      onDisk `shouldBe` b
      receiver <- loadPipelineF path Nothing
      wire <- encryptStreamOneShot sender (BC.pack "on-disk")
      back <- decryptStreamOneShot receiver wire
      back `shouldBe` BC.pack "on-disk"
      removeFile path
      loadPipelineF path Nothing `shouldFailWithStatus` [statusBadInput]
      freePipeline receiver
      freePipeline sender

    it "setMaxWorkers clamps; closed Pipeline maps to statusTripleClosed" $ do
      sender <- newPipeline "singlemsg-triple-mac-v1"
      setMaxWorkers sender 2
      setMaxWorkers sender (-1)
      setMaxWorkers sender 100000
      b <- save sender
      receiver <- loadPipeline b Nothing
      setMaxWorkers receiver 1
      wire <- encryptMessage sender (BC.pack "workers")
      back <- decryptMessage receiver wire
      back `shouldBe` BC.pack "workers"
      closePipeline receiver
      save receiver `shouldFailWithStatus` [statusTripleClosed]
      setMaxWorkers receiver 2 `shouldFailWithStatus` [statusTripleClosed]
      freePipeline receiver
      freePipeline sender

  describe "opts builder" $ do
    it "renders typed setters as the expected query string" $ do
      let q = renderOpts $ mconcat
            [ permMaster (BS.pack [0xAB, 0x01])
            , wrapMaster (BS.pack [0xCD, 0xEF])
            , withParallax True
            , withWrapper False
            , nonceBits 512
            , keyBits 1024
            , innerHash "areion512"
            , parallaxPalette ["aescmac", "chacha20", "blake3"]
            ]
      q `shouldBe` BC.pack
        "pm=ab01&wm=cdef&withParallax=true&withWrapper=false&\
        \nonceBits=512&keyBits=1024&innerHash=areion512&\
        \parallaxPalette=aescmac,chacha20,blake3"

    it "percent-encodes bytes outside the URL-safe subset" $ do
      renderOpts (opt "mode" "a b&c=d%")
        `shouldBe` BC.pack "mode=a%20b%26c%3Dd%25"
      renderOpts emptyOpts `shouldBe` BC.pack ""

    it "innerHashes override round-trips on a width-512 profile" $ do
      -- Per-call Opts.MixedHashes override over a width-512 shipped
      -- base profile; the blob carries the resolved constellation, so
      -- the receiver Pipeline (loaded from the blob) resolves the same
      -- mixed inner-hash bundle as the sender without an override.
      let mix = innerHashes
            [ "areion512", "blake2b512", "areion512", "blake2b512"
            , "areion512", "blake2b512", "areion512", "blake2b512"
            ]
      sender <- initPipeline "singlemsg-triple-mac-v1" mix
      blobBytes <- save sender
      receiver <- loadPipeline blobBytes Nothing
      let plain = payload 4096 42
      wire <- encryptMessage sender plain
      back <- decryptMessage receiver wire
      back `shouldBe` plain
      freePipeline receiver
      freePipeline sender

  describe "runtime surface" $ do
    it "hash registry enumerates in registry order" $ do
      names <- hashNames
      names `shouldNotBe` []
      head names `shouldBe` "aesitb128"
      names `shouldSatisfy` elem "areion512"
      names `shouldSatisfy` elem "blake3"
      names `shouldSatisfy` notElem "nope"

    it "GOMAXPROCS queries and restores" $ do
      before <- setGomaxprocs 0
      before `shouldSatisfy` (> 0)
      prev <- setGomaxprocs 2
      prev `shouldBe` before
      setGomaxprocs 0 >>= (`shouldBe` 2)
      _ <- setGomaxprocs before
      setGomaxprocs 0 >>= (`shouldBe` before)

    it "pool counters report the advertised slot count and grow" $ do
      n <- poolStatsLen
      n `shouldSatisfy` (> 8)
      before <- poolStats
      length before `shouldBe` n
      let tiers = fromIntegral (head before) :: Int
      tiers `shouldSatisfy` (> 0)
      n `shouldBe` 1 + 5 * tiers + 8
      pipe <- newPipeline "singlemsg-triple-mac-v1"
      let plain = payload 2048 97
      wire <- encryptMessage pipe plain
      back <- decryptMessage pipe wire
      back `shouldBe` plain
      freePipeline pipe
      after <- poolStats
      -- Slot 1 + 5*i + 1 is tier i's checkout count; at least one tier
      -- was checked out by the round trip above.
      let moved = or [ after !! (1 + 5 * i + 1) > before !! (1 + 5 * i + 1)
                     | i <- [0 .. tiers - 1] ]
      moved `shouldBe` True

    it "heap profile is written and is non-empty" $ do
      dir <- getTemporaryDirectory
      let path = dir ++ "/itb-haskell-heap.prof"
      writeHeapProfile path
      bytes <- BS.readFile path
      BS.length bytes `shouldSatisfy` (> 0)
      removeFile path

    it "heap profile with no path and no env fallback is statusBadInput" $
      writeHeapProfile "" `shouldFailWithStatus` [statusBadInput]

  describe "DRBG fill primitive" $ do
    it "round-trips through a loaded blob under csprng and aesitb128" $
      forM_ ["csprng", "aesitb128"] $ \name -> do
        sender <- initPipeline "singlemsg-triple-mac-v1" (drbg name)
        blobBytes <- save sender
        receiver <- loadPipeline blobBytes Nothing
        let plain = BC.pack ("drbg " ++ name)
        wire <- encryptMessage sender plain
        back <- decryptMessage receiver wire
        back `shouldBe` plain
        let reverse' = BC.pack ("reverse " ++ name)
        wire' <- encryptMessage receiver reverse'
        back' <- decryptMessage sender wire'
        back' `shouldBe` reverse'
        freePipeline receiver
        freePipeline sender

    it "inspect reports drbg; the default carries none; an unknown name is statusRecipePrimitiveUnknown" $ do
      sender <- initPipeline "singlemsg-triple-mac-v1" (drbg "csprng")
      inspected <- save sender >>= inspect
      inspected `shouldSatisfy` isInfixOf "\"drbg\":\"csprng\""
      freePipeline sender
      -- With no drbg set the record carries no drbg key, and no
      -- shipped profile names one.
      plain <- newPipeline "singlemsg-triple-mac-v1"
      defaultRecord <- save plain >>= inspect
      defaultRecord `shouldSatisfy` (not . isInfixOf "\"drbg\":")
      freePipeline plain
      looked <- lookupProfile "singlemsg-triple-mac-v1"
      looked `shouldSatisfy` (not . isInfixOf "\"drbg\":")
      initPipeline "singlemsg-triple-mac-v1" (drbg "nope")
        `shouldThrow` \e -> statusCode e == statusRecipePrimitiveUnknown
                            && "nope" `isInfixOf` lastError e

    it "a register copy of an inspected record keeps drbg" $ do
      sender <- initPipeline "singlemsg-triple-mac-v1" (drbg "csprng")
      inspected <- save sender >>= inspect
      -- The inspection-only fields are dropped; drbg is a recipe field
      -- and stays in the registered copy.
      let record = foldr dropScalarKey inspected
            ["name", "nonce_bits", "barrier_fill", "container_mode"]
      register "haskell-binding-test-drbg-copy" record
      looked <- lookupProfile "haskell-binding-test-drbg-copy"
      looked `shouldSatisfy` isInfixOf "\"drbg\":\"csprng\""
      freePipeline sender

-- | Splits a ByteString into slices of at most @n@ bytes (zero-copy).
chunksOf :: Int -> BS.ByteString -> [BS.ByteString]
chunksOf n bs
  | BS.null bs = []
  | otherwise = BS.take n bs : chunksOf n (BS.drop n bs)

-- | Removes a @"key":value,@ member with a scalar value from a flat
-- JSON object rendering; the record is left unchanged when the key is
-- absent.
dropScalarKey :: String -> String -> String
dropScalarKey key = go
  where
    needle = "\"" ++ key ++ "\":"
    go [] = []
    go s@(c : rest)
      | take (length needle) s == needle =
          let afterValue = dropWhile (/= ',') (drop (length needle) s)
          in drop 1 afterValue
      | otherwise = c : go rest
