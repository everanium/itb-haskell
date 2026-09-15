-- | Fluent builder for the opts pass-through string.
--
-- The builder performs no validation — every key\/value pair is
-- rendered into a percent-encoded URL query string and passed through
-- to Go verbatim; libitb3 rejects unknown keys or bad values with a
-- diagnostic surfaced via 'ITB3.Errors.ITBError'. Primitive \/ MAC \/
-- cipher \/ palette names are opaque strings.
--
-- 'Opts' is a 'Monoid', so pairs compose fluently:
--
-- > nonceBits 512 <> keyBits 1024 <> withParallax False
module ITB3.Opts
  ( Opts
  , emptyOpts
  , renderOpts
    -- * Typed setters
  , permMaster
  , wrapMaster
  , withParallax
  , withWrapper
  , maxWorkers
  , nonceBits
  , barrierFill
  , chunkSize
  , keyBits
  , parallaxSegmentSize
  , macName
  , innerHash
  , innerHashes
  , outerCipher
  , parallaxPalette
    -- * Escape hatch
  , opt
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.List (intercalate)
import Data.Word (Word8)
import Text.Printf (printf)

-- | Accumulated @key=value@ pairs, rendered by 'renderOpts'.
newtype Opts = Opts [(String, String)]
  deriving (Show, Eq)

instance Semigroup Opts where
  Opts a <> Opts b = Opts (a <> b)

instance Monoid Opts where
  mempty = Opts []

-- | No options — libitb3 applies the profile defaults.
emptyOpts :: Opts
emptyOpts = mempty

-- | Escape hatch appending a raw @key=value@ pair. Covers every key
-- the Go side accepts for Init overrides. Profile registration takes
-- a profile JSON record instead (see 'ITB3.Pipeline.register').
opt :: String -> String -> Opts
opt k v = Opts [(k, v)]

-- | Hex-encodes the parallax master override (@pm@).
permMaster :: BS.ByteString -> Opts
permMaster = opt "pm" . hex

-- | Hex-encodes the wrapper master override (@wm@).
wrapMaster :: BS.ByteString -> Opts
wrapMaster = opt "wm" . hex

withParallax :: Bool -> Opts
withParallax = opt "withParallax" . boolStr

withWrapper :: Bool -> Opts
withWrapper = opt "withWrapper" . boolStr

maxWorkers :: Int -> Opts
maxWorkers = opt "maxWorkers" . show

nonceBits :: Int -> Opts
nonceBits = opt "nonceBits" . show

barrierFill :: Int -> Opts
barrierFill = opt "barrierFill" . show

chunkSize :: Int -> Opts
chunkSize = opt "chunkSize" . show

keyBits :: Int -> Opts
keyBits = opt "keyBits" . show

parallaxSegmentSize :: Int -> Opts
parallaxSegmentSize = opt "parallaxSegmentSize" . show

macName :: String -> Opts
macName = opt "macName"

innerHash :: String -> Opts
innerHash = opt "innerHash"

-- | Per-call override for @Opts.MixedHashes [8]string@ on the Go
-- side. Comma-joins the 8 slot names into the @innerHashes@ opts
-- key. Slot ordering is
-- @[noise, lock, data1, data2, data3, start1, start2, start3]@.
-- Fail-fast validation surfaces at Init on the Go side; a typo'd
-- slot or width mismatch surfaces with an error naming the offending
-- slot. When both this and 'innerHash' are set, the mixed override
-- wins on the Go side.
innerHashes :: [String] -> Opts
innerHashes = opt "innerHashes" . intercalate ","

outerCipher :: String -> Opts
outerCipher = opt "outerCipher"

-- | Comma-joins the palette names (@parallaxPalette@).
parallaxPalette :: [String] -> Opts
parallaxPalette = opt "parallaxPalette" . intercalate ","

-- | Renders the accumulated pairs as a percent-encoded query string.
renderOpts :: Opts -> BS.ByteString
renderOpts (Opts pairs) =
  BC.pack . intercalate "&" $ [enc k <> "=" <> enc v | (k, v) <- pairs]

boolStr :: Bool -> String
boolStr True  = "true"
boolStr False = "false"

-- | Minimal percent-encoding: the accepted values are ASCII names,
-- decimal integers, @true@ \/ @false@, hex, and comma-separated
-- lists, so everything outside the URL-safe subset (plus @,@) is
-- escaped byte-wise.
enc :: String -> String
enc = concatMap escByte . BS.unpack . BC.pack
  where
    escByte :: Word8 -> String
    escByte b
      | urlSafe b = [toEnum (fromIntegral b)]
      | otherwise = printf "%%%02X" b
    urlSafe b =
      (b >= 0x41 && b <= 0x5A)      -- A-Z
        || (b >= 0x61 && b <= 0x7A) -- a-z
        || (b >= 0x30 && b <= 0x39) -- 0-9
        || b `BS.elem` BC.pack "-._~,"

hex :: BS.ByteString -> String
hex = concatMap (printf "%02x") . BS.unpack
