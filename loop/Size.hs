-- | Size and duration parsing, the monotonic clock, and the human
-- renderings of sizes, rates and durations. Every rendering here is
-- part of the output contract shared with the Go harness and the other
-- bindings' loop utilities, so the formats are fixed to the character,
-- not to taste.
module Size
  ( parseSize
  , parseDuration
  , nowNs
  , humanBytes
  , humanBytesSigned
  , humanRate
  , humanDuration
  , mbPerSec
  , roundNs
  ) where

import Data.Char (isDigit, isSpace, toUpper)
import Data.Int (Int64)
import Data.List (isSuffixOf)
import GHC.Clock (getMonotonicTimeNSec)
import Text.Printf (printf)

-- | Parses a human byte-size string (@16MB@, @1MiB@, @512K@,
-- @1073741824@) into a byte count. Every suffix is a binary multiple:
-- K\/KB\/KiB = 1024, M\/MB\/MiB = 1024^2, G\/GB\/GiB = 1024^3, B or
-- none = bytes; matching is case-insensitive and surrounding
-- whitespace is trimmed. 'Nothing' on a malformed or negative value.
parseSize :: String -> Maybe Int64
parseSize raw
  | null upper = Nothing
  | null digits = Nothing
  | not (all isDigit digits) = Nothing
  | otherwise =
      let n = read digits :: Integer
          v = n * fromIntegral mult
      in if v > fromIntegral (maxBound :: Int64) then Nothing else Just (fromIntegral v)
  where
    upper = map toUpper (trim raw)
    (mult, digits) = case [ (m, take (length upper - length sfx) upper)
                          | (sfx, m) <- suffixes, sfx `isSuffixOf` upper ] of
      ((m, d) : _) -> (m, dropWhileEnd isSpace d)
      []           -> (1 :: Int64, upper)
    -- A two-letter suffix is tried before the single letter it ends
    -- with, or "MIB" would match "B" and leave "MI" as the digits.
    suffixes =
      [ ("KIB", 1024), ("KB", 1024), ("K", 1024)
      , ("MIB", 1048576), ("MB", 1048576), ("M", 1048576)
      , ("GIB", 1073741824), ("GB", 1073741824), ("G", 1073741824)
      , ("B", 1)
      ]

trim :: String -> String
trim = dropWhileEnd isSpace . dropWhile isSpace

dropWhileEnd :: (a -> Bool) -> [a] -> [a]
dropWhileEnd p = foldr (\x xs -> if p x && null xs then [] else x : xs) []

-- | One unit of the duration grammar, in the order the parser probes
-- them: a two-letter unit has to be tried before the single letter it
-- ends with, or "ms" would match "m" and leave a stray "s".
durationUnits :: [(String, Double)]
durationUnits =
  [ ("ns", 1), ("us", 1e3), ("ms", 1e6)
  , ("s", 1e9), ("m", 60e9), ("h", 3600e9)
  ]

-- | Parses the Go duration grammar — a sequence of decimal numbers
-- each followed by a unit (h, m, s, ms, us, ns), such as @30s@, @5m@,
-- @1h30m@, @3s500ms@, @1.5s@ — into nanoseconds. 'Nothing' on a
-- malformed string.
parseDuration :: String -> Maybe Int64
parseDuration "" = Nothing
parseDuration s0 = go s0 0
  where
    go "" total
      | total > 9.2e18 = Nothing
      | otherwise      = Just (truncate total)
    go s total = do
      let (num, rest) = span (\c -> isDigit c || c == '.') s
      if null num || not (isDigit (head s) || head s == '.')
        then Nothing
        else do
          v <- readDouble num
          (mult, rest') <- unitOf rest
          if v < 0 then Nothing else go rest' (total + v * mult)
    unitOf s = case [ (m, drop (length u) s)
                    | (u, m) <- durationUnits
                    , take (length u) s == u
                    , not (alphaAt (drop (length u) s)) ] of
      (x : _) -> Just x
      []      -> Nothing
    alphaAt (c : _) = c `elem` (['a' .. 'z'] ++ ['A' .. 'Z'])
    alphaAt []      = False
    readDouble t = case reads (if head t == '.' then '0' : t else t) of
      [(v, "")] -> Just (v :: Double)
      _         -> Nothing

-- | Monotonic wall clock in nanoseconds.
nowNs :: IO Int64
nowNs = fromIntegral <$> getMonotonicTimeNSec

-- | Renders a byte count with a binary-unit suffix: @1.0GiB@,
-- @16.0MiB@, @4.0KiB@, @512B@.
humanBytes :: Int64 -> String
humanBytes n
  | n >= 1073741824 = printf "%.1fGiB" (fromIntegral n / 1073741824 :: Double)
  | n >= 1048576    = printf "%.1fMiB" (fromIntegral n / 1048576 :: Double)
  | n >= 1024       = printf "%.1fKiB" (fromIntegral n / 1024 :: Double)
  | otherwise       = show n ++ "B"

-- | Renders a possibly-negative byte delta with an explicit sign.
humanBytesSigned :: Int64 -> String
humanBytesSigned n
  | n < 0     = '-' : humanBytes (negate n)
  | otherwise = '+' : humanBytes n

-- | Binary MiB per second over a nanosecond window; 0 when the window
-- is unmeasured.
mbPerSec :: Int64 -> Int64 -> Double
mbPerSec bytes ns
  | ns <= 0   = 0
  | otherwise = fromIntegral bytes / 1048576 / (fromIntegral ns / 1e9)

-- | Renders a throughput as @123.4MB\/s@ (binary MiB per second) or
-- @n\/a@ for an unmeasured window.
humanRate :: Int64 -> Int64 -> String
humanRate bytes ns
  | ns <= 0   = "n/a"
  | otherwise = printf "%.1fMB/s" (mbPerSec bytes ns)

-- | The fractional part of a nanosecond remainder (0 .. 1e9) as
-- @.ddd@ with trailing zeros removed; the empty string for zero.
fraction :: Int64 -> String
fraction 0 = ""
fraction frac = '.' : reverse (dropWhile (== '0') (reverse padded))
  where
    digits = show frac
    padded = replicate (9 - length digits) '0' ++ digits

-- | Renders a duration the way Go's @time.Duration@ prints: below one
-- second as milliseconds (@900ms@, @1.5ms@); otherwise @[Hh][Mm]Ss@
-- where the hour part appears when non-zero, the minute part when the
-- hour part appears or the minutes are non-zero, and the seconds carry
-- their fraction with trailing zeros removed (@5s@, @5.003s@, @1m0s@,
-- @1m5.25s@, @1h0m0s@). The caller rounds first.
humanDuration :: Int64 -> String
humanDuration nanos
  | ns == 0 = "0s"
  | ns < 1000000000 =
      show (ns `div` 1000000) ++ fraction ((ns `mod` 1000000) * 1000) ++ "ms"
  | otherwise = hoursPart ++ minutesPart ++ show seconds ++ fraction frac ++ "s"
  where
    ns = abs nanos
    hours = ns `div` 3600000000000
    rem1 = ns `mod` 3600000000000
    minutes = rem1 `div` 60000000000
    rem2 = rem1 `mod` 60000000000
    seconds = rem2 `div` 1000000000
    frac = rem2 `mod` 1000000000
    hoursPart = if hours > 0 then show hours ++ "h" else ""
    minutesPart =
      if hours > 0 || minutes > 0 then show minutes ++ "m" else ""

-- | Rounds a nanosecond count to a multiple of the unit, half away
-- from zero — the rounding the @duration:@ and @warmup:@ lines apply
-- before rendering.
roundNs :: Int64 -> Int64 -> Int64
roundNs ns unit = (ns + unit `div` 2) `div` unit * unit
