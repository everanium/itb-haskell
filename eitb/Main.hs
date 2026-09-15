-- | eitb — command-line demonstrator for the ITB Haskell binding.
--
-- Subcommands:
--
-- >  eitb version                                   library + binding versions
-- >  eitb profiles                                  registered profile catalogue
-- >  eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
-- >  eitb decrypt <profile> <blob-hex> <in-file> <out-file>
--
-- @encrypt@ prints the session blob to stderr as hex; feed that hex
-- back to @decrypt@ on the receiving side. @profiles@ lists the
-- registered profile catalogue one name per line; the profiles that
-- carry a cipher surface are the ones @encrypt@ / @decrypt@ accept.
module Main (main) where

import Control.Exception (SomeException, displayException, fromException, try)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.Char (digitToInt, isHexDigit)
import Data.List (isPrefixOf)
import System.Directory (createDirectoryIfMissing)
import System.Environment (getArgs)
import System.Exit (exitFailure, exitWith, ExitCode (..))
import System.FilePath (takeDirectory)
import System.IO (hPutStrLn, stderr)
import Text.Printf (printf)

import ITB3

main :: IO ()
main = do
  args <- getArgs
  result <- try $ case args of
    ["version"] -> cmdVersion
    ["profiles"] -> cmdProfiles
    ["encrypt", profile, inFile, outFile] -> cmdEncrypt profile inFile outFile
    ["decrypt", profile, blobHex, inFile, outFile] ->
      cmdDecrypt profile blobHex inFile outFile
    _ -> do
      hPutStrLn stderr $
        "usage: eitb version\n\
        \       eitb profiles\n\
        \       eitb encrypt <profile> <in-file> <out-file>\n\
        \       eitb decrypt <profile> <blob-hex> <in-file> <out-file>"
      exitWith (ExitFailure 2)
  case result of
    Right () -> pure ()
    -- The usage branch exits through the ExitCode exception; let it
    -- propagate with its own code instead of reporting it as an error.
    Left e | Just code <- fromException e -> exitWith (code :: ExitCode)
    Left e -> do
      hPutStrLn stderr ("eitb: " <> displayException (e :: SomeException))
      exitFailure

cmdVersion :: IO ()
cmdVersion = do
  v <- version
  putStrLn ("libitb3 " <> v)
  putStrLn ("itb-haskell " <> bindingVersion)

cmdProfiles :: IO ()
cmdProfiles = profiles >>= mapM_ putStrLn

-- Profiles whose canonical name begins with "streaming-" route
-- through the one-shot streaming buffered pair instead of the Single
-- Message pair.
isStreamingProfile :: String -> Bool
isStreamingProfile = ("streaming-" `isPrefixOf`)

-- Recursively create the parent directory of `path` (mkdir -p).
ensureParentDir :: FilePath -> IO ()
ensureParentDir path = createDirectoryIfMissing True (takeDirectory path)

cmdEncrypt :: String -> FilePath -> FilePath -> IO ()
cmdEncrypt profile inFile outFile = do
  plain <- BS.readFile inFile
  pipe <- newPipeline profile
  wire <- if isStreamingProfile profile
    then encryptStreamOneShot pipe plain
    else encryptMessage pipe plain
  ensureParentDir outFile
  BS.writeFile outFile wire
  blobBytes <- save pipe
  hPutStrLn stderr (hexEncode blobBytes)
  printf "encrypted %s -> %s (%d -> %d bytes)\n"
         inFile outFile (BS.length plain) (BS.length wire)
  freePipeline pipe

cmdDecrypt :: String -> String -> FilePath -> FilePath -> IO ()
cmdDecrypt profile blobHex inFile outFile = do
  blobBytes <- either fail pure (hexDecode blobHex)
  wire <- BS.readFile inFile
  -- The profile shape travels inside the blob; the profile argument
  -- only selects the Single Message or streaming cipher pair.
  pipe <- loadPipeline blobBytes Nothing
  plain <- if isStreamingProfile profile
    then decryptStreamOneShot pipe wire
    else decryptMessage pipe wire
  ensureParentDir outFile
  BS.writeFile outFile plain
  printf "decrypted %s -> %s (%d -> %d bytes)\n"
         inFile outFile (BS.length wire) (BS.length plain)
  freePipeline pipe

hexEncode :: BS.ByteString -> String
hexEncode = concatMap (printf "%02x") . BS.unpack

hexDecode :: String -> Either String BS.ByteString
hexDecode s
  | odd (length s) = Left "blob hex has odd length"
  | not (all isHexDigit s) = Left "blob hex contains a non-hex character"
  | otherwise = Right (BC.pack (pairUp s))
  where
    pairUp (a : b : rest) =
      toEnum (digitToInt a * 16 + digitToInt b) : pairUp rest
    pairUp _ = []
