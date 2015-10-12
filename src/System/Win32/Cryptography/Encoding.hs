{-# LANGUAGE OverloadedStrings, PatternSynonyms #-}
module System.Win32.Cryptography.Encoding
  ( CryptStringFlags (..)
  , pattern CRYPT_STRING_BASE64HEADER
  , pattern CRYPT_STRING_BASE64
  , pattern CRYPT_STRING_BINARY
  , pattern CRYPT_STRING_BASE64REQUESTHEADER
  , pattern CRYPT_STRING_HEX
  , pattern CRYPT_STRING_HEXASCII
  , pattern CRYPT_STRING_BASE64_ANY
  , pattern CRYPT_STRING_ANY
  , pattern CRYPT_STRING_HEX_ANY
  , pattern CRYPT_STRING_BASE64X509CRLHEADER
  , pattern CRYPT_STRING_HEXADDR
  , pattern CRYPT_STRING_HEXASCIIADDR
  , pattern CRYPT_STRING_HEXRAW
  , pattern CRYPT_STRING_STRICT
  , CryptStringToBinaryResult (..)
  , cryptStringToBinary
  ) where

import Control.Exception
import Foreign
import System.Win32.Cryptography.Encoding.Internal
import System.Win32.Cryptography.Types
import System.Win32.Error.Foreign
import System.Win32 (localFree)
import System.Win32.Types hiding (failIfFalse_)
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Text as T
import qualified Data.Text.Foreign as T

-- Damn these "cstbr". Where is my OverloadedRecords, please? :-P
data CryptStringToBinaryResult = CryptStringToBinaryResult
  { cstbrOutput :: B.ByteString
  , cstbrSkip   :: DWORD
  , cstbrFlags  :: CryptStringFlags
  }

cryptStringToBinary :: T.Text -> CryptStringFlags -> IO CryptStringToBinaryResult
cryptStringToBinary src flags = T.useAsPtr src $ \ptr len ->
  alloca $ \pcbBinary ->
  alloca $ \pdwSkip ->
  alloca $ \pdwFlags -> do
    failIfFalse_ "CryptStringToBinary" $ c_CryptStringToBinary (castPtr ptr) (fromIntegral len) flags nullPtr pcbBinary pdwSkip pdwFlags
    bytesNeeded <- peek pcbBinary
    allocaBytes (fromIntegral bytesNeeded) $ \pbBinary -> do
      failIfFalse_ "CryptStringToBinary" $ c_CryptStringToBinary (castPtr ptr) (fromIntegral len) flags pbBinary pcbBinary pdwSkip pdwFlags
      -- Technically the following is not necessary, but I'm very cautious so I'll peek the value again.
      bytesWritten <- peek pcbBinary
      output <- B.packCStringLen (pbBinary, fromIntegral bytesWritten)
      skip <- peek pdwSkip
      outFlags <- peek pdwFlags
      return $ CryptStringToBinaryResult output skip outFlags

cryptDecodeObjectEx :: EncodingType -> CryptStructType -> B.ByteString -> CryptDecodeFlags -> IO B.ByteString
cryptDecodeObjectEx encType structType input flags =
  either (\x act -> act $ intPtrToPtr x) (B.useAsCString) (unCryptStructType structType) $ \lpszStructType ->
  BU.unsafeUseAsCStringLen input $ \(pbEncoded, cbEncoded) ->
  alloca $ \pvStructInfo ->
  alloca $ \pcbStructInfo -> do
    let flags' = flags .|. CRYPT_DECODE_ALLOC_FLAG
    mask_ $ do
      failIfFalse_ "CryptDecodeObjectEx" $ c_CryptDecodeObjectEx encType lpszStructType pbEncoded (fromIntegral cbEncoded) flags' nullPtr (castPtr pvStructInfo) pcbStructInfo
      outputBuf <- peek pvStructInfo
      outputLen <- peek pcbStructInfo
      output <- B.packCStringLen (outputBuf, fromIntegral outputLen)
      localFree pvStructInfo
      return output
