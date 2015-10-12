{-# LANGUAGE CPP, ForeignFunctionInterface, GeneralizedNewtypeDeriving, PatternSynonyms #-}
module System.Win32.Cryptography.Encoding.Internal where

import Foreign
import Foreign.C.Types
import System.Win32.Cryptography.Helpers
import System.Win32.Cryptography.Types
import System.Win32.Types
import Text.Printf
import qualified Data.ByteString as B

#include <windows.h>
#include <Wincrypt.h>

newtype CryptStringFlags = CryptStringFlags { unCryptStringFlags :: DWORD }
  deriving (Eq, Bits, Storable)

pattern CRYPT_STRING_BASE64HEADER = CryptStringFlags #{const CRYPT_STRING_BASE64HEADER}
pattern CRYPT_STRING_BASE64 = CryptStringFlags #{const CRYPT_STRING_BASE64}
pattern CRYPT_STRING_BINARY = CryptStringFlags #{const CRYPT_STRING_BINARY}
pattern CRYPT_STRING_BASE64REQUESTHEADER = CryptStringFlags #{const CRYPT_STRING_BASE64REQUESTHEADER}
pattern CRYPT_STRING_HEX = CryptStringFlags #{const CRYPT_STRING_HEX}
pattern CRYPT_STRING_HEXASCII = CryptStringFlags #{const CRYPT_STRING_HEXASCII}
pattern CRYPT_STRING_BASE64_ANY = CryptStringFlags #{const CRYPT_STRING_BASE64_ANY}
pattern CRYPT_STRING_ANY = CryptStringFlags #{const CRYPT_STRING_ANY}
pattern CRYPT_STRING_HEX_ANY = CryptStringFlags #{const CRYPT_STRING_HEX_ANY}
pattern CRYPT_STRING_BASE64X509CRLHEADER = CryptStringFlags #{const CRYPT_STRING_BASE64X509CRLHEADER}
pattern CRYPT_STRING_HEXADDR = CryptStringFlags #{const CRYPT_STRING_HEXADDR}
pattern CRYPT_STRING_HEXASCIIADDR = CryptStringFlags #{const CRYPT_STRING_HEXASCIIADDR}
pattern CRYPT_STRING_HEXRAW = CryptStringFlags #{const CRYPT_STRING_HEXRAW}
pattern CRYPT_STRING_STRICT = CryptStringFlags #{const CRYPT_STRING_STRICT}

cryptStringFlagsNames :: [(CryptStringFlags, String)]
cryptStringFlagsNames =
  [ (CRYPT_STRING_BASE64HEADER, "CRYPT_STRING_BASE64HEADER")
  , (CRYPT_STRING_BASE64, "CRYPT_STRING_BASE64")
  , (CRYPT_STRING_BINARY, "CRYPT_STRING_BINARY")
  , (CRYPT_STRING_BASE64REQUESTHEADER, "CRYPT_STRING_BASE64REQUESTHEADER")
  , (CRYPT_STRING_HEX, "CRYPT_STRING_HEX")
  , (CRYPT_STRING_HEXASCII, "CRYPT_STRING_HEXASCII")
  , (CRYPT_STRING_BASE64_ANY, "CRYPT_STRING_BASE64_ANY")
  , (CRYPT_STRING_ANY, "CRYPT_STRING_ANY")
  , (CRYPT_STRING_HEX_ANY, "CRYPT_STRING_HEX_ANY")
  , (CRYPT_STRING_BASE64X509CRLHEADER, "CRYPT_STRING_BASE64X509CRLHEADER")
  , (CRYPT_STRING_HEXADDR, "CRYPT_STRING_HEXADDR")
  , (CRYPT_STRING_HEXASCIIADDR, "CRYPT_STRING_HEXASCIIADDR")
  , (CRYPT_STRING_HEXRAW, "CRYPT_STRING_HEXRAW")
  , (CRYPT_STRING_STRICT, "CRYPT_STRING_STRICT")
  ]

instance Show CryptStringFlags where
  show x = printf "CryptStringFlags{ %s }" (parseEnumWithFlags cryptStringFlagsNames [CRYPT_STRING_STRICT] unCryptStringFlags x)

-- BOOL WINAPI CryptStringToBinary(
--   _In_    LPCTSTR pszString,
--   _In_    DWORD   cchString,
--   _In_    DWORD   dwFlags,
--   _In_    BYTE    *pbBinary,
--   _Inout_ DWORD   *pcbBinary,
--   _Out_   DWORD   *pdwSkip,
--   _Out_   DWORD   *pdwFlags
-- );
foreign import WINDOWS_CCONV "wincrypt.h CryptStringToBinaryW"
  c_CryptStringToBinary
    :: LPWSTR -- pszString
    -> DWORD -- cchString
    -> CryptStringFlags -- dwFlags
    -> Ptr CChar -- pbBinary
    -> Ptr DWORD -- pcbBinary
    -> Ptr DWORD -- pdwSkip
    -> Ptr CryptStringFlags -- pdwFlags
    -> IO BOOL

newtype CryptStructType = CryptStructType { unCryptStructType :: Either IntPtr B.ByteString }
  deriving (Eq)

pattern PKCS_RSA_PRIVATE_KEY = CryptStructType (Left #{const PKCS_RSA_PRIVATE_KEY})

newtype CryptDecodeFlags = CryptDecodeFlags { unCryptDecodeFlags :: DWORD }
  deriving (Eq, Bits, Storable)

pattern CRYPT_DECODE_NOCOPY_FLAG = CryptDecodeFlags #{const CRYPT_DECODE_NOCOPY_FLAG}
pattern CRYPT_DECODE_TO_BE_SIGNED_FLAG = CryptDecodeFlags #{const CRYPT_DECODE_TO_BE_SIGNED_FLAG}
pattern CRYPT_DECODE_SHARE_OID_STRING_FLAG = CryptDecodeFlags #{const CRYPT_DECODE_SHARE_OID_STRING_FLAG}
pattern CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG = CryptDecodeFlags #{const CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG}
pattern CRYPT_DECODE_ALLOC_FLAG = CryptDecodeFlags #{const CRYPT_DECODE_ALLOC_FLAG}
pattern CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG = CryptDecodeFlags #{const CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG}
pattern CRYPT_DECODE_ENABLE_PUNYCODE_FLAG = CryptDecodeFlags #{const CRYPT_DECODE_ENABLE_PUNYCODE_FLAG}
pattern CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG = CryptDecodeFlags #{const CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG}

cryptDecodeFlagsNames :: [(CryptDecodeFlags, String)]
cryptDecodeFlagsNames =
  [ (CRYPT_DECODE_NOCOPY_FLAG, "CRYPT_DECODE_NOCOPY_FLAG")
  , (CRYPT_DECODE_TO_BE_SIGNED_FLAG, "CRYPT_DECODE_TO_BE_SIGNED_FLAG")
  , (CRYPT_DECODE_SHARE_OID_STRING_FLAG, "CRYPT_DECODE_SHARE_OID_STRING_FLAG")
  , (CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG, "CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG")
  , (CRYPT_DECODE_ALLOC_FLAG, "CRYPT_DECODE_ALLOC_FLAG")
  , (CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG, "CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG")
  , (CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, "CRYPT_DECODE_ENABLE_PUNYCODE_FLAG")
  , (CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG, "CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG")
  ]

instance Show CryptDecodeFlags where
  show x = printf "CryptDecodeFlags { %s }" (parseBitFlags cryptDecodeFlagsNames unCryptDecodeFlags x)

data CRYPT_DECODE_PARA

type PCRYPT_DECODE_PARA = Ptr CRYPT_DECODE_PARA

-- BOOL WINAPI CryptDecodeObjectEx(
--   _In_          DWORD              dwCertEncodingType,
--   _In_          LPCSTR             lpszStructType,
--   _In_    const BYTE               *pbEncoded,
--   _In_          DWORD              cbEncoded,
--   _In_          DWORD              dwFlags,
--   _In_          PCRYPT_DECODE_PARA pDecodePara,
--   _Out_         void               *pvStructInfo,
--   _Inout_       DWORD              *pcbStructInfo
-- );
foreign import WINDOWS_CCONV "wincrypt.h CryptDecodeObjectEx"
  c_CryptDecodeObjectEx
    :: EncodingType -- dwCertEncodingType
    -> LPSTR -- lpszStructType
    -> Ptr CChar -- pbEncoded
    -> DWORD -- cbEncoded
    -> CryptDecodeFlags -- dwFlags
    -> PCRYPT_DECODE_PARA -- pDecodePara
    -> Ptr () -- pvStructInfo
    -> Ptr DWORD -- pcbStructInfo
    -> IO BOOL
