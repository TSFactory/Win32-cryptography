{-# LANGUAGE CPP, ForeignFunctionInterface, GeneralizedNewtypeDeriving, PatternSynonyms #-}
module System.Win32.Cryptography.Encoding.Internal where

import Foreign
import Foreign.C.Types
import System.Win32.Cryptography.Helpers
import System.Win32.Types
import Text.Printf

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
foreign import WINDOWS_CCONV "windows.h CryptStringToBinaryW"
  c_CryptStringToBinary
    :: LPWSTR -- pszString
    -> DWORD -- cchString
    -> CryptStringFlags -- dwFlags
    -> Ptr CChar -- pbBinary
    -> Ptr DWORD -- pcbBinary
    -> Ptr DWORD -- pdwSkip
    -> Ptr CryptStringFlags -- pdwFlags
    -> IO BOOL
