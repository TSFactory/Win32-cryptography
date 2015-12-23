{-# LANGUAGE CPP, ForeignFunctionInterface #-}
module System.Win32.Cryptography.Hash.Internal where

import Foreign
import Foreign.C
import System.Win32.Cryptography.Types
import System.Win32.Types

-- BOOL WINAPI CryptCreateHash(
--   _In_  HCRYPTPROV hProv,
--   _In_  ALG_ID     Algid,
--   _In_  HCRYPTKEY  hKey,
--   _In_  DWORD      dwFlags,
--   _Out_ HCRYPTHASH *phHash
-- );
foreign import WINDOWS_CCONV "wincrypt.h CryptCreateHash"
  c_CryptCreateHash
    :: HCRYPTPROV -- hProv
    -> ALG_ID -- Algid
    -> HCRYPTKEY -- hKey
    -> DWORD -- dwFlags
    -> Ptr HCRYPTHASH -- phHash
    -> IO BOOL

-- BOOL WINAPI CryptDestroyHash(
--   _In_ HCRYPTHASH hHash
-- );
foreign import WINDOWS_CCONV "wincrypt.h CryptDestroyHash"
  c_CryptDestroyHash
    :: HCRYPTHASH -- hHash
    -> IO BOOL

type HCRYPTPROV_LEGACY = HANDLE

-- BOOL WINAPI CryptHashCertificate(
--   _In_          HCRYPTPROV_LEGACY hCryptProv,
--   _In_          ALG_ID            Algid,
--   _In_          DWORD             dwFlags,
--   _In_    const BYTE              *pbEncoded,
--   _In_          DWORD             cbEncoded,
--   _Out_         BYTE              *pbComputedHash,
--   _Inout_       DWORD             *pcbComputedHash
-- );
foreign import WINDOWS_CCONV "wincrypt.h CryptHashCertificate"
  c_CryptHashCertificate
    :: HCRYPTPROV_LEGACY -- hCryptProv
    -> ALG_ID -- Algid
    -> DWORD -- dwFlags
    -> Ptr CChar -- pbEncoded
    -> DWORD -- cbEncoded
    -> Ptr CChar -- pbComputedHash
    -> Ptr DWORD -- pcbComputedHash
    -> IO BOOL
