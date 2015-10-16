{-# LANGUAGE PatternSynonyms #-}
module System.Win32.Cryptography.Errors
  ( pattern NTE_BAD_UID
  , pattern NTE_BAD_HASH
  , pattern NTE_BAD_KEY
  , pattern NTE_BAD_LEN
  , pattern NTE_BAD_DATA
  , pattern NTE_BAD_SIGNATURE
  , pattern NTE_BAD_VER
  , pattern NTE_BAD_ALGID
  , pattern NTE_BAD_FLAGS
  , pattern NTE_BAD_TYPE
  , pattern NTE_BAD_KEY_STATE
  , pattern NTE_BAD_HASH_STATE
  , pattern NTE_NO_KEY
  , pattern NTE_NO_MEMORY
  , pattern NTE_EXISTS
  , pattern NTE_PERM
  , pattern NTE_NOT_FOUND
  , pattern NTE_DOUBLE_ENCRYPT
  , pattern NTE_BAD_PROVIDER
  , pattern NTE_BAD_PROV_TYPE
  , pattern NTE_BAD_PUBLIC_KEY
  , pattern NTE_BAD_KEYSET
  , pattern NTE_PROV_TYPE_NOT_DEF
  , pattern NTE_PROV_TYPE_ENTRY_BAD
  , pattern NTE_KEYSET_NOT_DEF
  , pattern NTE_KEYSET_ENTRY_BAD
  , pattern NTE_PROV_TYPE_NO_MATCH
  , pattern NTE_SIGNATURE_FILE_BAD
  , pattern NTE_PROVIDER_DLL_FAIL
  , pattern NTE_PROV_DLL_NOT_FOUND
  , pattern NTE_BAD_KEYSET_PARAM
  , pattern NTE_FAIL
  , pattern NTE_SYS_ERR
  , pattern NTE_SILENT_CONTEXT
  , pattern NTE_TOKEN_KEYSET_STORAGE_FULL
  , pattern NTE_TEMPORARY_PROFILE
  , pattern NTE_FIXEDPARAMETER
  ) where

#include <Windows.h>

pattern NTE_BAD_UID = #{const NTE_BAD_UID}
pattern NTE_BAD_HASH = #{const NTE_BAD_HASH}
pattern NTE_BAD_KEY = #{const NTE_BAD_KEY}
pattern NTE_BAD_LEN = #{const NTE_BAD_LEN}
pattern NTE_BAD_DATA = #{const NTE_BAD_DATA}
pattern NTE_BAD_SIGNATURE = #{const NTE_BAD_SIGNATURE}
pattern NTE_BAD_VER = #{const NTE_BAD_VER}
pattern NTE_BAD_ALGID = #{const NTE_BAD_ALGID}
pattern NTE_BAD_FLAGS = #{const NTE_BAD_FLAGS}
pattern NTE_BAD_TYPE = #{const NTE_BAD_TYPE}
pattern NTE_BAD_KEY_STATE = #{const NTE_BAD_KEY_STATE}
pattern NTE_BAD_HASH_STATE = #{const NTE_BAD_HASH_STATE}
pattern NTE_NO_KEY = #{const NTE_NO_KEY}
pattern NTE_NO_MEMORY = #{const NTE_NO_MEMORY}
pattern NTE_EXISTS = #{const NTE_EXISTS}
pattern NTE_PERM = #{const NTE_PERM}
pattern NTE_NOT_FOUND = #{const NTE_NOT_FOUND}
pattern NTE_DOUBLE_ENCRYPT = #{const NTE_DOUBLE_ENCRYPT}
pattern NTE_BAD_PROVIDER = #{const NTE_BAD_PROVIDER}
pattern NTE_BAD_PROV_TYPE = #{const NTE_BAD_PROV_TYPE}
pattern NTE_BAD_PUBLIC_KEY = #{const NTE_BAD_PUBLIC_KEY}
pattern NTE_BAD_KEYSET = #{const NTE_BAD_KEYSET}
pattern NTE_PROV_TYPE_NOT_DEF = #{const NTE_PROV_TYPE_NOT_DEF}
pattern NTE_PROV_TYPE_ENTRY_BAD = #{const NTE_PROV_TYPE_ENTRY_BAD}
pattern NTE_KEYSET_NOT_DEF = #{const NTE_KEYSET_NOT_DEF}
pattern NTE_KEYSET_ENTRY_BAD = #{const NTE_KEYSET_ENTRY_BAD}
pattern NTE_PROV_TYPE_NO_MATCH = #{const NTE_PROV_TYPE_NO_MATCH}
pattern NTE_SIGNATURE_FILE_BAD = #{const NTE_SIGNATURE_FILE_BAD}
pattern NTE_PROVIDER_DLL_FAIL = #{const NTE_PROVIDER_DLL_FAIL}
pattern NTE_PROV_DLL_NOT_FOUND = #{const NTE_PROV_DLL_NOT_FOUND}
pattern NTE_BAD_KEYSET_PARAM = #{const NTE_BAD_KEYSET_PARAM}
pattern NTE_FAIL = #{const NTE_FAIL}
pattern NTE_SYS_ERR = #{const NTE_SYS_ERR}
pattern NTE_SILENT_CONTEXT = #{const NTE_SILENT_CONTEXT}
pattern NTE_TOKEN_KEYSET_STORAGE_FULL = #{const NTE_TOKEN_KEYSET_STORAGE_FULL}
pattern NTE_TEMPORARY_PROFILE = #{const NTE_TEMPORARY_PROFILE}
pattern NTE_FIXEDPARAMETER = #{const NTE_FIXEDPARAMETER}
