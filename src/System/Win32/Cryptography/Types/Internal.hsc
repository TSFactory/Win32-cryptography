{-# LANGUAGE GeneralizedNewtypeDeriving, PatternSynonyms #-}
module System.Win32.Cryptography.Types.Internal where

import Foreign
import Foreign.C.Types
import System.Win32.Cryptography.Helpers
import System.Win32.Types
import Text.Printf

#include <windows.h>
#include <Wincrypt.h>

type HCERTSTORE = HANDLE
type HCRYPTPROV = HANDLE

newtype ALG_ID = ALG_ID { unAlgId :: CUInt }
  deriving (Eq, Storable)

pattern CALG_MD2 = ALG_ID #{const CALG_MD2}
pattern CALG_MD4 = ALG_ID #{const CALG_MD4}
pattern CALG_MD5 = ALG_ID #{const CALG_MD5}
pattern CALG_SHA = ALG_ID #{const CALG_SHA}
pattern CALG_SHA1 = ALG_ID #{const CALG_SHA1}
pattern CALG_MAC = ALG_ID #{const CALG_MAC}
pattern CALG_RSA_SIGN = ALG_ID #{const CALG_RSA_SIGN}
pattern CALG_DSS_SIGN = ALG_ID #{const CALG_DSS_SIGN}
pattern CALG_NO_SIGN = ALG_ID #{const CALG_NO_SIGN}
pattern CALG_RSA_KEYX = ALG_ID #{const CALG_RSA_KEYX}
pattern CALG_DES = ALG_ID #{const CALG_DES}
pattern CALG_3DES_112 = ALG_ID #{const CALG_3DES_112}
pattern CALG_3DES = ALG_ID #{const CALG_3DES}
pattern CALG_DESX = ALG_ID #{const CALG_DESX}
pattern CALG_RC2 = ALG_ID #{const CALG_RC2}
pattern CALG_RC4 = ALG_ID #{const CALG_RC4}
pattern CALG_SEAL = ALG_ID #{const CALG_SEAL}
pattern CALG_DH_SF = ALG_ID #{const CALG_DH_SF}
pattern CALG_DH_EPHEM = ALG_ID #{const CALG_DH_EPHEM}
pattern CALG_AGREEDKEY_ANY = ALG_ID #{const CALG_AGREEDKEY_ANY}
pattern CALG_KEA_KEYX = ALG_ID #{const CALG_KEA_KEYX}
pattern CALG_HUGHES_MD5 = ALG_ID #{const CALG_HUGHES_MD5}
pattern CALG_SKIPJACK = ALG_ID #{const CALG_SKIPJACK}
pattern CALG_TEK = ALG_ID #{const CALG_TEK}
pattern CALG_CYLINK_MEK = ALG_ID #{const CALG_CYLINK_MEK}
pattern CALG_SSL3_SHAMD5 = ALG_ID #{const CALG_SSL3_SHAMD5}
pattern CALG_SSL3_MASTER = ALG_ID #{const CALG_SSL3_MASTER}
pattern CALG_SCHANNEL_MASTER_HASH = ALG_ID #{const CALG_SCHANNEL_MASTER_HASH}
pattern CALG_SCHANNEL_MAC_KEY = ALG_ID #{const CALG_SCHANNEL_MAC_KEY}
pattern CALG_SCHANNEL_ENC_KEY = ALG_ID #{const CALG_SCHANNEL_ENC_KEY}
pattern CALG_PCT1_MASTER = ALG_ID #{const CALG_PCT1_MASTER}
pattern CALG_SSL2_MASTER = ALG_ID #{const CALG_SSL2_MASTER}
pattern CALG_TLS1_MASTER = ALG_ID #{const CALG_TLS1_MASTER}
pattern CALG_RC5 = ALG_ID #{const CALG_RC5}
pattern CALG_HMAC = ALG_ID #{const CALG_HMAC}
pattern CALG_TLS1PRF = ALG_ID #{const CALG_TLS1PRF}
pattern CALG_HASH_REPLACE_OWF = ALG_ID #{const CALG_HASH_REPLACE_OWF}
pattern CALG_AES_128 = ALG_ID #{const CALG_AES_128}
pattern CALG_AES_192 = ALG_ID #{const CALG_AES_192}
pattern CALG_AES_256 = ALG_ID #{const CALG_AES_256}
pattern CALG_AES = ALG_ID #{const CALG_AES}
pattern CALG_SHA_256 = ALG_ID #{const CALG_SHA_256}
pattern CALG_SHA_384 = ALG_ID #{const CALG_SHA_384}
pattern CALG_SHA_512 = ALG_ID #{const CALG_SHA_512}

algIdNames :: [(ALG_ID, String)]
algIdNames =
  [ (CALG_MD2, "CALG_MD2")
  , (CALG_MD4, "CALG_MD4")
  , (CALG_MD5, "CALG_MD5")
  , (CALG_SHA, "CALG_SHA")
  , (CALG_SHA1, "CALG_SHA1")
  , (CALG_MAC, "CALG_MAC")
  , (CALG_RSA_SIGN, "CALG_RSA_SIGN")
  , (CALG_DSS_SIGN, "CALG_DSS_SIGN")
  , (CALG_NO_SIGN, "CALG_NO_SIGN")
  , (CALG_RSA_KEYX, "CALG_RSA_KEYX")
  , (CALG_DES, "CALG_DES")
  , (CALG_3DES_112, "CALG_3DES_112")
  , (CALG_3DES, "CALG_3DES")
  , (CALG_DESX, "CALG_DESX")
  , (CALG_RC2, "CALG_RC2")
  , (CALG_RC4, "CALG_RC4")
  , (CALG_SEAL, "CALG_SEAL")
  , (CALG_DH_SF, "CALG_DH_SF")
  , (CALG_DH_EPHEM, "CALG_DH_EPHEM")
  , (CALG_AGREEDKEY_ANY, "CALG_AGREEDKEY_ANY")
  , (CALG_KEA_KEYX, "CALG_KEA_KEYX")
  , (CALG_HUGHES_MD5, "CALG_HUGHES_MD5")
  , (CALG_SKIPJACK, "CALG_SKIPJACK")
  , (CALG_TEK, "CALG_TEK")
  , (CALG_CYLINK_MEK, "CALG_CYLINK_MEK")
  , (CALG_SSL3_SHAMD5, "CALG_SSL3_SHAMD5")
  , (CALG_SSL3_MASTER, "CALG_SSL3_MASTER")
  , (CALG_SCHANNEL_MASTER_HASH, "CALG_SCHANNEL_MASTER_HASH")
  , (CALG_SCHANNEL_MAC_KEY, "CALG_SCHANNEL_MAC_KEY")
  , (CALG_SCHANNEL_ENC_KEY, "CALG_SCHANNEL_ENC_KEY")
  , (CALG_PCT1_MASTER, "CALG_PCT1_MASTER")
  , (CALG_SSL2_MASTER, "CALG_SSL2_MASTER")
  , (CALG_TLS1_MASTER, "CALG_TLS1_MASTER")
  , (CALG_RC5, "CALG_RC5")
  , (CALG_HMAC, "CALG_HMAC")
  , (CALG_TLS1PRF, "CALG_TLS1PRF")
  , (CALG_HASH_REPLACE_OWF, "CALG_HASH_REPLACE_OWF")
  , (CALG_AES_128, "CALG_AES_128")
  , (CALG_AES_192, "CALG_AES_192")
  , (CALG_AES_256, "CALG_AES_256")
  , (CALG_AES, "CALG_AES")
  , (CALG_SHA_256, "CALG_SHA_256")
  , (CALG_SHA_384, "CALG_SHA_384")
  , (CALG_SHA_512, "CALG_SHA_512")
  ]

instance Show ALG_ID where
  show x = printf "ALG_ID { %s }" (pickName algIdNames unAlgId x)

newtype EncodingType = EncodingType { unEncodingType :: DWORD }
  deriving (Eq, Bits, Storable)

pattern X509_ASN_ENCODING = EncodingType #{const X509_ASN_ENCODING}
pattern PKCS_7_ASN_ENCODING = EncodingType #{const PKCS_7_ASN_ENCODING}

encodingTypeNames :: [(EncodingType, String)]
encodingTypeNames =
  [ (X509_ASN_ENCODING, "X509_ASN_ENCODING")
  , (PKCS_7_ASN_ENCODING, "PKCS_7_ASN_ENCODING")
  ]

instance Show EncodingType where
  show x = printf "EncodingType { %s }" (parseBitFlags encodingTypeNames unEncodingType x)
