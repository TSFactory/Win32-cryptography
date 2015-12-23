{-# LANGUAGE PatternSynonyms #-}
module System.Win32.Cryptography.Types
  ( -- * Reexports from 'System.Win32.Cryptography.Certificates'
    PCERT_CONTEXT
    -- * Other types
  , EncodingType (..)
  , pattern X509_ASN_ENCODING
  , pattern PKCS_7_ASN_ENCODING
  , HCERTSTORE
  , HCRYPTPROV
  , HCRYPTKEY
  , HCRYPTHASH
  , ALG_ID (..)
  , pattern CALG_MD2
  , pattern CALG_MD4
  , pattern CALG_MD5
  , pattern CALG_SHA
  , pattern CALG_SHA1
  , pattern CALG_MAC
  , pattern CALG_RSA_SIGN
  , pattern CALG_DSS_SIGN
  , pattern CALG_NO_SIGN
  , pattern CALG_RSA_KEYX
  , pattern CALG_DES
  , pattern CALG_3DES_112
  , pattern CALG_3DES
  , pattern CALG_DESX
  , pattern CALG_RC2
  , pattern CALG_RC4
  , pattern CALG_SEAL
  , pattern CALG_DH_SF
  , pattern CALG_DH_EPHEM
  , pattern CALG_AGREEDKEY_ANY
  , pattern CALG_KEA_KEYX
  , pattern CALG_HUGHES_MD5
  , pattern CALG_SKIPJACK
  , pattern CALG_TEK
  , pattern CALG_CYLINK_MEK
  , pattern CALG_SSL3_SHAMD5
  , pattern CALG_SSL3_MASTER
  , pattern CALG_SCHANNEL_MASTER_HASH
  , pattern CALG_SCHANNEL_MAC_KEY
  , pattern CALG_SCHANNEL_ENC_KEY
  , pattern CALG_PCT1_MASTER
  , pattern CALG_SSL2_MASTER
  , pattern CALG_TLS1_MASTER
  , pattern CALG_RC5
  , pattern CALG_HMAC
  , pattern CALG_TLS1PRF
  , pattern CALG_HASH_REPLACE_OWF
  , pattern CALG_AES_128
  , pattern CALG_AES_192
  , pattern CALG_AES_256
  , pattern CALG_AES
  , pattern CALG_SHA_256
  , pattern CALG_SHA_384
  , pattern CALG_SHA_512
  ) where

import System.Win32.Cryptography.Certificates.Internal
import System.Win32.Cryptography.Types.Internal
