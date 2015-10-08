{-# LANGUAGE CPP, ForeignFunctionInterface, GeneralizedNewtypeDeriving, PatternSynonyms #-}
module System.Win32.Cryptography.Certificates.Internal where

import Data.Bits
import Foreign
import Foreign.C.Types
import System.Win32.Cryptography.Helpers
import System.Win32.Cryptography.Types.Internal
import System.Win32.Time
import System.Win32.Types
import Text.Printf

#include <windows.h>
#include <Wincrypt.h>

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

data CERT_CONTEXT = CERT_CONTEXT
  { dwCertEncodingType :: EncodingType
  , pbCertEncoded      :: Ptr CChar
  , cbCertEncoded      :: DWORD
  , pCertInfo          :: PCERT_INFO
  , hCertStore         :: HCERTSTORE
  } deriving (Show)

type PCERT_CONTEXT = Ptr CERT_CONTEXT

instance Storable CERT_CONTEXT where
  sizeOf _ = #{size CERT_CONTEXT}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke CERT_CONTEXT, dwCertEncodingType} p $ dwCertEncodingType x
    #{poke CERT_CONTEXT, pbCertEncoded} p $ pbCertEncoded x
    #{poke CERT_CONTEXT, cbCertEncoded} p $ cbCertEncoded x
    #{poke CERT_CONTEXT, pCertInfo} p $ pCertInfo x
    #{poke CERT_CONTEXT, hCertStore} p $ hCertStore x
  peek p = CERT_CONTEXT
    <$> #{peek CERT_CONTEXT, dwCertEncodingType} p
    <*> #{peek CERT_CONTEXT, pbCertEncoded} p
    <*> #{peek CERT_CONTEXT, cbCertEncoded} p
    <*> #{peek CERT_CONTEXT, pCertInfo} p
    <*> #{peek CERT_CONTEXT, hCertStore} p

newtype CertVersion = CertVersion { unCertVersion :: DWORD }
  deriving (Eq, Storable)

pattern CERT_V1 = CertVersion #{const CERT_V1}
pattern CERT_V2 = CertVersion #{const CERT_V2}
pattern CERT_V3 = CertVersion #{const CERT_V3}

certVersionNames :: [(CertVersion, String)]
certVersionNames =
  [ (CERT_V1, "CERT_V1")
  , (CERT_V2, "CERT_V2")
  , (CERT_V3, "CERT_V3")
  ]

instance Show CertVersion where
  show x = printf "CertVersion { %s }" (pickName certVersionNames unCertVersion x)

data CERT_INFO = CERT_INFO
  { dwVersion            :: CertVersion
  , serialNumber         :: CRYPT_INTEGER_BLOB
  , signatureAlgorithm   :: CRYPT_ALGORITHM_IDENTIFIER
  , issuer               :: CERT_NAME_BLOB
  , notBefore            :: FILETIME
  , notAfter             :: FILETIME
  , subject              :: CERT_NAME_BLOB
  , subjectPublicKeyInfo :: CERT_PUBLIC_KEY_INFO
  , issuerUniqueId       :: CRYPT_BIT_BLOB
  , subjectUniqueId      :: CRYPT_BIT_BLOB
  , cExtension           :: DWORD
  , rgExtension          :: PCERT_EXTENSION
  } deriving (Show)

instance Storable CERT_INFO where
  sizeOf _ = #{size CERT_INFO}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke CERT_INFO, dwVersion} p $ dwVersion x
    #{poke CERT_INFO, SerialNumber} p $ serialNumber x
    #{poke CERT_INFO, SignatureAlgorithm} p $ signatureAlgorithm x
    #{poke CERT_INFO, Issuer} p $ issuer x
    #{poke CERT_INFO, NotBefore} p $ notBefore x
    #{poke CERT_INFO, NotAfter} p $ notAfter x
    #{poke CERT_INFO, Subject} p $ subject x
    #{poke CERT_INFO, SubjectPublicKeyInfo} p $ subjectPublicKeyInfo x
    #{poke CERT_INFO, IssuerUniqueId} p $ issuerUniqueId x
    #{poke CERT_INFO, SubjectUniqueId} p $ subjectUniqueId x
    #{poke CERT_INFO, cExtension} p $ cExtension x
    #{poke CERT_INFO, rgExtension} p $ rgExtension x
  peek p = CERT_INFO
    <$> #{peek CERT_INFO, dwVersion} p
    <*> #{peek CERT_INFO, SerialNumber} p
    <*> #{peek CERT_INFO, SignatureAlgorithm} p
    <*> #{peek CERT_INFO, Issuer} p
    <*> #{peek CERT_INFO, NotBefore} p
    <*> #{peek CERT_INFO, NotAfter} p
    <*> #{peek CERT_INFO, Subject} p
    <*> #{peek CERT_INFO, SubjectPublicKeyInfo} p
    <*> #{peek CERT_INFO, IssuerUniqueId} p
    <*> #{peek CERT_INFO, SubjectUniqueId} p
    <*> #{peek CERT_INFO, cExtension} p
    <*> #{peek CERT_INFO, rgExtension} p

type PCERT_INFO = Ptr CERT_INFO

data CRYPTOAPI_BLOB = CRYPTOAPI_BLOB
  { blobCbData :: DWORD
  , blobPbData :: Ptr CChar
  } deriving (Show)

instance Storable CRYPTOAPI_BLOB where
  sizeOf _ = #{size CRYPT_DATA_BLOB}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke CRYPT_DATA_BLOB, cbData} p $ blobCbData x
    #{poke CRYPT_DATA_BLOB, pbData} p $ blobPbData x
  peek p = CRYPTOAPI_BLOB
    <$> #{peek CRYPT_DATA_BLOB, cbData} p
    <*> #{peek CRYPT_DATA_BLOB, pbData} p

type CRYPT_INTEGER_BLOB = CRYPTOAPI_BLOB
type PCRYPT_INTEGER_BLOB = Ptr CRYPT_INTEGER_BLOB
type CRYPT_UINT_BLOB = CRYPTOAPI_BLOB
type PCRYPT_UINT_BLOB = Ptr CRYPT_UINT_BLOB
type CRYPT_OBJID_BLOB = CRYPTOAPI_BLOB
type PCRYPT_OBJID_BLOB = Ptr CRYPT_OBJID_BLOB
type CERT_NAME_BLOB = CRYPTOAPI_BLOB
type PCERT_NAME_BLOB = Ptr CERT_NAME_BLOB
type CERT_RDN_VALUE_BLOB = CRYPTOAPI_BLOB
type PCERT_RDN_VALUE_BLOB = Ptr CERT_RDN_VALUE_BLOB
type CERT_BLOB = CRYPTOAPI_BLOB
type PCERT_BLOB = Ptr CERT_BLOB
type CRL_BLOB = CRYPTOAPI_BLOB
type PCRL_BLOB = Ptr CRL_BLOB
type DATA_BLOB = CRYPTOAPI_BLOB
type PDATA_BLOB = Ptr DATA_BLOB
type CRYPT_DATA_BLOB = CRYPTOAPI_BLOB
type PCRYPT_DATA_BLOB = Ptr CRYPT_DATA_BLOB
type CRYPT_HASH_BLOB = CRYPTOAPI_BLOB
type PCRYPT_HASH_BLOB = Ptr CRYPT_HASH_BLOB
type CRYPT_DIGEST_BLOB = CRYPTOAPI_BLOB
type PCRYPT_DIGEST_BLOB = Ptr CRYPT_DIGEST_BLOB
type CRYPT_DER_BLOB = CRYPTOAPI_BLOB
type PCRYPT_DER_BLOB = Ptr CRYPT_DER_BLOB
type CRYPT_ATTR_BLOB = CRYPTOAPI_BLOB
type PCRYPT_ATTR_BLOB = Ptr CRYPT_ATTR_BLOB

data CRYPT_ALGORITHM_IDENTIFIER = CRYPT_ALGORITHM_IDENTIFIER
  { algPszObjId   :: LPSTR
  , algParameters :: CRYPT_OBJID_BLOB
  } deriving (Show)

instance Storable CRYPT_ALGORITHM_IDENTIFIER where
  sizeOf _ = #{size CRYPT_ALGORITHM_IDENTIFIER}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke CRYPT_ALGORITHM_IDENTIFIER, pszObjId} p $ algPszObjId x
    #{poke CRYPT_ALGORITHM_IDENTIFIER, Parameters} p $ algParameters x
  peek p = CRYPT_ALGORITHM_IDENTIFIER
    <$> #{peek CRYPT_ALGORITHM_IDENTIFIER, pszObjId} p
    <*> #{peek CRYPT_ALGORITHM_IDENTIFIER, Parameters} p

data CRYPT_BIT_BLOB = CRYPT_BIT_BLOB
  { bitBlobCbData      :: DWORD
  , bitBlobPbData      :: Ptr CChar
  , bitBlobCUnusedBits :: DWORD
  } deriving (Show)

instance Storable CRYPT_BIT_BLOB where
  sizeOf _ = #{size CRYPT_BIT_BLOB}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke CRYPT_BIT_BLOB, cbData} p $ bitBlobCbData x
    #{poke CRYPT_BIT_BLOB, pbData} p $ bitBlobPbData x
    #{poke CRYPT_BIT_BLOB, cUnusedBits} p $ bitBlobCUnusedBits x
  peek p = CRYPT_BIT_BLOB
    <$> #{peek CRYPT_BIT_BLOB, cbData} p
    <*> #{peek CRYPT_BIT_BLOB, pbData} p
    <*> #{peek CRYPT_BIT_BLOB, cUnusedBits} p

data CERT_PUBLIC_KEY_INFO = CERT_PUBLIC_KEY_INFO
  { algorithm :: CRYPT_ALGORITHM_IDENTIFIER
  , publicKey :: CRYPT_BIT_BLOB
  } deriving (Show)

instance Storable CERT_PUBLIC_KEY_INFO where
  sizeOf _ = #{size CERT_PUBLIC_KEY_INFO}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke CERT_PUBLIC_KEY_INFO, Algorithm} p $ algorithm x
    #{poke CERT_PUBLIC_KEY_INFO, PublicKey} p $ publicKey x
  peek p = CERT_PUBLIC_KEY_INFO
    <$> #{peek CERT_PUBLIC_KEY_INFO, Algorithm} p
    <*> #{peek CERT_PUBLIC_KEY_INFO, PublicKey} p

data CERT_EXTENSION = CERT_EXTENSION
  { extPszObjId  :: LPSTR
  , extFCritical :: BOOL
  , extValue     :: CRYPT_OBJID_BLOB
  } deriving (Show)

instance Storable CERT_EXTENSION where
  sizeOf _ = #{size CERT_EXTENSION}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke CERT_EXTENSION, pszObjId} p $ extPszObjId x
    #{poke CERT_EXTENSION, fCritical} p $ extFCritical x
    #{poke CERT_EXTENSION, Value} p $ extValue x
  peek p = CERT_EXTENSION
    <$> #{peek CERT_EXTENSION, pszObjId} p
    <*> #{peek CERT_EXTENSION, fCritical} p
    <*> #{peek CERT_EXTENSION, Value} p

type PCERT_EXTENSION = Ptr CERT_EXTENSION

-- PCCERT_CONTEXT WINAPI CertCreateCertificateContext(
--   _In_       DWORD dwCertEncodingType,
--   _In_ const BYTE  *pbCertEncoded,
--   _In_       DWORD cbCertEncoded
-- );
foreign import WINDOWS_CCONV "windows.h CertCreateCertificateContext"
  c_CertCreateCertificateContext
    :: EncodingType -- dwCertEncodingType
    -> Ptr CChar -- pbCertEncoded
    -> DWORD -- cbCertEncoded
    -> IO PCERT_CONTEXT

-- BOOL WINAPI CertFreeCertificateContext(
--   _In_ PCCERT_CONTEXT pCertContext
-- );
foreign import WINDOWS_CCONV "windows.h CertFreeCertificateContext"
  c_CertFreeCertificateContext
    :: PCERT_CONTEXT
    -> IO BOOL
