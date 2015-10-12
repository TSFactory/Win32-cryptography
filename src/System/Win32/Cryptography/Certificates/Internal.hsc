{-# LANGUAGE CPP, ForeignFunctionInterface, GeneralizedNewtypeDeriving, OverloadedStrings, PatternSynonyms #-}
module System.Win32.Cryptography.Certificates.Internal where

import Data.Bits
import Foreign
import Foreign.C.Types
import System.Win32.Cryptography.Helpers
import System.Win32.Cryptography.Types.Internal
import System.Win32.Time
import System.Win32.Types
import Text.Printf
import qualified Data.Text as T

#include <windows.h>
#include <Wincrypt.h>

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
foreign import WINDOWS_CCONV "wincrypt.h CertCreateCertificateContext"
  c_CertCreateCertificateContext
    :: EncodingType -- dwCertEncodingType
    -> Ptr CChar -- pbCertEncoded
    -> DWORD -- cbCertEncoded
    -> IO PCERT_CONTEXT

-- BOOL WINAPI CertFreeCertificateContext(
--   _In_ PCCERT_CONTEXT pCertContext
-- );
foreign import WINDOWS_CCONV "wincrypt.h CertFreeCertificateContext"
  c_CertFreeCertificateContext
    :: PCERT_CONTEXT
    -> IO BOOL

newtype CertPropId = CertPropId { unCertPropId :: DWORD }
  deriving (Eq, Storable)

pattern CERT_KEY_PROV_HANDLE_PROP_ID = CertPropId #{const CERT_KEY_PROV_HANDLE_PROP_ID}
pattern CERT_KEY_PROV_INFO_PROP_ID = CertPropId #{const CERT_KEY_PROV_INFO_PROP_ID}
pattern CERT_SHA1_HASH_PROP_ID = CertPropId #{const CERT_SHA1_HASH_PROP_ID}
pattern CERT_MD5_HASH_PROP_ID = CertPropId #{const CERT_MD5_HASH_PROP_ID}
pattern CERT_HASH_PROP_ID = CertPropId #{const CERT_HASH_PROP_ID}
pattern CERT_KEY_CONTEXT_PROP_ID = CertPropId #{const CERT_KEY_CONTEXT_PROP_ID}
pattern CERT_KEY_SPEC_PROP_ID = CertPropId #{const CERT_KEY_SPEC_PROP_ID}
pattern CERT_IE30_RESERVED_PROP_ID = CertPropId #{const CERT_IE30_RESERVED_PROP_ID}
pattern CERT_PUBKEY_HASH_RESERVED_PROP_ID = CertPropId #{const CERT_PUBKEY_HASH_RESERVED_PROP_ID}
pattern CERT_ENHKEY_USAGE_PROP_ID = CertPropId #{const CERT_ENHKEY_USAGE_PROP_ID}
pattern CERT_CTL_USAGE_PROP_ID = CertPropId #{const CERT_CTL_USAGE_PROP_ID}
pattern CERT_NEXT_UPDATE_LOCATION_PROP_ID = CertPropId #{const CERT_NEXT_UPDATE_LOCATION_PROP_ID}
pattern CERT_FRIENDLY_NAME_PROP_ID = CertPropId #{const CERT_FRIENDLY_NAME_PROP_ID}
pattern CERT_PVK_FILE_PROP_ID = CertPropId #{const CERT_PVK_FILE_PROP_ID}
pattern CERT_DESCRIPTION_PROP_ID = CertPropId #{const CERT_DESCRIPTION_PROP_ID}
pattern CERT_ACCESS_STATE_PROP_ID = CertPropId #{const CERT_ACCESS_STATE_PROP_ID}
pattern CERT_SIGNATURE_HASH_PROP_ID = CertPropId #{const CERT_SIGNATURE_HASH_PROP_ID}
pattern CERT_SMART_CARD_DATA_PROP_ID = CertPropId #{const CERT_SMART_CARD_DATA_PROP_ID}
pattern CERT_EFS_PROP_ID = CertPropId #{const CERT_EFS_PROP_ID}
pattern CERT_FORTEZZA_DATA_PROP_ID = CertPropId #{const CERT_FORTEZZA_DATA_PROP_ID}
pattern CERT_ARCHIVED_PROP_ID = CertPropId #{const CERT_ARCHIVED_PROP_ID}
pattern CERT_KEY_IDENTIFIER_PROP_ID = CertPropId #{const CERT_KEY_IDENTIFIER_PROP_ID}
pattern CERT_AUTO_ENROLL_PROP_ID = CertPropId #{const CERT_AUTO_ENROLL_PROP_ID}
pattern CERT_PUBKEY_ALG_PARA_PROP_ID = CertPropId #{const CERT_PUBKEY_ALG_PARA_PROP_ID}
pattern CERT_CROSS_CERT_DIST_POINTS_PROP_ID = CertPropId #{const CERT_CROSS_CERT_DIST_POINTS_PROP_ID}
pattern CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID = CertPropId #{const CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID}
pattern CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID = CertPropId #{const CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID}
pattern CERT_ENROLLMENT_PROP_ID = CertPropId #{const CERT_ENROLLMENT_PROP_ID}
pattern CERT_DATE_STAMP_PROP_ID = CertPropId #{const CERT_DATE_STAMP_PROP_ID}
pattern CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID = CertPropId #{const CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID}
pattern CERT_SUBJECT_NAME_MD5_HASH_PROP_ID = CertPropId #{const CERT_SUBJECT_NAME_MD5_HASH_PROP_ID}
pattern CERT_EXTENDED_ERROR_INFO_PROP_ID = CertPropId #{const CERT_EXTENDED_ERROR_INFO_PROP_ID}
pattern CERT_RENEWAL_PROP_ID = CertPropId #{const CERT_RENEWAL_PROP_ID}
pattern CERT_ARCHIVED_KEY_HASH_PROP_ID = CertPropId #{const CERT_ARCHIVED_KEY_HASH_PROP_ID}
pattern CERT_AUTO_ENROLL_RETRY_PROP_ID = CertPropId #{const CERT_AUTO_ENROLL_RETRY_PROP_ID}
pattern CERT_AIA_URL_RETRIEVED_PROP_ID = CertPropId #{const CERT_AIA_URL_RETRIEVED_PROP_ID}
pattern CERT_AUTHORITY_INFO_ACCESS_PROP_ID = CertPropId #{const CERT_AUTHORITY_INFO_ACCESS_PROP_ID}
pattern CERT_BACKED_UP_PROP_ID = CertPropId #{const CERT_BACKED_UP_PROP_ID}
pattern CERT_OCSP_RESPONSE_PROP_ID = CertPropId #{const CERT_OCSP_RESPONSE_PROP_ID}
pattern CERT_REQUEST_ORIGINATOR_PROP_ID = CertPropId #{const CERT_REQUEST_ORIGINATOR_PROP_ID}
pattern CERT_SOURCE_LOCATION_PROP_ID = CertPropId #{const CERT_SOURCE_LOCATION_PROP_ID}
pattern CERT_SOURCE_URL_PROP_ID = CertPropId #{const CERT_SOURCE_URL_PROP_ID}
pattern CERT_NEW_KEY_PROP_ID = CertPropId #{const CERT_NEW_KEY_PROP_ID}
pattern CERT_OCSP_CACHE_PREFIX_PROP_ID = CertPropId #{const CERT_OCSP_CACHE_PREFIX_PROP_ID}
pattern CERT_SMART_CARD_ROOT_INFO_PROP_ID = CertPropId #{const CERT_SMART_CARD_ROOT_INFO_PROP_ID}
pattern CERT_NO_AUTO_EXPIRE_CHECK_PROP_ID = CertPropId #{const CERT_NO_AUTO_EXPIRE_CHECK_PROP_ID}
pattern CERT_NCRYPT_KEY_HANDLE_PROP_ID = CertPropId #{const CERT_NCRYPT_KEY_HANDLE_PROP_ID}
pattern CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID = CertPropId #{const CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID}
pattern CERT_SUBJECT_INFO_ACCESS_PROP_ID = CertPropId #{const CERT_SUBJECT_INFO_ACCESS_PROP_ID}
pattern CERT_CA_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID = CertPropId #{const CERT_CA_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID}
pattern CERT_CA_DISABLE_CRL_PROP_ID = CertPropId #{const CERT_CA_DISABLE_CRL_PROP_ID}
pattern CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID = CertPropId #{const CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID}
pattern CERT_ROOT_PROGRAM_NAME_CONSTRAINTS_PROP_ID = CertPropId #{const CERT_ROOT_PROGRAM_NAME_CONSTRAINTS_PROP_ID}
pattern CERT_SUBJECT_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID = CertPropId #{const CERT_SUBJECT_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID}
pattern CERT_SUBJECT_DISABLE_CRL_PROP_ID = CertPropId #{const CERT_SUBJECT_DISABLE_CRL_PROP_ID}
pattern CERT_CEP_PROP_ID = CertPropId #{const CERT_CEP_PROP_ID}
pattern CERT_SIGN_HASH_CNG_ALG_PROP_ID = CertPropId #{const CERT_SIGN_HASH_CNG_ALG_PROP_ID}
pattern CERT_SCARD_PIN_ID_PROP_ID = CertPropId #{const CERT_SCARD_PIN_ID_PROP_ID}
pattern CERT_SCARD_PIN_INFO_PROP_ID = CertPropId #{const CERT_SCARD_PIN_INFO_PROP_ID}
pattern CERT_SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID = CertPropId #{const CERT_SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID}
pattern CERT_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID = CertPropId #{const CERT_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID}
pattern CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID = CertPropId #{const CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID}
pattern CERT_ISSUER_CHAIN_SIGN_HASH_CNG_ALG_PROP_ID = CertPropId #{const CERT_ISSUER_CHAIN_SIGN_HASH_CNG_ALG_PROP_ID}
pattern CERT_ISSUER_CHAIN_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID = CertPropId #{const CERT_ISSUER_CHAIN_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID}
pattern CERT_NO_EXPIRE_NOTIFICATION_PROP_ID = CertPropId #{const CERT_NO_EXPIRE_NOTIFICATION_PROP_ID}
pattern CERT_AUTH_ROOT_SHA256_HASH_PROP_ID = CertPropId #{const CERT_AUTH_ROOT_SHA256_HASH_PROP_ID}
pattern CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID = CertPropId #{const CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID}
pattern CERT_HCRYPTPROV_TRANSFER_PROP_ID = CertPropId #{const CERT_HCRYPTPROV_TRANSFER_PROP_ID}
pattern CERT_SMART_CARD_READER_PROP_ID = CertPropId #{const CERT_SMART_CARD_READER_PROP_ID}
pattern CERT_SEND_AS_TRUSTED_ISSUER_PROP_ID = CertPropId #{const CERT_SEND_AS_TRUSTED_ISSUER_PROP_ID}
pattern CERT_KEY_REPAIR_ATTEMPTED_PROP_ID = CertPropId #{const CERT_KEY_REPAIR_ATTEMPTED_PROP_ID}
pattern CERT_DISALLOWED_FILETIME_PROP_ID = CertPropId #{const CERT_DISALLOWED_FILETIME_PROP_ID}
pattern CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID = CertPropId #{const CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID}
pattern CERT_SMART_CARD_READER_NON_REMOVABLE_PROP_ID = CertPropId #{const CERT_SMART_CARD_READER_NON_REMOVABLE_PROP_ID}

certPropIdNames :: [(CertPropId, String)]
certPropIdNames =
  [ (CERT_KEY_PROV_HANDLE_PROP_ID, "CERT_KEY_PROV_HANDLE_PROP_ID")
  , (CERT_KEY_PROV_INFO_PROP_ID, "CERT_KEY_PROV_INFO_PROP_ID")
  , (CERT_SHA1_HASH_PROP_ID, "CERT_SHA1_HASH_PROP_ID")
  , (CERT_MD5_HASH_PROP_ID, "CERT_MD5_HASH_PROP_ID")
  , (CERT_HASH_PROP_ID, "CERT_HASH_PROP_ID")
  , (CERT_KEY_CONTEXT_PROP_ID, "CERT_KEY_CONTEXT_PROP_ID")
  , (CERT_KEY_SPEC_PROP_ID, "CERT_KEY_SPEC_PROP_ID")
  , (CERT_IE30_RESERVED_PROP_ID, "CERT_IE30_RESERVED_PROP_ID")
  , (CERT_PUBKEY_HASH_RESERVED_PROP_ID, "CERT_PUBKEY_HASH_RESERVED_PROP_ID")
  , (CERT_ENHKEY_USAGE_PROP_ID, "CERT_ENHKEY_USAGE_PROP_ID")
  , (CERT_CTL_USAGE_PROP_ID, "CERT_CTL_USAGE_PROP_ID")
  , (CERT_NEXT_UPDATE_LOCATION_PROP_ID, "CERT_NEXT_UPDATE_LOCATION_PROP_ID")
  , (CERT_FRIENDLY_NAME_PROP_ID, "CERT_FRIENDLY_NAME_PROP_ID")
  , (CERT_PVK_FILE_PROP_ID, "CERT_PVK_FILE_PROP_ID")
  , (CERT_DESCRIPTION_PROP_ID, "CERT_DESCRIPTION_PROP_ID")
  , (CERT_ACCESS_STATE_PROP_ID, "CERT_ACCESS_STATE_PROP_ID")
  , (CERT_SIGNATURE_HASH_PROP_ID, "CERT_SIGNATURE_HASH_PROP_ID")
  , (CERT_SMART_CARD_DATA_PROP_ID, "CERT_SMART_CARD_DATA_PROP_ID")
  , (CERT_EFS_PROP_ID, "CERT_EFS_PROP_ID")
  , (CERT_FORTEZZA_DATA_PROP_ID, "CERT_FORTEZZA_DATA_PROP_ID")
  , (CERT_ARCHIVED_PROP_ID, "CERT_ARCHIVED_PROP_ID")
  , (CERT_KEY_IDENTIFIER_PROP_ID, "CERT_KEY_IDENTIFIER_PROP_ID")
  , (CERT_AUTO_ENROLL_PROP_ID, "CERT_AUTO_ENROLL_PROP_ID")
  , (CERT_PUBKEY_ALG_PARA_PROP_ID, "CERT_PUBKEY_ALG_PARA_PROP_ID")
  , (CERT_CROSS_CERT_DIST_POINTS_PROP_ID, "CERT_CROSS_CERT_DIST_POINTS_PROP_ID")
  , (CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID, "CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID")
  , (CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID, "CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID")
  , (CERT_ENROLLMENT_PROP_ID, "CERT_ENROLLMENT_PROP_ID")
  , (CERT_DATE_STAMP_PROP_ID, "CERT_DATE_STAMP_PROP_ID")
  , (CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID, "CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID")
  , (CERT_SUBJECT_NAME_MD5_HASH_PROP_ID, "CERT_SUBJECT_NAME_MD5_HASH_PROP_ID")
  , (CERT_EXTENDED_ERROR_INFO_PROP_ID, "CERT_EXTENDED_ERROR_INFO_PROP_ID")
  , (CERT_RENEWAL_PROP_ID, "CERT_RENEWAL_PROP_ID")
  , (CERT_ARCHIVED_KEY_HASH_PROP_ID, "CERT_ARCHIVED_KEY_HASH_PROP_ID")
  , (CERT_AUTO_ENROLL_RETRY_PROP_ID, "CERT_AUTO_ENROLL_RETRY_PROP_ID")
  , (CERT_AIA_URL_RETRIEVED_PROP_ID, "CERT_AIA_URL_RETRIEVED_PROP_ID")
  , (CERT_AUTHORITY_INFO_ACCESS_PROP_ID, "CERT_AUTHORITY_INFO_ACCESS_PROP_ID")
  , (CERT_BACKED_UP_PROP_ID, "CERT_BACKED_UP_PROP_ID")
  , (CERT_OCSP_RESPONSE_PROP_ID, "CERT_OCSP_RESPONSE_PROP_ID")
  , (CERT_REQUEST_ORIGINATOR_PROP_ID, "CERT_REQUEST_ORIGINATOR_PROP_ID")
  , (CERT_SOURCE_LOCATION_PROP_ID, "CERT_SOURCE_LOCATION_PROP_ID")
  , (CERT_SOURCE_URL_PROP_ID, "CERT_SOURCE_URL_PROP_ID")
  , (CERT_NEW_KEY_PROP_ID, "CERT_NEW_KEY_PROP_ID")
  , (CERT_OCSP_CACHE_PREFIX_PROP_ID, "CERT_OCSP_CACHE_PREFIX_PROP_ID")
  , (CERT_SMART_CARD_ROOT_INFO_PROP_ID, "CERT_SMART_CARD_ROOT_INFO_PROP_ID")
  , (CERT_NO_AUTO_EXPIRE_CHECK_PROP_ID, "CERT_NO_AUTO_EXPIRE_CHECK_PROP_ID")
  , (CERT_NCRYPT_KEY_HANDLE_PROP_ID, "CERT_NCRYPT_KEY_HANDLE_PROP_ID")
  , (CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID, "CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID")
  , (CERT_SUBJECT_INFO_ACCESS_PROP_ID, "CERT_SUBJECT_INFO_ACCESS_PROP_ID")
  , (CERT_CA_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID, "CERT_CA_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID")
  , (CERT_CA_DISABLE_CRL_PROP_ID, "CERT_CA_DISABLE_CRL_PROP_ID")
  , (CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID, "CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID")
  , (CERT_ROOT_PROGRAM_NAME_CONSTRAINTS_PROP_ID, "CERT_ROOT_PROGRAM_NAME_CONSTRAINTS_PROP_ID")
  , (CERT_SUBJECT_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID, "CERT_SUBJECT_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID")
  , (CERT_SUBJECT_DISABLE_CRL_PROP_ID, "CERT_SUBJECT_DISABLE_CRL_PROP_ID")
  , (CERT_CEP_PROP_ID, "CERT_CEP_PROP_ID")
  , (CERT_SIGN_HASH_CNG_ALG_PROP_ID, "CERT_SIGN_HASH_CNG_ALG_PROP_ID")
  , (CERT_SCARD_PIN_ID_PROP_ID, "CERT_SCARD_PIN_ID_PROP_ID")
  , (CERT_SCARD_PIN_INFO_PROP_ID, "CERT_SCARD_PIN_INFO_PROP_ID")
  , (CERT_SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID, "CERT_SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID")
  , (CERT_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID, "CERT_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID")
  , (CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID, "CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID")
  , (CERT_ISSUER_CHAIN_SIGN_HASH_CNG_ALG_PROP_ID, "CERT_ISSUER_CHAIN_SIGN_HASH_CNG_ALG_PROP_ID")
  , (CERT_ISSUER_CHAIN_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID, "CERT_ISSUER_CHAIN_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID")
  , (CERT_NO_EXPIRE_NOTIFICATION_PROP_ID, "CERT_NO_EXPIRE_NOTIFICATION_PROP_ID")
  , (CERT_AUTH_ROOT_SHA256_HASH_PROP_ID, "CERT_AUTH_ROOT_SHA256_HASH_PROP_ID")
  , (CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID, "CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID")
  , (CERT_HCRYPTPROV_TRANSFER_PROP_ID, "CERT_HCRYPTPROV_TRANSFER_PROP_ID")
  , (CERT_SMART_CARD_READER_PROP_ID, "CERT_SMART_CARD_READER_PROP_ID")
  , (CERT_SEND_AS_TRUSTED_ISSUER_PROP_ID, "CERT_SEND_AS_TRUSTED_ISSUER_PROP_ID")
  , (CERT_KEY_REPAIR_ATTEMPTED_PROP_ID, "CERT_KEY_REPAIR_ATTEMPTED_PROP_ID")
  , (CERT_DISALLOWED_FILETIME_PROP_ID, "CERT_DISALLOWED_FILETIME_PROP_ID")
  , (CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID, "CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID")
  , (CERT_SMART_CARD_READER_NON_REMOVABLE_PROP_ID, "CERT_SMART_CARD_READER_NON_REMOVABLE_PROP_ID")
  ]

instance Show CertPropId where
  show x = printf "CertPropId { %s }" (pickName certPropIdNames unCertPropId x)

-- BOOL WINAPI CertSetCertificateContextProperty(
--   _In_       PCCERT_CONTEXT pCertContext,
--   _In_       DWORD          dwPropId,
--   _In_       DWORD          dwFlags,
--   _In_ const void           *pvData
-- );
foreign import WINDOWS_CCONV "wincrypt.h CertSetCertificateContextProperty"
  c_CertSetCertificateContextProperty
    :: PCERT_CONTEXT -- pCertContext
    -> CertPropId -- dwPropId
    -> DWORD -- dwFlags
    -> Ptr () -- pvData
    -> IO BOOL

-- BOOL WINAPI CertGetCertificateContextProperty(
--   _In_    PCCERT_CONTEXT pCertContext,
--   _In_    DWORD          dwPropId,
--   _Out_   void           *pvData,
--   _Inout_ DWORD          *pcbData
-- );
foreign import WINDOWS_CCONV "wincrypt.h CertGetCertificateContextProperty"
  c_CertGetCertificateContextProperty
    :: PCERT_CONTEXT -- pCertContext
    -> CertPropId -- dwPropId
    -> Ptr () -- pvData
    -> Ptr DWORD -- pcbData
    -> IO BOOL

newtype CertKeySpec = CertKeySpec { unCertKeySpec :: DWORD }
  deriving (Eq, Storable)

pattern AT_KEYEXCHANGE = CertKeySpec #{const AT_KEYEXCHANGE}
pattern AT_SIGNATURE = CertKeySpec #{const AT_SIGNATURE}
pattern CERT_NCRYPT_KEY_SPEC = CertKeySpec #{const CERT_NCRYPT_KEY_SPEC}

certKeySpecNames :: [(CertKeySpec, String)]
certKeySpecNames =
  [ (AT_KEYEXCHANGE, "AT_KEYEXCHANGE")
  , (AT_SIGNATURE, "AT_SIGNATURE")
  , (CERT_NCRYPT_KEY_SPEC, "CERT_NCRYPT_KEY_SPEC")
  ]

instance Show CertKeySpec where
  show x = printf "CertKeySpec { %s }" (pickName certKeySpecNames unCertKeySpec x)

data CERT_KEY_CONTEXT = CERT_KEY_CONTEXT
  { certKeyCbSize         :: DWORD
  , certKeyCryptProvOrKey :: HANDLE
  , certKeyDwKeySpec      :: CertKeySpec
  } deriving (Show)

instance Storable CERT_KEY_CONTEXT where
  sizeOf _ = #{size CERT_KEY_CONTEXT}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke CERT_KEY_CONTEXT, cbSize} p $ certKeyCbSize x
    #{poke CERT_KEY_CONTEXT, hCryptProv} p $ certKeyCryptProvOrKey x
    #{poke CERT_KEY_CONTEXT, dwKeySpec} p $ certKeyDwKeySpec x
  peek p = CERT_KEY_CONTEXT
    <$> #{peek CERT_KEY_CONTEXT, cbSize} p
    <*> #{peek CERT_KEY_CONTEXT, hCryptProv} p
    <*> #{peek CERT_KEY_CONTEXT, dwKeySpec} p

newtype CryptAcquireContextFlags = CryptAcquireContextFlags { unCryptAcquireContextFlags :: DWORD }
  deriving (Eq, Bits, Storable)

pattern CRYPT_VERIFYCONTEXT = CryptAcquireContextFlags #{const CRYPT_VERIFYCONTEXT}
pattern CRYPT_NEWKEYSET = CryptAcquireContextFlags #{const CRYPT_NEWKEYSET}
pattern CRYPT_DELETEKEYSET = CryptAcquireContextFlags #{const CRYPT_DELETEKEYSET}
pattern CRYPT_MACHINE_KEYSET = CryptAcquireContextFlags #{const CRYPT_MACHINE_KEYSET}
pattern CRYPT_SILENT = CryptAcquireContextFlags #{const CRYPT_SILENT}
-- pattern CRYPT_DEFAULT_CONTAINER_OPTIONAL = CryptAcquireContextFlags #{const CRYPT_DEFAULT_CONTAINER_OPTIONAL}

cryptAcquireContextNames :: [(CryptAcquireContextFlags, String)]
cryptAcquireContextNames =
  [ (CRYPT_VERIFYCONTEXT, "CRYPT_VERIFYCONTEXT")
  , (CRYPT_NEWKEYSET, "CRYPT_NEWKEYSET")
  , (CRYPT_DELETEKEYSET, "CRYPT_DELETEKEYSET")
  , (CRYPT_MACHINE_KEYSET, "CRYPT_MACHINE_KEYSET")
  , (CRYPT_SILENT, "CRYPT_SILENT")
--  , (CRYPT_DEFAULT_CONTAINER_OPTIONAL, "CRYPT_DEFAULT_CONTAINER_OPTIONAL")
  ]

instance Show CryptAcquireContextFlags where
  show x = printf "CryptAcquireContextFlags{ %s }" (parseBitFlags cryptAcquireContextNames unCryptAcquireContextFlags x)

newtype CryptProvType = CryptProvType { unCryptProvType :: DWORD }
  deriving (Eq, Storable)

pattern PROV_RSA_FULL = CryptProvType #{const PROV_RSA_FULL}
pattern PROV_RSA_SIG = CryptProvType #{const PROV_RSA_SIG}
pattern PROV_DSS = CryptProvType #{const PROV_DSS}
pattern PROV_FORTEZZA = CryptProvType #{const PROV_FORTEZZA}
pattern PROV_MS_EXCHANGE = CryptProvType #{const PROV_MS_EXCHANGE}
pattern PROV_SSL = CryptProvType #{const PROV_SSL}
pattern PROV_RSA_SCHANNEL = CryptProvType #{const PROV_RSA_SCHANNEL}
pattern PROV_DSS_DH = CryptProvType #{const PROV_DSS_DH}
pattern PROV_EC_ECDSA_SIG = CryptProvType #{const PROV_EC_ECDSA_SIG}
pattern PROV_EC_ECNRA_SIG = CryptProvType #{const PROV_EC_ECNRA_SIG}
pattern PROV_EC_ECDSA_FULL = CryptProvType #{const PROV_EC_ECDSA_FULL}
pattern PROV_EC_ECNRA_FULL = CryptProvType #{const PROV_EC_ECNRA_FULL}
pattern PROV_DH_SCHANNEL = CryptProvType #{const PROV_DH_SCHANNEL}
pattern PROV_SPYRUS_LYNKS = CryptProvType #{const PROV_SPYRUS_LYNKS}
pattern PROV_RNG = CryptProvType #{const PROV_RNG}
pattern PROV_INTEL_SEC = CryptProvType #{const PROV_INTEL_SEC}
pattern PROV_REPLACE_OWF = CryptProvType #{const PROV_REPLACE_OWF}
pattern PROV_RSA_AES = CryptProvType #{const PROV_RSA_AES}

cryptProvTypeNames :: [(CryptProvType, String)]
cryptProvTypeNames =
  [ (PROV_RSA_FULL, "PROV_RSA_FULL")
  , (PROV_RSA_SIG, "PROV_RSA_SIG")
  , (PROV_DSS, "PROV_DSS")
  , (PROV_FORTEZZA, "PROV_FORTEZZA")
  , (PROV_MS_EXCHANGE, "PROV_MS_EXCHANGE")
  , (PROV_SSL, "PROV_SSL")
  , (PROV_RSA_SCHANNEL, "PROV_RSA_SCHANNEL")
  , (PROV_DSS_DH, "PROV_DSS_DH")
  , (PROV_EC_ECDSA_SIG, "PROV_EC_ECDSA_SIG")
  , (PROV_EC_ECNRA_SIG, "PROV_EC_ECNRA_SIG")
  , (PROV_EC_ECDSA_FULL, "PROV_EC_ECDSA_FULL")
  , (PROV_EC_ECNRA_FULL, "PROV_EC_ECNRA_FULL")
  , (PROV_DH_SCHANNEL, "PROV_DH_SCHANNEL")
  , (PROV_SPYRUS_LYNKS, "PROV_SPYRUS_LYNKS")
  , (PROV_RNG, "PROV_RNG")
  , (PROV_INTEL_SEC, "PROV_INTEL_SEC")
  , (PROV_REPLACE_OWF, "PROV_REPLACE_OWF")
  , (PROV_RSA_AES, "PROV_RSA_AES")
  ]

instance Show CryptProvType where
  show x = printf "CryptProvType { %s }" (pickName cryptProvTypeNames unCryptProvType x)

pattern MS_DEF_PROV :: T.Text
pattern MS_DEF_PROV = #{const_str MS_DEF_PROV}
pattern MS_ENHANCED_PROV :: T.Text
pattern MS_ENHANCED_PROV = #{const_str MS_ENHANCED_PROV}
pattern MS_STRONG_PROV :: T.Text
pattern MS_STRONG_PROV = #{const_str MS_STRONG_PROV}
pattern MS_DEF_RSA_SIG_PROV :: T.Text
pattern MS_DEF_RSA_SIG_PROV = #{const_str MS_DEF_RSA_SIG_PROV}
pattern MS_DEF_RSA_SCHANNEL_PROV :: T.Text
pattern MS_DEF_RSA_SCHANNEL_PROV = #{const_str MS_DEF_RSA_SCHANNEL_PROV}
pattern MS_DEF_DSS_PROV :: T.Text
pattern MS_DEF_DSS_PROV = #{const_str MS_DEF_DSS_PROV}
pattern MS_DEF_DSS_DH_PROV :: T.Text
pattern MS_DEF_DSS_DH_PROV = #{const_str MS_DEF_DSS_DH_PROV}
pattern MS_ENH_DSS_DH_PROV :: T.Text
pattern MS_ENH_DSS_DH_PROV = #{const_str MS_ENH_DSS_DH_PROV}
pattern MS_DEF_DH_SCHANNEL_PROV :: T.Text
pattern MS_DEF_DH_SCHANNEL_PROV = #{const_str MS_DEF_DH_SCHANNEL_PROV}
pattern MS_SCARD_PROV :: T.Text
pattern MS_SCARD_PROV = #{const_str MS_SCARD_PROV}
pattern MS_ENH_RSA_AES_PROV :: T.Text
pattern MS_ENH_RSA_AES_PROV = #{const_str MS_ENH_RSA_AES_PROV}
pattern MS_ENH_RSA_AES_PROV_XP :: T.Text
pattern MS_ENH_RSA_AES_PROV_XP = #{const_str MS_ENH_RSA_AES_PROV_XP}

-- BOOL WINAPI CryptAcquireContext(
--   _Out_ HCRYPTPROV *phProv,
--   _In_  LPCTSTR    pszContainer,
--   _In_  LPCTSTR    pszProvider,
--   _In_  DWORD      dwProvType,
--   _In_  DWORD      dwFlags
-- );
foreign import WINDOWS_CCONV "wincrypt.h CryptAcquireContextW"
  c_CryptAcquireContext
    :: Ptr HCRYPTPROV -- phProv
    -> LPWSTR -- pszContainer
    -> LPWSTR -- pszProvider
    -> CryptProvType -- dwProvType
    -> CryptAcquireContextFlags -- dwFlags
    -> IO BOOL

-- BOOL WINAPI CryptReleaseContext(
--  _In_ HCRYPTPROV hProv,
--  _In_ DWORD      dwFlags
-- );
foreign import WINDOWS_CCONV "wincrypt.h CryptReleaseContext"
  c_CryptReleaseContext
    :: HCRYPTPROV -- hProv
    -> DWORD -- dwFlags
    -> IO BOOL
