{-# LANGUAGE OverloadedStrings, PatternSynonyms #-}
module System.Win32.Cryptography.Certificates
  ( PCERT_CONTEXT
  , certCreateCertificateContext
  , withCertCreateCertificateContext
  , CryptAcquireContextFlags (..)
  , pattern CRYPT_VERIFYCONTEXT
  , pattern CRYPT_NEWKEYSET
  , pattern CRYPT_DELETEKEYSET
  , pattern CRYPT_MACHINE_KEYSET
  , pattern CRYPT_SILENT
  , CryptProvType (..)
  , pattern PROV_RSA_FULL
  , pattern PROV_RSA_SIG
  , pattern PROV_DSS
  , pattern PROV_FORTEZZA
  , pattern PROV_MS_EXCHANGE
  , pattern PROV_SSL
  , pattern PROV_RSA_SCHANNEL
  , pattern PROV_DSS_DH
  , pattern PROV_EC_ECDSA_SIG
  , pattern PROV_EC_ECNRA_SIG
  , pattern PROV_EC_ECDSA_FULL
  , pattern PROV_EC_ECNRA_FULL
  , pattern PROV_DH_SCHANNEL
  , pattern PROV_SPYRUS_LYNKS
  , pattern PROV_RNG
  , pattern PROV_INTEL_SEC
  , pattern PROV_REPLACE_OWF
  , pattern PROV_RSA_AES
  , pattern MS_DEF_PROV
  , pattern MS_ENHANCED_PROV
  , pattern MS_STRONG_PROV
  , pattern MS_DEF_RSA_SIG_PROV
  , pattern MS_DEF_RSA_SCHANNEL_PROV
  , pattern MS_DEF_DSS_PROV
  , pattern MS_DEF_DSS_DH_PROV
  , pattern MS_ENH_DSS_DH_PROV
  , pattern MS_DEF_DH_SCHANNEL_PROV
  , pattern MS_SCARD_PROV
  , pattern MS_ENH_RSA_AES_PROV
  , pattern MS_ENH_RSA_AES_PROV_XP
  , cryptAcquireContext
  , certContextFromX509
  ) where

import Control.Exception (bracket)
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans.Resource
import Data.ASN1.Types
import Foreign hiding (void)
import System.Win32.Cryptography.Certificates.Internal
import System.Win32.Cryptography.Helpers
import System.Win32.Cryptography.Types
import System.Win32.Error.Foreign
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Text as T
import qualified Data.X509 as X509

-- | Wrapper over CertCreateCertificateContext Windows API function. Creates a 'PCERT_CONTEXT' from a
-- given buffer and encoding of data in that buffer.
certCreateCertificateContext :: EncodingType -> B.ByteString -> ResourceT IO (ReleaseKey, PCERT_CONTEXT)
certCreateCertificateContext encType buffer = resourceMask $ \_ -> do
    certContext <- liftIO $ BU.unsafeUseAsCStringLen buffer $ \(ptr, len) ->
      failIfNull "CertCreateCertificateContext" $ c_CertCreateCertificateContext encType ptr (fromIntegral len)
    releaseKey <- register . void $ c_CertFreeCertificateContext certContext
    return (releaseKey, certContext)

-- | A bracket-like function wrapper over CertCreateCertificateContext Windows API function. Pointer
-- given to action parameter is valid only while that action runs and should not be used afterwards.
withCertCreateCertificateContext :: EncodingType -> B.ByteString -> (PCERT_CONTEXT -> IO a) -> IO a
withCertCreateCertificateContext encType buffer act = BU.unsafeUseAsCStringLen buffer $ \(ptr, len) -> bracket
  (failIfNull "CertCreateCertificateContext" $ c_CertCreateCertificateContext encType ptr (fromIntegral len))
  (void . c_CertFreeCertificateContext)
  act

cryptAcquireContext :: Maybe T.Text -> Maybe T.Text -> CryptProvType -> CryptAcquireContextFlags -> ResourceT IO (ReleaseKey, HCRYPTPROV)
cryptAcquireContext container provider provType flags = resourceMask $ \_ -> do
    cryptProv <- liftIO go
    releaseKey <- register . void $ c_CryptReleaseContext cryptProv 0
    return (releaseKey, cryptProv)
  where
    go = alloca $ \phProv ->
         maybe ($ nullPtr) useAsPtr0 container $ \pszContainer ->
         maybe ($ nullPtr) useAsPtr0 provider $ \pszProvider -> do
           failIfFalse_ "CryptAcquireContext" $ c_CryptAcquireContext phProv pszContainer pszProvider provType flags
           peek phProv

cryptProvFromPrivateKey :: X509.PrivKey -> ResourceT IO (ReleaseKey, HCRYPTPROV)
cryptProvFromPrivateKey privKey = case privKey of
  X509.PrivKeyRSA rsaPrivKey -> do
    (releaseKey, cryptProv) <- cryptAcquireContext Nothing (Just MS_DEF_PROV) PROV_RSA_FULL CRYPT_VERIFYCONTEXT
    return (releaseKey, cryptProv)
  _ -> error "Importing key types other than RSA isn't implemented yet"

certContextFromX509 :: (X509.Certificate, Maybe X509.PrivKey) -> ResourceT IO (ReleaseKey, PCERT_CONTEXT)
certContextFromX509 (cert, maybeKey) = do
  let certPem = BL.toStrict $ ASN1.encodeASN1 ASN1.DER (toASN1 cert [])
  (ctxRelease, ctx) <- certCreateCertificateContext X509_ASN_ENCODING certPem
  -- forM_ maybeKey
  return (ctxRelease, ctx)
