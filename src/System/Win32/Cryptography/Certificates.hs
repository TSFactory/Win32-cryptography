{-# LANGUAGE OverloadedStrings, PatternSynonyms #-}
module System.Win32.Cryptography.Certificates
  ( PCERT_CONTEXT
  , EncodingType (..)
  , pattern X509_ASN_ENCODING
  , pattern PKCS_7_ASN_ENCODING
  , certCreateCertificateContext
  , withCertCreateCertificateContext
  ) where

import Control.Exception (bracket)
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans.Resource
import System.Win32.Cryptography.Certificates.Internal
import System.Win32.Error.Foreign
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as BU

-- | Wrapper over a CertCreateCertificateContext Windows API function. Creates a CERT_CONTEXT from a
-- given buffer and encoding type of the data in that buffer.
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
