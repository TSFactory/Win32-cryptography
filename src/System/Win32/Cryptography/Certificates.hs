{-# LANGUAGE MagicHash, OverloadedStrings, PatternSynonyms, ScopedTypeVariables #-}
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
  , cryptProvFromPrivateKey
  , certContextFromX509
  ) where

import Control.Exception (bracket)
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans.Control
import Control.Monad.Trans.Resource
import Data.ASN1.Types
import Data.IORef
import Foreign hiding (void)
import Foreign.C
import GHC.Integer.GMP.Internals
import GHC.Ptr
import GHC.Types
import System.Win32.Cryptography.Certificates.Internal
import System.Win32.Cryptography.Helpers
import System.Win32.Cryptography.Types
import System.Win32.Error.Foreign
import qualified Crypto.PubKey.RSA as RSA
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

withPrivateKeyBlob :: RSA.PrivateKey -> (CStringLen -> IO a) -> IO a
withPrivateKeyBlob privKey act =
    allocaBytes blobSize $ \pBlob -> do
      posRef <- newIORef pBlob
      writeStorable posRef BLOBHEADER
        { blobType = PRIVATEKEYBLOB
        , blobVersion = CUR_BLOB_VERSION
        , blobReserved = 0
        , blobAiKeyAlg = CALG_RSA_KEYX
        }
      writeStorable posRef RSAPUBKEY
        { rsapubMagic = RSA2
        , rsapubBitlen = fromIntegral $ keySize * 8
        , rsapubPubexp = fromIntegral $ RSA.public_e $ RSA.private_pub privKey
        }
      writeInteger posRef keySize . RSA.public_n $ RSA.private_pub privKey
      writeInteger posRef halfSize $ RSA.private_p privKey
      writeInteger posRef halfSize $ RSA.private_q privKey
      writeInteger posRef halfSize $ RSA.private_dP privKey
      writeInteger posRef halfSize $ RSA.private_dQ privKey
      writeInteger posRef halfSize $ RSA.private_qinv privKey
      writeInteger posRef keySize $ RSA.private_d privKey
      act $ (castPtr pBlob, blobSize)
  where
    keySize = RSA.public_size $ RSA.private_pub privKey
    halfSize = keySize `div` 2
    blobSize = sizeOf (undefined :: BLOBHEADER)
             + sizeOf (undefined :: RSAPUBKEY)
             + keySize -- modulus
             + halfSize -- prime1
             + halfSize -- prime2
             + halfSize -- exponent1
             + halfSize -- exponent2
             + halfSize -- coefficient
             + keySize -- privateExponent
    writeStorable posRef x = do
      pos <- readIORef posRef
      poke (castPtr pos) x
      writeIORef posRef (pos `plusPtr` sizeOf x)
    writeInteger posRef sz x = do
      pos@(Ptr addr) <- readIORef posRef
      when (W# (sizeInBaseInteger x 256#) > fromIntegral sz) $ error ("Failed to fit given integer into " ++ show sz ++ " bytes.")
      exportIntegerToAddr x addr 0#
      writeIORef posRef (pos `plusPtr` sz)

cryptProvFromPrivateKey :: X509.PrivKey -> ResourceT IO (ReleaseKey, HCRYPTPROV)
cryptProvFromPrivateKey privKey = case privKey of
  X509.PrivKeyRSA rsaPrivKey -> do
    (releaseProv, cryptProv) <- cryptAcquireContext Nothing (Just MS_DEF_PROV) PROV_RSA_FULL CRYPT_VERIFYCONTEXT
    (releaseKey, cryptKey) <- restoreM =<< liftBaseWith (\runInBase ->
      withPrivateKeyBlob rsaPrivKey $ \(pBlob, blobLen) ->
        let allocKey = alloca $ \phKey -> do
              failIfFalse_ "CryptImportKey" $ c_CryptImportKey cryptProv (castPtr pBlob) (fromIntegral blobLen) nullPtr zeroBits phKey
              peek phKey
            releaseKey = void . c_CryptDestroyKey
        in  runInBase $ allocate allocKey releaseKey)
    releaseAll <- resourceMask $ \_ -> do
      maybeReleaseKey <- unprotect releaseKey
      maybeReleaseProv <- unprotect releaseProv
      register $ do
        forM_ maybeReleaseKey id
        forM_ maybeReleaseProv id
    return (releaseAll, cryptProv)
  _ -> error "Importing key types other than RSA isn't implemented yet"

certContextFromX509 :: (X509.Certificate, Maybe X509.PrivKey) -> ResourceT IO (ReleaseKey, PCERT_CONTEXT)
certContextFromX509 (cert, maybeKey) = do
  let certPem = BL.toStrict $ ASN1.encodeASN1 ASN1.DER (toASN1 cert [])
  (ctxRelease, ctx) <- certCreateCertificateContext X509_ASN_ENCODING certPem
  maybeReleaseAndProv <- forM maybeKey cryptProvFromPrivateKey
  releaseAll <- resourceMask $ \_ -> do
    maybeCtxRelease <- unprotect ctxRelease
    maybeProvRelease <- join <$> forM maybeReleaseAndProv (unprotect . fst)
    register $ do
      forM_ maybeProvRelease id
      forM_ maybeCtxRelease id
  return (releaseAll, ctx)
