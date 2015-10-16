{-# LANGUAGE MagicHash, OverloadedStrings, PatternSynonyms, RecordWildCards, ScopedTypeVariables #-}
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
  , CertKeySpec (..)
  , pattern AT_KEYEXCHANGE
  , pattern AT_SIGNATURE
  , pattern CERT_NCRYPT_KEY_SPEC
  , cryptAcquireContext
  , cryptImportRSAKey
  , certContextFromX509
  , KeyProvInfoFlags (..)
  , pattern CERT_SET_KEY_PROV_HANDLE_PROP_ID
  , pattern KEY_PROV_INFO_CRYPT_MACHINE_KEYSET
  , pattern KEY_PROV_INFO_CRYPT_SILENT
  , CryptKeyProvInfo (..)
  , certSetCertificateContextKeyProvInfo
  ) where

import Control.Exception (bracket)
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans.Control
import Control.Monad.Trans.Resource
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
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
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
cryptAcquireContext container provider provType flags = allocate allocContext releaseContext
  where
    allocContext =
      alloca $ \phProv ->
         maybe ($ nullPtr) useAsPtr0 container $ \pszContainer ->
         maybe ($ nullPtr) useAsPtr0 provider $ \pszProvider -> do
           failIfFalse_ "CryptAcquireContext" $ c_CryptAcquireContext phProv pszContainer pszProvider provType flags
           peek phProv
    releaseContext prov =
      if flags .&. CRYPT_DELETEKEYSET /= zeroBits
        then return ()
        else void $ c_CryptReleaseContext prov 0

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

-- The whole sad story is as follows: Windows CryptoAPI doesn't have a way to use
-- temporary keypair together with a CRYPT_KEY_PROV_INFO structure. This structure
-- actually requires us to provide a true valid key container name, which means
-- that goddamn container must be persisted. That's why there is no reliable way
-- of creating both certificate and keypair from X509.SignedCertificate and
-- RSA.PrivateKey on the fly.

cryptImportRSAKey :: HCRYPTPROV -> RSA.PrivateKey -> ResourceT IO (ReleaseKey, HCRYPTKEY)
cryptImportRSAKey prov key = allocate allocKey releaseKey
  where
    allocKey = withPrivateKeyBlob key $ \(pBlob, blobLen) ->
               alloca $ \phKey -> do
                 failIfFalse_ "CryptImportKey" $ c_CryptImportKey prov (castPtr pBlob) (fromIntegral blobLen) nullPtr zeroBits phKey
                 peek phKey
    releaseKey = void . c_CryptDestroyKey

certContextFromX509 :: X509.SignedCertificate -> ResourceT IO (ReleaseKey, PCERT_CONTEXT)
certContextFromX509 cert = certCreateCertificateContext X509_ASN_ENCODING (X509.encodeSignedObject cert)

data CryptKeyProvInfo = CryptKeyProvInfo
  { keyContainerName :: T.Text
  , keyProvName      :: T.Text
  , keyProvType      :: CryptProvType
  , keyProvInfoFlags :: KeyProvInfoFlags
  , keySpec          :: CertKeySpec
  -- provParam stuff is omitted because type-safe wrappers aren't implemented yet.
  } deriving (Show)

certSetCertificateContextKeyProvInfo :: PCERT_CONTEXT -> CryptKeyProvInfo -> IO ()
certSetCertificateContextKeyProvInfo ctx CryptKeyProvInfo{..} =
  useAsPtr0 keyContainerName $ \szContName ->
  useAsPtr0 keyProvName $ \szProvName ->
  with CRYPT_KEY_PROV_INFO
    { pwszContainerName = szContName
    , pwszProvName = szProvName
    , dwProvType = keyProvType
    , dwFlags = keyProvInfoFlags
    , cProvParam = 0
    , rgProvParam = nullPtr
    , dwKeySpec = keySpec
    } $ \pData ->
    failIfFalse_ "CertSetCertificateContextProperty" $ c_CertSetCertificateContextProperty ctx CERT_KEY_PROV_INFO_PROP_ID 0 (castPtr pData)
