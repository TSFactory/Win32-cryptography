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
  , HCERTSTORE
  , pattern CERT_STORE_PROV_MSG
  , pattern CERT_STORE_PROV_MEMORY
  , pattern CERT_STORE_PROV_FILE
  , pattern CERT_STORE_PROV_REG
  , pattern CERT_STORE_PROV_PKCS7
  , pattern CERT_STORE_PROV_SERIALIZED
  , pattern CERT_STORE_PROV_FILENAME_A
  , pattern CERT_STORE_PROV_FILENAME_W
  , pattern CERT_STORE_PROV_FILENAME
  , pattern CERT_STORE_PROV_SYSTEM_A
  , pattern CERT_STORE_PROV_SYSTEM_W
  , pattern CERT_STORE_PROV_SYSTEM
  , pattern CERT_STORE_PROV_COLLECTION
  , pattern CERT_STORE_PROV_SYSTEM_REGISTRY_A
  , pattern CERT_STORE_PROV_SYSTEM_REGISTRY_W
  , pattern CERT_STORE_PROV_SYSTEM_REGISTRY
  , pattern CERT_STORE_PROV_PHYSICAL_W
  , pattern CERT_STORE_PROV_PHYSICAL
  , pattern CERT_STORE_BACKUP_RESTORE_FLAG
  , pattern CERT_STORE_CREATE_NEW_FLAG
  , pattern CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG
  , pattern CERT_STORE_DELETE_FLAG
  , pattern CERT_STORE_ENUM_ARCHIVED_FLAG
  , pattern CERT_STORE_MAXIMUM_ALLOWED_FLAG
  , pattern CERT_STORE_NO_CRYPT_RELEASE_FLAG
  , pattern CERT_STORE_OPEN_EXISTING_FLAG
  , pattern CERT_STORE_READONLY_FLAG
  , pattern CERT_STORE_SET_LOCALIZED_NAME_FLAG
  , pattern CERT_STORE_SHARE_CONTEXT_FLAG
  , pattern CERT_STORE_UPDATE_KEYID_FLAG
  , pattern CERT_SYSTEM_STORE_CURRENT_SERVICE
  , pattern CERT_SYSTEM_STORE_CURRENT_USER
  , pattern CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY
  , pattern CERT_SYSTEM_STORE_LOCAL_MACHINE
  , pattern CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE
  , pattern CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY
  , pattern CERT_SYSTEM_STORE_SERVICES
  , pattern CERT_SYSTEM_STORE_USERS
  , certOpenStore
  , pattern CERT_CLOSE_STORE_CHECK_FLAG
  , pattern CERT_CLOSE_STORE_FORCE_FLAG
  , certCloseStore
  , certFreeCertificateContext
  , unsafeEnumCertificatesInStore
  , getAllCertificatesInStore
  , certDuplicateCertificateContext
  , CertInfo (..)
  , Thumbprint (..)
  , certContextGetInfo
  , certFindBySHA1
  , CertificateFindType (..)
  , certFindCertificate
  ) where

import Control.Exception
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.IO.Unlift (withRunInIO)
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
import System.Win32.Cryptography.Hash (cryptHashCertificate)
import System.Win32.Cryptography.Types
import System.Win32.Error.Foreign
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Unsafe as BU
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Foreign as T
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

withStoreProviderPtr :: StoreProvider -> (Ptr CChar -> IO a) -> IO a
withStoreProviderPtr sp act = case sp of
  StoreProviderPredefined predef -> act $ intPtrToPtr predef
  StoreProviderCustom custom -> BU.unsafeUseAsCString custom act

certOpenStore :: StoreProvider -> EncodingType -> CertOpenStoreFlags -> Ptr () -> ResourceT IO (ReleaseKey, HCERTSTORE)
certOpenStore prov encType cosFlags pvPara = withRunInIO $ \runInIo ->
  withStoreProviderPtr prov $ \lpszStoreProvider -> runInIo $
    allocate
      (failIfNull "CertOpenStore" $ c_CertOpenStore lpszStoreProvider encType nullPtr cosFlags pvPara)
      (\s -> certCloseStore s zeroBits)

-- | Closes given cert store. Never throws (even if fails).
certCloseStore :: HCERTSTORE -> CloseStoreFlags -> IO ()
certCloseStore store flags = void $ c_CertCloseStore store flags

-- | Enumerates certificates in store by running given action with each of them.
-- This function is unsafe because after given action returns, its parameter should
-- no longer be used.
-- Action should return 'True' if enumeration should continue and 'False' if
-- enumeration should terminate without visiting remaining certificates.
unsafeEnumCertificatesInStore :: HCERTSTORE -> (PCERT_CONTEXT -> IO Bool) -> IO ()
unsafeEnumCertificatesInStore store act = do
  lastCertContextRef <- newIORef nullPtr
  let loop = do
        lastCertContext <- readIORef lastCertContextRef
        res <- do
          cert <- mask_ $
            do cert <- c_CertEnumCertificatesInStore store lastCertContext
               writeIORef lastCertContextRef cert
               return cert
          if cert == nullPtr
            then pure Nothing
            else Just <$> act cert
        case res of
          Just True -> loop
          _ -> return ()
  loop `finally` (readIORef lastCertContextRef >>= \lastCertContext -> unless (lastCertContext == nullPtr) (certFreeCertificateContext lastCertContext))

-- | Frees given certificate context. Never throws (even if fails)
certFreeCertificateContext :: PCERT_CONTEXT -> IO ()
certFreeCertificateContext = void . c_CertFreeCertificateContext

getAllCertificatesInStore :: HCERTSTORE -> ResourceT IO [(ReleaseKey, PCERT_CONTEXT)]
getAllCertificatesInStore store = do
  resultRef <- liftIO $ newIORef []
  withRunInIO $ \runInIo -> unsafeEnumCertificatesInStore store $ \cert -> do
    dup <- runInIo $ allocate (certDuplicateCertificateContext cert) certFreeCertificateContext
    modifyIORef resultRef $ \x -> x `mappend` [dup]
    return True
  liftIO $ readIORef resultRef

certDuplicateCertificateContext :: PCERT_CONTEXT -> IO PCERT_CONTEXT
certDuplicateCertificateContext = failIfNull "CertDuplicateCertificateContext" . c_CertDuplicateCertificateContext

newtype Thumbprint = Thumbprint
  { thumbprintBytes :: B.ByteString
  } deriving (Eq, Ord)

instance Show Thumbprint where
  show = C8.unpack . B16.encode . thumbprintBytes

-- | There is actually much more information in the underlying Windows API CERT_INFO structure.
-- That info just is not present in this structure. Feel free to add it if you have a need.
data CertInfo = CertInfo
  { certInfoIssuer  :: T.Text
  , certInfoSubject :: T.Text
  , certThumbprint  :: Thumbprint
  } deriving (Show)

certContextGetInfo :: PCERT_CONTEXT -> IO (Maybe CertInfo)
certContextGetInfo pCtx = if pCtx == nullPtr then return Nothing else do
  ctx <- peek pCtx
  if pCertInfo ctx == nullPtr then return Nothing else Just <$> do
    let certIssuerPtr = certInfoIssuerPtr $ pCertInfo ctx
        certSubjectPtr = certInfoSubjectPtr $ pCertInfo ctx
    certIssuer <- certNameToStr certIssuerPtr CERT_SIMPLE_NAME_STR
    certSubject <- certNameToStr certSubjectPtr CERT_SIMPLE_NAME_STR
    certSha1 <- cryptHashCertificate CALG_SHA1 pCtx
    return CertInfo
      { certInfoIssuer = certIssuer
      , certInfoSubject = certSubject
      , certThumbprint = Thumbprint certSha1
      }

certNameToStr :: PCERT_NAME_BLOB -> StrType -> IO T.Text
certNameToStr name strType = if name == nullPtr then return T.empty else do
  charsNeeded <- c_CertNameToStr X509_ASN_ENCODING name strType nullPtr 0
  if charsNeeded == 0 then return T.empty else allocaBytes ((fromIntegral charsNeeded) * sizeOf (undefined :: CWchar)) $ \psz -> do
    newLen <- c_CertNameToStr X509_ASN_ENCODING name strType psz charsNeeded
    T.fromPtr (castPtr psz) (fromIntegral newLen - 1)

certFindInStore :: HCERTSTORE -> CertFindType -> Ptr () -> PCERT_CONTEXT -> ResourceT IO (Maybe (ReleaseKey, PCERT_CONTEXT))
certFindInStore store findType findPara findPrevContext = do
  res <- liftIO $ c_CertFindCertificateInStore store X509_ASN_ENCODING 0 findType findPara findPrevContext
  if res == nullPtr
    then return Nothing
    else do
      releaseKey <- register $ certFreeCertificateContext res
      return $ Just (releaseKey, res)

data CertificateFindType
  = CertFindAny
  | CertFindBySHA1 B.ByteString
  | CertFindHasPrivateKey
  | CertFindBySubj T.Text

certFindCertificate :: HCERTSTORE -> CertificateFindType -> ResourceT IO (Maybe (ReleaseKey, PCERT_CONTEXT))
certFindCertificate store findtype = withRunInIO $ \runInIo -> do
  let find ctype cparam =
        runInIo $ resourceMask $ \_ ->
          certFindInStore store ctype (castPtr cparam) nullPtr

  case findtype of
    CertFindAny ->
      find CERT_FIND_ANY nullPtr

    CertFindBySHA1 sha1 ->
      BU.unsafeUseAsCStringLen sha1 $ \(sha1Bytes, sha1Length) ->
        let sha1Blob = CRYPTOAPI_BLOB
              { blobPbData = castPtr sha1Bytes
              , blobCbData = fromIntegral sha1Length
              }
        in with sha1Blob $ \pvFindPara ->
          find CERT_FIND_SHA1_HASH pvFindPara

    CertFindHasPrivateKey ->
      find CERT_FIND_HAS_PRIVATE_KEY nullPtr

    CertFindBySubj subj ->
      useAsPtr0 subj $ \szSubj -> find CERT_FIND_SUBJECT_STR szSubj

certFindBySHA1 :: HCERTSTORE -> B.ByteString -> ResourceT IO (Maybe (ReleaseKey, PCERT_CONTEXT))
certFindBySHA1 store = certFindCertificate store . CertFindBySHA1
