{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
module System.Win32.Cryptography.Hash
  ( cryptCreateHash
  , cryptHashCertificate
  ) where

import Control.Monad
import Control.Monad.Trans.Control
import Control.Monad.Trans.Resource
import Data.Maybe
import Foreign hiding (void)
import Foreign.C
import System.Win32.Cryptography.Certificates.Internal
import System.Win32.Cryptography.Hash.Internal
import System.Win32.Cryptography.Types
import System.Win32.Error.Foreign
import System.Win32.Types hiding (failIfFalse_)
import qualified Data.ByteString as B

cryptCreateHash :: HCRYPTPROV -> ALG_ID -> Maybe HCRYPTKEY -> ResourceT IO (ReleaseKey, HCRYPTHASH)
cryptCreateHash cryptProv alg maybeKey = liftBaseWith $ \runInBase ->
  alloca $ \(pBuffer :: Ptr HCRYPTHASH) -> runInBase $
    allocate
      (do failIfFalse_ "CryptCreateHash" $ c_CryptCreateHash cryptProv alg (fromMaybe nullPtr maybeKey) 0 pBuffer
          peek pBuffer)
      (void . c_CryptDestroyHash)

cryptHashCertificate :: ALG_ID -> PCERT_CONTEXT -> IO B.ByteString
cryptHashCertificate alg certContext = if certContext == nullPtr then return B.empty else do
  (pbEncoded, cbEncoded) <- (\x -> (pbCertEncoded x, cbCertEncoded x)) <$> peek certContext
  alloca $ \(pcbComputedHash :: Ptr DWORD) -> do
    failIfFalse_ "CryptHashCertificate" $ c_CryptHashCertificate nullPtr alg 0 pbEncoded cbEncoded nullPtr pcbComputedHash
    bufferSize <- peek pcbComputedHash
    allocaBytes (fromIntegral bufferSize) $ \(pbComputedHash :: Ptr CChar) -> do
      failIfFalse_ "c_CryptHashCertificate" $ c_CryptHashCertificate nullPtr alg 0 pbEncoded cbEncoded pbComputedHash pcbComputedHash
      actualSize <- peek pcbComputedHash
      B.packCStringLen (pbComputedHash, fromIntegral actualSize)
