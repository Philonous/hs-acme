{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Network.Acme.Types where

import           Control.Lens
import qualified Control.Lens as L
import qualified Control.Monad.Catch as Ex
import           Control.Monad.State
import           Control.Monad.Trans
import qualified Crypto.JOSE as J
import qualified Crypto.JOSE.Types as J
import qualified Crypto.Random as CR
import           Data.Aeson
import           Data.Aeson.Lens
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import           Data.Data
import           Data.Default
import           Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HMap
import qualified Data.List as List
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Maybe
import           Data.Monoid
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import           GHC.Generics
import qualified Network.Wreq as Wreq

import           Network.Acme.Util

type RNG = CR.ChaChaDRG

data AcmeException = AcmeParseError String
                   | AcmeDirectoryResourceNotFound Resource
                   | AcmeNoNonce
                     deriving (Typeable, Show, Eq)

instance Ex.Exception AcmeException

data Resource = ResourceNewReg
              | ResourceRecoverReg
              | ResourceNewAuthz
              | ResourceNewCert
              | ResourceRevokeCert
              | ResourceReg
              | ResourceAuthz
              | ResourceChallenge
              | ResourceCert
                deriving (Show, Eq, Ord, Typeable, Data, Generic)

makePrisms ''Resource

resourceName :: Resource -> Text
resourceName ResourceNewReg     = "new-reg"
resourceName ResourceRecoverReg = "recover-reg"
resourceName ResourceNewAuthz   = "new-authz"
resourceName ResourceNewCert    = "new-cert"
resourceName ResourceRevokeCert = "revoke-cert"
resourceName ResourceReg        = "reg"
resourceName ResourceAuthz      = "authz"
resourceName ResourceChallenge  = "challenge"
resourceName ResourceCert       = "cert"

resourceFromName :: Text -> Maybe Resource
resourceFromName "new-reg"     = Just ResourceNewReg
resourceFromName "recover-reg" = Just ResourceRecoverReg
resourceFromName "new-authz"   = Just ResourceNewAuthz
resourceFromName "new-cert"    = Just ResourceNewCert
resourceFromName "revoke-cert" = Just ResourceRevokeCert
resourceFromName "reg"         = Just ResourceReg
resourceFromName "authz"       = Just ResourceAuthz
resourceFromName "challenge"   = Just ResourceChallenge
resourceFromName "cert"        = Just ResourceCert
resourceFromName _             = Nothing

type Nonce = Text

newtype Directory = Directory {unDirectory :: Map Resource Text}
                    deriving (Show, Eq, Typeable, Data, Generic)

makePrisms ''Directory


data AcmeState = AcmeState { acmeStateNonces :: ![Nonce]
                           , acmeStateDirectory :: !Directory
                           , acmeStateRandomState :: !RNG
                           , acmeStateJwsAlg :: !J.Alg
                           , acmeStateJwsKey :: !J.KeyMaterial
                           , acmeStateDirectoryUrl :: !Text
                           } deriving (Typeable, Generic)

makeLensesWith camelCaseFields ''AcmeState

newtype Acme a = Acme { unAcme :: StateT AcmeState IO a}
               deriving ( Functor, Applicative, Monad, MonadIO
                        , Ex.MonadThrow, Ex.MonadCatch
                        )


instance CR.MonadRandom Acme where
    getRandomBytes len = do
        g <- Acme $ use randomState
        let (bytes, g') = CR.withRandomBytes g len id
        Acme $ randomState L..= g'
        return bytes

instance FromJSON Directory where
    parseJSON = withObject "directory" $ \o ->
      fmap (Directory . Map.fromList) .
        forM (HMap.toList o) $ \(k, v) -> do
            res <- case resourceFromName k of
                    Nothing -> fail $ Text.unpack k ++ " is not a resource"
                    Just r -> return r
            url <- parseJSON v
            return (res, url)


makeLensesWith camelCaseFields ''Directory

dirUrl :: Text
dirUrl = "https://acme-v01.api.letsencrypt.org/directory"

runAcme :: J.Alg -> J.KeyMaterial -> Text -> Acme a -> IO a
runAcme alg key dirUrl (Acme f) = do
    g <- CR.drgNew
    evalStateT f AcmeState{ acmeStateNonces = []
                          , acmeStateDirectory = Directory $ Map.empty
                          , acmeStateRandomState = g
                          , acmeStateJwsAlg = alg
                          , acmeStateJwsKey = key
                          , acmeStateDirectoryUrl = dirUrl
                          }

getResource :: Resource -> Acme Text
getResource resType = do
    Directory dir <- Acme $ use directory
    case Map.lookup resType dir of
     Nothing -> Ex.throwM $ AcmeDirectoryResourceNotFound resType
     Just r -> return r


saveNonce :: Wreq.Response body -> Acme ()
saveNonce res = do
    let nonce = (Text.decodeUtf8 <$> (maybeToList . List.lookup "Replay-Nonce"
                                       $ res ^. Wreq.responseHeaders))
    Acme $ nonces <>= nonce

acquireNonce :: Acme ()
acquireNonce = do
    url <- Acme $ use directoryUrl
    res <- liftIO $ Wreq.head_ (Text.unpack url)
    saveNonce res

getNonce :: Acme Nonce
getNonce = go False
  where
    go s = do
        nonces' <- Acme $ use nonces
        case nonces' of
         [] -> if s then Ex.throwM AcmeNoNonce
                 else do
                   acquireNonce
                   go True
         (n:ns) -> do
             Acme $ nonces L..= ns
             return n

getDirectory :: Acme ()
getDirectory = do
    url <- Acme $ use directoryUrl
    res <- liftIO $ Wreq.asJSON =<< Wreq.get (Text.unpack url)
    saveNonce res
    Acme $ directory L..= res ^. Wreq.responseBody
    return ()

genKey :: IO J.KeyMaterial
genKey = do
    g <- CR.drgNew
    let (key, _) = CR.withDRG g (J.gen (4096`div`8))
    return $ J.RSAKeyMaterial key

getJwk = do
    key <- Acme $ use jwsKey
    return $ J.JWK key Nothing Nothing Nothing Nothing Nothing Nothing
                   Nothing Nothing

sign :: ToJSON a => a -> Acme Value
sign payload = do
    alg <- Acme $ use jwsAlg
    jwk <- getJwk
    nonce <- getNonce
    let payloadBS = BSL.toStrict $ encode payload
        header = def{ J.headerAlg = Just alg
                    , J.headerJwk = Just jwk
                    , J.headerOther = HMap.singleton "nonce" (String nonce)
                    }
    jws@(J.JWS _ sigs) <- doSign jwk header $ J.newJWS payloadBS
    liftIO . print $ J.toCompact jws
    let Object jwsO = toJSON jws
        headerO = HMap.fromList [ ("protected", (String $ J.toArmour header))
                                -- , ("header", toJSON header)
                                ]
    return . Object . (headerO <>) . flattenJws $ jwsO
  where
    flattenJws o =
        let mbs = o ^? at "signatures" . _Just . _Array . _head . _Object
                       . at "signature" . _Just . _String
        in case mbs of
            Nothing -> error "flattenJws: Could not find signatures"
            Just s -> HMap.insert "signature" (String s)
                       $ HMap.delete "signatures" o
    doSign jwk header x = do
        x' <- J.signJWS x header jwk
        case x' of
         Left e -> error (show e) -- @TODO
         Right r -> return (r :: J.JWS)

-- sendRequest :: (FromJSON res, ToJSON a) =>
--                Resource
--             -> a
--             -> Acme res
sendRequest reqType reqData = do
    url <- getResource reqType
    jws <- sign reqData
    liftIO . print $ encode jws
    res <- liftIO $ Wreq.asJSON =<< Wreq.post (Text.unpack url) jws
    saveNonce res
    return $ res ^. Wreq.responseBody

-- class FromJSON (ResourceResponse r) => ResourceRequest r where
--     data ResourceResponse r :: *
--     resourceType :: r -> AcmeResource


data NewReg = NewReg { newRegContact :: ![Text] }
              deriving (Show, Eq, Typeable, Data, Generic)

deriveJSON ''NewReg

foo = do
    key <- genKey
    let newReg = NewReg ["mailto:no@spam.com"]
    runAcme J.RS256 key dirUrl $ do
        getDirectory
        res <- sendRequest ResourceNewReg newReg :: Acme Value
        liftIO $ print res
        return ()
