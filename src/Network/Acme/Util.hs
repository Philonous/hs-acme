module Network.Acme.Util where

import qualified Data.Aeson.TH as Aeson
import           Data.Char
import           Data.List
import           Language.Haskell.TH

dropPrefix :: [Char] -> [Char] -> [Char]
dropPrefix pre list =
    case stripPrefix pre list of
     Nothing -> error $ "Can't strip prefix " ++ pre ++ " from " ++ list
     Just l -> l

decap :: [Char] -> [Char]
decap [] = []
decap (c:cs) = toLower c : cs

deriveJSON :: Name -> Q [Dec]
deriveJSON name = do
    let nameStr = nameBase name
        pre = decap nameStr
        opts = Aeson.defaultOptions
                 {Aeson.fieldLabelModifier = decap . dropPrefix pre}
    Aeson.deriveJSON opts name
