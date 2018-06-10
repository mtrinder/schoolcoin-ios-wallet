//
//  BRSchnorr.swift
//  breadwallet
//
//  Created by MarkTrinder on 6/5/18.
//  Copyright © 2018 breadwallet LLC. All rights reserved.
//

import Foundation

class BRSchnorr {
    
    let schnorr = BRSchnorrLib()

    func GenerateKeyPair() {
        schnorr.generateKeys()
    }

    func SetPrivateKey (privKeyData: Data)  {
        schnorr.setSecretKey(privKeyData)
    }

    func SetPublicKey (pubKeyData: Data)  {
        schnorr.setPublicKey(pubKeyData)
    }

    func GetPrivateKey () -> String {
        return (schnorr.getSecretKeyHex()?.description)!
    }
    
    func GetPublicKey () -> String {
        return (schnorr.getPublicKeyHex()?.description)!
    }

    func GetUncompressedPublicKey () -> String {
        return (schnorr.getUncompressedPublicKeyHex()?.description)!
    }
    
    func CurveModuloAddition(a: String, b: String) -> Data? {
        let modAddHex = schnorr.curveModuloAddHex(a + "h", b + "h")
        return (modAddHex?.hexToData)
    }
    
    func CurvePointAddition(a: String) -> Data? {
        let modAddHex = schnorr.curvePointMultiplyAddHex(a + "h")
        return (modAddHex?.hexToData)
    }
    
    func SignTxHash (hash: Data) -> Data {
        let signedHex = schnorr.schnorrSignSig(hash)

        let data = (signedHex?.hexToData)!
        let check = VerifyTxHash(hash: hash, sig: data)
        if (check == 1){
            return data
        }
        
        return Data(capacity: 1)
    }

    func VerifyTxHash (hash: Data, sig: Data) -> Int32 {
        let result = schnorr.schnorrVerifySig(hash, sig)
        return result ? 1 : 0
    }
}

