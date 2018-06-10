//
//  MWCore.swift
//  breadwallet
//
//  Created by MarkTrinder on 12/5/18.
//  Copyright © 2018 breadwallet LLC. All rights reserved.
//

import Foundation
import BRCore

// *****************************************************
// ** this func must be called as the app is starting **
// *****************************************************

func setBRCoreCallbacks()
{
    // Problem: The Elliptic Curve logic as well as the Schnorr functions
    //          are written in C++. So how can the BRCore library use it
    //          to create keys and sign transactions? BRCore is written in C.
    //
    // Answer:  We need to create a separate library for the C++ code and
    //          then use a bridging class (written in Objective-C) that
    //          can instantiate C++ objects and call the methods.
    //
    // The is how we achive it:
    //
    // > C-function pointers are assigned to Swift functions
    // > The Swift functions call bridging Objective-C class
    // > The BRCore code (written in C) uses the functions pointers
    //
    // Used for
    // - Pirvate/Public key creation on secp256r1 elliptic curve
    // - BIP32 Pulic Key derivation from Public Master Key
    // - Schnorr signature creation/verification for transaction

    _BRBIP32PublicKeyFromSecret = publicKeyFromSecret
    _BRBIP32UncompressedPublicKeyFromSecret = publicUncompressedKeyFromSecret
    _BIP32DeriveChildPrivateKey = deriveChildPrivateKey
    _BIP32DeriveChildPublicKey = deriveChildPublicKey
    _BRTransactionSign = signHashFromSecret
    _BRTransactionVerify = verifyHashFromPublicKey
}

func verifyHashFromPublicKey(key: UnsafeMutablePointer<UInt8>?, pubKeyLen: UnsafeMutablePointer<Int>?, a: UnsafeMutablePointer<UInt256>?, sig: UnsafeMutablePointer<UInt8>?, sigLen: UnsafeMutablePointer<Int>?)
    -> Int32
{
    let hash = a?.pointee.hexString
    let hashData = hash?.hexToData
    
    var len = pubKeyLen?.pointee
    let keyData = Data(bytes: key!, count: len!)
    let curveAndSig = BRSchnorr()

    len = sigLen?.pointee
    let sigData = Data(bytes: sig!, count: len!)
    
    curveAndSig.SetPublicKey(pubKeyData: keyData)
    let result = curveAndSig.VerifyTxHash(hash: hashData!, sig: sigData)
    return result
}

func signHashFromSecret(secret: UnsafeMutablePointer<UInt256>?, a: UnsafeMutablePointer<UInt256>?)
    -> UnsafePointer<UInt8>?
{
    var key = BRKey(secret: secret!, compact:false)
    let hash = a?.pointee.hexString
    let hashData = hash?.hexToData
    
    var privKey = key?.privKey()!
    privKey?.removeLast()
    
    let curveAndSig = BRSchnorr()
    curveAndSig.SetPrivateKey(privKeyData: privKey!.base58DecodeCheck())
    let signedResult = curveAndSig.SignTxHash(hash: hashData!)
    
    let result = signedResult.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) in
        return ptr
    }

    return UnsafePointer(result)
}

func publicKeyFromSecret(secret: UnsafeMutablePointer<UInt256>?, size: UnsafeMutablePointer<Int>?)
    -> UnsafePointer<UInt8>?
{
    var key = BRKey(secret: secret!, compact:false)
    
    var privKey = key?.privKey()!
    privKey?.removeLast()
    
    let curveAndSig = BRSchnorr()
    curveAndSig.SetPrivateKey(privKeyData: privKey!.base58DecodeCheck())
    
    var pubKey = curveAndSig.GetPublicKey().hexToData
    
    let _ = pubKey?.withUnsafeBytes { (ptr: UnsafePointer<CUnsignedChar>) in
        MWKeySetPubKey(&key!, ptr, pubKey!.count)
    }
    
    let result = key?.pubKeyCopy()
    size?.pointee = result!.count
    
    return UnsafePointer(result)
}

func publicUncompressedKeyFromSecret(secret: UnsafeMutablePointer<UInt256>?, size: UnsafeMutablePointer<Int>?)
    -> UnsafePointer<UInt8>?
{
    var key = BRKey(secret: secret!, compact:false)
    
    var privKey = key?.privKey()!
    privKey?.removeLast()
    
    let curveAndSig = BRSchnorr()
    curveAndSig.SetPrivateKey(privKeyData: privKey!.base58DecodeCheck())
    
    var pubKey = curveAndSig.GetUncompressedPublicKey().hexToData
    
    let _ = pubKey?.withUnsafeBytes { (ptr: UnsafePointer<CUnsignedChar>) in
        MWKeySetPubKey(&key!, ptr, pubKey!.count)
    }
    
    let result = key?.pubKeyCopy()
    size?.pointee = result!.count
    
    return UnsafePointer(result)
}

func deriveChildPrivateKey(a: UnsafeMutablePointer<UInt256>?, b: UnsafeMutablePointer<UInt256>?)
    -> UnsafePointer<CUnsignedChar>?
{
    let intA = a?.pointee.hexString
    let intB = b?.pointee.hexString
    
    var key = BRKey(secret: a!, compact:false);
    
    let curveAndSig = BRSchnorr()
    
    let modAddResult = curveAndSig.CurveModuloAddition(a: intA!, b: intB!)
    
    let _ = modAddResult?.withUnsafeBytes { (ptr: UnsafePointer<CUnsignedChar>) in
        MWKeySetPrivKeyBytes(&key!, ptr, modAddResult!.count)
    }

    let result = key?.privKeyCopy()

    return UnsafePointer(result)
}

func deriveChildPublicKey(key: UnsafeMutablePointer<UInt8>?, pubKeyLen: UnsafeMutablePointer<Int>?, i: UnsafeMutablePointer<UInt256>?)
    -> UnsafePointer<CUnsignedChar>?
{
    let len = pubKeyLen?.pointee
    let keyData = Data(bytes: key!, count: len!)
    let intI = i?.pointee.hexString
    
    var key = BRKey(pubKeyMW: Array(keyData));

    let curveAndSig = BRSchnorr()

    curveAndSig.SetPublicKey(pubKeyData: keyData)

    let addResult = curveAndSig.CurvePointAddition(a: intI!)
    
    let _ = addResult?.withUnsafeBytes { (ptr: UnsafePointer<CUnsignedChar>) in
        MWKeySetPubKey(&key!, ptr, addResult!.count)
    }

    let result = key?.pubKeyCopy()
    pubKeyLen?.pointee = result!.count

    return UnsafePointer(result)
}







