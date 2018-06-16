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
    _BIP32DeriveChildPrivateKey = deriveChildPrivateKey
    _BIP32DeriveChildPublicKey = deriveChildPublicKey
    _BRTransactionSign = signHashFromSecret
    _BRTransactionVerify = verifyHashFromPublicKey
}

struct MWVariables {
    static var curveAndSignature = BRSchnorr()
}

func verifyHashFromPublicKey(key: UnsafeMutablePointer<UInt8>?, pubKeyLen: UnsafeMutablePointer<Int>?, a: UnsafeMutablePointer<UInt256>?, sig: UnsafeMutablePointer<UInt8>?, sigLen: UnsafeMutablePointer<Int>?)
    -> Int32
{
    let hash = a?.pointee.hexString
    var hashData = hash?.hexToData
    
    var len = pubKeyLen?.pointee
    let keyData = Data(bytes: key!, count: len!)

    len = sigLen?.pointee
    let sigData = Data(bytes: sig!, count: len!)
    
    MWVariables.curveAndSignature.SetPublicKey(pubKeyData: keyData)
    let result = MWVariables.curveAndSignature.VerifyTxHash(hash: hashData!, sig: sigData)
    
    hashData = nil
    
    return result
}

func signHashFromSecret(secret: UnsafeMutablePointer<UInt256>?, a: UnsafeMutablePointer<UInt256>?, sig: UnsafeMutablePointer<UInt8>?)
    -> Int32
{
    var key = BRKey(secret: secret!, compact:false)
    let hash = a?.pointee.hexString
    var hashData = hash?.hexToData
    
    var privKey = key?.privKey()!
    privKey?.removeLast()
    
    MWVariables.curveAndSignature.SetPrivateKey(privKeyData: privKey!.base58DecodeCheck())
    let signedResult = MWVariables.curveAndSignature.SignTxHash(hash: hashData!)
    
    let _ = signedResult?.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) in
        sig?.assign(from: ptr, count: signedResult!.count)
    }

    hashData = nil

    return 1
}

func publicKeyFromSecret(secret: UnsafeMutablePointer<UInt256>?, size: UnsafeMutablePointer<Int>?, k: UnsafeMutablePointer<UInt8>?)
    -> Int32
{
    var key = BRKey(secret: secret!, compact:false)
    var privKey = key?.privKey()!
    privKey?.removeLast()
    
    MWVariables.curveAndSignature.SetPrivateKey(privKeyData: privKey!.base58DecodeCheck())
    let keyHex = MWVariables.curveAndSignature.GetPublicKey()
    var pubKey = keyHex.hexToData
    
    let _ = pubKey?.withUnsafeBytes { (ptr: UnsafePointer<CUnsignedChar>) in
        MWKeySetPubKey(&key!, ptr, pubKey!.count)
        k?.assign(from: ptr, count: pubKey!.count)
        size?.pointee = pubKey!.count
    }
    
    pubKey = nil
    
    return 1;
}

func deriveChildPrivateKey(a: UnsafeMutablePointer<UInt256>?, b: UnsafeMutablePointer<UInt256>?, c: UnsafeMutablePointer<CUnsignedChar>?)
    -> Int32
{
    let intA = a?.pointee.hexString
    let intB = b?.pointee.hexString
    
    var key = BRKey(secret: a!, compact:false);
    
    let modAddResult = MWVariables.curveAndSignature.CurveModuloAddition(a: intA!, b: intB!)
    
    let _ = modAddResult?.withUnsafeBytes { (ptr: UnsafePointer<CUnsignedChar>) in
        MWKeySetPrivKeyBytes(&key!, ptr, modAddResult!.count)
        c?.assign(from: ptr, count: modAddResult!.count)
    }

    return 1;
}

func deriveChildPublicKey(key: UnsafeMutablePointer<UInt8>?, pubKeyLen: UnsafeMutablePointer<Int>?, i: UnsafeMutablePointer<UInt256>?, c: UnsafeMutablePointer<CUnsignedChar>?)
    -> Int32
{
    let len = pubKeyLen?.pointee
    let keyData = Data(bytes: key!, count: len!)
    let intI = i?.pointee.hexString
    
    var key = BRKey(pubKeyMW: Array(keyData));

    MWVariables.curveAndSignature.SetPublicKey(pubKeyData: keyData)
    let addResult = MWVariables.curveAndSignature.CurvePointAddition(a: intI!)
    
    let _ = addResult?.withUnsafeBytes { (ptr: UnsafePointer<CUnsignedChar>) in
        MWKeySetPubKey(&key!, ptr, addResult!.count)
        c?.assign(from: ptr, count: addResult!.count)
        pubKeyLen?.pointee = addResult!.count
    }

    return 1
}







