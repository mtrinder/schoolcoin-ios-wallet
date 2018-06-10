//
//  Secp256r1Tests.swift
//  breadwalletTests
//
//  Created by MarkTrinder on 2/5/18.
//  Copyright © 2018 breadwallet LLC. All rights reserved.
//

import XCTest
@testable import breadwallet
@testable import BRCore

class Secp256r1Tests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        setBRCoreCallbacks()
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testMaxcoinSchnorrGenerateKeyPair() {
        let curveAndSig = BRSchnorr()
        curveAndSig.GenerateKeyPair()
        var key = BRKey(privKey: curveAndSig.GetPrivateKey())
        let priv = key?.privKey();
        XCTAssertTrue(priv!.count > 0)
    }
    
    func testMaxcoinPrivKeyIsValid() {
        let privkey = "5JCDKoPn2Ymd2RZQDCJXnwPnRzwRTEohBgZyeV35ycxaZwDyzrc"
        guard let nfkdPhrase = CFStringCreateMutableCopy(secureAllocator, 0, privkey as CFString) else { return }
        CFStringNormalize(nfkdPhrase, .KD)
        XCTAssertTrue(MWPrivKeyIsValid(nfkdPhrase as String) == 1)
    }

    func testMaxcoinPubKeyWithSchnorr() {
        
        let privKeyWIF = "5JfUbmJzRbqxdHuxW5KMSBfWAhh1vsg7bFxeFYW7kGiqWUEHqWR"
        let pubKeyCompressed = "mJfNtNZWFdV2zPM6fVW9Pk41XUnWjCSRoz"
        
        let curveAndSig = BRSchnorr()

        curveAndSig.SetPrivateKey(privKeyData: privKeyWIF.base58DecodeCheck())
        
        var key = BRKey(privKey: privKeyWIF)

        key?.compressed = 0
        var privKey = key?.privKey()!
        privKey?.removeLast()
        
        XCTAssertTrue(privKey == privKeyWIF)

        var pubKey = curveAndSig.GetPublicKey().hexToData
        
        let _ = pubKey?.withUnsafeBytes { (ptr: UnsafePointer<CUnsignedChar>) in
            MWKeySetPubKey(&key!, ptr, pubKey!.count)
        }
        
        XCTAssertTrue(key?.addressMW() == pubKeyCompressed)
    }

    func testMaxcoinMWKeyPubKey() {
        
        let privKeyWIF = "5JfUbmJzRbqxdHuxW5KMSBfWAhh1vsg7bFxeFYW7kGiqWUEHqWR"
        let pubKeyCompressed = "mJfNtNZWFdV2zPM6fVW9Pk41XUnWjCSRoz"
        
        // set the WIF key
        var key = BRKey(privKey: privKeyWIF)

        // extract the public key
        key?.compressed = 1
        let keyLength = MWKeyPubKey(&key!, nil, 0)
        var pubKey = [UInt8](repeating: 0, count: keyLength)
        MWKeyPubKey(&key!, &pubKey, pubKey.count)

        // check the compressed address
        var keyWithPublicKey = BRKey(pubKeyMW: pubKey);

        XCTAssertTrue(keyWithPublicKey?.addressMW() == pubKeyCompressed)
    }
    
    func testMaxcoinBIP39() {
        var key = BRKey()
        var seed = UInt512()
        
        let phrase = "kind butter gasp around unfair tape again suit else example toast orphan"
        guard let nfkdPhrase = CFStringCreateMutableCopy(secureAllocator, 0, phrase as CFString) else { return }
        CFStringNormalize(nfkdPhrase, .KD)

        // get the seed from the BIP39 phrase
        BRBIP39DeriveKey(&seed, nfkdPhrase as String, nil)
        
        MWBIP32PrivKey(&key, &seed, MemoryLayout<UInt512>.size, UInt32(SEQUENCE_INTERNAL_CHAIN), 2 | 0x80000000);

        // Get WIF key from the generated one
        key.compressed = 0 // BRSchnorr (using secp256r1) needs uncompressed private keys
        var privKeyWIF = key.privKey()!
        privKeyWIF.removeLast()
        
        // use the WIF to set the private key on the Elliptic Curve
        let curveAndSig = BRSchnorr()
        curveAndSig.SetPrivateKey(privKeyData: privKeyWIF.base58DecodeCheck())
        
        // sanity check: use the private key on the Elliptic Curve to create a WIF key and test it's the same
        var keyTest = BRKey(privKey: curveAndSig.GetPrivateKey())
        var privKeyTest = keyTest?.privKey()
        privKeyTest?.removeLast()
        
        XCTAssertTrue(privKeyTest == privKeyWIF)
    }
    
    func testMaxcoinBIP32MasterPubKey() {
        var seed = UInt512()

        let phrase = "kind butter gasp around unfair tape again suit else example toast orphan"

        guard let nfkdPhrase = CFStringCreateMutableCopy(secureAllocator, 0, phrase as CFString) else { return }
        CFStringNormalize(nfkdPhrase, .KD)
        
        BRBIP39DeriveKey(&seed, nfkdPhrase as String, nil)
        let masterPubKey = MWBIP32MasterPubKey(&seed, MemoryLayout<UInt512>.size)
        
        XCTAssertTrue(masterPubKey.pubKey.0 == 2)
        XCTAssertTrue(masterPubKey.fingerPrint == 935776041)
    }
    
    func testMaxcoinBIP32PubKey() {
        var seed = UInt512()

        let phrase = "kind butter gasp around unfair tape again suit else example toast orphan"
        guard let nfkdPhrase = CFStringCreateMutableCopy(secureAllocator, 0, phrase as CFString) else { return }
        CFStringNormalize(nfkdPhrase, .KD)

        // create the seed from the BIP39 phrase words
        BRBIP39DeriveKey(&seed, nfkdPhrase as String, nil)

        // create the master public key from the seed
        let masterPubKey = MWBIP32MasterPubKey(&seed, MemoryLayout<UInt512>.size)

        // create a child public key from the master (copied to pubKey)
        let size = MWBIP32PubKey(nil, 0, masterPubKey, 0, 0)
        let pubKey = [UInt8](repeating: 0, count: size)
        let pubKeyPtr = UnsafeMutablePointer(mutating: pubKey)
        
        // access the key & check the address
        MWBIP32PubKey(pubKeyPtr, size, masterPubKey, 0, 0)
        var key = BRKey(pubKeyMW: pubKey)
        
        let pubAddress = key?.addressMW()
        XCTAssertTrue(pubAddress == "mbpy574cfB5Jv3rSZecY3cQtxBEsztNRxn")
    }
    
    func testMaxcoinSchnorrSignatures() {
        let privKeyWIF = "5JfUbmJzRbqxdHuxW5KMSBfWAhh1vsg7bFxeFYW7kGiqWUEHqWR"
        let length = 64 // Schnorr signatures are 64 bytes long
        
        // create the hash
        let data = Data(repeating: 0, count: 10)
        let hash256 = data.sha256.uInt256

        // set up the priv/pub key pair
        var key = BRKey(privKey: privKeyWIF)
        key?.compressed = 1
        let x = MWKeyPubKey(&key!, nil, 0)
        var pubKey = [UInt8](repeating: 0, count: x)
        MWKeyPubKey(&key!, &pubKey, pubKey.count)

        // a pointer to the signature (signed hash)
        let pointer = UnsafeMutableRawPointer.allocate(bytes: length, alignedTo: MemoryLayout<Int8>.alignment)
        
        MWKeySign(&key!, pointer, length, hash256) // sign it
        
        // access the signature as an array to pass back
        let u8ptr = pointer.bindMemory(to: UInt8.self, capacity: length)
        let u8Buffer = UnsafeBufferPointer(start: u8ptr, count: length)
        let array = Array(u8Buffer)

        let result = MWKeyVerify(&key!, hash256, UnsafeMutablePointer(mutating: array), length) // verify it

        XCTAssertTrue(result == 1)
    }
}

