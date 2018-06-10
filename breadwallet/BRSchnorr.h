//
//  BRSchnorr.h
//  breadwallet
//
//  Created by MarkTrinder on 6/5/18.
//  Copyright © 2018 breadwallet LLC. All rights reserved.
//

#ifndef BRSchnorr_h
#define BRSchnorr_h

#import <Foundation/Foundation.h>

@interface BRSchnorrLib : NSObject

// Private / Public Key Functions
//
- (void)GenerateKeys;
- (void)SetSecretKey:(NSData *) privKey;
- (void)SetPublicKey:(NSData *) privKey;
- (NSString *)GetSecretKeyHex;
- (NSString *)GetPublicKeyHex;
- (NSString *)GetUncompressedPublicKeyHex;

// BIP32 Elliptic Curve Functions
//
- (NSString *)CurveModuloAddHex:(NSString *)a :(NSString *)b;
- (NSString *)CurvePointMultiplyAddHex:(NSString *)a;

// Schnorr Signature Functions
//
- (NSString *) SchnorrSignSig:(NSData *) hash;
- (bool) SchnorrVerifySig:(NSData *)hash :(NSData *)sig;

@end

#endif /* BRSchnorr_h */
