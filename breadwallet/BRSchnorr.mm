//
//  BRSchnorr.m
//  breadwallet
//
//  Created by MarkTrinder on 6/5/18.
//  Copyright © 2018 breadwallet LLC. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "BRSchnorr.h"
#import <Schnorr.h>

@implementation BRSchnorrLib

SchnorrCPP::CCurve *curveWithSchnorr;

- (id)init {
    self = [super init];
    if (self) {
        curveWithSchnorr = new SchnorrCPP::CCurve();
    }
    return self;
}

- (void)GenerateKeys
{
    curveWithSchnorr->GenerateKeys();
}

- (void) SetSecretKey: (NSData *) privKeyData
{
    unsigned char* array = (unsigned char*) [privKeyData bytes];
    
    std::vector<unsigned char> vchKey = std::vector<unsigned char>(array, array + [privKeyData length]);
    
    curveWithSchnorr->SetVchSecretKey(vchKey);
}

- (void) SetPublicKey: (NSData *) pubKeyData
{
    unsigned char* array = (unsigned char*) [pubKeyData bytes];
    
    std::vector<unsigned char> vchKey = std::vector<unsigned char>(array, array + [pubKeyData length]);
    
    curveWithSchnorr->SetVchPublicKey(vchKey);
}

- (NSString *)GetSecretKeyHex
{
    std::vector<unsigned char> vchKey;
    curveWithSchnorr->GetVchSecretKey(vchKey);
    
    unsigned char * data = vchKey.data();
    NSMutableString *hex = [NSMutableString string];
    for (int i=0; i<vchKey.size(); i++) [hex appendFormat:@"%02x", data[i]];
    
    return [NSString stringWithString:hex];
}

- (NSString *)GetPublicKeyHex
{
    std::vector<unsigned char> vchKey;
    curveWithSchnorr->GetVchPublicKey(vchKey);
 
    unsigned char * data = vchKey.data();
    NSMutableString *hex = [NSMutableString string];
    for (int i=0; i<vchKey.size(); i++) [hex appendFormat:@"%02x", data[i]];
    
    return [NSString stringWithString:hex];
}

- (NSString *)CurveModuloAddHex:(NSString *)a :(NSString *)b
{
    if(![a hasSuffix:@"h"]) return @"";
    if(![b hasSuffix:@"h"]) return @"";

    // CryptoPP::Integer will load a number from Hex string with "h" at the end
    // Example - "25dccf642c2f034de7b767fd4704cf09e6e12456023c670e1885f682893f8aa4h"
    CryptoPP::Integer* intA = new CryptoPP::Integer([a UTF8String]);
    CryptoPP::Integer* intB = new CryptoPP::Integer([b UTF8String]);

    std::vector<unsigned char> bytes;
    
    curveWithSchnorr->ModuloAddToHex(*intA, *intB, bytes);

    unsigned char * data = bytes.data();
    NSMutableString *hex = [NSMutableString string];
    for (int i=0; i<bytes.size(); i++) [hex appendFormat:@"%02x", data[i]];
    
    return [NSString stringWithString:hex];
}

- (NSString *)CurvePointMultiplyAddHex:(NSString *)a
{
    if(![a hasSuffix:@"h"]) return @"";
    
    // CryptoPP::Integer will load a number from Hex string with "h" at the end
    // Example - "25dccf642c2f034de7b767fd4704cf09e6e12456023c670e1885f682893f8aa4h"
    CryptoPP::Integer* intA = new CryptoPP::Integer([a UTF8String]);
    
    std::vector<unsigned char> bytes;
    
    curveWithSchnorr->GetVchPointMultiplyAdd(*intA, bytes);

    unsigned char * data = bytes.data();
    NSMutableString *hex = [NSMutableString string];
    for (int i=0; i<bytes.size(); i++) [hex appendFormat:@"%02x", data[i]];
    
    return [NSString stringWithString:hex];
}

// private key must have been set before calling
- (NSString *) SchnorrSignSig: (NSData *) hash
{
    if (!curveWithSchnorr->HasPrivateKey()) return @"";

    std::vector<unsigned char> vchSig;

    unsigned char* array = (unsigned char*) [hash bytes];
    std::vector<unsigned char> vchHash = std::vector<unsigned char>(array, array + [hash length]);

    curveWithSchnorr->Sign(vchHash, vchSig);
    
    unsigned char * data = vchSig.data();
    NSMutableString *hex = [NSMutableString string];
    for (int i=0; i<vchSig.size(); i++) [hex appendFormat:@"%02x", data[i]];
    
    return [NSString stringWithString:hex];
}

// public key must have set before calling
- (bool) SchnorrVerifySig:(NSData *)hash :(NSData *)sig
{
    if (!curveWithSchnorr->HasPublicKey()) return false;
    
    unsigned char* array = (unsigned char*) [hash bytes];
    std::vector<unsigned char> vchHash = std::vector<unsigned char>(array, array + [hash length]);

    array = (unsigned char*) [sig bytes];
    std::vector<unsigned char> vchSig = std::vector<unsigned char>(array, array + [sig length]);

    return curveWithSchnorr->Verify(vchHash, vchSig);
}


@end
