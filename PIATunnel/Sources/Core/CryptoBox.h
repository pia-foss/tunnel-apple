//
//  CryptoBox.h
//  PIATunnel
//
//  Created by Davide De Rosa on 2/4/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "Encryption.h"

extern const NSInteger CryptoBoxMaxHMACLength;

// encrypt/decrypt are mutually thread-safe

@interface CryptoBox : NSObject <Encrypter, Decrypter>

+ (BOOL)preparePRNGWithSeed:(const uint8_t *)seed length:(NSInteger)length;

- (instancetype)initWithCipherAlgorithm:(NSString *)cipherAlgorithm digestAlgorithm:(NSString *)digestAlgorithm;

- (void)configureWithCipherEncKey:(const uint8_t *)cipherEncKey
                     cipherDecKey:(const uint8_t *)cipherDecKey
                       hmacEncKey:(const uint8_t *)hmacEncKey
                       hmacDecKey:(const uint8_t *)hmacDecKey;

// WARNING: hmac must be able to hold HMAC result
+ (BOOL)hmacWithDigestName:(NSString *)digestName
                    secret:(const uint8_t *)secret
              secretLength:(NSInteger)secretLength
                      data:(const uint8_t *)data
                dataLength:(NSInteger)dataLength
                      hmac:(uint8_t *)hmac
                hmacLength:(NSInteger *)hmacLength
                     error:(NSError **)error;

- (nonnull id<Encrypter>)encrypter;
- (nonnull id<Decrypter>)decrypter;

@end
