//
//  Encryption.h
//  PIATunnel
//
//  Created by Davide De Rosa on 3/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "ZeroingData.h"

@protocol DataPathEncrypter;
@protocol DataPathDecrypter;

// WARNING: dest must be able to hold ciphertext
@protocol Encrypter

- (void)configureEncryptionWithCipherKey:(nonnull ZeroingData *)cipherKey hmacKey:(nonnull ZeroingData *)hmacKey;
- (int)overheadLength;
- (int)extraLength;

- (NSData *)encryptData:(nonnull NSData *)data offset:(NSInteger)offset extra:(const uint8_t *)extra error:(NSError **)error;
- (BOOL)encryptBytes:(nonnull const uint8_t *)bytes length:(NSInteger)length dest:(nonnull uint8_t *)dest destLength:(nonnull NSInteger *)destLength extra:(const uint8_t *)extra error:(NSError **)error;

- (nonnull id<DataPathEncrypter>)dataPathEncrypter;

@end

// WARNING: dest must be able to hold plaintext
@protocol Decrypter

- (void)configureDecryptionWithCipherKey:(nonnull ZeroingData *)cipherKey hmacKey:(nonnull ZeroingData *)hmacKey;
- (int)overheadLength;
- (int)extraLength;

- (NSData *)decryptData:(nonnull NSData *)data offset:(NSInteger)offset extra:(const uint8_t *)extra error:(NSError **)error;
- (BOOL)decryptBytes:(nonnull const uint8_t *)bytes length:(NSInteger)length dest:(nonnull uint8_t *)dest destLength:(nonnull NSInteger *)destLength extra:(const uint8_t *)extra error:(NSError **)error;

- (nonnull id<DataPathDecrypter>)dataPathDecrypter;

@end
