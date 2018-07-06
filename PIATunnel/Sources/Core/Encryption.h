//
//  Encryption.h
//  PIATunnel
//
//  Created by Davide De Rosa on 3/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol Encrypter

- (void)configureEncryptionWithCipherKey:(nonnull const uint8_t *)cipherKey hmacKey:(nonnull const uint8_t *)hmacKey;
- (int)overheadLength;

- (NSData *)encryptData:(nonnull NSData *)data offset:(NSInteger)offset error:(NSError **)error;

// WARNING: dest must be able to hold ciphertext
- (BOOL)encryptBytes:(nonnull const uint8_t *)bytes length:(int)length dest:(nonnull uint8_t *)dest destLength:(int *)destLength error:(NSError **)error;

@end

@protocol Decrypter

- (void)configureDecryptionWithCipherKey:(nonnull const uint8_t *)cipherKey hmacKey:(nonnull const uint8_t *)hmacKey;
- (int)overheadLength;

- (NSData *)decryptData:(nonnull NSData *)data offset:(NSInteger)offset error:(NSError **)error;

// WARNING: dest must be able to hold plaintext
- (BOOL)decryptBytes:(nonnull const uint8_t *)bytes length:(int)length dest:(nonnull uint8_t *)dest destLength:(int *)destLength error:(NSError **)error;

@end
