//
//  Encryption.h
//  PIATunnel
//
//  Created by Davide De Rosa on 3/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol Encrypter

- (int)overheadLength;
- (NSData *)encryptData:(NSData *)data offset:(NSInteger)offset error:(NSError **)error;

// WARNING: dest must be able to hold ciphertext
- (int)encryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest error:(NSError **)error;

@end

@protocol Decrypter

- (int)overheadLength;
- (NSData *)decryptData:(NSData *)data offset:(NSInteger)offset error:(NSError **)error;

// WARNING: dest must be able to hold plaintext
- (int)decryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest error:(NSError **)error;

@end
