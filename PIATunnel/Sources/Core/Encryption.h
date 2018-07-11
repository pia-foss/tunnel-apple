//
//  Encryption.h
//  PIATunnel
//
//  Created by Davide De Rosa on 3/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "ZeroingData.h"

// WARNING: dest must be able to hold ciphertext
@protocol Encrypter

- (void)configureEncryptionWithCipherKey:(nonnull ZeroingData *)cipherKey hmacKey:(nonnull ZeroingData *)hmacKey;
- (int)overheadLength;

- (NSData *)encryptData:(nonnull NSData *)data offset:(NSInteger)offset packetId:(uint32_t)packetId error:(NSError **)error;
- (BOOL)encryptBytes:(nonnull const uint8_t *)bytes length:(int)length dest:(nonnull uint8_t *)dest destLength:(nonnull int *)destLength packetId:(uint32_t)packetId error:(NSError **)error;

// DataPath
- (void)assembleDataPacketWithPacketId:(uint32_t)packetId compression:(uint8_t)compression payload:(NSData *)payload into:(nonnull uint8_t *)dest length:(nonnull int *)length;
- (NSData *)encryptedDataPacketWithHeader:(uint8_t)header packetId:(uint32_t)packetId payload:(const uint8_t *)payload payloadLength:(int)payloadLength error:(NSError **)error;

@end

// WARNING: dest must be able to hold plaintext
@protocol Decrypter

- (void)configureDecryptionWithCipherKey:(nonnull ZeroingData *)cipherKey hmacKey:(nonnull ZeroingData *)hmacKey;
- (int)overheadLength;

- (NSData *)decryptData:(nonnull NSData *)data offset:(NSInteger)offset packetId:(uint32_t)packetId error:(NSError **)error;
- (BOOL)decryptBytes:(nonnull const uint8_t *)bytes length:(int)length dest:(nonnull uint8_t *)dest destLength:(nonnull int *)destLength packetId:(uint32_t)packetId error:(NSError **)error;

// DataPath
- (BOOL)decryptDataPacket:(NSData *)packet into:(nonnull uint8_t *)dest length:(nonnull int *)length packetId:(nonnull uint32_t *)packetId error:(NSError **)error;
- (uint8_t *)parsePayloadWithDataPacket:(nonnull uint8_t *)packet packetLength:(int)packetLength length:(nonnull int *)length compression:(nonnull uint8_t *)compression;

@end
