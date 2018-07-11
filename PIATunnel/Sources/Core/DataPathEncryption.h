//
//  DataPathEncryption.h
//  PIATunnel
//
//  Created by Davide De Rosa on 11/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol DataPathEncrypter

- (int)overheadLength;
- (void)setPeerId:(uint32_t)peerId;
- (void)assembleDataPacketWithPacketId:(uint32_t)packetId compression:(uint8_t)compression payload:(NSData *)payload into:(nonnull uint8_t *)dest length:(nonnull NSInteger *)length;
- (NSData *)encryptedDataPacketWithKey:(uint8_t)key packetId:(uint32_t)packetId payload:(const uint8_t *)payload payloadLength:(NSInteger)payloadLength error:(NSError **)error;

@end

@protocol DataPathDecrypter

- (int)overheadLength;
- (void)setPeerId:(uint32_t)peerId;
- (BOOL)decryptDataPacket:(nonnull NSData *)packet into:(nonnull uint8_t *)dest length:(nonnull NSInteger *)length packetId:(nonnull uint32_t *)packetId error:(NSError **)error;
- (nonnull const uint8_t *)parsePayloadWithDataPacket:(nonnull const uint8_t *)packet packetLength:(NSInteger)packetLength length:(nonnull NSInteger *)length compression:(nonnull uint8_t *)compression;

@end
