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
- (void)assembleDataPacketWithPacketId:(uint32_t)packetId compression:(uint8_t)compression payload:(NSData *)payload into:(nonnull uint8_t *)dest length:(nonnull int *)length;
- (NSData *)encryptedDataPacketWithKey:(uint8_t)key packetId:(uint32_t)packetId payload:(const uint8_t *)payload payloadLength:(int)payloadLength error:(NSError **)error;

@end

@protocol DataPathDecrypter

- (int)overheadLength;
- (void)setPeerId:(uint32_t)peerId;
- (BOOL)decryptDataPacket:(NSData *)packet into:(nonnull uint8_t *)dest length:(nonnull int *)length packetId:(nonnull uint32_t *)packetId error:(NSError **)error;
- (uint8_t *)parsePayloadWithDataPacket:(nonnull uint8_t *)packet packetLength:(int)packetLength length:(nonnull int *)length compression:(nonnull uint8_t *)compression;

@end
