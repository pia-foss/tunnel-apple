//
//  DataPath.h
//  PIATunnel
//
//  Created by Davide De Rosa on 3/2/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol DataPathEncrypter;
@protocol DataPathDecrypter;

// send/receive should be mutually thread-safe

@interface DataPath : NSObject

@property (nonatomic, assign) uint32_t maxPacketId;

- (instancetype)initWithEncrypter:(id<DataPathEncrypter>)encrypter
                        decrypter:(id<DataPathDecrypter>)decrypter
                       maxPackets:(NSInteger)maxPackets
             usesReplayProtection:(BOOL)usesReplayProtection;

- (void)setPeerId:(uint32_t)peerId; // 24-bit, discard most significant byte

- (NSArray<NSData *> *)encryptPackets:(nonnull NSArray<NSData *> *)packets key:(uint8_t)key error:(NSError **)error;
- (NSArray<NSData *> *)decryptPackets:(nonnull NSArray<NSData *> *)packets keepAlive:(nullable bool *)keepAlive error:(NSError **)error;

@end
