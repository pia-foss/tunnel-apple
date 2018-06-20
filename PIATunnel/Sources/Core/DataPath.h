//
//  DataPath.h
//  PIATunnel
//
//  Created by Davide De Rosa on 3/2/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

// send/receive should be mutually thread-safe

@protocol DataPath

- (void)setMaxPacketId:(uint32_t)maxPacketId;

- (NSArray<NSData *> *)encryptPackets:(nonnull NSArray<NSData *> *)packets key:(uint8_t)key error:(NSError **)error;
- (NSArray<NSData *> *)decryptPackets:(nonnull NSArray<NSData *> *)packets keepAlive:(nonnull bool *)keepAlive error:(NSError **)error;

@end
