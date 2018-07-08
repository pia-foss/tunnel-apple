//
//  ZeroingData.h
//  PIATunnel
//
//  Created by Davide De Rosa on 4/28/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ZeroingData : NSObject

@property (nonatomic, readonly) const uint8_t *bytes;
@property (nonatomic, readonly) uint8_t *mutableBytes;
@property (nonatomic, readonly) NSInteger count;

- (instancetype)initWithCount:(NSInteger)count;
- (instancetype)initWithBytes:(const uint8_t *)bytes count:(NSInteger)count;
- (instancetype)initWithUInt8:(uint8_t)uint8;
- (instancetype)initWithUInt16:(uint16_t)uint16;

- (instancetype)initWithData:(NSData *)data;
- (instancetype)initWithData:(NSData *)data offset:(NSInteger)offset count:(NSInteger)count;
- (instancetype)initWithString:(NSString *)string nullTerminated:(BOOL)nullTerminated;

- (void)appendData:(ZeroingData *)other;
//- (void)truncateToSize:(NSInteger)size;
- (void)removeUntilOffset:(NSInteger)until;
- (void)zero;

- (nonnull ZeroingData *)appendingData:(ZeroingData *)other;
- (nonnull ZeroingData *)withOffset:(NSInteger)offset count:(NSInteger)count;
- (uint16_t)UInt16ValueFromOffset:(NSInteger)from;
- (uint16_t)networkUInt16ValueFromOffset:(NSInteger)from;
- (NSString *)nullTerminatedStringFromOffset:(NSInteger)from;

- (BOOL)isEqualToData:(NSData *)data;
- (nonnull NSString *)toHex;

@end
