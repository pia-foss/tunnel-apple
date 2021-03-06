//
//  DataPath.m
//  PIATunnel
//
//  Created by Davide De Rosa on 3/2/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <arpa/inet.h>

#import "DataPath.h"
#import "DataPathEncryption.h"
#import "MSS.h"
#import "ReplayProtector.h"
#import "Allocation.h"
#import "Errors.h"

#define DataPathByteAlignment   16

@interface DataPath ()

@property (nonatomic, strong) id<DataPathEncrypter> encrypter;
@property (nonatomic, strong) id<DataPathDecrypter> decrypter;
@property (nonatomic, assign) int packetCapacity;

// outbound -> UDP
@property (nonatomic, strong) NSMutableArray *outPackets;
@property (nonatomic, assign) uint32_t outPacketId;
@property (nonatomic, unsafe_unretained) uint8_t *encBuffer;
@property (nonatomic, assign) int encBufferCapacity;

// inbound -> TUN
@property (nonatomic, strong) NSMutableArray *inPackets;
@property (nonatomic, strong) NSArray *inProtocols;
@property (nonatomic, unsafe_unretained) uint8_t *decBuffer;
@property (nonatomic, assign) int decBufferCapacity;
@property (nonatomic, strong) ReplayProtector *inReplay;

@end

@implementation DataPath

+ (uint8_t *)alignedPointer:(uint8_t *)pointer
{
    uint8_t *stack = pointer;
    uintptr_t addr = (uintptr_t)stack;
    if (addr % DataPathByteAlignment != 0) {
        addr += DataPathByteAlignment - addr % DataPathByteAlignment;
    }
    return (uint8_t *)addr;
}

- (instancetype)initWithEncrypter:(id<DataPathEncrypter>)encrypter decrypter:(id<DataPathDecrypter>)decrypter maxPackets:(NSInteger)maxPackets usesReplayProtection:(BOOL)usesReplayProtection
{
    NSParameterAssert(encrypter);
    NSParameterAssert(decrypter);
    NSParameterAssert(maxPackets > 0);
    
    if ((self = [super init])) {
        self.encrypter = encrypter;
        self.decrypter = decrypter;
        
        self.maxPacketId = UINT32_MAX - 10000;
        self.outPackets = [[NSMutableArray alloc] initWithCapacity:maxPackets];
        self.outPacketId = 0;
        self.encBufferCapacity = 65000;
        self.encBuffer = allocate_safely(self.encBufferCapacity);
        
        self.inPackets = [[NSMutableArray alloc] initWithCapacity:maxPackets];
        NSMutableArray *protocols = [[NSMutableArray alloc] initWithCapacity:maxPackets];
        for (NSUInteger i = 0; i < maxPackets; ++i) {
            [protocols addObject:@(AF_INET)];
        }
        self.inProtocols = protocols;
        self.decBufferCapacity = 65000;
        self.decBuffer = allocate_safely(self.decBufferCapacity);
        if (usesReplayProtection) {
            self.inReplay = [[ReplayProtector alloc] init];
        }
    }
    return self;
}

- (void)dealloc
{
    bzero(self.encBuffer, self.encBufferCapacity);
    bzero(self.decBuffer, self.decBufferCapacity);
    free(self.encBuffer);
    free(self.decBuffer);
}

- (void)adjustEncBufferToPacketSize:(int)size
{
    const int neededCapacity = DataPathByteAlignment + (int)safe_crypto_capacity(size, self.encrypter.overheadLength);
    if (self.encBufferCapacity >= neededCapacity) {
        return;
    }
    bzero(self.encBuffer, self.encBufferCapacity);
    free(self.encBuffer);
    self.encBufferCapacity = neededCapacity;
    self.encBuffer = allocate_safely(self.encBufferCapacity);
}

- (void)adjustDecBufferToPacketSize:(int)size
{
    const int neededCapacity = DataPathByteAlignment + (int)safe_crypto_capacity(size, self.decrypter.overheadLength);
    if (self.decBufferCapacity >= neededCapacity) {
        return;
    }
    bzero(self.decBuffer, self.decBufferCapacity);
    free(self.decBuffer);
    self.decBufferCapacity = neededCapacity;
    self.decBuffer = allocate_safely(self.decBufferCapacity);
}

- (uint8_t *)encBufferAligned
{
    return [[self class] alignedPointer:self.encBuffer];
}

- (uint8_t *)decBufferAligned
{
    return [[self class] alignedPointer:self.decBuffer];
}

- (void)setPeerId:(uint32_t)peerId
{
    NSAssert(self.encrypter, @"Setting peer-id to nil encrypter");
    NSAssert(self.decrypter, @"Setting peer-id to nil decrypter");

    [self.encrypter setPeerId:peerId];
    [self.decrypter setPeerId:peerId];
}

#pragma mark DataPath

- (NSArray<NSData *> *)encryptPackets:(NSArray<NSData *> *)packets key:(uint8_t)key error:(NSError *__autoreleasing *)error
{
    NSAssert(self.encrypter.peerId == self.decrypter.peerId, @"Peer-id mismatch in DataPath encrypter/decrypter");
    
    if (self.outPacketId > self.maxPacketId) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeDataPathOverflow);
        }
        return nil;
    }
    
    [self.outPackets removeAllObjects];
    
    for (NSData *raw in packets) {
        self.outPacketId += 1;
        
        // may resize encBuffer to hold encrypted payload
        [self adjustEncBufferToPacketSize:(int)raw.length];
        
        uint8_t *payload = self.encBufferAligned;
        NSInteger payloadLength;
        [self.encrypter assembleDataPacketWithPacketId:self.outPacketId
                                           compression:DataPacketCompressNone
                                               payload:raw
                                                  into:payload
                                                length:&payloadLength];
        MSSFix(payload, payloadLength);
        
        NSData *encryptedPacket = [self.encrypter encryptedDataPacketWithKey:key
                                                                    packetId:self.outPacketId
                                                                     payload:payload
                                                               payloadLength:payloadLength
                                                                       error:error];
        if (!encryptedPacket) {
            return nil;
        }
        
        [self.outPackets addObject:encryptedPacket];
    }
    
    return self.outPackets;
}

//- (NSArray<NSData *> *)decryptPackets:(NSArray<NSData *> *)packets error:(NSError *__autoreleasing *)error
- (NSArray<NSData *> *)decryptPackets:(NSArray<NSData *> *)packets keepAlive:(bool *)keepAlive error:(NSError *__autoreleasing *)error
{
    NSAssert(self.encrypter.peerId == self.decrypter.peerId, @"Peer-id mismatch in DataPath encrypter/decrypter");

    [self.inPackets removeAllObjects];
    
    for (NSData *encryptedPacket in packets) {
        
        // may resize decBuffer to encryptedPacket.length
        [self adjustDecBufferToPacketSize:(int)encryptedPacket.length];
        
        uint8_t *packet = self.decBufferAligned;
        NSInteger packetLength = INT_MAX;
        uint32_t packetId;
        const BOOL success = [self.decrypter decryptDataPacket:encryptedPacket
                                                          into:packet
                                                        length:&packetLength
                                                      packetId:&packetId
                                                         error:error];
        if (!success) {
            return nil;
        }
        if (packetId > self.maxPacketId) {
            if (error) {
                *error = PIATunnelErrorWithCode(PIATunnelErrorCodeDataPathOverflow);
            }
            return nil;
        }
        if (self.inReplay && [self.inReplay isReplayedPacketId:packetId]) {
            continue;
        }
        
        NSInteger payloadLength;
        uint8_t compression;
        const uint8_t *payload = [self.decrypter parsePayloadWithDataPacket:packet
                                                               packetLength:packetLength
                                                                     length:&payloadLength
                                                                compression:&compression];
        
        if ((payloadLength == sizeof(DataPacketPingData)) && !memcmp(payload, DataPacketPingData, payloadLength)) {
            if (keepAlive) {
                *keepAlive = true;
            }
            continue;
        }
        
//        MSSFix(payload, payloadLength);
        
        NSData *raw = [[NSData alloc] initWithBytes:payload length:payloadLength];
        [self.inPackets addObject:raw];
    }
    
    return self.inPackets;
}

@end
