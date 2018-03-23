//
//  PointerBasedDataPath.m
//  PIATunnel
//
//  Created by Davide De Rosa on 3/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <arpa/inet.h>

#import "PointerBasedDataPath.h"
#import "MSS.h"
#import "ReplayProtector.h"
#import "Allocation.h"
#import "Errors.h"

static const uint8_t DataPathCodeDataV1         = 0x06;
static const uint8_t DataPathCodeNoCompress     = 0xfa;
static const uint8_t DataPathPingData[]         = { 0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48 };

#define DataPathByteAlignment   16

@interface PointerBasedDataPath ()

@property (nonatomic, strong) id<Encrypter> encrypter;
@property (nonatomic, strong) id<Decrypter> decrypter;
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

@implementation PointerBasedDataPath

+ (uint8_t *)alignedPointer:(uint8_t *)pointer
{
    uint8_t *stack = pointer;
    uintptr_t addr = (uintptr_t)stack;
    if (addr % DataPathByteAlignment != 0) {
        addr += DataPathByteAlignment - addr % DataPathByteAlignment;
    }
    return (uint8_t *)addr;
}

- (instancetype)initWithEncrypter:(id<Encrypter>)encrypter decrypter:(id<Decrypter>)decrypter maxPackets:(NSInteger)maxPackets usesReplayProtection:(BOOL)usesReplayProtection
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

#pragma mark DataPath

- (NSArray<NSData *> *)encryptPackets:(NSArray<NSData *> *)packets key:(uint8_t)key error:(NSError *__autoreleasing *)error
{
    if (self.outPacketId > self.maxPacketId) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeDataPathOverflow);
        }
        return nil;
    }
    
    [self.outPackets removeAllObjects];
    
    for (NSData *payload in packets) {
        self.outPacketId += 1;
        
        // may resize encBuffer to hold encrypted payload
        [self adjustEncBufferToPacketSize:(int)payload.length];

        uint8_t *decryptedPacketStart = self.encBufferAligned;
        uint8_t *decryptedPacketPtr = decryptedPacketStart;

        *(uint32_t *)decryptedPacketPtr = htonl(self.outPacketId);
        decryptedPacketPtr += sizeof(uint32_t);
        *decryptedPacketPtr = DataPathCodeNoCompress;
        decryptedPacketPtr += sizeof(uint8_t);
        memcpy(decryptedPacketPtr, payload.bytes, payload.length);
        const int decryptedPacketLength = (int)(decryptedPacketPtr - decryptedPacketStart + payload.length);
        MSSFix(decryptedPacketPtr, decryptedPacketLength);
        
        const int encryptedPacketCapacity = 1 + (int)safe_crypto_capacity(decryptedPacketLength, self.encrypter.overheadLength);
        NSMutableData *encryptedPacket = [[NSMutableData alloc] initWithLength:encryptedPacketCapacity];
        uint8_t *encryptedPacketPtr = encryptedPacket.mutableBytes;
        const int encryptedPayloadLength = [self.encrypter encryptBytes:decryptedPacketStart
                                                                 length:decryptedPacketLength
                                                                   dest:(encryptedPacketPtr + 1) // skip header byte
                                                                  error:error];

        NSAssert(encryptedPayloadLength <= encryptedPacketCapacity, @"Did not allocate enough bytes for payload");

        if (encryptedPayloadLength == -1) {
            return nil;
        }
        
        // set header byte
        *encryptedPacketPtr = (DataPathCodeDataV1 << 3 | (key & 0b111));
        encryptedPacket.length = 1 + encryptedPayloadLength;
        
        [self.outPackets addObject:encryptedPacket];
    }
    
    return self.outPackets;
}

- (NSArray<NSData *> *)decryptPackets:(NSArray<NSData *> *)packets error:(NSError *__autoreleasing *)error
{
    [self.inPackets removeAllObjects];
    
    for (NSData *encryptedPacket in packets) {
        
        // may resize decBuffer to encryptedPacket.length
        [self adjustDecBufferToPacketSize:(int)encryptedPacket.length];

        uint8_t *decryptedPacketStart = self.decBufferAligned;
        uint8_t *decryptedPacketPtr = decryptedPacketStart;

        // skip header byte = (code, key)
        const int decryptedPacketLength = [self.decrypter decryptBytes:(encryptedPacket.bytes + 1)
                                                                length:(int)(encryptedPacket.length - 1)
                                                                  dest:decryptedPacketStart
                                                                 error:error];
        if (decryptedPacketLength == -1) {
            return nil;
        }
        
        const uint32_t packetId = ntohl(*(uint32_t *)decryptedPacketPtr);
        decryptedPacketPtr += sizeof(uint32_t);
        
        if (packetId > self.maxPacketId) {
            if (error) {
                *error = PIATunnelErrorWithCode(PIATunnelErrorCodeDataPathOverflow);
            }
            return nil;
        }

        // skip compression byte
        decryptedPacketPtr += sizeof(uint8_t);
        
        if (self.inReplay && [self.inReplay isReplayedPacketId:packetId]) {
            continue;
        }
        
        uint8_t *payloadPtr = decryptedPacketPtr;
        const int payloadLength = decryptedPacketLength - (int)(decryptedPacketPtr - decryptedPacketStart);
        if ((payloadLength == sizeof(DataPathPingData)) && !memcmp(payloadPtr, DataPathPingData, payloadLength)) {
            continue;
        }
        MSSFix(payloadPtr, payloadLength);
        
        NSData *payload = [[NSData alloc] initWithBytes:payloadPtr length:payloadLength];
        [self.inPackets addObject:payload];
    }
    
    return self.inPackets;
}

@end
