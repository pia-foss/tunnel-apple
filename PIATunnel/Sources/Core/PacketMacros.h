//
//  PacketMacros.h
//  PIATunnel
//
//  Created by Davide De Rosa on 11/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

#define PacketHeaderLength          1
#define PacketHeaderDataV2Length    4
#define PacketIdLength              4

typedef NS_ENUM(uint8_t, PacketCode) {
    PacketCodeSoftResetV1           = 0x03,
    PacketCodeControlV1             = 0x04,
    PacketCodeAckV1                 = 0x05,
    PacketCodeDataV1                = 0x06,
    PacketCodeHardResetClientV2     = 0x07,
    PacketCodeHardResetServerV2     = 0x08,
    PacketCodeDataV2                = 0x09,
    PacketCodeUnknown               = 0xff
};

extern const uint8_t DataPacketCompressNone;
extern const uint8_t DataPacketPingData[16];

static inline int PacketHeaderSet(uint8_t *_Nonnull to, PacketCode code, uint8_t key)
{
    *(uint8_t *)to = (code << 3) | (key & 0b111);
    return sizeof(uint8_t);
}

// Ruby: header
static inline NSData *_Nonnull PacketWithHeader(PacketCode code, uint8_t key, NSData *sessionId)
{
    NSMutableData *to = [[NSMutableData alloc] initWithLength:(PacketHeaderLength + (sessionId ? sessionId.length : 0))];
    const int offset = PacketHeaderSet(to.mutableBytes, code, key);
    if (sessionId) {
        memcpy(to.mutableBytes + offset, sessionId.bytes, sessionId.length);
    }
    return to;
}

static inline int PacketHeaderSetDataV2(uint8_t *_Nonnull to, uint8_t key, uint32_t peerId)
{
    *(uint32_t *)to = ((PacketCodeDataV2 << 3) | (key & 0b111)) | htonl(peerId & 0xffffff);
    return sizeof(uint32_t);
}

static inline int PacketHeaderGetDataV2PeerId(const uint8_t *_Nonnull from)
{
    return ntohl(*(const uint32_t *)from & 0xffffff00);
}

static inline NSData *_Nonnull PacketWithHeaderDataV2(uint8_t key, uint32_t peerId, NSData *sessionId)
{
    NSMutableData *to = [[NSMutableData alloc] initWithLength:(PacketHeaderDataV2Length + (sessionId ? sessionId.length : 0))];
    const int offset = PacketHeaderSetDataV2(to.mutableBytes, key, peerId);
    if (sessionId) {
        memcpy(to.mutableBytes + offset, sessionId.bytes, sessionId.length);
    }
    return to;
}
