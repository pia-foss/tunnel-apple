//
//  PacketMacros.h
//  PIATunnel
//
//  Created by Davide De Rosa on 11/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

#define PacketHeaderLength      1
#define PacketIdLength          4

typedef NS_ENUM(uint8_t, PacketCode) {
    PacketCodeSoftResetV1           = 0x03,
    PacketCodeControlV1             = 0x04,
    PacketCodeAckV1                 = 0x05,
    PacketCodeDataV1                = 0x06,
    PacketCodeHardResetClientV2     = 0x07,
    PacketCodeHardResetServerV2     = 0x08,
    PacketCodeUnknown               = 0xff
};

extern const uint8_t DataPacketCompressNone;
extern const uint8_t DataPacketPingData[16];

// Ruby: header
static inline NSData *_Nonnull PacketWithHeader(PacketCode code, uint8_t key, NSData *sessionId)
{
    NSMutableData *to = [[NSMutableData alloc] initWithLength:(1 + (sessionId ? sessionId.length : 0))];
    *(uint8_t *)to.mutableBytes = (code << 3) | (key & 0b111);
    if (sessionId) {
        memcpy(to.mutableBytes + 1, sessionId.bytes, sessionId.length);
    }
    return to;
}
