//
//  CryptoCBC.m
//  PIATunnel
//
//  Created by Davide De Rosa on 06/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <openssl/evp.h>
#import <openssl/hmac.h>
#import <openssl/rand.h>

#import "CryptoCBC.h"
#import "CryptoMacros.h"
#import "PacketMacros.h"
#import "Allocation.h"
#import "Errors.h"

const NSInteger CryptoCBCMaxHMACLength = 100;

@interface CryptoCBC ()

@property (nonatomic, unsafe_unretained) const EVP_CIPHER *cipher;
@property (nonatomic, unsafe_unretained) const EVP_MD *digest;
@property (nonatomic, assign) int cipherKeyLength;
@property (nonatomic, assign) int cipherIVLength;
@property (nonatomic, assign) int digestLength;
@property (nonatomic, assign) int overheadLength;

@property (nonatomic, unsafe_unretained) EVP_CIPHER_CTX *cipherCtxEnc;
@property (nonatomic, unsafe_unretained) EVP_CIPHER_CTX *cipherCtxDec;
@property (nonatomic, unsafe_unretained) HMAC_CTX *hmacCtxEnc;
@property (nonatomic, unsafe_unretained) HMAC_CTX *hmacCtxDec;
@property (nonatomic, unsafe_unretained) uint8_t *bufferDecHMAC;

@end

@implementation CryptoCBC

- (instancetype)initWithCipherName:(NSString *)cipherName digestName:(NSString *)digestName
{
    NSParameterAssert([[cipherName uppercaseString] hasSuffix:@"CBC"]);
    
    self = [super init];
    if (self) {
        self.cipher = EVP_get_cipherbyname([cipherName cStringUsingEncoding:NSASCIIStringEncoding]);
        NSAssert(self.cipher, @"Unknown cipher '%@'", cipherName);
        self.digest = EVP_get_digestbyname([digestName cStringUsingEncoding:NSASCIIStringEncoding]);
        NSAssert(self.digest, @"Unknown digest '%@'", digestName);

        self.cipherKeyLength = EVP_CIPHER_key_length(self.cipher);
        self.cipherIVLength = EVP_CIPHER_iv_length(self.cipher);
        self.digestLength = EVP_MD_size(self.digest);
        self.overheadLength = self.cipherIVLength + self.digestLength;

        self.cipherCtxEnc = EVP_CIPHER_CTX_new();
        self.cipherCtxDec = EVP_CIPHER_CTX_new();
        self.hmacCtxEnc = HMAC_CTX_new();
        self.hmacCtxDec = HMAC_CTX_new();
        self.bufferDecHMAC = allocate_safely(CryptoCBCMaxHMACLength);
    }
    return self;
}

- (void)dealloc
{
    EVP_CIPHER_CTX_free(self.cipherCtxEnc);
    EVP_CIPHER_CTX_free(self.cipherCtxDec);
    HMAC_CTX_free(self.hmacCtxEnc);
    HMAC_CTX_free(self.hmacCtxDec);
    bzero(self.bufferDecHMAC, CryptoCBCMaxHMACLength);
    free(self.bufferDecHMAC);
    
    self.cipher = NULL;
    self.digest = NULL;
}

#pragma mark Encrypter

- (void)configureEncryptionWithCipherKey:(ZeroingData *)cipherKey hmacKey:(ZeroingData *)hmacKey
{
    NSParameterAssert(cipherKey.count >= self.cipherKeyLength);

    EVP_CIPHER_CTX_reset(self.cipherCtxEnc);
    EVP_CipherInit(self.cipherCtxEnc, self.cipher, cipherKey.bytes, NULL, 1);

    HMAC_CTX_reset(self.hmacCtxEnc);
    HMAC_Init_ex(self.hmacCtxEnc, hmacKey.bytes, self.digestLength, self.digest, NULL);
}

- (NSData *)encryptData:(NSData *)data offset:(NSInteger)offset packetId:(uint32_t)packetId error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(data);
    
    const uint8_t *bytes = data.bytes + offset;
    const int length = (int)(data.length - offset);
    const int maxOutputSize = (int)safe_crypto_capacity(data.length, self.overheadLength);
    
    NSMutableData *dest = [[NSMutableData alloc] initWithLength:maxOutputSize];
    int encryptedLength = INT_MAX;
    if (![self encryptBytes:bytes length:length dest:dest.mutableBytes destLength:&encryptedLength packetId:packetId error:error]) {
        return nil;
    }
    dest.length = encryptedLength;
    return dest;
}

- (BOOL)encryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest destLength:(int *)destLength packetId:(uint32_t)packetId error:(NSError *__autoreleasing *)error
{
    uint8_t *outIV = dest + self.digestLength;
    uint8_t *outEncrypted = dest + self.digestLength + self.cipherIVLength;
    int l1 = 0, l2 = 0;
    unsigned int l3 = 0;
    int code = 1;
    
    if (RAND_bytes(outIV, self.cipherIVLength) != 1) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeCryptoBoxRandomGenerator);
        }
        return NO;
    }
    
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherInit(self.cipherCtxEnc, NULL, NULL, outIV, -1);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherUpdate(self.cipherCtxEnc, outEncrypted, &l1, bytes, length);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherFinal(self.cipherCtxEnc, outEncrypted + l1, &l2);
    
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Init_ex(self.hmacCtxEnc, NULL, 0, NULL, NULL);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Update(self.hmacCtxEnc, outIV, l1 + l2 + self.cipherIVLength);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Final(self.hmacCtxEnc, dest, &l3);
    
    *destLength = l1 + l2 + self.cipherIVLength + self.digestLength;
    
    PIA_CRYPTO_RETURN_STATUS(code)
}

- (id<DataPathEncrypter>)dataPathEncrypter
{
    return [[DataPathCryptoCBC alloc] initWithCrypto:self];
}

#pragma mark Decrypter

- (void)configureDecryptionWithCipherKey:(ZeroingData *)cipherKey hmacKey:(ZeroingData *)hmacKey
{
    NSParameterAssert(cipherKey.count >= self.cipherKeyLength);

    EVP_CIPHER_CTX_reset(self.cipherCtxDec);
    EVP_CipherInit(self.cipherCtxDec, self.cipher, cipherKey.bytes, NULL, 0);
    
    HMAC_CTX_reset(self.hmacCtxDec);
    HMAC_Init_ex(self.hmacCtxDec, hmacKey.bytes, self.digestLength, self.digest, NULL);
}

- (NSData *)decryptData:(NSData *)data offset:(NSInteger)offset packetId:(uint32_t)packetId error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(data);
    
    const uint8_t *bytes = data.bytes + offset;
    const int length = (int)(data.length - offset);
    const int maxOutputSize = (int)safe_crypto_capacity(data.length, self.overheadLength);
    
    NSMutableData *dest = [[NSMutableData alloc] initWithLength:maxOutputSize];
    int decryptedLength;
    if (![self decryptBytes:bytes length:length dest:dest.mutableBytes destLength:&decryptedLength packetId:packetId error:error]) {
        return nil;
    }
    dest.length = decryptedLength;
    return dest;
}

- (BOOL)decryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest destLength:(int *)destLength packetId:(uint32_t)packetId error:(NSError *__autoreleasing *)error
{
    const uint8_t *iv = bytes + self.digestLength;
    const uint8_t *encrypted = bytes + self.digestLength + self.cipherIVLength;
    int l1 = 0, l2 = 0;
    int code = 1;
    
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Init_ex(self.hmacCtxDec, NULL, 0, NULL, NULL);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Update(self.hmacCtxDec, bytes + self.digestLength, length - self.digestLength);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Final(self.hmacCtxDec, self.bufferDecHMAC, (unsigned *)&l1);
    
    if (PIA_CRYPTO_SUCCESS(code) && CRYPTO_memcmp(self.bufferDecHMAC, bytes, self.digestLength) != 0) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeCryptoBoxHMAC);
        }
        return NO;
    }
    
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherInit(self.cipherCtxDec, NULL, NULL, iv, -1);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherUpdate(self.cipherCtxDec, dest, &l1, encrypted, length - self.digestLength - self.cipherIVLength);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherFinal(self.cipherCtxDec, dest + l1, &l2);
    
    *destLength = l1 + l2;
    
    PIA_CRYPTO_RETURN_STATUS(code)
}

- (id<DataPathDecrypter>)dataPathDecrypter
{
    return [[DataPathCryptoCBC alloc] initWithCrypto:self];
}

@end

#pragma mark -

@interface DataPathCryptoCBC ()

@property (nonatomic, strong) CryptoCBC *crypto;
@property (nonatomic, assign) int headerLength;
@property (nonatomic, copy) void (^setDataHeader)(uint8_t *, uint8_t);
@property (nonatomic, copy) BOOL (^checkPeerId)(const uint8_t *);

@end

@implementation DataPathCryptoCBC

- (instancetype)initWithCrypto:(CryptoCBC *)crypto
{
    if ((self = [super init])) {
        self.crypto = crypto;
        self.peerId = PacketPeerIdDisabled;
    }
    return self;
}

- (int)overheadLength
{
    return self.crypto.overheadLength;
}

- (void)setPeerId:(uint32_t)peerId
{
    _peerId = peerId & 0xffffff;

    if (_peerId == PacketPeerIdDisabled) {
        self.headerLength = 1;
        self.setDataHeader = ^(uint8_t *to, uint8_t key) {
            PacketHeaderSet(to, PacketCodeDataV1, key);
        };
    }
    else {
        self.headerLength = 4;
        self.setDataHeader = ^(uint8_t *to, uint8_t key) {
            PacketHeaderSetDataV2(to, key, peerId);
        };
        self.checkPeerId = ^BOOL(const uint8_t *ptr) {
            return (PacketHeaderGetDataV2PeerId(ptr) == self.peerId);
        };
    }
}

#pragma mark DataPathEncrypter

- (void)assembleDataPacketWithPacketId:(uint32_t)packetId compression:(uint8_t)compression payload:(NSData *)payload into:(uint8_t *)dest length:(int *)length
{
    uint8_t *ptr = dest;
    *(uint32_t *)ptr = htonl(packetId);
    ptr += sizeof(uint32_t);
    *ptr = compression;
    ptr += sizeof(uint8_t);
    memcpy(ptr, payload.bytes, payload.length);
    *length = (int)(ptr - dest + payload.length);
}

- (NSData *)encryptedDataPacketWithKey:(uint8_t)key packetId:(uint32_t)packetId payload:(const uint8_t *)payload payloadLength:(int)payloadLength error:(NSError *__autoreleasing *)error
{
    const int capacity = self.headerLength + (int)safe_crypto_capacity(payloadLength, self.crypto.overheadLength);
    NSMutableData *encryptedPacket = [[NSMutableData alloc] initWithLength:capacity];
    uint8_t *ptr = encryptedPacket.mutableBytes;
    int encryptedPayloadLength = INT_MAX;
    const BOOL success = [self.crypto encryptBytes:payload
                                            length:payloadLength
                                              dest:(ptr + self.headerLength) // skip header byte
                                        destLength:&encryptedPayloadLength
                                          packetId:packetId
                                             error:error];
    
    NSAssert(encryptedPayloadLength <= capacity, @"Did not allocate enough bytes for payload");
    
    if (!success) {
        return nil;
    }

    self.setDataHeader(ptr, key);
    encryptedPacket.length = self.headerLength + encryptedPayloadLength;
    return encryptedPacket;
}

#pragma mark DataPathDecrypter

- (BOOL)decryptDataPacket:(NSData *)packet into:(uint8_t *)dest length:(int *)length packetId:(nonnull uint32_t *)packetId error:(NSError *__autoreleasing *)error
{
    // skip header = (code, key)
    const BOOL success = [self.crypto decryptBytes:(packet.bytes + self.headerLength)
                                            length:(int)(packet.length - self.headerLength)
                                              dest:dest
                                        destLength:length
                                          packetId:0   // ignored
                                             error:error];
    if (!success) {
        return NO;
    }
    if (self.checkPeerId && !self.checkPeerId(packet.bytes)) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeDataPathPeerIdMismatch);
        }
        return NO;
    }
    *packetId = ntohl(*(uint32_t *)dest);
    return YES;
}

- (uint8_t *)parsePayloadWithDataPacket:(uint8_t *)packet packetLength:(int)packetLength length:(int *)length compression:(uint8_t *)compression
{
    uint8_t *ptr = packet;
    ptr += sizeof(uint32_t); // packet id
    *compression = *ptr;
    ptr += sizeof(uint8_t); // compression byte
    *length = packetLength - (int)(ptr - packet);
    return ptr;
}

@end
