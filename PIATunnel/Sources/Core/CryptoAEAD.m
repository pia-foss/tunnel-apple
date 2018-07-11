//
//  CryptoAEAD.m
//  PIATunnel
//
//  Created by Davide De Rosa on 06/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <openssl/evp.h>
#import <openssl/hmac.h>
#import <openssl/rand.h>

#import "CryptoAEAD.h"
#import "CryptoMacros.h"
#import "Allocation.h"
#import "Errors.h"

const NSInteger CryptoAEADADLength      = 4; // packetId
const NSInteger CryptoAEADTagLength     = 16;

@interface CryptoAEAD ()

@property (nonatomic, unsafe_unretained) const EVP_CIPHER *cipher;
@property (nonatomic, assign) int cipherKeyLength;
@property (nonatomic, assign) int cipherIVLength; // 12 (AD packetId + HMAC key)
@property (nonatomic, assign) int overheadLength;

@property (nonatomic, unsafe_unretained) EVP_CIPHER_CTX *cipherCtxEnc;
@property (nonatomic, unsafe_unretained) EVP_CIPHER_CTX *cipherCtxDec;
@property (nonatomic, unsafe_unretained) uint8_t *cipherIVEnc;
@property (nonatomic, unsafe_unretained) uint8_t *cipherIVDec;

@end

@implementation CryptoAEAD

- (instancetype)initWithCipherName:(NSString *)cipherName
{
    NSParameterAssert([[cipherName uppercaseString] hasSuffix:@"GCM"]);
    
    self = [super init];
    if (self) {
        self.cipher = EVP_get_cipherbyname([cipherName cStringUsingEncoding:NSASCIIStringEncoding]);
        NSAssert(self.cipher, @"Unknown cipher '%@'", cipherName);
        
        self.cipherKeyLength = EVP_CIPHER_key_length(self.cipher);
        self.cipherIVLength = EVP_CIPHER_iv_length(self.cipher);
        self.overheadLength = CryptoAEADTagLength;
        
        self.cipherCtxEnc = EVP_CIPHER_CTX_new();
        self.cipherCtxDec = EVP_CIPHER_CTX_new();
        self.cipherIVEnc = allocate_safely(self.cipherIVLength);
        self.cipherIVDec = allocate_safely(self.cipherIVLength);
    }
    return self;
}

- (void)dealloc
{
    EVP_CIPHER_CTX_free(self.cipherCtxEnc);
    EVP_CIPHER_CTX_free(self.cipherCtxDec);
    bzero(self.cipherIVEnc, self.cipherIVLength);
    bzero(self.cipherIVDec, self.cipherIVLength);
    free(self.cipherIVEnc);
    free(self.cipherIVDec);

    self.cipher = NULL;
}

#pragma mark Encrypter

- (void)configureEncryptionWithCipherKey:(ZeroingData *)cipherKey hmacKey:(ZeroingData *)hmacKey
{
    NSParameterAssert(cipherKey.count >= self.cipherKeyLength);
    
    EVP_CIPHER_CTX_reset(self.cipherCtxEnc);
    EVP_CipherInit(self.cipherCtxEnc, self.cipher, cipherKey.bytes, NULL, 1);

    [self prepareIV:self.cipherIVEnc withHMACKey:hmacKey];
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
    int l1 = 0, l2 = 0;
    int x = 0;
    int code = 1;

    const uint8_t *ad = (const uint8_t *)&packetId;
    memcpy(self.cipherIVEnc, ad, CryptoAEADADLength);
    
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherInit(self.cipherCtxEnc, NULL, NULL, self.cipherIVEnc, -1);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherUpdate(self.cipherCtxEnc, NULL, &x, ad, CryptoAEADADLength);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherUpdate(self.cipherCtxEnc, dest + CryptoAEADTagLength, &l1, bytes, length);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherFinal(self.cipherCtxEnc, dest + CryptoAEADTagLength + l1, &l2);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CIPHER_CTX_ctrl(self.cipherCtxEnc, EVP_CTRL_GCM_GET_TAG, CryptoAEADTagLength, dest);

    *destLength = CryptoAEADTagLength + l1 + l2;

//    NSLog(@">>> ENC iv: %@", [NSData dataWithBytes:self.cipherIVEnc length:self.cipherIVLength]);
//    NSLog(@">>> ENC ad: %@", [NSData dataWithBytes:ad length:4]);
//    NSLog(@">>> ENC tag: %@", [NSData dataWithBytes:dest length:CryptoAEADTagLength]);
//    NSLog(@">>> ENC dest: %@", [NSData dataWithBytes:dest + CryptoAEADTagLength length:*destLength - CryptoAEADTagLength]);

    PIA_CRYPTO_RETURN_STATUS(code)
}

- (void)assembleDataPacketWithPacketId:(uint32_t)packetId compression:(uint8_t)compression payload:(NSData *)payload into:(uint8_t *)dest length:(int *)length
{
    uint8_t *ptr = dest;
    *ptr = compression;
    ptr += sizeof(uint8_t);
    memcpy(ptr, payload.bytes, payload.length);
    *length = (int)(ptr - dest + payload.length);
}

- (NSData *)encryptedDataPacketWithHeader:(uint8_t)header packetId:(uint32_t)packetId payload:(const uint8_t *)payload payloadLength:(int)payloadLength error:(NSError *__autoreleasing *)error
{
    const int capacity = 5 + (int)safe_crypto_capacity(payloadLength, self.overheadLength);
    NSMutableData *encryptedPacket = [[NSMutableData alloc] initWithLength:capacity];
    uint8_t *ptr = encryptedPacket.mutableBytes;
    int encryptedPayloadLength = INT_MAX;
    const BOOL success = [self encryptBytes:payload
                                     length:payloadLength
                                       dest:(ptr + 5) // skip header and packet id
                                 destLength:&encryptedPayloadLength
                                   packetId:htonl(packetId)
                                      error:error];
    
    NSAssert(encryptedPayloadLength <= capacity, @"Did not allocate enough bytes for payload");
    
    if (!success) {
        return nil;
    }
    
    // set header byte
    *ptr = header;
    *(uint32_t *)(ptr + 1) = htonl(packetId);
    encryptedPacket.length = 5 + encryptedPayloadLength;
    return encryptedPacket;
}

#pragma mark Decrypter

- (void)configureDecryptionWithCipherKey:(ZeroingData *)cipherKey hmacKey:(ZeroingData *)hmacKey
{
    NSParameterAssert(cipherKey.count >= self.cipherKeyLength);
    
    EVP_CIPHER_CTX_reset(self.cipherCtxDec);
    EVP_CipherInit(self.cipherCtxDec, self.cipher, cipherKey.bytes, NULL, 0);
    
    [self prepareIV:self.cipherIVDec withHMACKey:hmacKey];
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
    int l1 = 0, l2 = 0;
    int x = 0;
    int code = 1;
    
    const uint8_t *ad = (const uint8_t *)&packetId;
    memcpy(self.cipherIVDec, ad, CryptoAEADADLength);

    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherInit(self.cipherCtxDec, NULL, NULL, self.cipherIVDec, -1);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CIPHER_CTX_ctrl(self.cipherCtxDec, EVP_CTRL_GCM_SET_TAG, CryptoAEADTagLength, (uint8_t *)bytes);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherUpdate(self.cipherCtxDec, NULL, &x, ad, CryptoAEADADLength);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherUpdate(self.cipherCtxDec, dest, &l1, bytes + CryptoAEADTagLength, length - CryptoAEADTagLength);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherFinal(self.cipherCtxDec, dest + l1, &l2);

    *destLength = l1 + l2;
    
//    NSLog(@">>> DEC iv: %@", [NSData dataWithBytes:self.cipherIVDec length:self.cipherIVLength]);
//    NSLog(@">>> DEC ad: %@", [NSData dataWithBytes:ad length:4]);
//    NSLog(@">>> DEC tag: %@", [NSData dataWithBytes:bytes length:CryptoAEADTagLength]);
//    NSLog(@">>> DEC dest: %@", [NSData dataWithBytes:dest length:*destLength]);

    PIA_CRYPTO_RETURN_STATUS(code)
}

- (BOOL)decryptDataPacket:(NSData *)packet into:(uint8_t *)dest length:(int *)length packetId:(uint32_t *)packetId error:(NSError *__autoreleasing *)error
{
    // associated data from packet id after header
    const uint32_t ad = *(const uint32_t *)(packet.bytes + 1);

    // skip header byte + packet id
    const BOOL success = [self decryptBytes:(packet.bytes + 5)
                                     length:(int)(packet.length - 5)
                                       dest:dest
                                 destLength:length
                                   packetId:ad
                                      error:error];
    if (!success) {
        return NO;
    }
    *packetId = ntohl(ad);
    return YES;
}

- (uint8_t *)parsePayloadWithDataPacket:(uint8_t *)packet packetLength:(int)packetLength length:(int *)length compression:(uint8_t *)compression
{
    uint8_t *ptr = packet;
    *compression = *ptr;
    ptr += sizeof(uint8_t); // compression byte
    *length = packetLength - (int)(ptr - packet);
    return ptr;
}

#pragma mark Helpers

- (void)prepareIV:(uint8_t *)iv withHMACKey:(ZeroingData *)hmacKey
{
    bzero(iv, CryptoAEADADLength);
    memcpy(iv + CryptoAEADADLength, hmacKey.bytes, self.cipherIVLength - CryptoAEADADLength);
}

@end
