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

    PIA_CRYPTO_RETURN_STATUS(code)
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

    PIA_CRYPTO_RETURN_STATUS(code)
}

#pragma mark Helpers

- (void)prepareIV:(uint8_t *)iv withHMACKey:(ZeroingData *)hmacKey
{
    bzero(iv, CryptoAEADADLength);
    memcpy(iv + CryptoAEADADLength, hmacKey.bytes, self.cipherIVLength - CryptoAEADADLength);
}

@end
