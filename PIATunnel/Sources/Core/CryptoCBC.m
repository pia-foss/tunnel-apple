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
        self.digest = EVP_get_digestbyname([digestName cStringUsingEncoding:NSASCIIStringEncoding]);
        
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

- (void)configureEncryptionWithCipherKey:(const uint8_t *)cipherKey hmacKey:(const uint8_t *)hmacKey
{
    EVP_CIPHER_CTX_reset(self.cipherCtxEnc);
    EVP_CipherInit(self.cipherCtxEnc, self.cipher, cipherKey, NULL, 1);

    HMAC_CTX_reset(self.hmacCtxEnc);
    HMAC_Init_ex(self.hmacCtxEnc, hmacKey, self.digestLength, self.digest, NULL);
}

- (NSData *)encryptData:(NSData *)data offset:(NSInteger)offset error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(data);
    
    const uint8_t *bytes = data.bytes + offset;
    const int length = (int)(data.length - offset);
    const int maxOutputSize = (int)safe_crypto_capacity(data.length, self.overheadLength);
    
    NSMutableData *dest = [[NSMutableData alloc] initWithLength:maxOutputSize];
    int encryptedLength = INT_MAX;
    if (![self encryptBytes:bytes length:length dest:dest.mutableBytes destLength:&encryptedLength error:error]) {
        return nil;
    }
    dest.length = encryptedLength;
    return dest;
}

- (BOOL)encryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest destLength:(int *)destLength error:(NSError *__autoreleasing *)error
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
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherFinal(self.cipherCtxEnc, &outEncrypted[l1], &l2);
    
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Init_ex(self.hmacCtxEnc, NULL, 0, NULL, NULL);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Update(self.hmacCtxEnc, outIV, l1 + l2 + self.cipherIVLength);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Final(self.hmacCtxEnc, dest, &l3);
    
    *destLength = l1 + l2 + self.cipherIVLength + self.digestLength;
    
    PIA_CRYPTO_RETURN_STATUS(code)
}

#pragma mark Decrypter

- (void)configureDecryptionWithCipherKey:(const uint8_t *)cipherKey hmacKey:(const uint8_t *)hmacKey
{
    EVP_CIPHER_CTX_reset(self.cipherCtxDec);
    EVP_CipherInit(self.cipherCtxDec, self.cipher, cipherKey, NULL, 0);
    
    HMAC_CTX_reset(self.hmacCtxDec);
    HMAC_Init_ex(self.hmacCtxDec, hmacKey, self.digestLength, self.digest, NULL);
}

- (NSData *)decryptData:(NSData *)data offset:(NSInteger)offset error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(data);
    
    const uint8_t *bytes = data.bytes + offset;
    const int length = (int)(data.length - offset);
    const int maxOutputSize = (int)safe_crypto_capacity(data.length, self.overheadLength);
    
    NSMutableData *dest = [[NSMutableData alloc] initWithLength:maxOutputSize];
    int decryptedLength;
    if (![self decryptBytes:bytes length:length dest:dest.mutableBytes destLength:&decryptedLength error:error]) {
        return nil;
    }
    dest.length = decryptedLength;
    return dest;
}

- (BOOL)decryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest destLength:(int *)destLength error:(NSError *__autoreleasing *)error
{
    const uint8_t *iv = bytes + self.digestLength;
    const uint8_t *encrypted = bytes + self.digestLength + self.cipherIVLength;
    unsigned int l1 = 0, l2 = 0;
    int code = 1;
    
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Init_ex(self.hmacCtxDec, NULL, 0, NULL, NULL);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Update(self.hmacCtxDec, bytes + self.digestLength, length - self.digestLength);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Final(self.hmacCtxDec, self.bufferDecHMAC, &l1);
    
    if (PIA_CRYPTO_SUCCESS(code) && CRYPTO_memcmp(self.bufferDecHMAC, bytes, self.digestLength) != 0) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeCryptoBoxHMAC);
        }
        return NO;
    }
    
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherInit(self.cipherCtxDec, NULL, NULL, iv, -1);
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherUpdate(self.cipherCtxDec, dest, (int *)&l1, encrypted, (int)(length - self.digestLength - self.cipherIVLength));
    PIA_CRYPTO_TRACK_STATUS(code) EVP_CipherFinal(self.cipherCtxDec, dest + l1, (int *)&l2);
    
    *destLength = l1 + l2;
    
    PIA_CRYPTO_RETURN_STATUS(code)
}

@end
