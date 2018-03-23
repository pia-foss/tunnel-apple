//
//  CryptoBox.m
//  PIATunnel
//
//  Created by Davide De Rosa on 2/4/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <openssl/evp.h>
#import <openssl/hmac.h>
#import <openssl/rand.h>

#import "CryptoBox.h"
#import "Allocation.h"
#import "Errors.h"

const NSInteger CryptoBoxMaxHMACLength = 100;

@interface CryptoBoxEncrypter : NSObject <Encrypter>

@property (nonatomic, strong) CryptoBox *box;

@end

@implementation CryptoBoxEncrypter

- (instancetype)initWithBox:(CryptoBox *)box
{
    if ((self = [super init])) {
        self.box = box;
    }
    return self;
}

#pragma mark Encrypter

- (int)overheadLength
{
    return self.box.overheadLength;
}

- (NSData *)encryptData:(NSData *)data offset:(NSInteger)offset error:(NSError *__autoreleasing *)error
{
    return [self.box encryptData:data offset:offset error:error];
}

- (int)encryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest error:(NSError *__autoreleasing *)error
{
    return [self.box encryptBytes:bytes length:length dest:dest error:error];
}

@end

#pragma mark -

@interface CryptoBoxDecrypter : NSObject <Decrypter>

@property (nonatomic, strong) CryptoBox *box;

@end

@implementation CryptoBoxDecrypter

- (instancetype)initWithBox:(CryptoBox *)box
{
    if ((self = [super init])) {
        self.box = box;
    }
    return self;
}

#pragma mark Decrypter

- (int)overheadLength
{
    return self.box.overheadLength;
}

- (NSData *)decryptData:(NSData *)data offset:(NSInteger)offset error:(NSError *__autoreleasing *)error
{
    return [self.box decryptData:data offset:offset error:error];
}

- (int)decryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest error:(NSError *__autoreleasing *)error
{
    return [self.box decryptBytes:bytes length:length dest:dest error:error];
}

@end

#pragma mark -

void CryptoBoxEraseBytesSecurely(uint8_t *bytes, int length)
{
    memset(bytes, 0, length);
}

@interface CryptoBox ()

@property (nonatomic, strong) NSString *cipherAlgorithm;
@property (nonatomic, strong) NSString *digestAlgorithm;

@property (nonatomic, assign) BOOL isConfigured;
@property (nonatomic, unsafe_unretained) EVP_CIPHER_CTX *cipherCtxEnc;
@property (nonatomic, unsafe_unretained) EVP_CIPHER_CTX *cipherCtxDec;
@property (nonatomic, unsafe_unretained) HMAC_CTX *hmacCtxEnc;
@property (nonatomic, unsafe_unretained) HMAC_CTX *hmacCtxDec;
@property (nonatomic, assign) int cipherKeyLength;
@property (nonatomic, assign) int cipherIVLength;
@property (nonatomic, assign) int digestLength;
@property (nonatomic, assign) int overheadLength;

@property (nonatomic, unsafe_unretained) uint8_t *bufferDecHMAC;

@end

@implementation CryptoBox

+ (void)initialize
{
}

+ (BOOL)preparePRNGWithSeed:(const uint8_t *)seed length:(NSInteger)length
{
    unsigned char x[1];
    // make sure its initialized before seeding
    if (RAND_bytes(x, 1) != 1) {
        return NO;
    }
    RAND_seed(seed, (int)length);
    return YES;
}

- (instancetype)initWithCipherAlgorithm:(NSString *)cipherAlgorithm digestAlgorithm:(NSString *)digestAlgorithm
{
    NSParameterAssert(cipherAlgorithm);
    NSParameterAssert(digestAlgorithm);
    
    if ((self = [super init])) {
        self.cipherAlgorithm = cipherAlgorithm;
        self.digestAlgorithm = digestAlgorithm;

        self.cipherCtxEnc = EVP_CIPHER_CTX_new();
        self.cipherCtxDec = EVP_CIPHER_CTX_new();
        self.hmacCtxEnc = HMAC_CTX_new();
        self.hmacCtxDec = HMAC_CTX_new();
        self.bufferDecHMAC = allocate_safely(CryptoBoxMaxHMACLength);
    }
    return self;
}

- (void)dealloc
{
    if (!self.isConfigured) {
        return;
    }

    EVP_CIPHER_CTX_free(self.cipherCtxEnc);
    EVP_CIPHER_CTX_free(self.cipherCtxDec);
    HMAC_CTX_free(self.hmacCtxEnc);
    HMAC_CTX_free(self.hmacCtxDec);

    bzero(self.bufferDecHMAC, CryptoBoxMaxHMACLength);
    free(self.bufferDecHMAC);
}

- (void)configureWithCipherEncKey:(const uint8_t *)cipherEncKey
                     cipherDecKey:(const uint8_t *)cipherDecKey
                       hmacEncKey:(const uint8_t *)hmacEncKey
                       hmacDecKey:(const uint8_t *)hmacDecKey
{
    NSParameterAssert(cipherEncKey);
    NSParameterAssert(cipherDecKey);
    NSParameterAssert(hmacEncKey);
    NSParameterAssert(hmacDecKey);

    const EVP_CIPHER *cipher = EVP_get_cipherbyname([self.cipherAlgorithm cStringUsingEncoding:NSASCIIStringEncoding]);
    const EVP_MD *digest = EVP_get_digestbyname([self.digestAlgorithm cStringUsingEncoding:NSASCIIStringEncoding]);
    
    self.cipherKeyLength = EVP_CIPHER_key_length(cipher);
    self.cipherIVLength = EVP_CIPHER_iv_length(cipher);
    self.digestLength = EVP_MD_size(digest);
    self.overheadLength = self.cipherIVLength + self.digestLength;
    
    EVP_CIPHER_CTX_reset(self.cipherCtxEnc);
    EVP_CIPHER_CTX_reset(self.cipherCtxDec);
    EVP_CipherInit(self.cipherCtxEnc, cipher, cipherEncKey, NULL, 1);
    EVP_CipherInit(self.cipherCtxDec, cipher, cipherDecKey, NULL, 0);
    
    HMAC_CTX_reset(self.hmacCtxEnc);
    HMAC_CTX_reset(self.hmacCtxDec);
    HMAC_Init_ex(self.hmacCtxEnc, hmacEncKey, self.digestLength, digest, NULL);
    HMAC_Init_ex(self.hmacCtxDec, hmacDecKey, self.digestLength, digest, NULL);

    self.isConfigured = YES;
}

- (NSData *)encryptData:(NSData *)data offset:(NSInteger)offset error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(data);
    
    const uint8_t *bytes = data.bytes + offset;
    const int length = (int)(data.length - offset);
    const int maxOutputSize = (int)safe_crypto_capacity(data.length, self.overheadLength);

    NSMutableData *dest = [[NSMutableData alloc] initWithLength:maxOutputSize];
    const int encryptedLength = [self encryptBytes:bytes length:length dest:dest.mutableBytes error:error];
    if (encryptedLength < 0) {
        return nil;
    }
    dest.length = encryptedLength;
    return dest;
}

- (int)encryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest error:(NSError *__autoreleasing *)error
{
    uint8_t *outIV = dest + self.digestLength;
    uint8_t *outEncrypted = dest + self.digestLength + self.cipherIVLength;
    int l1, l2;
    unsigned int l3;
    
    if (RAND_bytes(outIV, self.cipherIVLength) != 1) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeCryptoBoxRandomGenerator);
        }
        return -1;
    }

    EVP_CipherInit(self.cipherCtxEnc, NULL, NULL, outIV, -1);
    EVP_CipherUpdate(self.cipherCtxEnc, outEncrypted, &l1, bytes, length);
    EVP_CipherFinal(self.cipherCtxEnc, &outEncrypted[l1], &l2);
    
    HMAC_Init_ex(self.hmacCtxEnc, NULL, 0, NULL, NULL);
    HMAC_Update(self.hmacCtxEnc, outIV, l1 + l2 + self.cipherIVLength);
    HMAC_Final(self.hmacCtxEnc, dest, &l3);
    
    return l1 + l2 + self.cipherIVLength + self.digestLength;
}

- (NSData *)decryptData:(NSData *)data offset:(NSInteger)offset error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(data);
    
    const uint8_t *bytes = data.bytes + offset;
    const int length = (int)(data.length - offset);
    const int maxOutputSize = (int)safe_crypto_capacity(data.length, self.overheadLength);

    NSMutableData *dest = [[NSMutableData alloc] initWithLength:maxOutputSize];
    const int decryptedLength = [self decryptBytes:bytes length:length dest:dest.mutableBytes error:error];
    if (decryptedLength < 0) {
        return nil;
    }
    dest.length = decryptedLength;
    return dest;
}

- (int)decryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest error:(NSError *__autoreleasing *)error
{
    const uint8_t *iv = bytes + self.digestLength;
    const uint8_t *encrypted = bytes + self.digestLength + self.cipherIVLength;
    unsigned int l1, l2;
    
    HMAC_Init_ex(self.hmacCtxDec, NULL, 0, NULL, NULL);
    HMAC_Update(self.hmacCtxDec, bytes + self.digestLength, length - self.digestLength);
    HMAC_Final(self.hmacCtxDec, self.bufferDecHMAC, &l1);

    if (CRYPTO_memcmp(self.bufferDecHMAC, bytes, self.digestLength) != 0) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeCryptoBoxHMAC);
        }
        return -1;
    }
    
    EVP_CipherInit(self.cipherCtxDec, NULL, NULL, iv, -1);
    EVP_CipherUpdate(self.cipherCtxDec, dest, (int *)&l1, encrypted, (int)(length - self.digestLength - self.cipherIVLength));
    EVP_CipherFinal(self.cipherCtxDec, dest + l1, (int *)&l2);
    
    return l1 + l2;
}

+ (void)hmacWithDigestName:(NSString *)digestName
                    secret:(const uint8_t *)secret
              secretLength:(NSInteger)secretLength
                      data:(const uint8_t *)data
                dataLength:(NSInteger)dataLength
                      hmac:(uint8_t *)hmac
                hmacLength:(NSInteger *)hmacLength
{
    NSParameterAssert(digestName);
    NSParameterAssert(secret);
    NSParameterAssert(data);
    
    unsigned int l;

    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_CTX_reset(ctx);
    HMAC_Init_ex(ctx, secret, (int)secretLength, EVP_get_digestbyname([digestName cStringUsingEncoding:NSASCIIStringEncoding]), NULL);
    HMAC_Update(ctx, data, dataLength);
    HMAC_Final(ctx, hmac, &l);
    HMAC_CTX_free(ctx);
    
    *hmacLength = l;
}

- (id<Encrypter>)encrypter
{
    return [[CryptoBoxEncrypter alloc] initWithBox:self];
}

- (id<Decrypter>)decrypter
{
    return [[CryptoBoxDecrypter alloc] initWithBox:self];
}

@end
