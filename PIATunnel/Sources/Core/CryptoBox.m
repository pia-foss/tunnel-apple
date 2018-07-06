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
#import "CryptoMacros.h"
#import "Allocation.h"
#import "Errors.h"

#import "CryptoCBC.h"

@interface CryptoBox ()

@property (nonatomic, strong) NSString *cipherAlgorithm;
@property (nonatomic, strong) NSString *digestAlgorithm;

@property (nonatomic, strong) id<Encrypter> encrypter;
@property (nonatomic, strong) id<Decrypter> decrypter;

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
//    NSParameterAssert(digestAlgorithm);
    
    if ((self = [super init])) {
        self.cipherAlgorithm = cipherAlgorithm;
        self.digestAlgorithm = digestAlgorithm;
    }
    return self;
}

- (void)dealloc
{
    self.encrypter = nil;
    self.decrypter = nil;
}

// these keys are coming from the OpenVPN negotiation despite the cipher
- (BOOL)configureWithCipherEncKey:(const uint8_t *)cipherEncKey
                     cipherDecKey:(const uint8_t *)cipherDecKey
                       hmacEncKey:(const uint8_t *)hmacEncKey
                       hmacDecKey:(const uint8_t *)hmacDecKey
                            error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(cipherEncKey);
    NSParameterAssert(cipherDecKey);
    NSParameterAssert(hmacEncKey);
    NSParameterAssert(hmacDecKey);

    if ([[self.cipherAlgorithm uppercaseString] hasSuffix:@"CBC"]) {
        if (!self.digestAlgorithm) {
            if (error) {
                *error = PIATunnelErrorWithCode(PIATunnelErrorCodeCryptoBoxAlgorithm);
            }
            return NO;
        }
        CryptoCBC *cbc = [[CryptoCBC alloc] initWithCipherName:self.cipherAlgorithm digestName:self.digestAlgorithm];
        self.encrypter = cbc;
        self.decrypter = cbc;
    }
    else if ([[self.cipherAlgorithm uppercaseString] hasSuffix:@"GCM"]) {
        // TODO: implement GCM
    }
    // not supported
    else {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeCryptoBoxAlgorithm);
        }
        return NO;
    }
    
    [self.encrypter configureEncryptionWithCipherKey:cipherEncKey hmacKey:hmacEncKey];
    [self.decrypter configureDecryptionWithCipherKey:cipherDecKey hmacKey:hmacDecKey];

    return YES;
}

+ (BOOL)hmacWithDigestName:(NSString *)digestName
                    secret:(const uint8_t *)secret
              secretLength:(NSInteger)secretLength
                      data:(const uint8_t *)data
                dataLength:(NSInteger)dataLength
                      hmac:(uint8_t *)hmac
                hmacLength:(NSInteger *)hmacLength
                     error:(NSError **)error
{
    NSParameterAssert(digestName);
    NSParameterAssert(secret);
    NSParameterAssert(data);
    
    unsigned int l = 0;
    int code = 1;

    HMAC_CTX *ctx = HMAC_CTX_new();
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_CTX_reset(ctx);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Init_ex(ctx, secret, (int)secretLength, EVP_get_digestbyname([digestName cStringUsingEncoding:NSASCIIStringEncoding]), NULL);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Update(ctx, data, dataLength);
    PIA_CRYPTO_TRACK_STATUS(code) HMAC_Final(ctx, hmac, &l);
    HMAC_CTX_free(ctx);
    
    *hmacLength = l;

    PIA_CRYPTO_RETURN_STATUS(code)
}

@end
