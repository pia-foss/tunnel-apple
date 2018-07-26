//
//  TLSBox.m
//  PIATunnel
//
//  Created by Davide De Rosa on 2/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <openssl/ssl.h>
#import <openssl/err.h>
#import <openssl/evp.h>

#import "TLSBox.h"
#import "Allocation.h"
#import "Errors.h"

const NSInteger TLSBoxMaxBufferLength = 16384;

NSString *const TLSBoxPeerVerificationErrorNotification = @"TLSBoxPeerVerificationErrorNotification";

static BOOL TLSBoxIsOpenSSLLoaded;

int TLSBoxVerifyPeer(int ok, X509_STORE_CTX *ctx) {
    if (!ok) {
        [[NSNotificationCenter defaultCenter] postNotificationName:TLSBoxPeerVerificationErrorNotification object:nil];
    }
    return ok;
}

@interface TLSBox ()

@property (nonatomic, strong) NSString *caPath;
@property (nonatomic, strong) NSString *certPath;
@property (nonatomic, strong) NSString *keyPath;

@property (nonatomic, assign) BOOL isConnected;

@property (nonatomic, unsafe_unretained) SSL_CTX *ctx;
@property (nonatomic, unsafe_unretained) SSL *ssl;
@property (nonatomic, unsafe_unretained) BIO *bioPlainText;
@property (nonatomic, unsafe_unretained) BIO *bioCipherTextIn;
@property (nonatomic, unsafe_unretained) BIO *bioCipherTextOut;

@property (nonatomic, unsafe_unretained) uint8_t *bufferCipherText;

@end

@implementation TLSBox

- (instancetype)init
{
    if((self = [super init])) {
        self.bufferCipherText = allocate_safely(TLSBoxMaxBufferLength);
    }
    
    return self;
}

- (instancetype)initWithCAPath:(NSString *)caPath certPath:(NSString *) certPath_ keyPath:(NSString *) keyPath_
{
    if ((self = [super init])) {
        self.caPath = caPath;
        self.certPath = certPath_;
        self.keyPath = keyPath_;
        self.bufferCipherText = allocate_safely(TLSBoxMaxBufferLength);
    }
    return self;
}

- (void)dealloc
{
    if (!self.ctx) {
        return;
    }

    BIO_free_all(self.bioPlainText);
    SSL_free(self.ssl);
    SSL_CTX_free(self.ctx);
    self.isConnected = NO;
    self.ctx = NULL;

    bzero(self.bufferCipherText, TLSBoxMaxBufferLength);
    free(self.bufferCipherText);
}

- (BOOL)startWithPeerVerification:(BOOL)peerVerification error:(NSError *__autoreleasing *)error
{
    if (!TLSBoxIsOpenSSLLoaded) {
//        OPENSSL_init_ssl(0, NULL);

        TLSBoxIsOpenSSLLoaded = YES;
    }
    
    self.ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_options(self.ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_COMPRESSION);
    if (peerVerification && self.caPath) {
        SSL_CTX_set_verify(self.ctx, SSL_VERIFY_PEER, TLSBoxVerifyPeer);
        if (!SSL_CTX_load_verify_locations(self.ctx, [self.caPath cStringUsingEncoding:NSASCIIStringEncoding], NULL)) {
            ERR_print_errors_fp(stdout);
            if (error) {
                *error = PIATunnelErrorWithCode(PIATunnelErrorCodeTLSBoxCA);
            }
            return NO;
        }
        
        if(!SSL_CTX_use_certificate_file(self.ctx, [self.certPath cStringUsingEncoding:NSASCIIStringEncoding], SSL_FILETYPE_PEM)) {
            ERR_print_errors_fp(stdout);
            if (error) {
                *error = PIATunnelErrorWithCode(PIATunnelErrorCodeTLSBoxCA);
            }
            return NO;
        }
        if(!SSL_CTX_use_PrivateKey_file(self.ctx, [self.keyPath cStringUsingEncoding:NSASCIIStringEncoding], SSL_FILETYPE_PEM)) {
            ERR_print_errors_fp(stdout);
            if (error) {
                *error = PIATunnelErrorWithCode(PIATunnelErrorCodeTLSBoxCA);
            }
            return NO;
        }
    }
    else {
        SSL_CTX_set_verify(self.ctx, SSL_VERIFY_NONE, NULL);
    }
    SSL_CTX_set1_curves_list(self.ctx, "X25519:prime256v1:secp521r1:secp384r1:secp256k1");

    self.ssl = SSL_new(self.ctx);
    
    self.bioPlainText = BIO_new(BIO_f_ssl());
    self.bioCipherTextIn  = BIO_new(BIO_s_mem());
    self.bioCipherTextOut = BIO_new(BIO_s_mem());
    
    SSL_set_connect_state(self.ssl);
    
    SSL_set_bio(self.ssl, self.bioCipherTextIn, self.bioCipherTextOut);
    BIO_set_ssl(self.bioPlainText, self.ssl, BIO_NOCLOSE);
    
    if (!SSL_do_handshake(self.ssl)) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeTLSBoxHandshake);
        }
        return NO;
    }
    return YES;
}

#pragma mark Pull

- (NSData *)pullCipherTextWithError:(NSError *__autoreleasing *)error
{
    if (!self.isConnected && !SSL_is_init_finished(self.ssl)) {
        SSL_do_handshake(self.ssl);
    }
    const int ret = BIO_read(self.bioCipherTextOut, self.bufferCipherText, TLSBoxMaxBufferLength);
    if (!self.isConnected && SSL_is_init_finished(self.ssl)) {
        self.isConnected = YES;
    }
    if (ret > 0) {
        return [NSData dataWithBytes:self.bufferCipherText length:ret];
    }
    if ((ret < 0) && !BIO_should_retry(self.bioCipherTextOut)) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeTLSBoxGeneric);
        }
    }
    return nil;
}

- (BOOL)pullRawPlainText:(uint8_t *)text length:(NSInteger *)length error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(text);
    NSParameterAssert(length);

    const int ret = BIO_read(self.bioPlainText, text, TLSBoxMaxBufferLength);
    if (ret > 0) {
        *length = ret;
        return YES;
    }
    if ((ret < 0) && !BIO_should_retry(self.bioPlainText)) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeTLSBoxGeneric);
        }
    }
    return NO;
}

#pragma mark Put

- (BOOL)putCipherText:(NSData *)text error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(text);
    
    return [self putRawCipherText:(const uint8_t *)text.bytes length:text.length error:error];
}

- (BOOL)putRawCipherText:(const uint8_t *)text length:(NSInteger)length error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(text);

    const int ret = BIO_write(self.bioCipherTextIn, text, (int)length);
    if (ret != length) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeTLSBoxGeneric);
        }
        return NO;
    }
    return YES;
}

- (BOOL)putPlainText:(NSString *)text error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(text);

    return [self putRawPlainText:(const uint8_t *)[text cStringUsingEncoding:NSASCIIStringEncoding] length:text.length error:error];
}

- (BOOL)putRawPlainText:(const uint8_t *)text length:(NSInteger)length error:(NSError *__autoreleasing *)error
{
    NSParameterAssert(text);

    const int ret = BIO_write(self.bioPlainText, text, (int)length);
    if (ret != length) {
        if (error) {
            *error = PIATunnelErrorWithCode(PIATunnelErrorCodeTLSBoxGeneric);
        }
        return NO;
    }
    return YES;
}

@end
