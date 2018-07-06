//
//  CryptoAEAD.m
//  PIATunnel
//
//  Created by Davide De Rosa on 06/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import "CryptoAEAD.h"

@implementation CryptoAEAD

- (instancetype)initWithCipherName:(NSString *)cipherName
{
    return nil;
}

- (int)overheadLength
{
    return 0;
}

#pragma mark Encrypter

- (void)configureEncryptionWithCipherKey:(ZeroingData *)cipherKey hmacKey:(ZeroingData *)hmacKey
{
}

- (NSData *)encryptData:(NSData *)data offset:(NSInteger)offset packetId:(uint32_t)packetId error:(NSError *__autoreleasing *)error
{
    return nil;
}

- (BOOL)encryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest destLength:(int *)destLength packetId:(uint32_t)packetId error:(NSError *__autoreleasing *)error
{
    return NO;
}

#pragma mark Decrypter

- (void)configureDecryptionWithCipherKey:(ZeroingData *)cipherKey hmacKey:(ZeroingData *)hmacKey
{
}

- (NSData *)decryptData:(NSData *)data offset:(NSInteger)offset packetId:(uint32_t)packetId error:(NSError *__autoreleasing *)error
{
    return nil;
}

- (BOOL)decryptBytes:(const uint8_t *)bytes length:(int)length dest:(uint8_t *)dest destLength:(int *)destLength packetId:(uint32_t)packetId error:(NSError *__autoreleasing *)error
{
    return NO;
}

@end
