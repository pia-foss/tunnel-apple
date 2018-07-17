//
//  CryptoAEAD.h
//  PIATunnel
//
//  Created by Davide De Rosa on 06/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "Encryption.h"
#import "DataPathEncryption.h"

NS_ASSUME_NONNULL_BEGIN

@interface CryptoAEAD : NSObject <Encrypter, Decrypter>

@property (nonatomic, assign) int extraLength;

- (instancetype)initWithCipherName:(nonnull NSString *)cipherName;

@end

@interface DataPathCryptoAEAD : NSObject <DataPathEncrypter, DataPathDecrypter>

@property (nonatomic, assign) uint32_t peerId;

- (instancetype)initWithCrypto:(nonnull CryptoAEAD *)crypto;

@end

NS_ASSUME_NONNULL_END
