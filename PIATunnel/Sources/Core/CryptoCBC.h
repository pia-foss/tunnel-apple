//
//  CryptoCBC.h
//  PIATunnel
//
//  Created by Davide De Rosa on 06/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "Encryption.h"
#import "DataPathEncryption.h"

NS_ASSUME_NONNULL_BEGIN

@interface CryptoCBC : NSObject <Encrypter, Decrypter>

- (instancetype)initWithCipherName:(nonnull NSString *)cipherName
                        digestName:(nonnull NSString *)digestName;

@end

@interface DataPathCryptoCBC : NSObject <DataPathEncrypter, DataPathDecrypter>

- (instancetype)initWithCrypto:(nonnull CryptoCBC *)crypto;

@end

NS_ASSUME_NONNULL_END
