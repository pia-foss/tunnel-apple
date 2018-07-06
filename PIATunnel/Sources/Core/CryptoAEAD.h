//
//  CryptoAEAD.h
//  PIATunnel
//
//  Created by Davide De Rosa on 06/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "Encryption.h"

NS_ASSUME_NONNULL_BEGIN

@interface CryptoAEAD : NSObject <Encrypter, Decrypter>

- (instancetype)initWithCipherName:(nonnull NSString *)cipherName;

@end

NS_ASSUME_NONNULL_END
