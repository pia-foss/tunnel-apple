//
//  PointerBasedDataPath.h
//  PIATunnel
//
//  Created by Davide De Rosa on 3/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "DataPath.h"
#import "Encryption.h"

@interface PointerBasedDataPath : NSObject <DataPath>

@property (nonatomic, assign) uint32_t maxPacketId;

- (instancetype)initWithEncrypter:(id<Encrypter>)encrypter
                        decrypter:(id<Decrypter>)decrypter
                       maxPackets:(NSInteger)maxPackets
             usesReplayProtection:(BOOL)usesReplayProtection;

@end
