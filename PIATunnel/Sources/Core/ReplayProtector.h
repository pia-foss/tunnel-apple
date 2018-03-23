//
//  ReplayProtector.h
//  PIATunnel
//
//  Created by Davide De Rosa on 2/17/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ReplayProtector : NSObject

- (BOOL)isReplayedPacketId:(uint32_t)packetId;

@end
