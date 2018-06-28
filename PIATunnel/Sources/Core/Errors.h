//
//  Errors.h
//  PIATunnel
//
//  Created by Davide De Rosa on 10/10/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString *const PIATunnelErrorDomain;

typedef NS_ENUM(int, PIATunnelErrorCode) {
    PIATunnelErrorCodeCryptoBoxRandomGenerator = 101,
    PIATunnelErrorCodeCryptoBoxHMAC,
    PIATunnelErrorCodeCryptoBoxEncryption,
    PIATunnelErrorCodeTLSBoxCA = 201,
    PIATunnelErrorCodeTLSBoxHandshake,
    PIATunnelErrorCodeTLSBoxGeneric,
    PIATunnelErrorCodeDataPathOverflow = 301
};

static inline NSError *PIATunnelErrorWithCode(PIATunnelErrorCode code) {
    return [NSError errorWithDomain:PIATunnelErrorDomain code:code userInfo:nil];
}
