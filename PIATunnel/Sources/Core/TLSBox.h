//
//  TLSBox.h
//  PIATunnel
//
//  Created by Davide De Rosa on 2/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

extern const NSInteger TLSBoxMaxBufferLength;

extern NSString *const TLSBoxPeerVerificationErrorNotification;

//
// cipher text is safe within NSData
// plain text might be sensitive and must avoid NSData
//
// WARNING: not thread-safe!
//
@interface TLSBox : NSObject

- (nonnull instancetype)initWithCAPath:(NSString *)caPath certPath:(NSString *) certPath_ keyPath:(NSString *) keyPath_;

- (BOOL)startWithPeerVerification:(BOOL)peerVerification error:(NSError **)error;

- (NSData *)pullCipherTextWithError:(NSError **)error;
// WARNING: text must be able to hold plain text output
- (BOOL)pullRawPlainText:(uint8_t *)text length:(NSInteger *)length error:(NSError **)error;

- (BOOL)putCipherText:(NSData *)text error:(NSError **)error;
- (BOOL)putRawCipherText:(const uint8_t *)text length:(NSInteger)length error:(NSError **)error;
- (BOOL)putPlainText:(NSString *)text error:(NSError **)error;
- (BOOL)putRawPlainText:(const uint8_t *)text length:(NSInteger)length error:(NSError **)error;

- (BOOL)isConnected;

@end
