//
//  SecureRandom.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import Security.SecRandom
import __PIATunnelNative

enum SecureRandomError: Error {
    case randomGenerator
}

class SecureRandom {
    @available(*, deprecated)
    static func uint32FromBuffer() throws -> UInt32 {
        var randomBuffer = [UInt8](repeating: 0, count: 4)

        if (SecRandomCopyBytes(kSecRandomDefault, 4, &randomBuffer) != 0) {
            throw SecureRandomError.randomGenerator
        }

        var randomNumber: UInt32 = 0
        for i in 0..<4 {
            let byte = randomBuffer[i]
            randomNumber |= (UInt32(byte) << UInt32(8 * i))
        }
        return randomNumber
    }
    
    static func uint32() throws -> UInt32 {
        var randomNumber: UInt32 = 0
        
        try withUnsafeMutablePointer(to: &randomNumber) {
            try $0.withMemoryRebound(to: UInt8.self, capacity: 4) { (randomBytes: UnsafeMutablePointer<UInt8>) -> Void in
                guard (SecRandomCopyBytes(kSecRandomDefault, 4, randomBytes) == 0) else {
                    throw SecureRandomError.randomGenerator
                }
            }
        }
        
        return randomNumber
    }

    static func data(length: Int) throws -> Data {
        var randomData = Data(count: length)

        try randomData.withUnsafeMutableBytes { (randomBytes: UnsafeMutablePointer<UInt8>) -> Void in
            guard (SecRandomCopyBytes(kSecRandomDefault, length, randomBytes) == 0) else {
                throw SecureRandomError.randomGenerator
            }
        }
        
        return randomData
    }

    static func safeData(length: Int) throws -> ZeroingData {
        let randomBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: length)
        defer {
//            randomBytes.initialize(to: 0, count: length)
            bzero(randomBytes, length)
            randomBytes.deallocate(capacity: length)
        }
        
        guard (SecRandomCopyBytes(kSecRandomDefault, length, randomBytes) == 0) else {
            throw SecureRandomError.randomGenerator
        }

        return Z(bytes: randomBytes, count: length)
    }
}
