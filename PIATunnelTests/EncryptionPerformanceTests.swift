//
//  EncryptionPerformanceTests.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 07/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import XCTest
@testable import PIATunnel
@testable import __PIATunnelNative

class EncryptionPerformanceTests: XCTestCase {
    private var cbcEncrypter: Encrypter!
    
    private var cbcDecrypter: Decrypter!
    
    private var gcmEncrypter: Encrypter!
    
    private var gcmDecrypter: Decrypter!
    
    override func setUp() {
        let cipherKey = try! SecureRandom.safeData(length: 32)
        let hmacKey = try! SecureRandom.safeData(length: 32)
        
        let cbc = CryptoBox(cipherAlgorithm: "aes-128-cbc", digestAlgorithm: "sha1")
        try! cbc.configure(withCipherEncKey: cipherKey, cipherDecKey: cipherKey, hmacEncKey: hmacKey, hmacDecKey: hmacKey)
        cbcEncrypter = cbc.encrypter()
        cbcDecrypter = cbc.decrypter()

        let gcm = CryptoBox(cipherAlgorithm: "aes-128-gcm", digestAlgorithm: nil)
        try! gcm.configure(withCipherEncKey: cipherKey, cipherDecKey: cipherKey, hmacEncKey: hmacKey, hmacDecKey: hmacKey)
        gcmEncrypter = gcm.encrypter()
        gcmDecrypter = gcm.decrypter()
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // 1.150s
    func testCBCEncryption() {
        let suite = TestUtils.generateDataSuite(1000, 100000)
        measure {
            for data in suite {
                let _ = try! self.cbcEncrypter.encryptData(data, offset: 0, extra: nil)
            }
        }
    }

    // 0.684s
    func testGCMEncryption() {
        let suite = TestUtils.generateDataSuite(1000, 100000)
        let extra: [UInt8] = [0x11, 0x22, 0x33, 0x44]
        measure {
            for data in suite {
                let _ = try! self.gcmEncrypter.encryptData(data, offset: 0, extra: extra)
            }
        }
    }
}
