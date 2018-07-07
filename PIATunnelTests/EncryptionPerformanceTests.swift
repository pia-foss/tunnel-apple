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
    
    override func setUp() {
        let cipherKey = try! SecureRandom.safeData(length: 32)
        let hmacKey = try! SecureRandom.safeData(length: 32)
        
        let cbc = CryptoBox(cipherAlgorithm: "aes-128-cbc", digestAlgorithm: "sha1")!
        cbc.configure(withCipherEncKey: cipherKey.bytes, cipherDecKey: cipherKey.bytes, hmacEncKey: hmacKey.bytes, hmacDecKey: hmacKey.bytes)
        cbcEncrypter = cbc.encrypter()
        cbcDecrypter = cbc.decrypter()
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // 1.215s
    func testCBCEncryption() {
        let suite = TestUtils.generateDataSuite(1000, 100000)
        measure {
            for data in suite {
                let _ = try! self.cbcEncrypter.encryptData(data, offset: 0)
            }
        }
    }
}
