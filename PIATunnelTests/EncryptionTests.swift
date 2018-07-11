//
//  EncryptionTests.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 07/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import XCTest
@testable import PIATunnel
@testable import __PIATunnelNative

class EncryptionTests: XCTestCase {
    private var cipherKey: ZeroingData!

    private var hmacKey: ZeroingData!
    
    override func setUp() {
        cipherKey = try! SecureRandom.safeData(length: 32)
        hmacKey = try! SecureRandom.safeData(length: 32)
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testCBC() {
        let cbc = CryptoBox(cipherAlgorithm: "aes-128-cbc", digestAlgorithm: "sha256")
        try! cbc.configure(withCipherEncKey: cipherKey, cipherDecKey: cipherKey, hmacEncKey: hmacKey, hmacDecKey: hmacKey)
        let enc = cbc.encrypter()
        let dec = cbc.decrypter()
        
        let plain = Data(hex: "00112233445566778899")
        let encrypted = try! enc.encryptData(plain, offset: 0, packetId: 0)
        let decrypted = try! dec.decryptData(encrypted, offset: 0, packetId: 0)
        XCTAssertEqual(plain, decrypted)
    }

    func testGCM() {
        let gcm = CryptoBox(cipherAlgorithm: "aes-256-gcm", digestAlgorithm: nil)
        try! gcm.configure(withCipherEncKey: cipherKey, cipherDecKey: cipherKey, hmacEncKey: hmacKey, hmacDecKey: hmacKey)
        let enc = gcm.encrypter()
        let dec = gcm.decrypter()
        
        let packetId: UInt32 = 0x56341200
        let plain = Data(hex: "00112233445566778899")
        let encrypted = try! enc.encryptData(plain, offset: 0, packetId: packetId)
        let decrypted = try! dec.decryptData(encrypted, offset: 0, packetId: packetId)
        XCTAssertEqual(plain, decrypted)
    }

//    func testCryptoOperation() {
//        let data = Data(hex: "aabbccddeeff")
//
//        print("Original : \(data.toHex())")
//        var enc: Data
//        var dec: Data
//
//        enc = Data()
//        enc.append(try! encrypter.encryptData(data, offset: 0, packetId: 0))
//        print("Encrypted: \(enc.toHex())")
//        dec = try! decrypter.decryptData(enc, offset: 0, packetId: 0)
//        print("Decrypted: \(dec.toHex())")
//        XCTAssert(dec == data)
//
//        let prefix = "abcdef"
//        enc = Data(hex: prefix)
//        enc.append(try! encrypter.encryptData(data, offset: 0, packetId: 0))
//        print("Encrypted: \(enc.toHex())")
//        dec = try! decrypter.decryptData(enc, offset: (prefix.count / 2), packetId: 0)
//        print("Decrypted: \(dec.toHex())")
//        XCTAssert(dec == data)
//    }
}
