//
//  DataPathEncryptionTests.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 11/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import XCTest
@testable import PIATunnel
@testable import __PIATunnelNative

class DataPathEncryptionTests: XCTestCase {
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
        privateTestDataPath(cipher: "aes-128-cbc", digest: "sha256", peerId: nil)
    }
    
    func testFloatingCBC() {
        privateTestDataPath(cipher: "aes-128-cbc", digest: "sha256", peerId: 0x64385837)
    }
    
    func testGCM() {
        privateTestDataPath(cipher: "aes-256-gcm", digest: nil, peerId: nil)
    }

    func testFloatingGCM() {
        privateTestDataPath(cipher: "aes-256-gcm", digest: nil, peerId: 0x64385837)
    }
    
    func privateTestDataPath(cipher: String, digest: String?, peerId: UInt32?) {
        let box = CryptoBox(cipherAlgorithm: cipher, digestAlgorithm: digest)
        try! box.configure(withCipherEncKey: cipherKey, cipherDecKey: cipherKey, hmacEncKey: hmacKey, hmacDecKey: hmacKey)
        let enc = box.encrypter().dataPathEncrypter()
        let dec = box.decrypter().dataPathDecrypter()
        
        if let peerId = peerId {
            enc.setPeerId(peerId)
            dec.setPeerId(peerId)
            XCTAssertEqual(enc.peerId(), peerId & 0xffffff)
            XCTAssertEqual(dec.peerId(), peerId & 0xffffff)
        }

        let payload = Data(hex: "00112233445566778899")
        let packetId: UInt32 = 0x56341200
        let key: UInt8 = 4
        let compression: UInt8 = DataPacketCompressNone
        var encryptedPayload: [UInt8] = [UInt8](repeating: 0, count: 1000)
        var encryptedPayloadLength: Int = 0
        enc.assembleDataPacket(withPacketId: packetId, compression: compression, payload: payload, into: &encryptedPayload, length: &encryptedPayloadLength)
        let encrypted = try! enc.encryptedDataPacket(withKey: key, packetId: packetId, payload: encryptedPayload, payloadLength: encryptedPayloadLength)

        var decrypted: [UInt8] = [UInt8](repeating: 0, count: 1000)
        var decryptedLength: Int = 0
        var decryptedPacketId: UInt32 = 0
        var decryptedPayloadLength: Int = 0
        var decryptedCompression: UInt8 = 0
        try! dec.decryptDataPacket(encrypted, into: &decrypted, length: &decryptedLength, packetId: &decryptedPacketId)
        let decryptedPtr = dec.parsePayload(withDataPacket: &decrypted, packetLength: decryptedLength, length: &decryptedPayloadLength, compression: &decryptedCompression)
        let decryptedPayload = Data(bytes: decryptedPtr, count: decryptedPayloadLength)

        XCTAssertEqual(payload, decryptedPayload)
        XCTAssertEqual(packetId, decryptedPacketId)
        XCTAssertEqual(compression, decryptedCompression)
    }
}
