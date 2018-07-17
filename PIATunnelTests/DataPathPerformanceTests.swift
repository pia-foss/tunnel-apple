//
//  DataPathPerformanceTests.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 07/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import XCTest
@testable import PIATunnel
@testable import __PIATunnelNative

class DataPathPerformanceTests: XCTestCase {
    private var dataPath: DataPath!

    private var encrypter: DataPathEncrypter!

    private var decrypter: DataPathDecrypter!
    
    override func setUp() {
        let ck = try! SecureRandom.safeData(length: 32)
        let hk = try! SecureRandom.safeData(length: 32)
        
        let crypto = try! EncryptionProxy("aes-128-cbc", "sha1", ck, ck, hk, hk)
        encrypter = crypto.encrypter()
        decrypter = crypto.decrypter()
        
        dataPath = DataPath(encrypter: encrypter, decrypter: decrypter, maxPackets: 200, usesReplayProtection: false)
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

//    // 28ms
//    func testHighLevel() {
//        let packets = TestUtils.generateDataSuite(1200, 1000)
//        var encryptedPackets: [Data]!
//        var decryptedPackets: [Data]!
//        
//        measure {
//            encryptedPackets = try! self.swiftDP.encryptPackets(packets, key: 0)
//            decryptedPackets = try! self.swiftDP.decryptPackets(encryptedPackets, keepAlive: nil)
//        }
//        
////        print(">>> \(packets?.count) packets")
//        XCTAssertEqual(decryptedPackets, packets)
//    }
    
    // 16ms
    func testPointerBased() {
        let packets = TestUtils.generateDataSuite(1200, 1000)
        var encryptedPackets: [Data]!
        var decryptedPackets: [Data]!
        
        measure {
            encryptedPackets = try! self.dataPath.encryptPackets(packets, key: 0)
            decryptedPackets = try! self.dataPath.decryptPackets(encryptedPackets, keepAlive: nil)
        }
        
//        print(">>> \(packets?.count) packets")
        XCTAssertEqual(decryptedPackets, packets)
    }
}
