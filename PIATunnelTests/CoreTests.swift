//
//  CoreTests.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 2/10/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import XCTest
@testable import PIATunnel
@testable import __PIATunnelNative

extension ZeroingData {
    var data: Data {
        return Data(bytes: bytes, count: count)
    }
}

extension SessionProxy {
    public static func mockProxy() -> SessionProxy {
        return try! SessionProxy(queue: DispatchQueue.main,
                                 encryption: EncryptionParameters("", "", "", ""),
                                 credentials: Credentials("", ""))
    }
}

class CoreTests: XCTestCase {
    var encrypter: Encrypter!
    
    var decrypter: Decrypter!
    
    var session: SessionProxy!
    
    var swiftDP: DataPath!
    
    var pointerDP: DataPath!
    
    override func setUp() {
        super.setUp()
        
        let ck = try! SecureRandom.safeData(length: 32)
        let hk = try! SecureRandom.safeData(length: 32)
        
        let crypto = try! EncryptionProxy("aes-128-cbc", "sha1", ck, ck, hk, hk)
        encrypter = crypto.encrypter()
        decrypter = crypto.decrypter()
        session = SessionProxy.mockProxy()
        
        swiftDP = HighLevelDataPath(encrypter: encrypter, decrypter: decrypter, usesReplayProtection: false)
        pointerDP = PointerBasedDataPath(encrypter: encrypter, decrypter: decrypter, maxPackets: 200, usesReplayProtection: false)!
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    private func generateDataSuite(_ size: Int, _ count: Int) -> [Data] {
        var suite = [Data]()
        for _ in 0..<count {
            suite.append(try! SecureRandom.data(length: size))
        }
        return suite
    }
    
    func testDataManipulation() {
        let data = Data([0x22, 0xff, 0xaa, 0xbb, 0x55, 0x66])
        
        XCTAssertEqual(data.UInt16Value(from: 3), 0x55bb)
        XCTAssertEqual(data.UInt32Value(from: 2), 0x6655bbaa)
        XCTAssertEqual(data.UInt16Value(from: 4), 0x6655)
        XCTAssertEqual(data.UInt32Value(from: 0), 0xbbaaff22)
        
        XCTAssertEqual(data.UInt16Value(from: 3), data.UInt16ValueFromPointers(from: 3))
        XCTAssertEqual(data.UInt32Value(from: 2), data.UInt32ValueFromPointers(from: 2))
        XCTAssertEqual(data.UInt16Value(from: 4), data.UInt16ValueFromPointers(from: 4))
        XCTAssertEqual(data.UInt32Value(from: 0), data.UInt32ValueFromPointers(from: 0))
    }
    
    func testUInt16FromLoop() {
        let data = Data([0x22, 0xff, 0xaa, 0xbb, 0x55, 0x66])
        
        measure {
            for _ in 0..<1000000 {
                let _ = data.UInt16Value(from: 3)
            }
        }
    }
    
    func testUInt16FromPointers() {
        let data = Data([0x22, 0xff, 0xaa, 0xbb, 0x55, 0x66])
        
        measure {
            for _ in 0..<1000000 {
                let _ = data.UInt16ValueFromPointers(from: 3)
            }
        }
    }
    
    func testUInt32FromLoop() {
        let data = Data([0x22, 0xff, 0xaa, 0xbb, 0x55, 0x66])
        
        measure {
            for _ in 0..<1000000 {
                let _ = data.UInt32Value(from: 1)
            }
        }
    }
    
    func testUInt32FromPointers() {
        let data = Data([0x22, 0xff, 0xaa, 0xbb, 0x55, 0x66])
        
        measure {
            for _ in 0..<1000000 {
                let _ = data.UInt32ValueFromPointers(from: 1)
            }
        }
    }
    
    func testRandomUInt32FromLoop() {
        measure {
            for _ in 0..<10000 {
                let _ = try! SecureRandom.uint32FromBuffer()
            }
        }
    }
    
    func testRandomUInt32FromPointers() {
        measure {
            for _ in 0..<10000 {
                let _ = try! SecureRandom.uint32()
            }
        }
    }
    
    func testRandom() {
        print(try! SecureRandom.uint32())
        print(try! SecureRandom.uint32())
        print(try! SecureRandom.uint32())
        print(try! SecureRandom.uint32())
        print(try! SecureRandom.uint32())
    }
    
    func uniqArray(_ v: [Int]) -> [Int] {
        return v.reduce([]){ $0.contains($1) ? $0 : $0 + [$1] }
    }
    
    func testControlQueueIn() {
        let seq1 = [0, 5, 2, 1, 4, 3]
        let seq2 = [5, 2, 1, 9, 4, 3, 0, 8, 7, 10, 4, 3, 5, 6]
        let seq3 = [5, 2, 11, 1, 2, 9, 4, 5, 5, 3, 8, 0, 6, 8, 2, 7, 10, 4, 3, 5, 6]
        
        for seq in [seq1, seq2, seq3] {
            XCTAssertEqual(uniqArray(seq.sorted()), handleControlSequence(seq))
        }
    }
    
    private func handleControlSequence(_ seq: [Int]) -> [Int] {
        var q = [Int]()
        var id = 0
        var hdl = [Int]()
        for p in seq {
            enqueueControl(&q, &id, p) {
                hdl.append($0)
            }
            print()
        }
        return hdl
    }
    
    private func enqueueControl(_ q: inout [Int], _ id: inout Int, _ p: Int, _ h: (Int) -> Void) {
        q.append(p)
        q.sort { (p1, p2) -> Bool in
            return (p1 < p2)
        }
        
        print("q = \(q)")
        print("id = \(id)")
        for p in q {
            print("test(\(p))")
            if (p < id) {
                q.removeFirst()
                continue
            }
            if (p != id) {
                return
            }
            
            h(p)
            print("handle(\(p))")
            id += 1
            q.removeFirst()
        }
    }
    
    func testCryptoOperation() {
        let data = Data(hex: "aabbccddeeff")
        
        print("Original : \(data.toHex())")
        var enc: Data
        var dec: Data
        
        enc = Data()
        enc.append(try! encrypter.encryptData(data, offset: 0, packetId: 0))
        print("Encrypted: \(enc.toHex())")
        dec = try! decrypter.decryptData(enc, offset: 0, packetId: 0)
        print("Decrypted: \(dec.toHex())")
        XCTAssert(dec == data)
        
        let prefix = "abcdef"
        enc = Data(hex: prefix)
        enc.append(try! encrypter.encryptData(data, offset: 0, packetId: 0))
        print("Encrypted: \(enc.toHex())")
        dec = try! decrypter.decryptData(enc, offset: (prefix.count / 2), packetId: 0)
        print("Decrypted: \(dec.toHex())")
        XCTAssert(dec == data)
    }
    
    func testRandomGenerator() {
        print("random UInt32: \(try! SecureRandom.uint32())")
        print("random bytes: \(try! SecureRandom.data(length: 12).toHex())")
    }
    
    // ~10s on desktop
    func testEncryptionTime() {
        let suite = generateDataSuite(1000, 100000)
        measure {
            for data in suite {
                let _ = try! self.encrypter.encryptData(data, offset: 0, packetId: 0)
            }
        }
    }
    
    func testMyPacketHeader() {
        let suite = generateDataSuite(1000, 200000)
        measure {
            for data in suite {
                CFSwapInt32BigToHost(data.UInt32Value(from: 0))
            }
        }
    }
    
    func testStevePacketHeader() {
        let suite = generateDataSuite(1000, 200000)
        measure {
            for data in suite {
                let _ = UInt32(bigEndian: data.subdata(in: 0..<4).withUnsafeBytes { $0.pointee })
            }
        }
    }
    
    func testDataSubdata() {
        let suite = generateDataSuite(1000, 100000)
        measure {
            for data in suite {
                let _ = data.subdata(in: 5..<data.count)
            }
        }
    }
    
    func testDataRemoveSubrange() {
        let suite = generateDataSuite(1000, 100000)
        measure {
            for var data in suite {
                data.removeSubrange(0..<5)
            }
        }
    }
    
    // 236ms on simulator
    func testDataPathHighLevel() {
        let packets = generateDataSuite(1200, 10000)
        var encryptedPackets: [Data]!
        var decryptedPackets: [Data]!
        
        measure {
            encryptedPackets = try! self.swiftDP.encryptPackets(packets, key: 0)
            decryptedPackets = try! self.swiftDP.decryptPackets(encryptedPackets, keepAlive: nil)
        }
        
        //        print(">>> \(packets?.count) packets")
        XCTAssertEqual(decryptedPackets, packets)
    }
    
    // 200ms on simulator
    func testDataPathPointer() {
        let packets = generateDataSuite(1200, 10000)
        var encryptedPackets: [Data]!
        var decryptedPackets: [Data]!
        
        measure {
            encryptedPackets = try! self.pointerDP.encryptPackets(packets, key: 0)
            decryptedPackets = try! self.pointerDP.decryptPackets(encryptedPackets, keepAlive: nil)
        }
        
        //        print(">>> \(packets?.count) packets")
        XCTAssertEqual(decryptedPackets, packets)
    }
    
    func testZeroingData() {
        let z1 = Z()
        z1.append(Z(Data(hex: "12345678")))
        z1.append(Z(Data(hex: "abcdef")))
        let z2 = z1.withOffset(2, count: 3) // 5678ab
        let z3 = z2.appending(Z(Data(hex: "aaddcc"))) // 5678abaaddcc
        
        XCTAssertEqual(z1.data, Data(hex: "12345678abcdef"))
        XCTAssertEqual(z2.data, Data(hex: "5678ab"))
        XCTAssertEqual(z3.data, Data(hex: "5678abaaddcc"))
    }
    
    func testPacketStream() {
        var bytes: [UInt8] = []
        var until: Int
        var packets: [Data]
        
        bytes.append(contentsOf: [0x00, 0x04])
        bytes.append(contentsOf: [0x10, 0x20, 0x30, 0x40])
        bytes.append(contentsOf: [0x00, 0x07])
        bytes.append(contentsOf: [0x10, 0x20, 0x30, 0x40, 0x50, 0x66, 0x77])
        bytes.append(contentsOf: [0x00, 0x01])
        bytes.append(contentsOf: [0xff])
        bytes.append(contentsOf: [0x00, 0x03])
        bytes.append(contentsOf: [0xaa])
        XCTAssertEqual(bytes.count, 21)

        (until, packets) = ControlPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 18)
        XCTAssertEqual(packets.count, 3)

        bytes.append(contentsOf: [0xbb, 0xcc])
        (until, packets) = ControlPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 23)
        XCTAssertEqual(packets.count, 4)

        bytes.append(contentsOf: [0x00, 0x05])
        (until, packets) = ControlPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 23)
        XCTAssertEqual(packets.count, 4)

        bytes.append(contentsOf: [0x11, 0x22, 0x33, 0x44])
        (until, packets) = ControlPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 23)
        XCTAssertEqual(packets.count, 4)

        bytes.append(contentsOf: [0x55])
        (until, packets) = ControlPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 30)
        XCTAssertEqual(packets.count, 5)
        
        //

        bytes.removeSubrange(0..<until)
        XCTAssertEqual(bytes.count, 0)

        bytes.append(contentsOf: [0x00, 0x04])
        bytes.append(contentsOf: [0x10, 0x20])
        (until, packets) = ControlPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 0)
        XCTAssertEqual(packets.count, 0)
        bytes.removeSubrange(0..<until)
        XCTAssertEqual(bytes.count, 4)

        bytes.append(contentsOf: [0x30, 0x40])
        bytes.append(contentsOf: [0x00, 0x07])
        bytes.append(contentsOf: [0x10, 0x20, 0x30, 0x40])
        (until, packets) = ControlPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 6)
        XCTAssertEqual(packets.count, 1)
        bytes.removeSubrange(0..<until)
        XCTAssertEqual(bytes.count, 6)

        bytes.append(contentsOf: [0x50, 0x66, 0x77])
        bytes.append(contentsOf: [0x00, 0x01])
        bytes.append(contentsOf: [0xff])
        bytes.append(contentsOf: [0x00, 0x03])
        bytes.append(contentsOf: [0xaa])
        (until, packets) = ControlPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 12)
        XCTAssertEqual(packets.count, 2)
        bytes.removeSubrange(0..<until)
        XCTAssertEqual(bytes.count, 3)

        bytes.append(contentsOf: [0xbb, 0xcc])
        (until, packets) = ControlPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 5)
        XCTAssertEqual(packets.count, 1)
        bytes.removeSubrange(0..<until)
        XCTAssertEqual(bytes.count, 0)
    }

    func testGCM() {
        let ck = try! SecureRandom.safeData(length: 32)
        let hk = try! SecureRandom.safeData(length: 32)

        let gcm = CryptoBox(cipherAlgorithm: "aes-256-gcm", digestAlgorithm: nil)
        try! gcm.configure(withCipherEncKey: ck, cipherDecKey: ck, hmacEncKey: hk, hmacDecKey: hk)
        let enc = gcm.encrypter()
        let dec = gcm.decrypter()

        let packetId: UInt32 = 0x56341200
        let plain = Data(hex: "00112233445566778899")
        let encrypted = try! enc.encryptData(plain, offset: 0, packetId: packetId)
        let decrypted = try! dec.decryptData(encrypted, offset: 0, packetId: packetId)
        XCTAssertEqual(plain, decrypted)
    }
}
