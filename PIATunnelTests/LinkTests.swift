//
//  LinkTests.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 07/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import XCTest
@testable import PIATunnel

class LinkTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // UDP
    
    func testUnreliableControlQueue() {
        let seq1 = [0, 5, 2, 1, 4, 3]
        let seq2 = [5, 2, 1, 9, 4, 3, 0, 8, 7, 10, 4, 3, 5, 6]
        let seq3 = [5, 2, 11, 1, 2, 9, 4, 5, 5, 3, 8, 0, 6, 8, 2, 7, 10, 4, 3, 5, 6]
        
        for seq in [seq1, seq2, seq3] {
            XCTAssertEqual(TestUtils.uniqArray(seq.sorted()), handleControlSequence(seq))
        }
    }
    
    // TCP
    
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
        
        (until, packets) = CommonPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 18)
        XCTAssertEqual(packets.count, 3)
        
        bytes.append(contentsOf: [0xbb, 0xcc])
        (until, packets) = CommonPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 23)
        XCTAssertEqual(packets.count, 4)
        
        bytes.append(contentsOf: [0x00, 0x05])
        (until, packets) = CommonPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 23)
        XCTAssertEqual(packets.count, 4)
        
        bytes.append(contentsOf: [0x11, 0x22, 0x33, 0x44])
        (until, packets) = CommonPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 23)
        XCTAssertEqual(packets.count, 4)
        
        bytes.append(contentsOf: [0x55])
        (until, packets) = CommonPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 30)
        XCTAssertEqual(packets.count, 5)
        
        //
        
        bytes.removeSubrange(0..<until)
        XCTAssertEqual(bytes.count, 0)
        
        bytes.append(contentsOf: [0x00, 0x04])
        bytes.append(contentsOf: [0x10, 0x20])
        (until, packets) = CommonPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 0)
        XCTAssertEqual(packets.count, 0)
        bytes.removeSubrange(0..<until)
        XCTAssertEqual(bytes.count, 4)
        
        bytes.append(contentsOf: [0x30, 0x40])
        bytes.append(contentsOf: [0x00, 0x07])
        bytes.append(contentsOf: [0x10, 0x20, 0x30, 0x40])
        (until, packets) = CommonPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 6)
        XCTAssertEqual(packets.count, 1)
        bytes.removeSubrange(0..<until)
        XCTAssertEqual(bytes.count, 6)
        
        bytes.append(contentsOf: [0x50, 0x66, 0x77])
        bytes.append(contentsOf: [0x00, 0x01])
        bytes.append(contentsOf: [0xff])
        bytes.append(contentsOf: [0x00, 0x03])
        bytes.append(contentsOf: [0xaa])
        (until, packets) = CommonPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 12)
        XCTAssertEqual(packets.count, 2)
        bytes.removeSubrange(0..<until)
        XCTAssertEqual(bytes.count, 3)
        
        bytes.append(contentsOf: [0xbb, 0xcc])
        (until, packets) = CommonPacket.parsed(Data(bytes: bytes))
        XCTAssertEqual(until, 5)
        XCTAssertEqual(packets.count, 1)
        bytes.removeSubrange(0..<until)
        XCTAssertEqual(bytes.count, 0)
    }

    // helpers

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
}
