//
//  RawPerformanceTests.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 07/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

import XCTest
@testable import PIATunnel

class RawPerformanceTests: XCTestCase {
    
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testUInt16FromBuffer() {
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
    
    func testUInt32FromBuffer() {
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
    
    func testRandomUInt32FromBuffer() {
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

    func testMyPacketHeader() {
        let suite = TestUtils.generateDataSuite(1000, 200000)
        measure {
            for data in suite {
                CFSwapInt32BigToHost(data.UInt32Value(from: 0))
            }
        }
    }

    func testStevePacketHeader() {
        let suite = TestUtils.generateDataSuite(1000, 200000)
        measure {
            for data in suite {
                let _ = UInt32(bigEndian: data.subdata(in: 0..<4).withUnsafeBytes { $0.pointee })
            }
        }
    }

    func testDataSubdata() {
        let suite = TestUtils.generateDataSuite(1000, 100000)
        measure {
            for data in suite {
                let _ = data.subdata(in: 5..<data.count)
            }
        }
    }

    func testDataRemoveSubrange() {
        let suite = TestUtils.generateDataSuite(1000, 100000)
        measure {
            for var data in suite {
                data.removeSubrange(0..<5)
            }
        }
    }
}
