//
//  DataManipulationTests.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 07/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import XCTest
@testable import PIATunnel

class DataManipulationTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testUInt() {
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
}
