//
//  RandomTests.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 07/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import XCTest
@testable import PIATunnel

class RandomTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testRandom1() {
        print(try! SecureRandom.uint32())
        print(try! SecureRandom.uint32())
        print(try! SecureRandom.uint32())
        print(try! SecureRandom.uint32())
        print(try! SecureRandom.uint32())
    }

    func testRandom2() {
        print("random UInt32: \(try! SecureRandom.uint32())")
        print("random bytes: \(try! SecureRandom.data(length: 12).toHex())")
    }
}
