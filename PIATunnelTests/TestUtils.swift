//
//  TestUtils.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 07/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
@testable import PIATunnel
@testable import __PIATunnelNative

class TestUtils {
    static func uniqArray(_ v: [Int]) -> [Int] {
        return v.reduce([]){ $0.contains($1) ? $0 : $0 + [$1] }
    }
    
    static func generateDataSuite(_ size: Int, _ count: Int) -> [Data] {
        var suite = [Data]()
        for _ in 0..<count {
            suite.append(try! SecureRandom.data(length: size))
        }
        return suite
    }
    
    private init() {
    }
}

extension ZeroingData {
    var data: Data {
        return Data(bytes: bytes, count: count)
    }
}
