//
//  ProtocolMacros.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/8/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import __PIATunnelNative

class ProtocolMacros {
    static let peerIdLength = 3

    static let sessionIdLength = 8
    
    static let packetIdLength = 4
    
    // UInt32(0) + UInt8(KeyMethod = 2)
    static let tlsPrefix = Data(hex: "0000000002")

    static let numberOfKeys = UInt8(8) // 3-bit
}
