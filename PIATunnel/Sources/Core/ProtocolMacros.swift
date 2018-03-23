//
//  ProtocolMacros.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/8/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

class ProtocolMacros {
    static let sessionIdLength = 8
    
    static let packetIdLength = 4
    
    // UInt32(0) + UInt8(KeyMethod = 2)
    static let tlsPrefix = Data(hex: "0000000002")

    static let noCompress = UInt8(0xfa)
    
    static let pingString = Data(hex: "2a187bf3641eb4cb07ed2d0a981fc748")
    
    static let numberOfKeys = UInt8(8) // 3-bit
    
    // Ruby: header
    static func appendHeader(to: inout Data, _ code: PacketCode, _ key: UInt8 = 0, _ sessionId: Data? = nil) -> Void {
        let firstByte = (code.rawValue << 3) | (key & 0b111)
        to.append(firstByte)
        if let sessionId = sessionId {
            to.append(sessionId)
        }
    }
}
