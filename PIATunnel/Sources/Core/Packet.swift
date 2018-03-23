//
//  Packet.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

enum PacketCode: UInt8 {
    case softResetV1            = 0x03
    
    case controlV1              = 0x04
    
    case ackV1                  = 0x05
    
    case dataV1                 = 0x06
    
    case hardResetClientV2      = 0x07
    
    case hardResetServerV2      = 0x08

    case unknown
}

protocol Packet {
    var packetId: UInt32 { get }
    
    var code: PacketCode { get }
}

class ControlPacket: Packet {
    let packetId: UInt32
    
    let code: PacketCode
    
    let key: UInt8
    
    let sessionId: Data?
    
    let payload: Data?
    
    var sentDate: Date?
    
    init(_ packetId: UInt32, _ code: PacketCode, _ key: UInt8, _ sessionId: Data?, _ payload: Data?) {
        self.packetId = packetId
        self.code = code
        self.key = key
        self.sessionId = sessionId
        self.payload = payload
        self.sentDate = nil
    }

    // Ruby: send_ctrl
    func toBuffer() -> Data {
        var raw = Data()
        ProtocolMacros.appendHeader(to: &raw, code, key, sessionId)
        raw.append(UInt8(0))
        raw.append(UInt32(packetId).bigEndian)
        if let payload = payload {
            raw.append(payload)
        }
        return raw
    }
}
