//
//  Packet.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import __PIATunnelNative

class CommonPacket {
    let packetId: UInt32
    
    let code: PacketCode
    
    let key: UInt8
    
    let sessionId: Data?
    
    let payload: Data?
    
    var sentDate: Date?

    static func parsed(_ stream: Data) -> (Int, [Data]) {
        var ni = 0
        var parsed: [Data] = []
        while (ni + 2 <= stream.count) {
            let packlen = Int(stream.networkUInt16Value(from: ni))
            let start = ni + 2
            let end = start + packlen
            guard (end <= stream.count) else {
                break
            }
            let packet = stream.subdata(offset: start, count: end - start)
            parsed.append(packet)
            ni = end
        }
        return (ni, parsed)
    }
    
    static func stream(_ packet: Data) -> Data {
        var stream = Data(capacity: 2 + packet.count)
        stream.append(UInt16(packet.count).bigEndian)
        stream.append(contentsOf: packet)
        return stream
    }
    
    static func stream(_ packets: [Data]) -> Data {
        var raw = Data()
        for payload in packets {
            raw.append(UInt16(payload.count).bigEndian)
            raw.append(payload)
        }
        return raw
    }
    
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
        var raw = PacketWithHeader(code, key, sessionId)
        raw.append(UInt8(0))
        raw.append(UInt32(packetId).bigEndian)
        if let payload = payload {
            raw.append(payload)
        }
        return raw
    }
}

class DataPacket {
    static let pingString = Data(hex: "2a187bf3641eb4cb07ed2d0a981fc748")
}
