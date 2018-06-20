//
//  HighLevelDataPath.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 3/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import SwiftyBeaver
import __PIATunnelNative

private let log = SwiftyBeaver.self

class HighLevelDataPath: DataPath {
    private let encrypter: Encrypter
    
    private let decrypter: Decrypter
    
    private var outPacketId: UInt32
    
    private let inReplay: ReplayProtector?
    
    var maxPacketId: UInt32
    
    init(encrypter: Encrypter, decrypter: Decrypter, usesReplayProtection: Bool) {
        self.encrypter = encrypter
        self.decrypter = decrypter

        maxPacketId = UInt32.max - 10000
        outPacketId = 0
        inReplay = (usesReplayProtection ? ReplayProtector() : nil)
    }
    
    // MARK: DataPath
    
    func setMaxPacketId(_ maxPacketId: UInt32) {
        self.maxPacketId = maxPacketId
    }
    
    func encryptPackets(_ packets: [Data], key: UInt8) throws -> [Data] {
        var outPackets = [Data]()
        
        for var payload in packets {
            guard (outPacketId <= maxPacketId) else {
                log.warning("Data: Exhausted out packetId, should reconnect")
                throw PIATunnelErrorWithCode(.dataPathOverflow)
            }
            
//            log.verbose("Data: Handle packet from TUN (\(data.count) bytes)")
            
            let packetId = outPacketId
            outPacketId += 1
            
            let payloadCount = payload.count
            payload.withUnsafeMutableBytes { (payloadBytes: UnsafeMutablePointer<UInt8>) in
                MSSFix(payloadBytes, Int32(payloadCount))
            }
            
            var decryptedPacket = Data()
            decryptedPacket.append(UInt32(packetId).bigEndian)
            decryptedPacket.append(ProtocolMacros.noCompress)
            decryptedPacket.append(payload)
            
//            log.verbose("Data: Built packetId \(packetId) with payload (\(payload.count) bytes)")
            
            let encryptedPayload: Data
            try encryptedPayload = encrypter.encryptData(decryptedPacket, offset: 0)
            
//            log.verbose("Data: Encrypted payload (\(encryptedPayload.count) bytes)")
            
            var encryptedPacket = Data()
            ProtocolMacros.appendHeader(to: &encryptedPacket, .dataV1, key)
            encryptedPacket.append(encryptedPayload)
            
//            log.verbose("Data: Enqueue encrypted packet to UDP (\(encryptedPacket.count) bytes)")
            
            outPackets.append(encryptedPacket)
        }
        
//        log.verbose("Data: Send \(outPackets.count) encrypted packets to UDP")

        return outPackets
    }
    
//    func decryptPackets(_ packets: [Data]) throws -> [Data] {
    func decryptPackets(_ packets: [Data], keepAlive: UnsafeMutablePointer<Bool>) throws -> [Data] {
        var inPackets = [Data]()
        
        for encryptedPacket in packets {
//            log.verbose("Data: Handle packet from UDP (\(encryptedPacket.count) bytes)")
            
            let decryptedPacket: Data
            try decryptedPacket = decrypter.decryptData(encryptedPacket, offset: 1) // skip (code, key)
            
//            log.verbose("Data: Decrypted packet (\(decryptedPacket.count) bytes)")
            
            var offset = 0
            let packetId = CFSwapInt32BigToHost(decryptedPacket.UInt32Value(from: offset))
            offset += 4
            
//            let compression = decryptedPacket[offset]
            let _ = decryptedPacket[offset]
            offset += 1
            
            guard (packetId <= maxPacketId) else {
                log.warning("Data: Exhausted in packetId, should reconnect")
                throw PIATunnelErrorWithCode(.dataPathOverflow)
            }
            
            if let replay = inReplay {
                guard !replay.isReplayedPacketId(packetId) else {
//                    log.verbose("Data: Replayed packet id \(packetId), do nothing")
                    continue
                }
            }
            
            var payload = decryptedPacket.subdata(in: offset..<decryptedPacket.count)
            guard (payload != ProtocolMacros.pingString) else {
                keepAlive.pointee = true
                continue
            }
            
            let payloadCount = payload.count
            payload.withUnsafeMutableBytes { (payloadBytes: UnsafeMutablePointer<UInt8>) in
                MSSFix(payloadBytes, Int32(payloadCount))
            }
            
//            log.verbose("Data: Enqueue decrypted payload for TUN (\(payload.count) bytes)")
            inPackets.append(payload)
        }
        
        return inPackets
    }
}
