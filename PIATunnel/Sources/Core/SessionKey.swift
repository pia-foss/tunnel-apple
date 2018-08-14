//
//  SessionKey.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 4/12/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import __PIATunnelNative
import SwiftyBeaver

private let log = SwiftyBeaver.self

class SessionKey {
    enum State {
        case invalid, hardReset, softReset, tls
    }
    
    enum ControlState {
        case preAuth, preIfConfig, connected
    }

    let id: UInt8 // 3-bit
    
    let startTime: Date
    
    var state = State.invalid
    
    var controlState: ControlState?
    
    var tlsOptional: TLSBox?

    var tls: TLSBox {
        guard let tls = tlsOptional else {
            fatalError("TLSBox accessed when nil")
        }
        return tls
    }
    
    var dataPath: DataPath?
    
    var softReset: Bool

    private var isTLSConnected: Bool
    
    private var canHandlePackets: Bool
    
    init(id: UInt8) {
        self.id = id

        startTime = Date()
        state = .invalid
        softReset = false
        isTLSConnected = false
        canHandlePackets = false
    }

    // Ruby: Key.hard_reset_timeout
    func didHardResetTimeOut(link: LinkInterface) -> Bool {
        return ((state == .hardReset) && (-startTime.timeIntervalSinceNow > link.hardResetTimeout))
    }
    
    // Ruby: Key.negotiate_timeout
    func didNegotiationTimeOut(link: LinkInterface) -> Bool {
        let timeout = (softReset ? CoreConfiguration.softNegotiationTimeout : link.negotiationTimeout)
        
        return ((controlState != .connected) && (-startTime.timeIntervalSinceNow > timeout))
    }
    
    // Ruby: Key.on_tls_connect
    func shouldOnTLSConnect() -> Bool {
        guard !isTLSConnected else {
            return false
        }
        if tls.isConnected() {
            isTLSConnected = true
        }
        return isTLSConnected
    }
    
    func startHandlingPackets(withPeerId peerId: UInt32? = nil) {
        dataPath?.setPeerId(peerId ?? PacketPeerIdDisabled)
        canHandlePackets = true
    }
    
    func encrypt(packets: [Data]) throws -> [Data]? {
        guard let dataPath = dataPath else {
            log.warning("Data: Set dataPath first")
            return nil
        }
        guard canHandlePackets else {
            log.warning("Data: Invoke startHandlingPackets() before encrypting")
            return nil
        }
        return try dataPath.encryptPackets(packets, key: id)
    }
    
    func decrypt(packets: [Data]) throws -> [Data]? {
        guard let dataPath = dataPath else {
            log.warning("Data: Set dataPath first")
            return nil
        }
        guard canHandlePackets else {
            log.warning("Data: Invoke startHandlingPackets() before decrypting")
            return nil
        }
        var keepAlive = false
        let decrypted = try dataPath.decryptPackets(packets, keepAlive: &keepAlive)
        if keepAlive {
            log.debug("Data: Received ping, do nothing")
        }
        return decrypted
    }
    
//    func dispose() {
//        tlsOptional = nil
//        dataPath = nil
//    }
}
