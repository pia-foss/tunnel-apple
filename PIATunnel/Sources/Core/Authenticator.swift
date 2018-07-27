//
//  Authenticator.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/9/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import SwiftyBeaver
import __PIATunnelNative

private let log = SwiftyBeaver.self

fileprivate extension ZeroingData {
    fileprivate func appendSized(_ buf: ZeroingData) {
        append(Z(UInt16(buf.count).bigEndian))
        append(buf)
    }
}

class Authenticator {
    private var controlBuffer: ZeroingData
    
    private(set) var preMaster: ZeroingData
    
    private(set) var random1: ZeroingData
    
    private(set) var random2: ZeroingData
    
    private(set) var serverRandom1: ZeroingData?

    private(set) var serverRandom2: ZeroingData?

    let username: ZeroingData
    
    let password: ZeroingData
    
    init(_ username: String, _ password: String) throws {
        preMaster = try SecureRandom.safeData(length: CoreConfiguration.preMasterLength)
        random1 = try SecureRandom.safeData(length: CoreConfiguration.randomLength)
        random2 = try SecureRandom.safeData(length: CoreConfiguration.randomLength)
        
        // XXX: not 100% secure, can't erase input username/password
        self.username = Z(username, nullTerminated: true)
        self.password = Z(password, nullTerminated: true)
        
        controlBuffer = Z()
    }
    
    // MARK: Authentication request

    // Ruby: on_tls_connect
    func putAuth(into: TLSBox) throws {
        let raw = Z(ProtocolMacros.tlsPrefix)
        
        // local keys
        raw.append(preMaster)
        raw.append(random1)
        raw.append(random2)
        
        // opts
        raw.appendSized(Z(UInt8(0)))
        
        // credentials
        raw.appendSized(username)
        raw.appendSized(password)

        // peer info
        raw.appendSized(Z(CoreConfiguration.peerInfo))

        if CoreConfiguration.logsSensitiveData {
            log.debug("TLS.auth: Put plaintext (\(raw.count) bytes): \(raw.toHex())")
        } else {
            log.debug("TLS.auth: Put plaintext (\(raw.count) bytes)")
        }
        
        try into.putRawPlainText(raw.bytes, length: raw.count)
    }
    
    // MARK: Server replies

    func appendControlData(_ data: ZeroingData) {
        controlBuffer.append(data)
    }
    
    func parseAuthReply() throws -> Bool {
        let prefixLength = ProtocolMacros.tlsPrefix.count

        // TLS prefix + random (x2) + opts length [+ opts]
        guard (controlBuffer.count >= prefixLength + 2 * CoreConfiguration.randomLength + 2) else {
            return false
        }
        
        let prefix = controlBuffer.withOffset(0, count: prefixLength)
        guard prefix.isEqual(to: ProtocolMacros.tlsPrefix) else {
            throw SessionError.wrongControlDataPrefix
        }
        
        var offset = ProtocolMacros.tlsPrefix.count
        
        let serverRandom1 = controlBuffer.withOffset(offset, count: CoreConfiguration.randomLength)
        offset += CoreConfiguration.randomLength
        
        let serverRandom2 = controlBuffer.withOffset(offset, count: CoreConfiguration.randomLength)
        offset += CoreConfiguration.randomLength
        
        let serverOptsLength = Int(controlBuffer.networkUInt16Value(fromOffset: offset))
        offset += 2
        
        guard controlBuffer.count >= offset + serverOptsLength else {
            return false
        }
        let serverOpts = controlBuffer.withOffset(offset, count: serverOptsLength)
        offset += serverOptsLength

        if CoreConfiguration.logsSensitiveData {
            log.debug("TLS.auth: Parsed server random: [\(serverRandom1.toHex()), \(serverRandom2.toHex())]")
        } else {
            log.debug("TLS.auth: Parsed server random")
        }
        
        if let serverOptsString = serverOpts.nullTerminatedString(fromOffset: 0) {
            log.debug("TLS.auth: Parsed server opts: \"\(serverOptsString)\"")
        }
        
        self.serverRandom1 = serverRandom1
        self.serverRandom2 = serverRandom2
        controlBuffer.remove(untilOffset: offset)
        
        return true
    }
    
    func parseMessages() -> [String] {
        var messages = [String]()
        var offset = 0
        
        while true {
            guard let msg = controlBuffer.nullTerminatedString(fromOffset: offset) else {
                break
            }
            messages.append(msg)
            offset += msg.count + 1
        }

        controlBuffer.remove(untilOffset: offset)

        return messages
    }
}
