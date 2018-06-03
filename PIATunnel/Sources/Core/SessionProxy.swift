//
//  SessionProxy.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import SwiftyBeaver
import __PIATunnelNative

private let log = SwiftyBeaver.self

/// The possible errors raised/thrown during `SessionProxy` operation.
public enum SessionError: Error {

    /// The connection attempt timed out.
    case connectionTimeout
    
    /// The peer failed to verify.
    case peerVerification

    /// The VPN session id is missing.
    case missingSessionId
    
    /// The VPN session id doesn't match.
    case sessionMismatch
    
    /// The connection key is wrong or wasn't expected.
    case badKey
    
    /// The TLS negotiation failed.
    case tlsError

    /// The control packet has an incorrect prefix payload.
    case wrongControlDataPrefix

    /// The provided credentials failed authentication.
    case badCredentials
    
    /// The reply to PUSH_REQUEST is malformed.
    case malformedPushReply

    /// A write operation failed at the link layer (e.g. network unreachable).
    case failedLinkWrite
    
    /// The server couldn't ping back before timeout.
    case pingTimeout
}

/// Observes major events notified by a `SessionProxy`.
public protocol SessionProxyDelegate: class {

    /**
     Called after starting a session.

     - Parameter remoteAddress: The address of the VPN server.
     - Parameter address: The obtained address.
     - Parameter gatewayAddress: The address of the gateway.
     - Parameter dnsServers: The DNS servers set up for this session.
     */
    func sessionDidStart(_: SessionProxy, remoteAddress: String, address: String, gatewayAddress: String, dnsServers: [String])
    
    /**
     Called after stopping a session.
     
     - Parameter shouldReconnect: When `true`, the session can/should be restarted. Usually because the stop reason was recoverable.
     - Seealso: `SessionProxy.reconnect(...)`
     */
    func sessionDidStop(_: SessionProxy, shouldReconnect: Bool)
}

/// Provides methods to set up and maintain an OpenVPN session.
public class SessionProxy {

    /// Wraps the encryption parameters of the session.
    public struct EncryptionParameters {

        /// The cipher algorithm for data encryption. Must follow OpenSSL nomenclature, e.g. "AES-128-CBC".
        public let cipherName: String
        
        /// The digest algorithm for HMAC. Must follow OpenSSL nomenclature, e.g. "SHA-1".
        public let digestName: String

        /// The path to the CA for TLS negotiation (PEM format).
        public let caPath: String

        /// The MD5 digest of the CA (computed from DER format).
        public let caDigest: String

        /// :nodoc:
        public init(_ cipherName: String, _ digestName: String, _ caPath: String, _ caDigest: String) {
            self.cipherName = cipherName
            self.digestName = digestName
            self.caPath = caPath
            self.caDigest = caDigest
        }
    }
    
    /// A set of credentials.
    public struct Credentials {

        /// An username.
        public let username: String

        /// A password.
        public let password: String

        /// :nodoc:
        public init(_ username: String, _ password: String) {
            self.username = username
            self.password = password
        }
    }
    
    private enum StopMethod {
        case shutdown
        
        case reconnect
    }
    
    // MARK: Configuration
    
    private let encryption: EncryptionParameters
    
    private let credentials: Credentials
    
    private let encodedSettings: Data
    
    /// Sends periodical keep-alive packets.
    public var sendsKeepAlive: Bool

    /// The number of seconds after which a renegotiation should be initiated. If `nil`, the client will never initiate a renegotiation.
    public var renegotiatesAfter: TimeInterval?
    
    /// An optional `SessionProxyDelegate` for receiving session events.
    public weak var delegate: SessionProxyDelegate?
    
    // MARK: State

    private let queue: DispatchQueue

    private var tlsObserver: NSObjectProtocol?

    private var keys: [UInt8: SessionKey]

    private var oldKeys: [SessionKey]

    private var negotiationKeyIdx: UInt8
    
    private var currentKeyIdx: UInt8?
    
    private var negotiationKey: SessionKey {
        guard let key = keys[negotiationKeyIdx] else {
            fatalError("Keys are empty or index \(negotiationKeyIdx) not found in \(keys.keys)")
        }
        return key
    }
    
    private var currentKey: SessionKey? {
        guard let i = currentKeyIdx else {
            return nil
        }
        return keys[i]
    }
    
    private var link: LinkInterface?
    
    private var tunnel: TunnelInterface?
    
    private var isReliableLink: Bool {
        return link?.isReliable ?? false
    }

    private var sessionId: Data?
    
    private var remoteSessionId: Data?

    private var authToken: String?
    
    private var nextPushRequestDate: Date?
    
    private var connectedDate: Date?

    private var lastPingOut: Date
    
    private var lastPingIn: Date
    
    private var isStopping: Bool
    
    private var isSuspended: Bool
    
    /// The optional reason why the session stopped.
    public private(set) var stopError: Error?
    
    // MARK: Control
    
    private let controlPlainBuffer: ZeroingData

    private var controlQueueOut: [ControlPacket]

    private var controlQueueIn: [ControlPacket]

    private var controlPendingAcks: Set<UInt32>
    
    private var controlPacketIdOut: UInt32

    private var controlPacketIdIn: UInt32
    
    private var authenticator: Authenticator?
    
    // MARK: Init

    /**
     Creates a VPN session.
     
     - Parameter queue: The `DispatchQueue` where to run the session loop.
     - Parameter encryption: The `SessionProxy.EncryptionParameters` to establish for this session.
     - Parameter credentials: The `SessionProxy.Credentials` required for authentication.
     */
    public init(queue: DispatchQueue, encryption: EncryptionParameters, credentials: Credentials) throws {
        self.queue = queue
        self.encryption = encryption
        self.credentials = credentials

        encodedSettings = try TunnelSettings(caMd5Digest: encryption.caDigest,
                                             cipherName: encryption.cipherName,
                                             digestName: encryption.digestName).encodedData()
        sendsKeepAlive = true
        renegotiatesAfter = nil
        
        keys = [:]
        oldKeys = []
        negotiationKeyIdx = 0
        lastPingOut = Date.distantPast
        lastPingIn = Date.distantPast
        isStopping = false
        isSuspended = false
        
        controlPlainBuffer = Z(count: TLSBoxMaxBufferLength)
        controlQueueOut = []
        controlQueueIn = []
        controlPendingAcks = []
        controlPacketIdOut = 0
        controlPacketIdIn = 0
    }
    
    deinit {
        cleanup()
    }
    
    // MARK: Public interface

    /**
     Establishes the link interface for this session. The interface must be up and running for sending and receiving packets.
     
     - Precondition: `link` is an active network interface.
     - Postcondition: The VPN negotiation is started.
     - Parameter link: The `LinkInterface` on which to establish the VPN session.
     */
    public func setLink(link: LinkInterface) {
        guard (self.link == nil) else {
            log.warning("Link interface already set!")
            return
        }

        log.debug("Starting VPN session")
        
        // WARNING: runs in notification source queue (we know it's "queue", but better be safe than sorry)
        tlsObserver = NotificationCenter.default.addObserver(forName: .TLSBoxPeerVerificationError, object: nil, queue: nil) { (notification) in
            self.queue.async {
                self.deferStop(.shutdown, SessionError.peerVerification)
            }
        }
        
        self.link = link
        start()
    }
    
    /**
     Establishes the tunnel interface for this session. The interface must be up and running for sending and receiving packets.
     
     - Precondition: `tunnel` is an active network interface.
     - Postcondition: The VPN data channel is open.
     - Parameter tunnel: The `TunnelInterface` on which to exchange the VPN data traffic.
     */
    public func setTunnel(tunnel: TunnelInterface) {
        guard (self.tunnel == nil) else {
            log.warning("Tunnel interface already set!")
            return
        }
        self.tunnel = tunnel
        loopTunnel()
    }

    /**
     Shuts down the session with an optional `Error` reason. Does nothing if the session is already stopped or about to stop.
     
     - Parameter error: An optional `Error` being the reason of the shutdown.
     */
    public func shutdown(error: Error?) {
        guard !isStopping else {
            log.warning("Ignore stop request, already stopping!")
            return
        }
        deferStop(.shutdown, error)
    }
    
    /**
     Shuts down the session with an optional `Error` reason and signals a reconnect flag to `SessionProxyDelegate.sessionDidStop(...)`. Does nothing if the session is already stopped or about to stop.
     
     - Parameter error: An optional `Error` being the reason of the shutdown.
     - Seealso: `SessionProxyDelegate.sessionDidStop(...)`
     */
    public func reconnect(error: Error?) {
        guard !isStopping else {
            log.warning("Ignore stop request, already stopping!")
            return
        }
        deferStop(.reconnect, error)
    }
    
    /**
     Suspends activity.
     */
    public func suspend() {
        log.info("Suspending...")

        isSuspended = true
    }

    /**
     Resumes activity and sends a packet to wake up link or trigger an early failure.
     */
    public func resume() {
        log.info("Resuming...")

        isSuspended = false
        ping()
    }

    // Ruby: cleanup
    /**
     Cleans up the session resources.
     */
    public func cleanup() {
        log.info("Cleaning up...")

        if let observer = tlsObserver {
            NotificationCenter.default.removeObserver(observer)
            tlsObserver = nil
        }
        
//        for (_, key) in keys {
//            key.dispose()
//        }
        keys.removeAll()
        oldKeys.removeAll()
        negotiationKeyIdx = 0
        currentKeyIdx = nil
        
        sessionId = nil
        remoteSessionId = nil
        authToken = nil
        nextPushRequestDate = nil
        connectedDate = nil
        authenticator = nil
        link = nil
        if !(tunnel?.isPersistent ?? false) {
            tunnel = nil
        }
        
        isStopping = false
        stopError = nil
    }

    // MARK: Loop

    // Ruby: start
    private func start() {
        loopLink()
        hardReset()

        guard !keys.isEmpty else {
            fatalError("Main loop must follow hard reset, keys are empty!")
        }

        loopNegotiation()
    }
    
    private func loopNegotiation() {
        guard let link = link else {
            return
        }
        guard !keys.isEmpty else {
            return
        }

        guard !negotiationKey.didHardResetTimeOut(link: link) else {
            doReconnect(error: SessionError.connectionTimeout)
            return
        }
        guard !negotiationKey.didNegotiationTimeOut(link: link) else {
            doShutdown(error: SessionError.connectionTimeout)
            return
        }
            
        if !isReliableLink {
            pushRequest()
            flushControlQueue()
        }
        
        guard (negotiationKey.controlState == .connected) else {
            queue.asyncAfter(deadline: .now() + Configuration.tickInterval) { [weak self] in
                self?.loopNegotiation()
            }
            return
        }

        // let loop die when negotiation is complete
    }

    // Ruby: udp_loop
    private func loopLink() {

        // WARNING: runs in Network.framework queue
        link?.setReadHandler { [weak self] (newPackets, error) in
            if let error = error {
                log.error("Failed LINK read: \(error)")
                return
            }
            
            if let packets = newPackets, !packets.isEmpty {
                self?.queue.sync {
                    self?.maybeRenegotiate()

//                    log.verbose("Received \(packets.count) packets from \(self.linkName)")
                    self?.receiveLink(packets: packets)
                }
            }
        }
    }

    // Ruby: tun_loop
    private func loopTunnel() {
        
        // WARNING: runs in NEPacketTunnelFlow queue
        tunnel?.setReadHandler { [weak self] (newPackets, error) in
            if let error = error {
                log.error("Failed TUN read: \(error)")
                return
            }

            if let packets = newPackets, !packets.isEmpty {
                self?.queue.sync {
//                    log.verbose("Received \(packets.count) packets from \(self.tunnelName)")
                    self?.receiveTunnel(packets: packets)
                }
            }
        }
    }

    // Ruby: recv_link
    private func receiveLink(packets: [Data]) {
        guard shouldHandlePackets() else {
            return
        }
        
        lastPingIn = Date()

        var dataPacketsByKey = [UInt8: [Data]]()
        
        for packet in packets {
//            log.verbose("Received data from \(linkName) (\(packet.count) bytes): \(packet.toHex())")

            guard let firstByte = packet.first else {
                return
            }
            let codeValue = firstByte >> 3
            guard let code = PacketCode(rawValue: codeValue) else {
                log.warning("Ignored unknown packet code \(codeValue)")
                return
            }
            let key = firstByte & 0b111

//            log.verbose("Parsed packet with (code, key) = (\(code), \(key))")
            
            if (code == .dataV1) {
                guard let _ = keys[key] else {
                    log.error("Key with id \(key) not found")
                    deferStop(.shutdown, SessionError.badKey)
                    return
                }

                // XXX: improve with array reference
                var dataPackets = dataPacketsByKey[key] ?? [Data]()
                dataPackets.append(packet)
                dataPacketsByKey[key] = dataPackets

                continue
            }
            
            var offset = 1
            let sessionId = packet.subdata(offset: offset, count: ProtocolMacros.sessionIdLength)
            offset += ProtocolMacros.sessionIdLength
            
            let ackSize = packet[offset]
            offset += 1

            log.debug("Packet has code \(code), sessionId \(sessionId.toHex()) and \(ackSize) acks entries")

            if (ackSize > 0) {
                var ackedPacketIds = [UInt32]()
                for _ in 0..<ackSize {
                    let ackedPacketId = CFSwapInt32BigToHost(packet.UInt32Value(from: offset))
                    ackedPacketIds.append(ackedPacketId)
                    offset += ProtocolMacros.packetIdLength
                }
                let remoteSessionId = packet.subdata(offset: offset, count: ProtocolMacros.sessionIdLength)
                offset += ProtocolMacros.sessionIdLength

                log.debug("Server acked packetIds \(ackedPacketIds) with remoteSessionId \(remoteSessionId.toHex())")

                handleAcks(ackedPacketIds, remoteSessionId: remoteSessionId)
            }

            if (code == .ackV1) {
                return
            }

            let packetId = CFSwapInt32BigToHost(packet.UInt32Value(from: offset))
            log.debug("Control packet has packetId \(packetId)")
            offset += ProtocolMacros.packetIdLength

            sendAck(key: key, packetId: packetId, remoteSessionId: sessionId)

            var payload: Data?
            if (offset < packet.count) {
                payload = packet.subdata(in: offset..<packet.count)

                if let payload = payload {
                    if Configuration.logsSensitiveData {
                        log.debug("Control packet payload (\(payload.count) bytes): \(payload.toHex())")
                    } else {
                        log.debug("Control packet payload (\(payload.count) bytes)")
                    }
                }
            }

            let controlPacket = ControlPacket(packetId, code, key, sessionId, payload)
            controlQueueIn.append(controlPacket)
            controlQueueIn.sort { $0.packetId < $1.packetId }
            
            for queuedControlPacket in controlQueueIn {
                if (queuedControlPacket.packetId < controlPacketIdIn) {
                    controlQueueIn.removeFirst()
                    continue
                }
                if (queuedControlPacket.packetId != controlPacketIdIn) {
                    return
                }

                handleControlPacket(queuedControlPacket)

                controlPacketIdIn += 1
                controlQueueIn.removeFirst()
            }
        }

        // send decrypted packets to tunnel all at once
        for (keyId, dataPackets) in dataPacketsByKey {
            guard let sessionKey = keys[keyId] else {
                log.warning("Accounted a data packet for which the cryptographic key hadn't been found")
                continue
            }
            handleDataPackets(dataPackets, key: sessionKey)
        }
    }
    
    // Ruby: recv_tun
    private func receiveTunnel(packets: [Data]) {
        guard shouldHandlePackets() else {
            return
        }
        sendDataPackets(packets)
        lastPingOut = Date()
    }
    
    // Ruby: ping
    private func ping() {
        guard (currentKey?.controlState == .connected) else {
            return
        }
        
        let now = Date()
        guard (now.timeIntervalSince(lastPingIn) <= Configuration.pingTimeout) else {
            deferStop(.shutdown, SessionError.pingTimeout)
            return
        }

        let elapsed = now.timeIntervalSince(lastPingOut)
        if sendsKeepAlive {
            defer {
                let remaining = min(Configuration.pingInterval, Configuration.pingInterval - elapsed)
                queue.asyncAfter(deadline: .now() + remaining) { [weak self] in
                    self?.ping()
                }
            }
        }

        guard (elapsed >= Configuration.pingInterval) else {
            return
        }
    
        log.debug("Send ping")
        
        sendDataPackets([ProtocolMacros.pingString])
        lastPingOut = Date()
    }
    
    // MARK: Handshake
    
    // Ruby: reset_ctrl
    private func resetControlChannel() {
        controlPlainBuffer.zero()
        controlQueueOut.removeAll()
        controlQueueIn.removeAll()
        controlPendingAcks.removeAll()
        controlPacketIdOut = 0
        controlPacketIdIn = 0
        authenticator = nil
    }
    
    // Ruby: hard_reset
    private func hardReset() {
        log.debug("Send hard reset")

        resetControlChannel()
        do {
            try sessionId = SecureRandom.data(length: ProtocolMacros.sessionIdLength)
        } catch let e {
            deferStop(.shutdown, e)
            return
        }
        negotiationKeyIdx = 0
        keys[negotiationKeyIdx] = SessionKey(id: UInt8(negotiationKeyIdx))
        log.debug("Negotiation key index is \(negotiationKeyIdx)")

        negotiationKey.state = .hardReset
        enqueueControlPackets(code: .hardResetClientV2, key: UInt8(negotiationKeyIdx), payload: encodedSettings)
    }
    
    // Ruby: soft_reset
    private func softReset() {
        log.debug("Send soft reset")
        
        resetControlChannel()
        negotiationKeyIdx = max(1, (negotiationKeyIdx + 1) % ProtocolMacros.numberOfKeys)
        keys[negotiationKeyIdx] = SessionKey(id: UInt8(negotiationKeyIdx))
        log.debug("Negotiation key index is \(negotiationKeyIdx)")

        negotiationKey.state = .softReset
        negotiationKey.softReset = true
        loopNegotiation()
        enqueueControlPackets(code: .softResetV1, key: UInt8(negotiationKeyIdx), payload: Data())
    }
    
    // Ruby: on_tls_connect
    private func onTLSConnect() {
        log.debug("TLS.connect: Handshake is complete")

        negotiationKey.controlState = .preAuth
        
        do {
            authenticator = try Authenticator(credentials.username, authToken ?? credentials.password)
            try authenticator?.putAuth(into: negotiationKey.tls)
        } catch let e {
            deferStop(.shutdown, e)
            return
        }

        guard let cipherTextOut = try? negotiationKey.tls.pullCipherText() else {
            log.verbose("TLS.auth: Still can't pull ciphertext")
            return
        }

        log.debug("TLS.auth: Pulled ciphertext (\(cipherTextOut.count) bytes)")
        enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)
    }
    
    // Ruby: push_request
    private func pushRequest() {
        guard (negotiationKey.controlState == .preIfConfig) else {
            return
        }
        if !isReliableLink {
            guard let targetDate = nextPushRequestDate, (Date() > targetDate) else {
                return
            }
        }
        
        log.debug("TLS.ifconfig: Put plaintext (PUSH_REQUEST)")
        try? negotiationKey.tls.putPlainText("PUSH_REQUEST\0")
        
        guard let cipherTextOut = try? negotiationKey.tls.pullCipherText() else {
            log.verbose("TLS.ifconfig: Still can't pull ciphertext")
            return
        }
        
        log.debug("TLS.ifconfig: Send pulled ciphertext (\(cipherTextOut.count) bytes)")
        enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)
        
        if negotiationKey.softReset {
            authenticator = nil
            negotiationKey.controlState = .connected
            connectedDate = Date()
            transitionKeys()
        }
        nextPushRequestDate = Date().addingTimeInterval(Configuration.retransmissionLimit)
    }
    
    private func maybeRenegotiate() {
        guard let renegotiatesAfter = renegotiatesAfter else {
            return
        }
        guard (negotiationKeyIdx == currentKeyIdx) else {
            return
        }
        
        let elapsed = -negotiationKey.startTime.timeIntervalSinceNow
        if (elapsed > renegotiatesAfter) {
            log.debug("Renegotiating after \(elapsed) seconds")
            softReset()
        }
    }
    
    // MARK: Control

    // Ruby: handle_ctrl_pkt
    private func handleControlPacket(_ packet: ControlPacket) {
        guard (packet.key == negotiationKey.id) else {
            log.error("Bad key in control packet (\(packet.key) != \(negotiationKey.id))")
//            deferStop(.shutdown, SessionError.badKey)
            return
        }
        
        log.debug("Handle control packet with code \(packet.code) and id \(packet.packetId)")

        if (((packet.code == .hardResetServerV2) && (negotiationKey.state == .hardReset)) ||
            ((packet.code == .softResetV1) && (negotiationKey.state == .softReset))) {
            
            if (negotiationKey.state == .hardReset) {
                guard let sessionId = packet.sessionId else {
                    deferStop(.shutdown, SessionError.missingSessionId)
                    return
                }
                remoteSessionId = sessionId
            }
            guard let remoteSessionId = remoteSessionId else {
                log.error("No remote session id")
                deferStop(.shutdown, SessionError.missingSessionId)
                return
            }
            guard (packet.sessionId == remoteSessionId) else {
                if let packetSessionId = packet.sessionId {
                    log.error("Packet session mismatch (\(packetSessionId.toHex()) != \(remoteSessionId.toHex()))")
                }
                deferStop(.shutdown, SessionError.sessionMismatch)
                return
            }

            negotiationKey.state = .tls

            log.debug("Remote sessionId is \(remoteSessionId.toHex())")
            log.debug("Start TLS handshake")

            negotiationKey.tlsOptional = TLSBox(caPath: encryption.caPath)
            do {
                try negotiationKey.tls.start(withPeerVerification: true)
            } catch let e {
                deferStop(.shutdown, e)
                return
            }

            guard let cipherTextOut = try? negotiationKey.tls.pullCipherText() else {
                deferStop(.shutdown, SessionError.tlsError)
                return
            }

            log.debug("TLS.connect: Pulled ciphertext (\(cipherTextOut.count) bytes)")
            enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)
        }
        else if ((packet.code == .controlV1) && (negotiationKey.state == .tls)) {
            guard let remoteSessionId = remoteSessionId else {
                deferStop(.shutdown, SessionError.missingSessionId)
                return
            }
            guard (packet.sessionId == remoteSessionId) else {
                if let packetSessionId = packet.sessionId {
                    log.error("Packet session mismatch (\(packetSessionId.toHex()) != \(remoteSessionId.toHex()))")
                }
                deferStop(.shutdown, SessionError.sessionMismatch)
                return
            }
            
            guard let cipherTextIn = packet.payload else {
                log.warning("TLS.connect: Control packet with empty payload?")
                return
            }

            log.debug("TLS.connect: Put received ciphertext (\(cipherTextIn.count) bytes)")
            try? negotiationKey.tls.putCipherText(cipherTextIn)

            if let cipherTextOut = try? negotiationKey.tls.pullCipherText() {
                log.debug("TLS.connect: Send pulled ciphertext (\(cipherTextOut.count) bytes)")
                enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)
            }
            
            if negotiationKey.shouldOnTLSConnect() {
                onTLSConnect()
            }

            do {
                var length = 0
                try negotiationKey.tls.pullRawPlainText(controlPlainBuffer.mutableBytes, length: &length)

                let controlData = controlPlainBuffer.withOffset(0, count: length)!
                handleControlData(controlData)
            } catch _ {
            }
        }
    }

    // Ruby: handle_ctrl_data
    private func handleControlData(_ data: ZeroingData) {
        guard let auth = authenticator else { return }

        if Configuration.logsSensitiveData {
            log.debug("Pulled plain control data (\(data.count) bytes): \(data.toHex())")
        } else {
            log.debug("Pulled plain control data (\(data.count) bytes)")
        }

        auth.appendControlData(data)

        if (negotiationKey.controlState == .preAuth) {
            guard auth.isAuthReplyComplete() else {
                return
            }
            guard auth.parseAuthReply() else {
                deferStop(.shutdown, SessionError.wrongControlDataPrefix)
                return
            }
            
            setupKeys()

            negotiationKey.controlState = .preIfConfig
            nextPushRequestDate = Date().addingTimeInterval(negotiationKey.softReset ? Configuration.softResetDelay : Configuration.retransmissionLimit)
            pushRequest()
        }
        
        for message in auth.parseMessages() {
            if Configuration.logsSensitiveData {
                log.debug("Parsed control message (\(message.count) bytes): \"\(message)\"")
            } else {
                log.debug("Parsed control message (\(message.count) bytes)")
            }
            handleControlMessage(message)
        }
    }

    // Ruby: handle_ctrl_msg
    private func handleControlMessage(_ message: String) {
        guard !message.hasPrefix("AUTH_FAILED") else {
            deferStop(.shutdown, SessionError.badCredentials)
            return
        }
        
        if ((negotiationKey.controlState == .preIfConfig) && message.hasPrefix("PUSH_REPLY")) {
            log.debug("Received PUSH_REPLY")

            let ifconfigRegexp = try! NSRegularExpression(pattern: "ifconfig [\\d\\.]+ [\\d\\.]+", options: [])
            let dnsRegexp = try! NSRegularExpression(pattern: "dhcp-option DNS [\\d\\.]+", options: [])
            let authTokenRegexp = try! NSRegularExpression(pattern: "auth-token [a-zA-Z0-9/=+]+", options: [])

            var ifconfigComponents: [String]?
            ifconfigRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count), using: { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                ifconfigComponents = match.components(separatedBy: " ")
            })
            
            guard let addresses = ifconfigComponents else {
                deferStop(.shutdown, SessionError.malformedPushReply)
                return
            }
            
            let address = addresses[1]
            let gatewayAddress = addresses[2]

            var dnsServers = [String]()
            dnsRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count), using: { (result, flags, _) in
                guard let range = result?.range else { return }

                let match = (message as NSString).substring(with: range)
                let dnsEntryComponents = match.components(separatedBy: " ")

                dnsServers.append(dnsEntryComponents[2])
            })
            
            authTokenRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count), using: { (result, flags, _) in
                guard let range = result?.range else { return }

                let match = (message as NSString).substring(with: range)
                let tokenComponents = match.components(separatedBy: " ")
                
                if (tokenComponents.count > 1) {
                    self.authToken = tokenComponents[1]
                }
            })
            
            authenticator = nil
            negotiationKey.controlState = .connected
            connectedDate = Date()
            transitionKeys()

            guard let remoteAddress = link?.remoteAddress else {
                fatalError("Could not resolve link remote address")
            }
            delegate?.sessionDidStart(self, remoteAddress: remoteAddress, address: address, gatewayAddress: gatewayAddress, dnsServers: dnsServers)

            if sendsKeepAlive {
                queue.asyncAfter(deadline: .now() + Configuration.pingInterval) { [weak self] in
                    self?.ping()
                }
            }
        }
    }
    
    // Ruby: transition_keys
    private func transitionKeys() {
        if let key = currentKey {
            oldKeys.append(key)
        }
        currentKeyIdx = negotiationKeyIdx
        cleanKeys()
    }
    
    // Ruby: clean_keys
    private func cleanKeys() {
        while (oldKeys.count > 1) {
            let key = oldKeys.removeFirst()
            keys.removeValue(forKey: key.id)
//            key.dispose()
        }
    }
    
    // Ruby: q_ctrl
    private func enqueueControlPackets(code: PacketCode, key: UInt8, payload: Data) {
        guard let link = link else {
            log.warning("Not writing to LINK, interface is down")
            return
        }
        
        let oldIdOut = controlPacketIdOut
        let maxCount = link.mtu
        var queuedCount = 0
        var offset = 0
        
        repeat {
            let subPayloadLength = min(maxCount, payload.count - offset)
            let subPayloadData = payload.subdata(offset: offset, count: subPayloadLength)
            let packet = ControlPacket(controlPacketIdOut, code, key, sessionId, subPayloadData)
            
            controlQueueOut.append(packet)
            controlPacketIdOut += 1
            offset += maxCount
            queuedCount += subPayloadLength
        } while (offset < payload.count)
        
        assert(queuedCount == payload.count)
        
        let packetCount = controlPacketIdOut - oldIdOut
        if (packetCount > 1) {
            log.debug("Enqueued \(packetCount) control packets [\(oldIdOut)-\(controlPacketIdOut - 1)]")
        } else {
            log.debug("Enqueued 1 control packet [\(oldIdOut)]")
        }
        
        flushControlQueue()
    }
    
    // Ruby: flush_ctrl_q_out
    private func flushControlQueue() {
        for controlPacket in controlQueueOut {
            if let sentDate = controlPacket.sentDate {
                let timeAgo = -sentDate.timeIntervalSinceNow
                guard (timeAgo >= Configuration.retransmissionLimit) else {
                    log.debug("Skip control packet with id \(controlPacket.packetId) (sent on \(sentDate), \(timeAgo) seconds ago)")
                    continue
                }
            }

            log.debug("Send control packet with code \(controlPacket.code)")

            if let payload = controlPacket.payload {
                if Configuration.logsSensitiveData {
                    log.debug("Control packet has payload (\(payload.count) bytes): \(payload.toHex())")
                } else {
                    log.debug("Control packet has payload (\(payload.count) bytes)")
                }
            }

            let raw = controlPacket.toBuffer()
            log.debug("Send control packet (\(raw.count) bytes): \(raw.toHex())")
            
            // track pending acks for sent packets
            controlPendingAcks.insert(controlPacket.packetId)

            // WARNING: runs in Network.framework queue
            link?.writePacket(raw) { [weak self] (error) in
                self?.queue.sync {
                    if let error = error {
                        log.error("Failed LINK write during control flush: \(error)")
                        self?.deferStop(.reconnect, SessionError.failedLinkWrite)
                        return
                    }
                }
            }
            controlPacket.sentDate = Date()
        }
//        log.verbose("Packets now pending ack: \(controlPendingAcks)")
    }
    
    // Ruby: setup_keys
    private func setupKeys() {
        guard let auth = authenticator else {
            fatalError("Setting up keys without having authenticated")
        }
        guard let sessionId = sessionId else {
            fatalError("Setting up keys without a local sessionId")
        }
        guard let remoteSessionId = remoteSessionId else {
            fatalError("Setting up keys without a remote sessionId")
        }
        guard let serverRandom1 = auth.serverRandom1, let serverRandom2 = auth.serverRandom2 else {
            fatalError("Setting up keys without server randoms")
        }
        
        if Configuration.logsSensitiveData {
            log.debug("Setup keys from the following components:")
            log.debug("\tpreMaster: \(auth.preMaster.toHex())")
            log.debug("\trandom1: \(auth.random1.toHex())")
            log.debug("\trandom2: \(auth.random2.toHex())")
            log.debug("\tserverRandom1: \(serverRandom1.toHex())")
            log.debug("\tserverRandom2: \(serverRandom2.toHex())")
            log.debug("\tsessionId: \(sessionId.toHex())")
            log.debug("\tremoteSessionId: \(remoteSessionId.toHex())")
        } else {
            log.debug("Setup keys")
        }

        let proxy = EncryptionProxy(encryption.cipherName, encryption.digestName, auth, sessionId, remoteSessionId)
        let encrypter = proxy.encrypter()
        let decrypter = proxy.decrypter()
        if Configuration.usesDataOptimization {
            negotiationKey.dataPath = PointerBasedDataPath(encrypter: encrypter,
                                                           decrypter: decrypter,
                                                           maxPackets: link?.packetBufferSize ?? 200,
                                                           usesReplayProtection: Configuration.usesReplayProtection)
        } else {
            negotiationKey.dataPath = HighLevelDataPath(encrypter: encrypter,
                                                        decrypter: decrypter,
                                                        usesReplayProtection: Configuration.usesReplayProtection)
        }
    }
    
    // MARK: Data

    // Ruby: handle_data_pkt
    private func handleDataPackets(_ packets: [Data], key: SessionKey) {
        do {
            guard let decryptedPackets = try key.decrypt(packets: packets) else {
                log.warning("Could not decrypt packets, is data path set?")
                return
            }
            guard !decryptedPackets.isEmpty else {
                return
            }

            tunnel?.writePackets(decryptedPackets, completionHandler: nil)
        } catch let e {
            deferStop(.reconnect, e)
        }
    }
    
    // Ruby: send_data_pkt
    private func sendDataPackets(_ packets: [Data]) {
        guard let key = currentKey else {
            return
        }
        do {
            guard let encryptedPackets = try key.encrypt(packets: packets) else {
                log.warning("Could not encrypt packets, is data path set?")
                return
            }
            guard !encryptedPackets.isEmpty else {
                return
            }
            
            // WARNING: runs in Network.framework queue
            link?.writePackets(encryptedPackets) { [weak self] (error) in
                self?.queue.sync {
                    if let error = error {
                        log.error("Data: Failed LINK write during send data: \(error)")
                        self?.deferStop(.reconnect, SessionError.failedLinkWrite)
                        return
                    }
//                    log.verbose("Data: \(encryptedPackets.count) packets successfully written to \(self.linkName)")
                }
            }
        } catch let e {
            deferStop(.reconnect, e)
        }
    }
    
    // MARK: Acks
    
    // Ruby: handle_acks
    private func handleAcks(_ packetIds: [UInt32], remoteSessionId: Data) {
        guard (remoteSessionId == sessionId) else {
            if let sessionId = sessionId {
                log.error("Ack session mismatch (\(remoteSessionId.toHex()) != \(sessionId.toHex()))")
            }
            deferStop(.shutdown, SessionError.sessionMismatch)
            return
        }
        
        // drop queued out packets if ack-ed
        for (i, controlPacket) in controlQueueOut.enumerated() {
            if packetIds.contains(controlPacket.packetId) {
                controlQueueOut.remove(at: i)
            }
        }

        // remove ack-ed packets from pending
        controlPendingAcks.subtract(packetIds)
//        log.verbose("Packets still pending ack: \(controlPendingAcks)")

        // retry PUSH_REQUEST if ack queue is empty (all sent packets were ack'ed)
        if (isReliableLink && controlPendingAcks.isEmpty) {
            pushRequest()
        }
    }
    
    // Ruby: send_ack
    private func sendAck(key: UInt8, packetId: UInt32, remoteSessionId: Data) {
        log.debug("Send ack for received packetId \(packetId)")

        var raw = Data()
        ProtocolMacros.appendHeader(to: &raw, .ackV1, key, sessionId)
        raw.append(UInt8(1)) // ackSize
        raw.append(UInt32(packetId).bigEndian)
        raw.append(remoteSessionId)
        
        // WARNING: runs in Network.framework queue
        link?.writePacket(raw) { [weak self] (error) in
            self?.queue.sync {
                if let error = error {
                    log.error("Failed LINK write during send ack for packetId \(packetId): \(error)")
                    self?.deferStop(.reconnect, SessionError.failedLinkWrite)
                    return
                }
                log.debug("Ack successfully written to LINK for packetId \(packetId)")
            }
        }
    }
    
    // MARK: Stop
    
    private func shouldHandlePackets() -> Bool {
        return (!isStopping && !keys.isEmpty)
    }
    
    private func deferStop(_ method: StopMethod, _ error: Error?) {
        isStopping = true
        
        switch method {
        case .shutdown:
            doShutdown(error: error)
        
        case .reconnect:
            doReconnect(error: error)
        }
    }
    
    private func doShutdown(error: Error?) {
        if let error = error {
            log.error("Trigger shutdown (error: \(error))")
        } else {
            log.info("Trigger shutdown on request")
        }
        stopError = error
        delegate?.sessionDidStop(self, shouldReconnect: false)
    }
    
    private func doReconnect(error: Error?) {
        if let error = error {
            log.error("Trigger reconnection (error: \(error))")
        } else {
            log.info("Trigger reconnection on request")
        }
        stopError = error
        delegate?.sessionDidStop(self, shouldReconnect: true)
    }
}
