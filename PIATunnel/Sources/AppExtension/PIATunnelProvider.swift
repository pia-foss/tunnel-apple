//
//  PIATunnelProvider.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/1/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import NetworkExtension
import SwiftyBeaver

private let log = SwiftyBeaver.self

/**
 Provides an all-in-one `NEPacketTunnelProvider` implementation for use in a
 Packet Tunnel Provider extension both on iOS and macOS.
 */
open class PIATunnelProvider: NEPacketTunnelProvider, SessionProxyDelegate {
    private static var udpContext = 0
    
    // MARK: Tweaks
    
    /// The log separator between sessions.
    public var logSeparator = "--- EOF ---"
    
    /// The maximum number of lines in the log.
    public var maxLogLines = 1000
    
    /// The number of milliseconds after which the tunnel is shut down forcibly.
    public var shutdownTimeout = 2000
    
    /// The number of milliseconds after a reconnection attempt is issued.
    public var reconnectionDelay = 1000
    
    /// The number of UDP failures after which the tunnel is expected to die.
    public var maxUDPFailures = 3

    // MARK: Constants
    
    private let memoryLog = MemoryDestination()

    private let observer = InterfaceObserver()
    
    private let tunnelQueue = DispatchQueue(label: PIATunnelProvider.description())
    
    private let prngSeedLength = 64
    
    private let caTmpFilename = "CA.pem"
    
    private var cachesURL: URL {
        return URL(fileURLWithPath: NSSearchPathForDirectoriesInDomains(.cachesDirectory, .userDomainMask, true)[0])
    }
    
    private var tmpCaURL: URL {
        return cachesURL.appendingPathComponent(caTmpFilename)
    }
    
    // MARK: Tunnel configuration

    private var bundleIdentifier: String!
    
    private var endpoint: AuthenticatedEndpoint!

    private var cfg: Configuration!
    
    // MARK: Internal state

    private var proxy: SessionProxy?
    
    private var udp: NWUDPSession?
    
    private var udpFailures = 0

    private var pendingStartHandler: ((Error?) -> Void)?
    
    private var pendingStopHandler: (() -> Void)?
    
    // MARK: NEPacketTunnelProvider (XPC queue)
    
    /// :nodoc:
    open override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        do {
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
                throw TunnelError.configuration
            }
            guard let bundleIdentifier = tunnelProtocol.providerBundleIdentifier else {
                throw TunnelError.configuration
            }
            guard let providerConfiguration = tunnelProtocol.providerConfiguration else {
                throw TunnelError.configuration
            }
            try endpoint = AuthenticatedEndpoint(protocolConfiguration: tunnelProtocol)
            try cfg = Configuration.parsed(from: providerConfiguration)
            self.bundleIdentifier = bundleIdentifier
        } catch let e {
            NSLog("Tunnel configuration incomplete!")
            cancelTunnelWithError(e)
            return
        }

        if var existingLog = cfg.existingLog {
            existingLog.append("")
            existingLog.append(logSeparator)
            existingLog.append("")
            memoryLog.buffer = existingLog
        }

        configureLogging(debug: cfg.shouldDebug)
        
        log.info("Starting tunnel...")
        
        guard EncryptionProxy.prepareRandomNumberGenerator(seedLength: prngSeedLength) else {
            cancelTunnelWithError(TunnelError.prngInitialization)
            return
        }
        
        do {
            try cfg.handshake.write(to: tmpCaURL)
        } catch {
            cancelTunnelWithError(TunnelError.certificateSerialization)
            return
        }

        cfg.print()
        
        let caPath = tmpCaURL.path
//        log.info("Temporary CA is stored to: \(caPath)")
        let encryption = SessionProxy.EncryptionParameters(cfg.cipher.rawValue, cfg.digest.rawValue, caPath, cfg.handshake.digest)
        let credentials = SessionProxy.Credentials(endpoint.username, endpoint.password)
        
        let proxy: SessionProxy
        do {
            proxy = try SessionProxy(queue: tunnelQueue, encryption: encryption, credentials: credentials)
        } catch let e {
            cancelTunnelWithError(e)
            return
        }
        if let renegotiatesAfterSeconds = cfg.renegotiatesAfterSeconds {
            proxy.renegotiatesAfter = Double(renegotiatesAfterSeconds)
        }
        proxy.delegate = self
        self.proxy = proxy

        logCurrentSSID()

        pendingStartHandler = completionHandler
        tunnelQueue.sync {
            self.connectTunnel(endpoint: NWHostEndpoint(hostname: endpoint.hostname, port: endpoint.port))
        }
    }
    
    /// :nodoc:
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        pendingStartHandler = nil
        log.info("Stopping tunnel...")
        
        // flush a first time early, possibly before kill
        flushLog()

        guard let proxy = proxy else {
            completionHandler()
            return
        }

        schedule(after: .milliseconds(shutdownTimeout)) {
            log.warning("Tunnel not responding after \(self.shutdownTimeout) milliseconds, forcing stop")
            self.flushLog()
            completionHandler()
        }
        pendingStopHandler = completionHandler
        tunnelQueue.sync {
            proxy.shutdown(error: nil)
        }
    }
    
    /// :nodoc:
    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        var response: Data?
        switch Message(messageData) {
        case .requestLog:
            response = memoryLog.buffer.joined(separator: "\n").data(using: .utf8)

        default:
            break
        }
        completionHandler?(response)
    }
    
    // MARK: Connection (tunnel queue)

    private func connectTunnel(endpoint: NWEndpoint) {
        log.info("Creating UDP session")
        log.info("Will connect to \(endpoint)")

        NotificationCenter.default.addObserver(self, selector: #selector(handleWifiChange), name: .__InterfaceObserverDidDetectWifiChange, object: nil)
        observer.start(queue: tunnelQueue)

        udp = createUDPSession(to: endpoint, from: nil)
        udp?.addObserver(self, forKeyPath: #keyPath(NWUDPSession.state), options: [.initial, .new], context: &PIATunnelProvider.udpContext)
        udp?.addObserver(self, forKeyPath: #keyPath(NWUDPSession.hasBetterPath), options: .new, context: &PIATunnelProvider.udpContext)
    }
    
    private func finishTunnelDisconnection(error: Error?) {
        proxy?.cleanup()

        observer.stop()
        NotificationCenter.default.removeObserver(self, name: .__InterfaceObserverDidDetectWifiChange, object: nil)

        udp?.removeObserver(self, forKeyPath: #keyPath(NWUDPSession.state), context: &PIATunnelProvider.udpContext)
        udp?.removeObserver(self, forKeyPath: #keyPath(NWUDPSession.hasBetterPath), context: &PIATunnelProvider.udpContext)
        udp = nil

        if let error = error {
            log.error("Tunnel did stop (error: \(error))")
        } else {
            log.info("Tunnel did stop on request")
        }

        flushLog()
    }

    private func disposeTunnel(error: Error?) {
        flushLog()

        proxy = nil
        let fm = FileManager.default
        try? fm.removeItem(at: tmpCaURL)
        
        // failed to start
        if (pendingStartHandler != nil) {
            pendingStartHandler?(error)
            pendingStartHandler = nil
        }
        // stopped intentionally
        else if (pendingStopHandler != nil) {
            pendingStopHandler?()
            pendingStopHandler = nil
        }
        // stopped externally, unrecoverable
        else {
            cancelTunnelWithError(error)
        }
    }
    
    private func handleUDPStateChange(udp: NWUDPSession) {
        guard let proxy = proxy else {
            fatalError("Observing UDP events without initializing a SessionProxy before")
        }

        var shouldShutdown = false
        var shutdownError: Error?

        switch udp.state {
        case .ready:
            proxy.setLink(link: NEUDPInterface(udp: udp))
            
        case .cancelled:
            shouldShutdown = true
            shutdownError = proxy.stopError
            
        case .failed:
            udpFailures += 1
            shouldShutdown = true
            shutdownError = proxy.stopError ?? TunnelError.udpError
            log.debug("UDP failures so far: \(udpFailures) (max = \(maxUDPFailures))")

        default:
            break
        }

        if shouldShutdown {
            finishTunnelDisconnection(error: shutdownError)
            if reasserting {
                guard (udpFailures < maxUDPFailures) else {
                    log.debug("Too many UDP failures (\(udpFailures)), tunnel will die now")
                    reasserting = false
                    disposeTunnel(error: shutdownError)
                    return
                }
                log.debug("Disconnection is recoverable, tunnel will reconnect in \(reconnectionDelay) milliseconds...")
                schedule(after: .milliseconds(reconnectionDelay)) {
                    self.connectTunnel(endpoint: udp.endpoint)
                }
                return
            }
            disposeTunnel(error: shutdownError)
        }
    }
    
    @objc private func handleWifiChange() {
        log.info("Stopping tunnel due to network change (will reconnect)")
        logCurrentSSID()
        proxy?.reconnect(error: TunnelError.networkChanged)
    }
    
    private func handlePathChange() {
        log.info("Stopping tunnel due to a new better path (will reconnect)")
        logCurrentSSID()
        proxy?.reconnect(error: TunnelError.networkChanged)
    }
    
    // MARK: Connection KVO (any queue)
    
    /// :nodoc:
    open override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        guard (context == &PIATunnelProvider.udpContext) else {
            super.observeValue(forKeyPath: keyPath, of: object, change: change, context: context)
            return
        }
        if let keyPath = keyPath {
            log.debug("KVO change reported (\(anyPointer(object)).\(keyPath))")
        }
        tunnelQueue.async {
            self.observeValueInTunnelQueue(forKeyPath: keyPath, of: object, change: change, context: context)
        }
    }

    private func observeValueInTunnelQueue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        if let keyPath = keyPath {
            log.debug("KVO change reported (\(anyPointer(object)).\(keyPath))")
        }
        guard let udp = object as? NWUDPSession, (udp == self.udp) else {
            log.warning("Discard KVO change from old UDP socket")
            return
        }
        guard let keyPath = keyPath else {
            return
        }
        switch keyPath {
        case #keyPath(NWUDPSession.state):
            if let resolvedEndpoint = udp.resolvedEndpoint {
                log.debug("UDP socket state is \(udp.state) (endpoint: \(udp.endpoint) -> \(resolvedEndpoint))")
            } else {
                log.debug("UDP socket state is \(udp.state) (endpoint: \(udp.endpoint) -> in progress)")
            }
            handleUDPStateChange(udp: udp)

        case #keyPath(NWUDPSession.hasBetterPath):
            guard udp.hasBetterPath else {
                break
            }
            log.debug("UDP socket has a better path")
            handlePathChange()
            
        default:
            break
        }
    }
    
    // MARK: SessionProxyDelegate (tunnel queue)

    /// :nodoc:
    public func sessionDidStart(_ proxy: SessionProxy, remoteAddress: String, address: String, gatewayAddress: String, dnsServers: [String]) {
        reasserting = false

        log.info("Tunnel did start")
        
        log.info("Returned ifconfig parameters:")
        log.info("\tTunnel: \(remoteAddress)")
        log.info("\tOwn address: \(address)")
        log.info("\tGateway: \(gatewayAddress)")
        log.info("\tDNS: \(dnsServers)")
        
        updateNetwork(tunnel: remoteAddress, vpn: address, gateway: gatewayAddress, dnsServers: dnsServers) { (error) in
            if let error = error {
                log.error("Failed to configure tunnel: \(error)")
                self.pendingStartHandler?(error)
                self.pendingStartHandler = nil
                return
            }
            
            log.info("Finished configuring tunnel!")
            self.tunnelQueue.sync {
                proxy.setTunnel(tunnel: NETunnelInterface(flow: self.packetFlow))
            }

            self.pendingStartHandler?(nil)
            self.pendingStartHandler = nil
        }
    }
    
    /// :nodoc:
    public func sessionDidStop(_: SessionProxy, shouldReconnect: Bool) {
        if shouldReconnect {
            reasserting = true
        }
        udp?.cancel()
    }

    private func updateNetwork(tunnel: String, vpn: String, gateway: String, dnsServers: [String], completionHandler: @escaping (Error?) -> Void) {
        
        // route all traffic to VPN
        let defaultRoute = NEIPv4Route.default()
        defaultRoute.gatewayAddress = gateway
        
        let ipv4Settings = NEIPv4Settings(addresses: [vpn], subnetMasks: ["255.255.255.255"])
        ipv4Settings.includedRoutes = [defaultRoute]
        ipv4Settings.excludedRoutes = []
        
        let dnsSettings = NEDNSSettings(servers: dnsServers)
        
        let newSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnel)
        newSettings.ipv4Settings = ipv4Settings
        newSettings.dnsSettings = dnsSettings
        newSettings.mtu = cfg.mtu
        
        setTunnelNetworkSettings(newSettings, completionHandler: completionHandler)
    }
    
    // MARK: Helpers
    
    private func configureLogging(debug: Bool) {
        let logLevel: SwiftyBeaver.Level = (debug ? .debug : .info)
        let logFormat = "$Dyyyy-MM-dd HH:mm:ss.SSS$d $L $N.$F:$l - $M"
        
        if debug {
            let console = ConsoleDestination()
            console.useNSLog = true
            console.minLevel = logLevel
            console.format = logFormat
            log.addDestination(console)
        }
        
        let memory = memoryLog
        memory.minLevel = logLevel
        memory.format = logFormat
        memory.maxLines = maxLogLines
        log.addDestination(memoryLog)
    }
    
    private func flushLog() {
        log.debug("Flushing log...")
        _ = log.flush(secondTimeout: 1)
        if let key = cfg.debugLogKey {
            let defaults = cfg.defaults
            defaults?.set(memoryLog.buffer, forKey: key)
            defaults?.synchronize()
        }
    }

    private func schedule(after: DispatchTimeInterval, block: @escaping () -> Void) {
        let deadline = DispatchTime.now() + after
        tunnelQueue.asyncAfter(deadline: deadline, execute: block)
    }

    private func logCurrentSSID() {
        if let ssid = observer.currentWifiNetworkName() {
            log.debug("Current SSID: '\(ssid)'")
        } else {
            log.debug("Current SSID: none (disconnected from WiFi)")
        }
    }
    
    private func anyPointer(_ object: Any?) -> UnsafeMutableRawPointer {
        let anyObject = object as AnyObject
        return Unmanaged<AnyObject>.passUnretained(anyObject).toOpaque()
    }
}
