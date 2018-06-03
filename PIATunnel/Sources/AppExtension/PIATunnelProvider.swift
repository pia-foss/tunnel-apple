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
open class PIATunnelProvider: NEPacketTunnelProvider {
    
    // MARK: Tweaks
    
    /// The log separator between sessions.
    public var logSeparator = "--- EOF ---"
    
    /// The maximum number of lines in the log.
    public var maxLogLines = 1000
    
    /// The number of milliseconds after which the tunnel gives up on a connection attempt.
    public var socketTimeout = 5000
    
    /// The number of milliseconds after which the tunnel is shut down forcibly.
    public var shutdownTimeout = 2000
    
    /// The number of milliseconds after which a reconnection attempt is issued.
    public var reconnectionDelay = 1000
    
    /// The number of link failures after which the tunnel is expected to die.
    public var maxLinkFailures = 3

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
    
    private var socket: GenericSocket?

    private var upgradedSocket: GenericSocket?
    
    private var linkFailures = 0

    private var pendingStartHandler: ((Error?) -> Void)?
    
    private var pendingStopHandler: (() -> Void)?
    
    // MARK: NEPacketTunnelProvider (XPC queue)
    
    /// :nodoc:
    open override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        do {
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
                throw ProviderError.configuration(field: "protocolConfiguration")
            }
            guard let bundleIdentifier = tunnelProtocol.providerBundleIdentifier else {
                throw ProviderError.configuration(field: "protocolConfiguration.bundleIdentifier")
            }
            guard let providerConfiguration = tunnelProtocol.providerConfiguration else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration")
            }
            try endpoint = AuthenticatedEndpoint(protocolConfiguration: tunnelProtocol)
            try cfg = Configuration.parsed(from: providerConfiguration)
            self.bundleIdentifier = bundleIdentifier
        } catch let e {
            var message: String?
            if let te = e as? ProviderError {
                switch te {
                case .credentials(let field):
                    message = "Tunnel credentials unavailable: \(field)"
                    
                case .configuration(let field):
                    message = "Tunnel configuration incomplete: \(field)"
                    
                default:
                    break
                }
            }
            NSLog(message ?? "Unexpected error in tunnel configuration: \(e)")
            cancelTunnelWithError(e)
            return
        }

        if var existingLog = cfg.existingLog {
            existingLog.append("")
            existingLog.append(logSeparator)
            existingLog.append("")
            memoryLog.start(with: existingLog)
        }

        configureLogging(debug: cfg.shouldDebug)
        
        log.info("Starting tunnel...")
        
        guard EncryptionProxy.prepareRandomNumberGenerator(seedLength: prngSeedLength) else {
            cancelTunnelWithError(ProviderError.prngInitialization)
            return
        }
        
        do {
            try cfg.handshake.write(to: tmpCaURL)
        } catch {
            cancelTunnelWithError(ProviderError.certificateSerialization)
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
            proxy.setTunnel(tunnel: NETunnelInterface(impl: packetFlow))
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
        defer {
            flushLog()
        }

        guard let proxy = proxy else {
            completionHandler()
            return
        }

        pendingStopHandler = completionHandler
        tunnelQueue.schedule(after: .milliseconds(shutdownTimeout)) {
            guard let pendingHandler = self.pendingStopHandler else {
                return
            }
            log.warning("Tunnel not responding after \(self.shutdownTimeout) milliseconds, forcing stop")
            pendingHandler()
        }
        tunnelQueue.sync {
            proxy.shutdown(error: nil)
        }
    }
    
    /// :nodoc:
    open override func sleep(completionHandler: @escaping () -> Void) {
        guard cfg.usesSleepHandlers else {
            return
        }
        completionHandler()
    }
    
    /// :nodoc:
    open override func wake() {
        guard cfg.usesSleepHandlers else {
            return
        }
    }
    
    /// :nodoc:
    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        var response: Data?
        switch Message(messageData) {
        case .requestLog:
            response = memoryLog.description.data(using: .utf8)

        default:
            break
        }
        completionHandler?(response)
    }
    
    // MARK: Connection (tunnel queue)

    private func connectTunnel(endpoint: NWEndpoint) {
        log.info("Creating link session")
        log.info("Will connect to \(endpoint)")
        
        let targetSocket = upgradedSocket ?? genericSocket(endpoint: endpoint)
        log.info("Socket type is \(type(of: targetSocket))")
        if let _ = upgradedSocket {
            log.info("Socket follows a path upgrade")
        }
        socket = targetSocket
        upgradedSocket = nil
        socket?.delegate = self
        socket?.observe(queue: tunnelQueue, activeTimeout: socketTimeout)
    }
    
    private func finishTunnelDisconnection(error: Error?) {
        proxy?.cleanup()
        
        socket?.delegate = nil
        socket?.unobserve()
        socket = nil
        
        if let error = error {
            log.error("Tunnel did stop (error: \(error))")
        } else {
            log.info("Tunnel did stop on request")
        }
    }
    
    private func disposeTunnel(error: Error?) {
        flushLog()
        
        // failed to start
        if (pendingStartHandler != nil) {
            
            //
            // CAUTION
            //
            // passing nil to this callback will result in an extremely undesired situation,
            // because NetworkExtension would interpret it as "successfully connected to VPN"
            //
            // if we end up here disposing the tunnel with a pending start handled, we are
            // 100% sure that something wrong happened while starting the tunnel. in such
            // case, here we then must also make sure that an error object is ALWAYS
            // provided, so we do this with optional fallback to .socketActivity
            //
            // socketActivity makes sense, given that any other error would normally come
            // from SessionProxy.stopError. other paths to disposeTunnel() are only coming
            // from stopTunnel(), in which case we don't need to feed an error parameter to
            // the stop completion handler
            //
            pendingStartHandler?(error ?? ProviderError.socketActivity)
            pendingStartHandler = nil
        }
        // stopped intentionally
        else if (pendingStopHandler != nil) {
            pendingStopHandler?()
            pendingStopHandler = nil
        }
        // stopped externally, unrecoverable
        else {
            let fm = FileManager.default
            try? fm.removeItem(at: tmpCaURL)
            cancelTunnelWithError(error)
        }
    }
    
    @objc private func handleWifiChange() {
        log.info("Stopping tunnel due to network change")
        logCurrentSSID()
        proxy?.shutdown(error: ProviderError.networkChanged)
    }
}

extension PIATunnelProvider: GenericSocketDelegate {
    
    // MARK: GenericSocketDelegate (tunnel queue)
    
    func socketDidBecomeActive(_ socket: GenericSocket) {
        proxy?.setLink(link: socket.link())
    }
    
    func socket(_ socket: GenericSocket, didShutdownWithFailure failure: Bool) {
        guard let proxy = proxy else {
            return
        }
        
        var shutdownError: Error?
        if !failure {
            shutdownError = proxy.stopError
        } else {
            shutdownError = proxy.stopError ?? ProviderError.linkError
            linkFailures += 1
            log.debug("Link failures so far: \(linkFailures) (max = \(maxLinkFailures))")
        }
        
        finishTunnelDisconnection(error: shutdownError)
        if reasserting {
            guard (linkFailures < maxLinkFailures) else {
                log.debug("Too many link failures (\(linkFailures)), tunnel will die now")
                reasserting = false
                disposeTunnel(error: shutdownError)
                return
            }
            log.debug("Disconnection is recoverable, tunnel will reconnect in \(reconnectionDelay) milliseconds...")
            tunnelQueue.schedule(after: .milliseconds(reconnectionDelay)) {
                self.connectTunnel(endpoint: socket.endpoint)
            }
            return
        }
        disposeTunnel(error: shutdownError)
    }
    
    func socketHasBetterPath(_ socket: GenericSocket) {
        log.info("Stopping tunnel due to a new better path")
        logCurrentSSID()
        upgradedSocket = socket.upgraded()
        proxy?.reconnect(error: ProviderError.networkChanged)
    }
}

extension PIATunnelProvider: SessionProxyDelegate {
    
    // MARK: SessionProxyDelegate (tunnel queue)
    
    /// :nodoc:
    public func sessionDidStart(_ proxy: SessionProxy, remoteAddress: String, address: String, gatewayAddress: String, dnsServers: [String]) {
        reasserting = false
        
        log.info("Session did start")
        
        log.info("Returned ifconfig parameters:")
        log.info("\tTunnel: \(remoteAddress)")
        log.info("\tOwn address: \(address)")
        log.info("\tGateway: \(gatewayAddress)")
        log.info("\tDNS: \(dnsServers)")
        
        bringNetworkUp(tunnel: remoteAddress, vpn: address, gateway: gatewayAddress, dnsServers: dnsServers) { (error) in
            if let error = error {
                log.error("Failed to configure tunnel: \(error)")
                self.pendingStartHandler?(error)
                self.pendingStartHandler = nil
                return
            }
            
            log.info("Tunnel interface is now UP")
            
            self.pendingStartHandler?(nil)
            self.pendingStartHandler = nil
        }
    }
    
    /// :nodoc:
    public func sessionDidStop(_: SessionProxy, shouldReconnect: Bool) {
        log.info("Session did stop")

        if shouldReconnect {
            reasserting = true
        }
        socket?.shutdown()
    }
    
    private func bringNetworkUp(tunnel: String, vpn: String, gateway: String, dnsServers: [String], completionHandler: @escaping (Error?) -> Void) {
        
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
}

extension PIATunnelProvider {
    
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
        if let defaults = cfg.defaults, let key = cfg.debugLogKey {
            memoryLog.flush(to: defaults, with: key)
        }
    }
    
    private func genericSocket(endpoint: NWEndpoint) -> GenericSocket {
        switch cfg.socketType {
        case .udp:
            let impl = createUDPSession(to: endpoint, from: nil)
            return NEUDPInterface(impl: impl)
            
        case .tcp:
            let impl = createTCPConnection(to: endpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
            return NETCPInterface(impl: impl)
        }
    }
    
    private func logCurrentSSID() {
        if let ssid = observer.currentWifiNetworkName() {
            log.debug("Current SSID: '\(ssid)'")
        } else {
            log.debug("Current SSID: none (disconnected from WiFi)")
        }
    }
    
//    private func anyPointer(_ object: Any?) -> UnsafeMutableRawPointer {
//        let anyObject = object as AnyObject
//        return Unmanaged<AnyObject>.passUnretained(anyObject).toOpaque()
//    }
}
