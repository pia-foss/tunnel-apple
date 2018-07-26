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
    
    /// An optional string describing host app version on tunnel start.
    public var appVersion: String?

    /// The log separator between sessions.
    public var logSeparator = "--- EOF ---"
    
    /// The maximum number of lines in the log.
    public var maxLogLines = 1000
    
    /// The number of milliseconds after which a DNS resolution fails.
    public var dnsTimeout = 3000
    
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
    
    private let certTmpFilename = "CERT.pem"
    
    private let keyTmpFilename = "KEY.pem"
    
    private var cachesURL: URL {
        return URL(fileURLWithPath: NSSearchPathForDirectoriesInDomains(.cachesDirectory, .userDomainMask, true)[0])
    }
    
    private var tmpCaURL: URL {
        return cachesURL.appendingPathComponent(caTmpFilename)
    }
    private var tmpCertURL: URL {
        return cachesURL.appendingPathComponent(certTmpFilename)
    }

    private var tmpKeyURL: URL {
        return cachesURL.appendingPathComponent(keyTmpFilename)
    }

    // MARK: Tunnel configuration

    private var cfg: Configuration!
    
    private var strategy: ConnectionStrategy!
    
    // MARK: Internal state

    private var proxy: SessionProxy?
    
    private var socket: GenericSocket?

    private var linkFailures = 0

    private var pendingStartHandler: ((Error?) -> Void)?
    
    private var pendingStopHandler: (() -> Void)?
    
    // MARK: NEPacketTunnelProvider (XPC queue)
    
    /// :nodoc:
    open override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        let endpoint: AuthenticatedEndpoint
        do {
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
                throw ProviderError.configuration(field: "protocolConfiguration")
            }
            guard let providerConfiguration = tunnelProtocol.providerConfiguration else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration")
            }
            try endpoint = AuthenticatedEndpoint(protocolConfiguration: tunnelProtocol)
            try cfg = Configuration.parsed(from: providerConfiguration)
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
            completionHandler(e)
            return
        }

        strategy = ConnectionStrategy(hostname: endpoint.hostname, configuration: cfg)

        if var existingLog = cfg.existingLog {
            if let i = existingLog.index(of: logSeparator) {
                existingLog.removeFirst(i + 2)
            }
            
            existingLog.append("")
            existingLog.append(logSeparator)
            existingLog.append("")
            memoryLog.start(with: existingLog)
        }

        configureLogging(
            debug: cfg.shouldDebug,
            customFormat: cfg.debugLogFormat
        )
        
        log.info("Starting tunnel...")
        
        guard EncryptionProxy.prepareRandomNumberGenerator(seedLength: prngSeedLength) else {
            completionHandler(ProviderError.prngInitialization)
            return
        }
        
        do {
            try cfg.handshake.write(to: tmpCaURL, custom: cfg.ca)
        } catch {
            completionHandler(ProviderError.certificateSerialization)
            return
        }
        
        do {
            try cfg.handshake.write(to: tmpCertURL, custom: cfg.cert)
        } catch {
            completionHandler(ProviderError.certificateSerialization)
            return
        }

        do {
            try cfg.handshake.write(to: tmpKeyURL, custom: cfg.key)
        } catch {
            completionHandler(ProviderError.certificateSerialization)
            return
        }

        cfg.print(appVersion: appVersion)
        
        let caPath = tmpCaURL.path
        let certPath = tmpCertURL.path
        let keyPath = tmpKeyURL.path
        
//        log.info("Temporary CA is stored to: \(caPath)")
        let encryption = SessionProxy.EncryptionParameters(cfg.cipher.rawValue, cfg.digest.rawValue, caPath, certPath, keyPath, cfg.handshake.digest)

        let credentials = SessionProxy.Credentials(endpoint.username, endpoint.password)
        
        let proxy: SessionProxy
        do {
            proxy = try SessionProxy(queue: tunnelQueue, encryption: encryption, credentials: credentials)
        } catch let e {
            completionHandler(e)
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
            self.connectTunnel()
        }
    }
    
    /// :nodoc:
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        pendingStartHandler = nil
        log.info("Stopping tunnel...")

        guard let proxy = proxy else {
            flushLog()
            completionHandler()
            return
        }

        pendingStopHandler = completionHandler
        tunnelQueue.schedule(after: .milliseconds(shutdownTimeout)) {
            guard let pendingHandler = self.pendingStopHandler else {
                return
            }
            log.warning("Tunnel not responding after \(self.shutdownTimeout) milliseconds, forcing stop")
            self.flushLog()
            pendingHandler()
        }
        tunnelQueue.sync {
            proxy.shutdown(error: nil)
        }
    }
    
    /// :nodoc:
    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        var response: Data?
        switch Message(messageData) {
        case .requestLog:
            response = memoryLog.description.data(using: .utf8)

        case .dataCount:
            if let proxy = proxy {
                response = Data()
                response?.append(UInt64(proxy.bytesIn))
                response?.append(UInt64(proxy.bytesOut))
            }
            
        default:
            break
        }
        completionHandler?(response)
    }
    
    // MARK: Connection (tunnel queue)
    
    private func connectTunnel(upgradedSocket: GenericSocket? = nil, preferredAddress: String? = nil) {
        log.info("Creating link session")
        
        // reuse upgraded socket
        if let upgradedSocket = upgradedSocket, !upgradedSocket.isShutdown {
            log.debug("Socket follows a path upgrade")
            connectTunnel(via: upgradedSocket)
            return
        }
        
        strategy.createSocket(from: self, timeout: dnsTimeout, preferredAddress: preferredAddress, queue: tunnelQueue) { (socket, error) in
            guard let socket = socket else {
                self.disposeTunnel(error: error)
                return
            }
            self.connectTunnel(via: socket)
        }
    }
    
    private func connectTunnel(via socket: GenericSocket) {
        log.info("Will connect to \(socket.endpoint)")

        log.debug("Socket type is \(type(of: socket))")
        self.socket = socket
        self.socket?.delegate = self
        self.socket?.observe(queue: tunnelQueue, activeTimeout: socketTimeout)
    }
    
    private func finishTunnelDisconnection(error: Error?) {
        if let proxy = proxy, !(reasserting && proxy.canRebindLink()) {
            proxy.cleanup()
        }
        
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
}

extension PIATunnelProvider: GenericSocketDelegate {
    
    // MARK: GenericSocketDelegate (tunnel queue)
    
    func socketDidTimeout(_ socket: GenericSocket) {
        log.debug("Socket timed out waiting for activity, cancelling...")
        reasserting = true
        socket.shutdown()
    }
    
    func socketShouldChangeProtocol(_ socket: GenericSocket) {
        guard strategy.tryNextProtocol() else {
            disposeTunnel(error: ProviderError.exhaustedProtocols)
            return
        }
    }
    
    func socketDidBecomeActive(_ socket: GenericSocket) {
        guard let proxy = proxy else {
            return
        }
        if proxy.canRebindLink() {
            proxy.rebindLink(socket.link())
            reasserting = false
        } else {
            proxy.setLink(socket.link())
        }
    }
    
    func socket(_ socket: GenericSocket, didShutdownWithFailure failure: Bool) {
        guard let proxy = proxy else {
            return
        }
        
        // upgrade available?
        let upgradedSocket = socket.upgraded()
        
        var shutdownError: Error?
        if !failure {
            shutdownError = proxy.stopError
        } else {
            shutdownError = proxy.stopError ?? ProviderError.linkError
            linkFailures += 1
            log.debug("Link failures so far: \(linkFailures) (max = \(maxLinkFailures))")
        }
        
        // treat negotiation timeout as socket timeout, UDP is connection-less
        if proxy.stopError as? SessionError == SessionError.negotiationTimeout {
            socketShouldChangeProtocol(socket)
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
                self.connectTunnel(upgradedSocket: upgradedSocket, preferredAddress: socket.endpoint.hostname)
            }
            return
        }
        disposeTunnel(error: shutdownError)
    }
    
    func socketHasBetterPath(_ socket: GenericSocket) {
        log.debug("Stopping tunnel due to a new better path")
        logCurrentSSID()
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
            
            proxy.setTunnel(tunnel: NETunnelInterface(impl: self.packetFlow))

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
    
    private func configureLogging(debug: Bool, customFormat: String? = nil) {
        let logLevel: SwiftyBeaver.Level = (debug ? .debug : .info)
        let logFormat = customFormat ?? "$Dyyyy-MM-dd HH:mm:ss.SSS$d $L $N.$F:$l - $M"
        
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
