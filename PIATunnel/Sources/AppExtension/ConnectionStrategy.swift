//
//  ConnectionStrategy.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 6/18/18.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import NetworkExtension
import SwiftyBeaver

private let log = SwiftyBeaver.self

class ConnectionStrategy {
    private let hostname: String

    private let prefersResolvedAddresses: Bool

    private var resolvedAddresses: [String]?
    
    private let endpointProtocols: [PIATunnelProvider.EndpointProtocol]
    
    private var currentProtocolIndex = 0

    init(hostname: String, configuration: PIATunnelProvider.Configuration) {
        precondition(!configuration.prefersResolvedAddresses || !(configuration.resolvedAddresses?.isEmpty ?? true))
        
        self.hostname = hostname
        prefersResolvedAddresses = configuration.prefersResolvedAddresses
        resolvedAddresses = configuration.resolvedAddresses
        endpointProtocols = configuration.endpointProtocols
    }

    func createSocket(from provider: NEProvider, timeout: Int, preferredAddress: String? = nil, completionHandler: @escaping (GenericSocket?, Error?) -> Void) {
        
        // reuse preferred address
        if let preferredAddress = preferredAddress {
            log.debug("Pick preferred address: \(preferredAddress)")
            let socket = provider.createSocket(to: preferredAddress, protocol: currentProtocol())
            completionHandler(socket, nil)
            return
        }
        
        // use any resolved address
        if prefersResolvedAddresses, let resolvedAddress = anyResolvedAddress() {
            log.debug("Pick resolved address: \(resolvedAddress)")
            let socket = provider.createSocket(to: resolvedAddress, protocol: currentProtocol())
            completionHandler(socket, nil)
            return
        }
        
        // fall back to DNS
        log.debug("DNS resolve hostname: \(hostname)")
        DNSResolver.resolve(hostname, timeout: timeout) { (addresses, error) in

            // refresh resolved addresses
            if let resolved = addresses, !resolved.isEmpty {
                self.resolvedAddresses = resolved

                log.debug("DNS resolved addresses: \(resolved)")
            } else {
                log.error("DNS resolution failed!")
            }

            guard let targetAddress = self.resolvedAddress(from: addresses) else {
                log.error("No resolved or fallback address available")
                completionHandler(nil, PIATunnelProvider.ProviderError.dnsFailure)
                return
            }

            let socket = provider.createSocket(to: targetAddress, protocol: self.currentProtocol())
            completionHandler(socket, nil)
        }
    }

    private func currentProtocol() -> PIATunnelProvider.EndpointProtocol {
        return endpointProtocols[currentProtocolIndex]
    }

    private func resolvedAddress(from addresses: [String]?) -> String? {
        guard let resolved = addresses, !resolved.isEmpty else {
            return anyResolvedAddress()
        }
        return resolved[0]
    }

    private func anyResolvedAddress() -> String? {
        guard let addresses = resolvedAddresses, !addresses.isEmpty else {
            return nil
        }
        let n = Int(arc4random() % UInt32(addresses.count))
        return addresses[n]
    }
}

private extension NEProvider {
    func createSocket(to address: String, protocol endpointProtocol: PIATunnelProvider.EndpointProtocol) -> GenericSocket {
        let endpoint = NWHostEndpoint(hostname: address, port: endpointProtocol.port)
        switch endpointProtocol.socketType {
        case .udp:
            let impl = createUDPSession(to: endpoint, from: nil)
            return NEUDPInterface(impl: impl)
            
        case .tcp:
            let impl = createTCPConnection(to: endpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
            return NETCPInterface(impl: impl)
        }
    }
}
