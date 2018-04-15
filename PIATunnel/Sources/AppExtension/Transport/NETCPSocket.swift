//
//  NETCPSocket.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 4/16/18.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import NetworkExtension
import SwiftyBeaver

private let log = SwiftyBeaver.self

class NETCPSocket: NSObject, GenericSocket {
    private static var linkContext = 0
    
    private let tcp: NWTCPConnection
    
    private weak var queue: DispatchQueue?
    
    var endpoint: NWEndpoint {
        return tcp.endpoint
    }
    
    var remoteAddress: String? {
        return (tcp.remoteAddress as? NWHostEndpoint)?.hostname
    }
    
    var hasBetterPath: Bool {
        return tcp.hasBetterPath
    }
    
    weak var delegate: GenericSocketDelegate?
    
    init(tcp: NWTCPConnection) {
        self.tcp = tcp
    }
    
    func observe(queue: DispatchQueue) {
        self.queue = queue
        tcp.addObserver(self, forKeyPath: #keyPath(NWTCPConnection.state), options: [.initial, .new], context: &NETCPSocket.linkContext)
        tcp.addObserver(self, forKeyPath: #keyPath(NWTCPConnection.hasBetterPath), options: .new, context: &NETCPSocket.linkContext)
    }
    
    func unobserve() {
        tcp.removeObserver(self, forKeyPath: #keyPath(NWTCPConnection.state), context: &NETCPSocket.linkContext)
        tcp.removeObserver(self, forKeyPath: #keyPath(NWTCPConnection.hasBetterPath), context: &NETCPSocket.linkContext)
    }
    
    func shutdown() {
        tcp.cancel()
    }
    
    func link() -> LinkInterface {
        return NETCPInterface(tcp: tcp)
    }
    
    // MARK: Connection KVO (any queue)
    
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        guard (context == &NETCPSocket.linkContext) else {
            super.observeValue(forKeyPath: keyPath, of: object, change: change, context: context)
            return
        }
//        if let keyPath = keyPath {
//            log.debug("KVO change reported (\(anyPointer(object)).\(keyPath))")
//        }
        queue?.async {
            self.observeValueInTunnelQueue(forKeyPath: keyPath, of: object, change: change, context: context)
        }
    }
    
    private func observeValueInTunnelQueue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
//        if let keyPath = keyPath {
//            log.debug("KVO change reported (\(anyPointer(object)).\(keyPath))")
//        }
        guard let tcp = object as? NWTCPConnection, (tcp == self.tcp) else {
            log.warning("Discard KVO change from old TCP socket")
            return
        }
        guard let keyPath = keyPath else {
            return
        }
        switch keyPath {
        case #keyPath(NWTCPConnection.state):
            if let resolvedEndpoint = tcp.remoteAddress {
                log.debug("TCP socket state is \(tcp.state) (endpoint: \(tcp.endpoint) -> \(resolvedEndpoint))")
            } else {
                log.debug("TCP socket state is \(tcp.state) (endpoint: \(tcp.endpoint) -> in progress)")
            }
            
            switch tcp.state {
            case .connected:
                delegate?.socketDidBecomeActive(self)
                
            case .cancelled:
                delegate?.socket(self, didShutdownWithFailure: false)
                
            case .disconnected:
                delegate?.socket(self, didShutdownWithFailure: true)
                
            default:
                break
            }
            
        case #keyPath(NWTCPConnection.hasBetterPath):
            guard tcp.hasBetterPath else {
                break
            }
            log.debug("TCP socket has a better path")
            delegate?.socketHasBetterPath(self)
            
        default:
            break
        }
    }
}
