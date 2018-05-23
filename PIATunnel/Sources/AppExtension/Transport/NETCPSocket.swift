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
    
    private let impl: NWTCPConnection
    
    private var isActive: Bool
    
    private weak var queue: DispatchQueue?
    
    var endpoint: NWEndpoint {
        return impl.endpoint
    }
    
    var remoteAddress: String? {
        return (impl.remoteAddress as? NWHostEndpoint)?.hostname
    }
    
    var hasBetterPath: Bool {
        return impl.hasBetterPath
    }
    
    weak var delegate: GenericSocketDelegate?
    
    init(impl: NWTCPConnection) {
        self.impl = impl
        isActive = false
    }
    
    func observe(queue: DispatchQueue, activeTimeout: Int) {
        isActive = false

        self.queue = queue
        queue.schedule(after: .milliseconds(activeTimeout)) { [weak self] in
            guard self?.isActive ?? false else {
                self?.impl.cancel()
                return
            }
        }
        impl.addObserver(self, forKeyPath: #keyPath(NWTCPConnection.state), options: [.initial, .new], context: &NETCPSocket.linkContext)
        impl.addObserver(self, forKeyPath: #keyPath(NWTCPConnection.hasBetterPath), options: .new, context: &NETCPSocket.linkContext)
    }
    
    func unobserve() {
        impl.removeObserver(self, forKeyPath: #keyPath(NWTCPConnection.state), context: &NETCPSocket.linkContext)
        impl.removeObserver(self, forKeyPath: #keyPath(NWTCPConnection.hasBetterPath), context: &NETCPSocket.linkContext)
    }
    
    func shutdown() {
        impl.cancel()
    }
    
    func link() -> LinkInterface {
        return NETCPInterface(impl: impl)
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
        guard let impl = object as? NWTCPConnection, (impl == self.impl) else {
            log.warning("Discard KVO change from old socket")
            return
        }
        guard let keyPath = keyPath else {
            return
        }
        switch keyPath {
        case #keyPath(NWTCPConnection.state):
            if let resolvedEndpoint = impl.remoteAddress {
                log.debug("Socket state is \(impl.state) (endpoint: \(impl.endpoint) -> \(resolvedEndpoint))")
            } else {
                log.debug("Socket state is \(impl.state) (endpoint: \(impl.endpoint) -> in progress)")
            }
            
            switch impl.state {
            case .connected:
                isActive = true
                delegate?.socketDidBecomeActive(self)
                
            case .cancelled:
                delegate?.socket(self, didShutdownWithFailure: false)
                
            case .disconnected:
                delegate?.socket(self, didShutdownWithFailure: true)
                
            default:
                break
            }
            
        case #keyPath(NWTCPConnection.hasBetterPath):
            guard impl.hasBetterPath else {
                break
            }
            log.debug("Socket has a better path")
            delegate?.socketHasBetterPath(self)
            
        default:
            break
        }
    }
}
