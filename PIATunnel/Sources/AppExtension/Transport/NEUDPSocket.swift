//
//  NEUDPSocket.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 4/16/18.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import NetworkExtension
import SwiftyBeaver

private let log = SwiftyBeaver.self

class NEUDPSocket: NSObject, GenericSocket {
    private static var linkContext = 0
    
    private let impl: NWUDPSession
    
    private weak var queue: DispatchQueue?
    
    var endpoint: NWEndpoint {
        return impl.endpoint
    }
    
    var remoteAddress: String? {
        return (impl.resolvedEndpoint as? NWHostEndpoint)?.hostname
    }
    
    var hasBetterPath: Bool {
        return impl.hasBetterPath
    }
    
    weak var delegate: GenericSocketDelegate?
    
    init(impl: NWUDPSession) {
        self.impl = impl
    }
    
    func observe(queue: DispatchQueue) {
        self.queue = queue
        impl.addObserver(self, forKeyPath: #keyPath(NWUDPSession.state), options: [.initial, .new], context: &NEUDPSocket.linkContext)
        impl.addObserver(self, forKeyPath: #keyPath(NWUDPSession.hasBetterPath), options: .new, context: &NEUDPSocket.linkContext)
    }
    
    func unobserve() {
        impl.removeObserver(self, forKeyPath: #keyPath(NWUDPSession.state), context: &NEUDPSocket.linkContext)
        impl.removeObserver(self, forKeyPath: #keyPath(NWUDPSession.hasBetterPath), context: &NEUDPSocket.linkContext)
    }
    
    func shutdown() {
        impl.cancel()
    }
    
    func link() -> LinkInterface {
        return NEUDPInterface(impl: impl)
    }

    // MARK: Connection KVO (any queue)
    
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        guard (context == &NEUDPSocket.linkContext) else {
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
        guard let impl = object as? NWUDPSession, (impl == self.impl) else {
            log.warning("Discard KVO change from old socket")
            return
        }
        guard let keyPath = keyPath else {
            return
        }
        switch keyPath {
        case #keyPath(NWUDPSession.state):
            if let resolvedEndpoint = impl.resolvedEndpoint {
                log.debug("Socket state is \(impl.state) (endpoint: \(impl.endpoint) -> \(resolvedEndpoint))")
            } else {
                log.debug("Socket state is \(impl.state) (endpoint: \(impl.endpoint) -> in progress)")
            }

            switch impl.state {
            case .ready:
                delegate?.socketDidBecomeActive(self)

            case .cancelled:
                delegate?.socket(self, didShutdownWithFailure: false)

            case .failed:
                delegate?.socket(self, didShutdownWithFailure: true)

            default:
                break
            }

        case #keyPath(NWUDPSession.hasBetterPath):
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
