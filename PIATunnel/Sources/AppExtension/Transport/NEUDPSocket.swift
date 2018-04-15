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
    
    private let udp: NWUDPSession
    
    private weak var queue: DispatchQueue?
    
    var endpoint: NWEndpoint {
        return udp.endpoint
    }
    
    var remoteAddress: String? {
        return (udp.resolvedEndpoint as? NWHostEndpoint)?.hostname
    }
    
    var hasBetterPath: Bool {
        return udp.hasBetterPath
    }
    
    weak var delegate: GenericSocketDelegate?
    
    init(udp: NWUDPSession) {
        self.udp = udp
    }
    
    func observe(queue: DispatchQueue) {
        self.queue = queue
        udp.addObserver(self, forKeyPath: #keyPath(NWUDPSession.state), options: [.initial, .new], context: &NEUDPSocket.linkContext)
        udp.addObserver(self, forKeyPath: #keyPath(NWUDPSession.hasBetterPath), options: .new, context: &NEUDPSocket.linkContext)
    }
    
    func unobserve() {
        udp.removeObserver(self, forKeyPath: #keyPath(NWUDPSession.state), context: &NEUDPSocket.linkContext)
        udp.removeObserver(self, forKeyPath: #keyPath(NWUDPSession.hasBetterPath), context: &NEUDPSocket.linkContext)
    }
    
    func shutdown() {
        udp.cancel()
    }
    
    func link() -> LinkInterface {
        return NEUDPInterface(udp: udp)
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
        guard let udp = object as? NWUDPSession, (udp == self.udp) else {
            log.warning("Discard KVO change from old socket")
            return
        }
        guard let keyPath = keyPath else {
            return
        }
        switch keyPath {
        case #keyPath(NWUDPSession.state):
            if let resolvedEndpoint = udp.resolvedEndpoint {
                log.debug("Socket state is \(udp.state) (endpoint: \(udp.endpoint) -> \(resolvedEndpoint))")
            } else {
                log.debug("Socket state is \(udp.state) (endpoint: \(udp.endpoint) -> in progress)")
            }

            switch udp.state {
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
            guard udp.hasBetterPath else {
                break
            }
            log.debug("Socket has a better path")
            delegate?.socketHasBetterPath(self)

        default:
            break
        }
    }
}
