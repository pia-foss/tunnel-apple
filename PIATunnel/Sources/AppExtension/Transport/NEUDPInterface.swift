//
//  NEUDPInterface.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 8/27/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import NetworkExtension
import SwiftyBeaver

private let log = SwiftyBeaver.self

class NEUDPInterface: NSObject, GenericSocket, LinkInterface {
    private static var linkContext = 0
    
    private let impl: NWUDPSession
    
    private let maxDatagrams: Int

    init(impl: NWUDPSession, maxDatagrams: Int = 200) {
        self.impl = impl
        self.maxDatagrams = maxDatagrams
        endpoint = impl.endpoint
        isActive = false
    }
    
    // MARK: GenericSocket
    
    private weak var queue: DispatchQueue?
    
    private var isActive: Bool
    
    let endpoint: NWEndpoint
    
    var remoteAddress: String? {
        return (impl.resolvedEndpoint as? NWHostEndpoint)?.hostname
    }
    
    var hasBetterPath: Bool {
        return impl.hasBetterPath
    }
    
    weak var delegate: GenericSocketDelegate?
    
    func observe(queue: DispatchQueue, activeTimeout: Int) {
        isActive = false
        
        self.queue = queue
        queue.schedule(after: .milliseconds(activeTimeout)) { [weak self] in
            guard let isActive = self?.isActive else {
                return
            }
            guard isActive else {
                log.debug("Socket timed out waiting for activity, cancelling...")
                self?.impl.cancel()
//                self?.impl.tryNextResolvedEndpoint()
                return
            }
        }
        impl.addObserver(self, forKeyPath: #keyPath(NWUDPSession.state), options: [.initial, .new], context: &NEUDPInterface.linkContext)
        impl.addObserver(self, forKeyPath: #keyPath(NWUDPSession.hasBetterPath), options: .new, context: &NEUDPInterface.linkContext)
    }
    
    func unobserve() {
        impl.removeObserver(self, forKeyPath: #keyPath(NWUDPSession.state), context: &NEUDPInterface.linkContext)
        impl.removeObserver(self, forKeyPath: #keyPath(NWUDPSession.hasBetterPath), context: &NEUDPInterface.linkContext)
    }
    
    func shutdown() {
        impl.cancel()
    }
    
    func upgraded() -> GenericSocket? {
        guard impl.hasBetterPath else {
            return nil
        }
        return NEUDPInterface(impl: NWUDPSession(upgradeFor: impl))
    }
    
    func link() -> LinkInterface {
        return self
    }
    
    // MARK: Connection KVO (any queue)
    
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        guard (context == &NEUDPInterface.linkContext) else {
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
                isActive = true
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

    // MARK: LinkInterface
    
    let isReliable: Bool = false
    
    let mtu: Int = 1000

    var packetBufferSize: Int {
        return maxDatagrams
    }

    let negotiationTimeout: TimeInterval = 10.0
    
    let hardResetTimeout: TimeInterval = 2.0
    
    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void) {
        impl.setReadHandler(handler, maxDatagrams: maxDatagrams)
    }
    
    func writePacket(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
        impl.writeDatagram(packet) { (error) in
            completionHandler?(error)
        }
    }
    
    func writePackets(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
        impl.writeMultipleDatagrams(packets) { (error) in
            completionHandler?(error)
        }
    }
}
