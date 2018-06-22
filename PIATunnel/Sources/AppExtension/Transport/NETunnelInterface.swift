//
//  NETunnelInterface.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 8/27/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import NetworkExtension

class NETunnelInterface: TunnelInterface {
    private weak var impl: NEPacketTunnelFlow?
    
    var isPersistent: Bool {
        return false
    }
    
    init(impl: NEPacketTunnelFlow) {
        self.impl = impl
    }
    
    func setReadHandler(queue: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {
        loopReadPackets(queue, handler)
    }
    
    private func loopReadPackets(_ queue: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {

        // WARNING: runs in NEPacketTunnelFlow queue
        impl?.readPackets { [weak self] (packets, protocols) in
            queue.sync {
                self?.loopReadPackets(queue, handler)
                handler(packets, nil)
            }
        }
    }
    
    func writePacket(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
        impl?.writePackets([packet], withProtocols: [AF_INET] as [NSNumber])
        completionHandler?(nil)
    }
    
    func writePackets(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
        let protocols = [Int32](repeating: AF_INET, count: packets.count) as [NSNumber]
        impl?.writePackets(packets, withProtocols: protocols)
        completionHandler?(nil)
    }
}
