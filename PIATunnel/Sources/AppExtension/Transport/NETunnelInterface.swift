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
        return true
    }
    
    init(impl: NEPacketTunnelFlow?) {
        self.impl = impl
    }
    
    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void) {
        loopReadPackets(handler)
    }
    
    private func loopReadPackets(_ handler: @escaping ([Data]?, Error?) -> Void) {
        impl?.readPackets { [weak self] (packets, protocols) in
            handler(packets, nil)
            self?.loopReadPackets(handler)
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
