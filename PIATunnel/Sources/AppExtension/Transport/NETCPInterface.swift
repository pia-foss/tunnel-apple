//
//  NETCPInterface.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 4/15/18.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import NetworkExtension

class NETCPInterface: LinkInterface {
    private let tcp: NWTCPConnection
    
    private let maxPacketSize: Int
    
    var isReliable: Bool {
        return true
    }

    var remoteAddress: String? {
        guard let endpoint = tcp.remoteAddress as? NWHostEndpoint else {
            return nil
        }
        return endpoint.hostname
    }
    
    var packetBufferSize: Int {
        return maxPacketSize
    }

    init(tcp: NWTCPConnection, maxPacketSize: Int = 32768) {
        self.tcp = tcp
        self.maxPacketSize = maxPacketSize
    }
    
    func setReadHandler(_ handler: @escaping ([Data]?, Error?) -> Void) {
        loopReadPackets(Data(), handler)
    }
    
    private func loopReadPackets(_ buffer: Data, _ handler: @escaping ([Data]?, Error?) -> Void) {
        tcp.readMinimumLength(2, maximumLength: packetBufferSize) { [weak self] (data, error) in
            guard let data = data else {
                handler(nil, error)
                return
            }

            var newBuffer = buffer
            newBuffer.append(contentsOf: data)
            let (until, packets) = ControlPacket.parsed(newBuffer)
            newBuffer.removeSubrange(0..<until)

            handler(packets, nil)
            self?.loopReadPackets(newBuffer, handler)
        }
    }

    func writePacket(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
        let stream = ControlPacket.stream(packet)
        tcp.write(stream) { (error) in
            completionHandler?(error)
        }
    }
    
    func writePackets(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
        let stream = ControlPacket.stream(packets)
        tcp.write(stream) { (error) in
            completionHandler?(error)
        }
    }
}
