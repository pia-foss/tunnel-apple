//
//  LinkInterface.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 8/27/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

/// Represents a specific I/O interface meant to work at the link layer (e.g. TCP/IP).
public protocol LinkInterface: IOInterface {

    /// When `true`, packets delivery is guaranteed.
    var isReliable: Bool { get }

    /// The literal address of the remote host.
    var remoteAddress: String? { get }

    /// The maximum size of a packet.
    var mtu: Int { get }
    
    /// The number of packets that this interface is able to bufferize.
    var packetBufferSize: Int { get }

    /// The language spoken over this link.
    var communicationType: CommunicationType { get }
    
    /// Timeout in seconds for negotiation start.
    var negotiationTimeout: TimeInterval { get }

    /// Timeout in seconds for HARD_RESET response.
    var hardResetTimeout: TimeInterval { get }

    /**
     Returns an optional payload to attach to the HARD_RESET packet.
     
     - Parameter encryption: The `SessionProxy.EncryptionParameters` to establish for this session.
     - Returns: The optional HARD_RESET payload.
     */
    func hardReset(with encryption: SessionProxy.EncryptionParameters) -> Data?
}
