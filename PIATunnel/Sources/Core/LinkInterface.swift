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

    /// The literal address of the remote host.
    var remoteAddress: String? { get }

    /// The number of packets that this interface is able to bufferize.
    var packetBufferSize: Int { get }
}
