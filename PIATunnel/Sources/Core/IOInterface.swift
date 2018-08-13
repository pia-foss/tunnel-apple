//
//  IOInterface.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 8/27/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

/// Represents an I/O interface able to read and write data.
public protocol IOInterface: class {

    /**
     Sets the handler for incoming packets. This only needs to be set once.

     - Parameter queue: The queue where to invoke the handler on.
     - Parameter handler: The handler invoked whenever an array of `Data` packets is received, with an optional `Error` in case a network failure occurs.
     */
    func setReadHandler(queue: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void)
    
    /**
     Writes a packet to the interface.

     - Parameter packet: The `Data` packet to write.
     - Parameter completionHandler: Invoked on write completion, with an optional `Error` in case a network failure occurs.
     */
    func writePacket(_ packet: Data, completionHandler: ((Error?) -> Void)?)
    
    /**
     Writes some packets to the interface.

     - Parameter packets: The array of `Data` packets to write.
     - Parameter completionHandler: Invoked on write completion, with an optional `Error` in case a network failure occurs.
     */
    func writePackets(_ packets: [Data], completionHandler: ((Error?) -> Void)?)
}
