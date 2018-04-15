//
//  NWTCPConnectionState+Description.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 4/16/18.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import NetworkExtension

/// :nodoc:
extension NWTCPConnectionState: CustomStringConvertible {
    public var description: String {
        switch self {
        case .cancelled: return "cancelled"
        case .connected: return "connected"
        case .connecting: return "connecting"
        case .disconnected: return "disconnected"
        case .invalid: return "invalid"
        case .waiting: return "waiting"
        }
    }
}
