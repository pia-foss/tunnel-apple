//
//  NWUDPSessionState+Description.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 9/24/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import NetworkExtension

/// :nodoc:
extension NWUDPSessionState: CustomStringConvertible {
    public var description: String {
        switch self {
        case .cancelled: return "cancelled"
        case .failed: return "failed"
        case .invalid: return "invalid"
        case .preparing: return "preparing"
        case .ready: return "ready"
        case .waiting: return "waiting"
        }
    }
}
