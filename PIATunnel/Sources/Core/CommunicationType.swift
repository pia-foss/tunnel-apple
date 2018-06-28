//
//  CommunicationType.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 6/28/18.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

/// The language spoken over a link.
public enum CommunicationType: String {
    
    /// PIA-patched OpenVPN server.
    case pia
    
    /// Stock OpenVPN server.
    case vanilla
}
