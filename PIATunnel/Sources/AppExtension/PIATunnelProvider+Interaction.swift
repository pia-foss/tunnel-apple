//
//  PIATunnelProvider+Interaction.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 9/24/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

extension PIATunnelProvider {

    // MARK: Interaction

    /// The messages accepted by `PIATunnelProvider`.
    public class Message: Equatable {
        
        /// Requests a snapshot of the latest debug log. Returns the log data decoded from UTF-8.
        public static let requestLog = Message(0xff)
        
        /// The underlying raw message `Data` to forward to the tunnel via IPC.
        public let data: Data
        
        private init(_ byte: UInt8) {
            data = Data(bytes: [byte])
        }
        
        init(_ data: Data) {
            self.data = data
        }
        
        // MARK: Equatable

        /// :nodoc:
        public static func ==(lhs: Message, rhs: Message) -> Bool {
            return (lhs.data == rhs.data)
        }
    }

    /// The errors raised by `PIATunnelProvider`.
    public enum ProviderError: Error {

        /// The `PIATunnelProvider.Configuration` provided is incorrect or incomplete.
        case configuration(field: String)
        
        /// Credentials are missing or protected (e.g. device locked).
        case credentials(field: String)
        
        /// The pseudo-random number generator could not be initialized.
        case prngInitialization
        
        /// The TLS certificate could not be serialized.
        case certificateSerialization
        
        /// Socket endpoint could not be resolved.
        case dnsFailure
        
        /// Socket failed to reach active state.
        case socketActivity
        
        /// An error occurred at the link level.
        case linkError
        
        /// The current network changed (e.g. switched from WiFi to data connection).
        case networkChanged
    }
}
