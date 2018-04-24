//
//  PIATunnelProvider+Configuration.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 10/23/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import NetworkExtension
import SwiftyBeaver

private let log = SwiftyBeaver.self

extension PIATunnelProvider {
    
    // MARK: Cryptography
    
    /// The available encryption algorithms.
    public enum Cipher: String {

        // WARNING: must match OpenSSL algorithm names

        /// AES encryption with 128-bit key size and CBC.
        case aes128cbc = "AES-128-CBC"
        
        /// AES encryption with 256-bit key size and CBC.
        case aes256cbc = "AES-256-CBC"
    }
    
    /// The available message digest algorithms.
    public enum Digest: String {
        
        // WARNING: must match OpenSSL algorithm names
        
        /// SHA1 message digest.
        case sha1 = "SHA1"
        
        /// SHA256 message digest.
        case sha256 = "SHA256"
    }
    
    /// The available certificates for handshake.
    public enum Handshake: String {
        
        /// Certificate with RSA 2048-bit key.
        case rsa2048 = "RSA-2048"
        
        /// Certificate with RSA 3072-bit key.
        case rsa3072 = "RSA-3072"

        /// Certificate with RSA 4096-bit key.
        case rsa4096 = "RSA-4096"
        
        /// Certificate with ECC based on secp256r1 curve.
        case ecc256r1 = "ECC-256r1"
        
        /// Certificate with ECC based on secp256k1 curve.
//        case ecc256k1 = "ECC-256k1"

        /// Certificate with ECC based on secp521r1 curve.
        case ecc521r1 = "ECC-521r1"
        
        private static let allDigests: [Handshake: String] = [
            .rsa2048: "e2fccccaba712ccc68449b1c56427ac1",
            .rsa3072: "2fcdb65712df9db7dae34a1f4a84e32d",
            .rsa4096: "ec085790314aa0ad4b01dda7b756a932",
            .ecc256r1: "6f0f23a616479329ce54614f76b52254",
//            .ecc256k1: "80c3b0f34001e4101e34fde9eb1dfa87",
            .ecc521r1: "82446e0c80706e33e6e793cebf1b0c59"
        ]
        
        var digest: String {
            return Handshake.allDigests[self]!
        }
        
        func write(to url: URL) throws {
            let bundle = Bundle(for: PIATunnelProvider.self)
            let certName = "PIA-\(rawValue)"
            guard let certUrl = bundle.url(forResource: certName, withExtension: "pem") else {
                fatalError("Could not find \(certName) TLS certificate")
            }
            let content = try String(contentsOf: certUrl)
            try content.write(to: url, atomically: true, encoding: .ascii)
        }
    }
}

extension PIATunnelProvider {

    // MARK: Configuration
    
    /// A socket type between UDP (recommended) and TCP.
    public enum SocketType: String {

        /// UDP socket type.
        case udp = "UDP"
        
        /// TCP socket type.
        case tcp = "TCP"
    }
    
    /// Encapsulates an endpoint along with the authentication credentials.
    public struct AuthenticatedEndpoint {
        
        /// The remote hostname or IP address.
        public let hostname: String
        
        /// The remote port.
        public let port: String
        
        /// The username.
        public let username: String
        
        /// The password.
        public let password: String
        
        /// :nodoc:
        public init(hostname: String, port: String, username: String, password: String) {
            self.hostname = hostname
            self.port = port
            self.username = username
            self.password = password
        }
        
        init(protocolConfiguration: NEVPNProtocol) throws {
            guard let address = protocolConfiguration.serverAddress else {
                throw TunnelError.configuration
            }
            let addressComponents = address.components(separatedBy: ":")
            guard (addressComponents.count == 2) else {
                throw TunnelError.configuration
            }
            guard let username = protocolConfiguration.username else {
                throw TunnelError.configuration
            }
            guard let passwordReference = protocolConfiguration.passwordReference else {
                throw TunnelError.configuration
            }
            guard let password = try? Keychain.password(for: username, reference: passwordReference) else {
                throw TunnelError.configuration
            }
            
            hostname = addressComponents[0]
            port = addressComponents[1]
            self.username = username
            self.password = password
        }
    }
    
    /// The way to create a `PIATunnelProvider.Configuration` object for the tunnel profile.
    public struct ConfigurationBuilder {
        
        // MARK: App group
        
        /// The name of a shared app group.
        public let appGroup: String
        
        // MARK: Tunnel parameters
        
        /// The socket type.
        public var socketType: SocketType
        
        /// The encryption algorithm.
        public var cipher: Cipher
        
        /// The message digest algorithm.
        public var digest: Digest
        
        /// The handshake certificate.
        public var handshake: Handshake
        
        /// The MTU of the tunnel.
        public var mtu: NSNumber
        
        /// The number of seconds after which a renegotiation is started. Set to `nil` to disable renegotiation.
        public var renegotiatesAfterSeconds: Int?
        
        // MARK: Debugging
        
        /// Enables debugging. If `true`, then `debugLogKey` is a mandatory field.
        public var shouldDebug: Bool
        
        /// The key in `defaults` where the latest debug log snapshot is stored. Ignored if `shouldDebug` is `false`.
        public var debugLogKey: String?
        
        // MARK: Building
        
        /**
         Default initializer.
         
         - Parameter appGroup: The name of the app group in which the tunnel extension lives in.
         */
        public init(appGroup: String) {
            self.appGroup = appGroup
            socketType = .udp
            cipher = .aes128cbc
            digest = .sha1
            handshake = .rsa2048
            mtu = 1500
            renegotiatesAfterSeconds = nil
            shouldDebug = false
            debugLogKey = nil
        }
        
        fileprivate init(providerConfiguration: [String: Any]) throws {
            let S = Configuration.Keys.self

            guard let appGroup = providerConfiguration[S.appGroup] as? String else {
                throw TunnelError.configuration
            }
            guard let cipherAlgorithm = providerConfiguration[S.cipherAlgorithm] as? String, let cipher = Cipher(rawValue: cipherAlgorithm) else {
                throw TunnelError.configuration
            }
            guard let digestAlgorithm = providerConfiguration[S.digestAlgorithm] as? String, let digest = Digest(rawValue: digestAlgorithm) else {
                throw TunnelError.configuration
            }

            // fallback to .rsa2048 in < 0.7 configurations (ca/caDigest)
            let fallbackHandshake: Handshake = .rsa2048
            var handshake: Handshake = fallbackHandshake
            if let handshakeCertificate = providerConfiguration[S.handshakeCertificate] as? String {
                handshake = Handshake(rawValue: handshakeCertificate) ?? fallbackHandshake
            }

            self.appGroup = appGroup

            if let socketTypeString = providerConfiguration[S.socketType] as? String, let socketType = SocketType(rawValue: socketTypeString) {
                self.socketType = socketType
            } else {
                socketType = .udp
            }
            self.cipher = cipher
            self.digest = digest
            self.handshake = handshake
            mtu = providerConfiguration[S.mtu] as? NSNumber ?? 1500
            renegotiatesAfterSeconds = providerConfiguration[S.renegotiatesAfter] as? Int

            shouldDebug = providerConfiguration[S.debug] as? Bool ?? false
            if shouldDebug {
                guard let debugLogKey = providerConfiguration[S.debugLogKey] as? String else {
                    throw TunnelError.configuration
                }
                self.debugLogKey = debugLogKey
            } else {
                debugLogKey = nil
            }
        }
        
        /**
         Builds a `PIATunnelProvider.Configuration` object that will connect to the provided endpoint.
         
         - Returns: A `PIATunnelProvider.Configuration` object with this builder and the additional method parameters.
         */
        public func build() -> Configuration {
            return Configuration(
                appGroup: appGroup,
                socketType: socketType,
                cipher: cipher,
                digest: digest,
                handshake: handshake,
                mtu: mtu,
                renegotiatesAfterSeconds: renegotiatesAfterSeconds,
                shouldDebug: shouldDebug,
                debugLogKey: shouldDebug ? debugLogKey : nil
            )
        }
    }
    
    /// Offers a bridge between the abstract `PIATunnelProvider.ConfigurationBuilder` and a concrete `NETunnelProviderProtocol` profile.
    public struct Configuration {
        struct Keys {
            static let appGroup = "AppGroup"
            
            static let socketType = "SocketType"
            
            static let cipherAlgorithm = "CipherAlgorithm"
            
            static let digestAlgorithm = "DigestAlgorithm"
            
            static let handshakeCertificate = "HandshakeCertificate"
            
            static let mtu = "MTU"
            
            static let renegotiatesAfter = "RenegotiatesAfter"
            
            static let debug = "Debug"
            
            static let debugLogKey = "DebugLogKey"
        }
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.appGroup`
        public let appGroup: String

        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.socketType`
        public let socketType: SocketType
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.cipher`
        public let cipher: Cipher
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.digest`
        public let digest: Digest
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.handshake`
        public let handshake: Handshake
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.mtu`
        public let mtu: NSNumber
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.renegotiatesAfterSeconds`
        public let renegotiatesAfterSeconds: Int?
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.shouldDebug`
        public let shouldDebug: Bool
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.debugLogKey`
        public let debugLogKey: String?
        
        // MARK: Shortcuts

        var defaults: UserDefaults? {
            return UserDefaults(suiteName: appGroup)
        }
        
        var existingLog: [String]? {
            guard shouldDebug, let key = debugLogKey else {
                return nil
            }
            return defaults?.array(forKey: key) as? [String]
        }
        
        // MARK: API
        
        /**
         Parses a new `PIATunnelProvider.Configuration` object from a provider configuration map.
         
         - Parameter from: The map to parse.
         - Returns: The parsed `PIATunnelProvider.Configuration` object.
         - Throws: `TunnelError.configuration` if `providerConfiguration` is incomplete.
         */
        public static func parsed(from providerConfiguration: [String: Any]) throws -> Configuration {
            let builder = try ConfigurationBuilder(providerConfiguration: providerConfiguration)
            return builder.build()
        }
        
        /**
         Returns a dictionary representation of this configuration for use with `NETunnelProviderProtocol.providerConfiguration`.

         - Returns: The dictionary representation of `self`.
         */
        public func generatedProviderConfiguration() -> [String: Any] {
            let S = Keys.self
            
            var dict: [String: Any] = [
                S.appGroup: appGroup,
                S.socketType: socketType.rawValue,
                S.cipherAlgorithm: cipher.rawValue,
                S.digestAlgorithm: digest.rawValue,
                S.handshakeCertificate: handshake.rawValue,
                S.mtu: mtu,
                S.debug: shouldDebug
            ]
            if let renegotiatesAfterSeconds = renegotiatesAfterSeconds {
                dict[S.renegotiatesAfter] = renegotiatesAfterSeconds
            }
            if let debugLogKey = debugLogKey {
                dict[S.debugLogKey] = debugLogKey
            }
            return dict
        }
        
        /**
         Generates a `NETunnelProviderProtocol` from this configuration.
         
         - Parameter bundleIdentifier: The provider bundle identifier required to locate the tunnel extension.
         - Parameter endpoint: The `PIATunnelProvider.AuthenticatedEndpoint` the tunnel will connect to.
         - Returns: The generated `NETunnelProviderProtocol` object.
         - Throws: `TunnelError.configuration` if unable to store the `endpoint.password` to the `appGroup` keychain.
         */
        public func generatedTunnelProtocol(withBundleIdentifier bundleIdentifier: String, endpoint: AuthenticatedEndpoint) throws -> NETunnelProviderProtocol {
            let protocolConfiguration = NETunnelProviderProtocol()
            
            let keychain = Keychain(group: appGroup)
            do {
                try keychain.set(password: endpoint.password, for: endpoint.username)
            } catch _ {
                throw TunnelError.configuration
            }
            
            protocolConfiguration.providerBundleIdentifier = bundleIdentifier
            protocolConfiguration.serverAddress = "\(endpoint.hostname):\(endpoint.port)"
            protocolConfiguration.username = endpoint.username
            protocolConfiguration.passwordReference = try? keychain.passwordReference(for: endpoint.username)
            protocolConfiguration.providerConfiguration = generatedProviderConfiguration()
            
            return protocolConfiguration
        }
        
        func print() {
//            log.info("Address: \(endpoint.hostname):\(endpoint.port)")
            log.info("Socket: \(socketType.rawValue)")
            log.info("Cipher: \(cipher.rawValue)")
            log.info("Digest: \(digest.rawValue)")
            log.info("Handshake: \(handshake.rawValue)")
            log.info("MTU: \(mtu)")
            if let renegotiatesAfterSeconds = renegotiatesAfterSeconds {
                log.info("Renegotiation: \(renegotiatesAfterSeconds) seconds")
            } else {
                log.info("Renegotiation: never")
            }
            log.info("Debug: \(shouldDebug)")
        }
    }
}

// MARK: Modification

extension PIATunnelProvider.Configuration: Equatable {

    /**
     Returns a `PIATunnelProvider.ConfigurationBuilder` to use this configuration as a starting point for a new one.

     - Returns: An editable `PIATunnelProvider.ConfigurationBuilder` initialized with this configuration.
     */
    public func builder() -> PIATunnelProvider.ConfigurationBuilder {
        var builder = PIATunnelProvider.ConfigurationBuilder(appGroup: appGroup)
        builder.socketType = socketType
        builder.cipher = cipher
        builder.digest = digest
        builder.handshake = handshake
        builder.mtu = mtu
        builder.renegotiatesAfterSeconds = renegotiatesAfterSeconds
        builder.shouldDebug = shouldDebug
        builder.debugLogKey = debugLogKey
        return builder
    }

    /// :nodoc:
    public static func ==(lhs: PIATunnelProvider.Configuration, rhs: PIATunnelProvider.Configuration) -> Bool {
        return (
            (lhs.socketType == rhs.socketType) &&
            (lhs.cipher == rhs.cipher) &&
            (lhs.digest == rhs.digest) &&
            (lhs.handshake == rhs.handshake) &&
            (lhs.mtu == rhs.mtu) &&
            (lhs.renegotiatesAfterSeconds == rhs.renegotiatesAfterSeconds)
        )
    }
}
