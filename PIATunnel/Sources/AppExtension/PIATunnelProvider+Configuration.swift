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

        /// AES encryption with 128-bit key size and GCM.
        case aes128gcm = "AES-128-GCM"

        /// AES encryption with 256-bit key size and GCM.
        case aes256gcm = "AES-256-GCM"
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
        case ecc256k1 = "ECC-256k1"

        /// Certificate with ECC based on secp521r1 curve.
        case ecc521r1 = "ECC-521r1"
        
        /// Custom certificate.
        ///
        /// - Seealso:
        case custom = "Custom"
        
        private static let allDigests: [Handshake: String] = [
            .rsa2048: "e2fccccaba712ccc68449b1c56427ac1",
            .rsa3072: "2fcdb65712df9db7dae34a1f4a84e32d",
            .rsa4096: "ec085790314aa0ad4b01dda7b756a932",
            .ecc256r1: "6f0f23a616479329ce54614f76b52254",
            .ecc256k1: "80c3b0f34001e4101e34fde9eb1dfa87",
            .ecc521r1: "82446e0c80706e33e6e793cebf1b0c59"
        ]
        
        var digest: String? {
            return Handshake.allDigests[self]
        }
        
        func write(to url: URL, custom: String? = nil) throws {
            precondition((self != .custom) || (custom != nil))
            
            // custom certificate?
            if self == .custom, let content = custom {
                try content.write(to: url, atomically: true, encoding: .ascii)
                return
            }

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
    
    /// Defines the communication protocol of an endpoint.
    public struct EndpointProtocol: Equatable, CustomStringConvertible {

        /// The socket type.
        public let socketType: SocketType
        
        /// The remote port.
        public let port: UInt16
        
        /// The communication type.
        public let communicationType: CommunicationType

        /// :nodoc:
        public init(_ socketType: SocketType, _ port: UInt16, _ communicationType: CommunicationType) {
            self.socketType = socketType
            self.port = port
            self.communicationType = communicationType
        }
        
        // MARK: Equatable
        
        /// :nodoc:
        public static func ==(lhs: EndpointProtocol, rhs: EndpointProtocol) -> Bool {
            return (lhs.socketType == rhs.socketType) && (lhs.port == rhs.port) && (lhs.communicationType == rhs.communicationType)
        }
        
        // MARK: CustomStringConvertible
        
        /// :nodoc:
        public var description: String {
            return "\(socketType.rawValue):\(port)"
        }
    }

    /// Encapsulates an endpoint along with the authentication credentials.
    public struct AuthenticatedEndpoint {
        
        /// The remote hostname or IP address.
        public let hostname: String
        
        /// The username.
        public let username: String
        
        /// The password.
        public let password: String
        
        /// :nodoc:
        public init(hostname: String, username: String, password: String) {
            self.hostname = hostname
            self.username = username
            self.password = password
        }
        
        init(protocolConfiguration: NEVPNProtocol) throws {
            guard let hostname = protocolConfiguration.serverAddress else {
                throw ProviderError.configuration(field: "protocolConfiguration.serverAddress")
            }
            guard let username = protocolConfiguration.username else {
                throw ProviderError.credentials(field: "protocolConfiguration.username")
            }
            guard let passwordReference = protocolConfiguration.passwordReference else {
                throw ProviderError.credentials(field: "protocolConfiguration.passwordReference")
            }
            guard let password = try? Keychain.password(for: username, reference: passwordReference) else {
                throw ProviderError.credentials(field: "protocolConfiguration.passwordReference (keychain)")
            }
            
            self.hostname = hostname
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
        
        /// Prefers resolved addresses over DNS resolution. `resolvedAddresses` must be set and non-empty. Default is `false`.
        ///
        /// - Seealso: `fallbackServerAddresses`
        public var prefersResolvedAddresses: Bool
        
        /// Resolved addresses in case DNS fails or `prefersResolvedAddresses` is `true`.
        public var resolvedAddresses: [String]?
        
        /// The accepted communication protocols. Must be non-empty.
        public var endpointProtocols: [EndpointProtocol]

        /// The encryption algorithm.
        public var cipher: Cipher
        
        /// The message digest algorithm.
        public var digest: Digest
        
        /// The handshake certificate.
        public var handshake: Handshake
        
        /// The custom CA certificate in PEM format in case `handshake == .custom`. Ignored otherwise.
        public var ca: String?
        
        /// The client certificate
        public var cert: String?
        
        /// The key for the client certificate
        public var key: String?
        
        /// The MTU of the tunnel.
        public var mtu: NSNumber
        
        /// The number of seconds after which a renegotiation is started. Set to `nil` to disable renegotiation.
        public var renegotiatesAfterSeconds: Int?
        
        // MARK: Debugging
        
        /// Enables debugging. If `true`, then `debugLogKey` is a mandatory field.
        public var shouldDebug: Bool
        
        /// The key in `defaults` where the latest debug log snapshot is stored. Ignored if `shouldDebug` is `false`.
        public var debugLogKey: String?
        
        /// Optional debug log format (SwiftyBeaver format).
        public var debugLogFormat: String?
        
        // MARK: Building
        
        /**
         Default initializer.
         
         - Parameter appGroup: The name of the app group in which the tunnel extension lives in.
         */
        public init(appGroup: String) {
            self.appGroup = appGroup
            prefersResolvedAddresses = false
            resolvedAddresses = nil
            endpointProtocols = [EndpointProtocol(.udp, 1194, .pia)]
            cipher = .aes128cbc
            digest = .sha1
            handshake = .rsa2048
            ca = nil
            cert = nil
            key = nil
            mtu = 1500
            renegotiatesAfterSeconds = nil
            shouldDebug = false
            debugLogKey = nil
            debugLogFormat = nil
        }
        
        fileprivate init(providerConfiguration: [String: Any]) throws {
            let S = Configuration.Keys.self

            guard let appGroup = providerConfiguration[S.appGroup] as? String else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.appGroup)]")
            }
            guard let cipherAlgorithm = providerConfiguration[S.cipherAlgorithm] as? String, let cipher = Cipher(rawValue: cipherAlgorithm) else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.cipherAlgorithm)]")
            }
            guard let digestAlgorithm = providerConfiguration[S.digestAlgorithm] as? String, let digest = Digest(rawValue: digestAlgorithm) else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.digestAlgorithm)]")
            }

            // fallback to .rsa2048 in < 0.7 configurations (ca/caDigest)
            let fallbackHandshake: Handshake = .rsa2048
            var handshake: Handshake = fallbackHandshake
            if let handshakeCertificate = providerConfiguration[S.handshakeCertificate] as? String {
                handshake = Handshake(rawValue: handshakeCertificate) ?? fallbackHandshake
            }
            if handshake == .custom {
                guard let ca = providerConfiguration[S.ca] as? String else {
                    throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.ca)]")
                }
                self.ca = ca
                
                guard let cert = providerConfiguration[S.cert] as? String else {
                        throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.cert)]")
                }
                self.cert = cert
                
                guard let key = providerConfiguration[S.key] as? String else {
                        throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.key)]")
                }
                self.key = key
            }

            self.appGroup = appGroup

            prefersResolvedAddresses = providerConfiguration[S.prefersResolvedAddresses] as? Bool ?? false
            resolvedAddresses = providerConfiguration[S.resolvedAddresses] as? [String]
            guard let endpointProtocolsStrings = providerConfiguration[S.endpointProtocols] as? [String], !endpointProtocolsStrings.isEmpty else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.endpointProtocols)] is nil or empty")
            }
            endpointProtocols = try endpointProtocolsStrings.map {
                let components = $0.components(separatedBy: ":")
                guard components.count == 3 else {
                    throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.endpointProtocols)] entries must be in the form 'socketType:port:communicationType'")
                }
                let socketTypeString = components[0]
                let portString = components[1]
                let communicationTypeString = components[2]
                guard let socketType = SocketType(rawValue: socketTypeString) else {
                    throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.endpointProtocols)] unrecognized socketType '\(socketTypeString)'")
                }
                guard let port = UInt16(portString) else {
                    throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.endpointProtocols)] non-numeric port '\(portString)'")
                }
                guard let communicationType = CommunicationType(rawValue: communicationTypeString) else {
                    throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.endpointProtocols)] unrecognized communicationType '\(communicationTypeString)'")
                }
                return EndpointProtocol(socketType, port, communicationType)
            }
            
            self.cipher = cipher
            self.digest = digest
            self.handshake = handshake
            mtu = providerConfiguration[S.mtu] as? NSNumber ?? 1500
            renegotiatesAfterSeconds = providerConfiguration[S.renegotiatesAfter] as? Int

            shouldDebug = providerConfiguration[S.debug] as? Bool ?? false
            if shouldDebug {
                guard let debugLogKey = providerConfiguration[S.debugLogKey] as? String else {
                    throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.debugLogKey)]")
                }
                self.debugLogKey = debugLogKey
                debugLogFormat = providerConfiguration[S.debugLogFormat] as? String
            } else {
                debugLogKey = nil
            }

            guard !prefersResolvedAddresses || !(resolvedAddresses?.isEmpty ?? true) else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.prefersResolvedAddresses)] is true but no [\(S.resolvedAddresses)]")
            }
        }
        
        /**
         Builds a `PIATunnelProvider.Configuration` object that will connect to the provided endpoint.
         
         - Returns: A `PIATunnelProvider.Configuration` object with this builder and the additional method parameters.
         */
        public func build() -> Configuration {
            return Configuration(
                appGroup: appGroup,
                prefersResolvedAddresses: prefersResolvedAddresses,
                resolvedAddresses: resolvedAddresses,
                endpointProtocols: endpointProtocols,
                cipher: cipher,
                digest: digest,
                handshake: handshake,
                ca: ca,
                cert: cert,
                key: key,
                mtu: mtu,
                renegotiatesAfterSeconds: renegotiatesAfterSeconds,
                shouldDebug: shouldDebug,
                debugLogKey: shouldDebug ? debugLogKey : nil,
                debugLogFormat: shouldDebug ? debugLogFormat : nil
            )
        }
    }
    
    /// Offers a bridge between the abstract `PIATunnelProvider.ConfigurationBuilder` and a concrete `NETunnelProviderProtocol` profile.
    public struct Configuration {
        struct Keys {
            static let appGroup = "AppGroup"
            
            static let prefersResolvedAddresses = "PrefersResolvedAddresses"

            static let resolvedAddresses = "ResolvedAddresses"

            static let endpointProtocols = "EndpointProtocols"
            
            static let cipherAlgorithm = "CipherAlgorithm"
            
            static let digestAlgorithm = "DigestAlgorithm"
            
            static let handshakeCertificate = "HandshakeCertificate"
            
            static let ca = "CA"
            
            static let cert = "CERT"
            
            static let key = "KEY"
            
            static let mtu = "MTU"
            
            static let renegotiatesAfter = "RenegotiatesAfter"
            
            static let debug = "Debug"
            
            static let debugLogKey = "DebugLogKey"
            
            static let debugLogFormat = "DebugLogFormat"
        }
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.appGroup`
        public let appGroup: String
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.prefersResolvedAddresses`
        public let prefersResolvedAddresses: Bool
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.resolvedAddresses`
        public let resolvedAddresses: [String]?

        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.endpointProtocols`
        public let endpointProtocols: [EndpointProtocol]
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.cipher`
        public let cipher: Cipher
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.digest`
        public let digest: Digest
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.handshake`
        public let handshake: Handshake
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.ca`
        public let ca: String?
        
        public let cert: String?
        
        public let key: String?
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.mtu`
        public let mtu: NSNumber
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.renegotiatesAfterSeconds`
        public let renegotiatesAfterSeconds: Int?
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.shouldDebug`
        public let shouldDebug: Bool
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.debugLogKey`
        public let debugLogKey: String?
        
        /// - Seealso: `PIATunnelProvider.ConfigurationBuilder.debugLogFormat`
        public let debugLogFormat: String?
        
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
         - Throws: `ProviderError.configuration` if `providerConfiguration` is incomplete.
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
                S.prefersResolvedAddresses: prefersResolvedAddresses,
                S.endpointProtocols: endpointProtocols.map {
                    "\($0.socketType.rawValue):\($0.port):\($0.communicationType.rawValue)"
                },
                S.cipherAlgorithm: cipher.rawValue,
                S.digestAlgorithm: digest.rawValue,
                S.handshakeCertificate: handshake.rawValue,
                S.mtu: mtu,
                S.debug: shouldDebug
            ]
            if let ca = ca {
                dict[S.ca] = ca
            }
            if let cert = cert {
                dict[S.cert] = cert
            }
            if let key = key {
                dict[S.key] = key
            }
            if let resolvedAddresses = resolvedAddresses {
                dict[S.resolvedAddresses] = resolvedAddresses
            }
            if let renegotiatesAfterSeconds = renegotiatesAfterSeconds {
                dict[S.renegotiatesAfter] = renegotiatesAfterSeconds
            }
            if let debugLogKey = debugLogKey {
                dict[S.debugLogKey] = debugLogKey
            }
            if let debugLogFormat = debugLogFormat {
                dict[S.debugLogFormat] = debugLogFormat
            }
            return dict
        }
        
        /**
         Generates a `NETunnelProviderProtocol` from this configuration.
         
         - Parameter bundleIdentifier: The provider bundle identifier required to locate the tunnel extension.
         - Parameter endpoint: The `PIATunnelProvider.AuthenticatedEndpoint` the tunnel will connect to.
         - Returns: The generated `NETunnelProviderProtocol` object.
         - Throws: `ProviderError.configuration` if unable to store the `endpoint.password` to the `appGroup` keychain.
         */
        public func generatedTunnelProtocol(withBundleIdentifier bundleIdentifier: String, endpoint: AuthenticatedEndpoint) throws -> NETunnelProviderProtocol {
            let protocolConfiguration = NETunnelProviderProtocol()
            
            let keychain = Keychain(group: appGroup)
            do {
                try keychain.set(password: endpoint.password, for: endpoint.username)
            } catch _ {
                throw ProviderError.credentials(field: "keychain.set()")
            }
            
            protocolConfiguration.providerBundleIdentifier = bundleIdentifier
            protocolConfiguration.serverAddress = endpoint.hostname
            protocolConfiguration.username = endpoint.username
            protocolConfiguration.passwordReference = try? keychain.passwordReference(for: endpoint.username)
            protocolConfiguration.providerConfiguration = generatedProviderConfiguration()
            
            return protocolConfiguration
        }
        
        func print(appVersion: String?) {
            if let appVersion = appVersion {
                log.info("App version: \(appVersion)")
            }
            
//            log.info("Address: \(endpoint.hostname):\(endpoint.port)")
            log.info("Protocols: \(endpointProtocols)")
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
        builder.endpointProtocols = endpointProtocols
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
            (lhs.endpointProtocols == rhs.endpointProtocols) &&
            (lhs.cipher == rhs.cipher) &&
            (lhs.digest == rhs.digest) &&
            (lhs.handshake == rhs.handshake) &&
            (lhs.mtu == rhs.mtu) &&
            (lhs.renegotiatesAfterSeconds == rhs.renegotiatesAfterSeconds)
        )
    }
}
