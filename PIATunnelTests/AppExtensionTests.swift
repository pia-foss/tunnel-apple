//
//  AppExtensionTests.swift
//  PIATunnelTests
//
//  Created by Davide De Rosa on 10/23/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import XCTest
@testable import PIATunnel
import NetworkExtension

class AppExtensionTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testConfiguration() {
        var builder: PIATunnelProvider.ConfigurationBuilder!
        var cfg: PIATunnelProvider.Configuration!

        let identifier = "com.example.Provider"
        let appGroup = "group.com.privateinternetaccess"
        let endpoint = PIATunnelProvider.AuthenticatedEndpoint(
            hostname: "example.com",
            port: "8080",
            username: "foo",
            password: "bar"
        )

        builder = PIATunnelProvider.ConfigurationBuilder(appGroup: appGroup)
        XCTAssertNotNil(builder)

        builder.cipher = .aes128cbc
        builder.digest = .sha256
        builder.handshake = .rsa3072
        cfg = builder.build()

        let proto = try? cfg.generatedTunnelProtocol(withBundleIdentifier: identifier, endpoint: endpoint)
        XCTAssertNotNil(proto)
        
        XCTAssertEqual(proto?.providerBundleIdentifier, identifier)
        XCTAssertEqual(proto?.serverAddress, "\(endpoint.hostname):\(endpoint.port)")
        XCTAssertEqual(proto?.username, endpoint.username)
        XCTAssertEqual(proto?.passwordReference, try? Keychain(group: appGroup).passwordReference(for: endpoint.username))

        if let pc = proto?.providerConfiguration {
            print("\(pc)")
        }
        
        let K = PIATunnelProvider.Configuration.Keys.self
        XCTAssertEqual(proto?.providerConfiguration?[K.appGroup] as? String, cfg.appGroup)
        XCTAssertEqual(proto?.providerConfiguration?[K.cipherAlgorithm] as? String, cfg.cipher.rawValue)
        XCTAssertEqual(proto?.providerConfiguration?[K.digestAlgorithm] as? String, cfg.digest.rawValue)
        XCTAssertEqual(proto?.providerConfiguration?[K.handshakeCertificate] as? String, cfg.handshake.rawValue)
        XCTAssertEqual(proto?.providerConfiguration?[K.mtu] as? NSNumber, cfg.mtu)
        XCTAssertEqual(proto?.providerConfiguration?[K.renegotiatesAfter] as? Int, cfg.renegotiatesAfterSeconds)
        XCTAssertEqual(proto?.providerConfiguration?[K.debug] as? Bool, cfg.shouldDebug)
        XCTAssertEqual(proto?.providerConfiguration?[K.debugLogKey] as? String, cfg.debugLogKey)
    }
}
