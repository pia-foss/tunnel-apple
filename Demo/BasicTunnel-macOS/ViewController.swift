//
//  ViewController.swift
//  BasicTunnel-macOS
//
//  Created by Davide De Rosa on 10/15/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Cocoa
import NetworkExtension
import PIATunnel

class ViewController: NSViewController {
    static let APP_GROUP = "group.com.privateinternetaccess.macos.demo.BasicTunnel"

    static let VPN_BUNDLE = "com.privateinternetaccess.macos.demo.BasicTunnel.BasicTunnelExtension"
    
    static let CIPHER: PIATunnelProvider.Cipher = .aes128cbc
    
    static let DIGEST: PIATunnelProvider.Digest = .sha1
    
    static let HANDSHAKE: PIATunnelProvider.Handshake = .rsa2048
    
    static let RENEG: Int? = nil
    
    static let DOWNLOAD_COUNT = 5
    
    @IBOutlet var textUsername: NSTextField!
    
    @IBOutlet var textPassword: NSTextField!
    
    @IBOutlet var textServer: NSTextField!
    
    @IBOutlet var textDomain: NSTextField!
    
    @IBOutlet var textPort: NSTextField!
    
    @IBOutlet var buttonConnection: NSButton!
    
    var currentManager: NETunnelProviderManager?
    
    var status = NEVPNStatus.invalid
    
    var downloadTask: URLSessionDataTask!
    
    var downloadCount = 0
    
    var downloadTimes = [TimeInterval]()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        textServer.stringValue = "germany"
        textDomain.stringValue = "privateinternetaccess.com"
//        textServer.text = "159.122.133.238"
//        textDomain.text = ""
        textPort.stringValue = "1198"
//        textPort.text = "8080"
        textUsername.stringValue = "myusername"
        textPassword.stringValue = "mypassword"
        
        NotificationCenter.default.addObserver(self,
                                               selector: #selector(VPNStatusDidChange(notification:)),
                                               name: .NEVPNStatusDidChange,
                                               object: nil)
        
        reloadCurrentManager(nil)
        
        //
        
        testFetchRef()
    }
    
    @IBAction func connectionClicked(_ sender: Any) {
        let block = {
            switch (self.status) {
            case .invalid, .disconnected:
                self.connect()
                
            case .connected, .connecting:
                self.disconnect()
                
            default:
                break
            }
        }
        
        if (status == .invalid) {
            reloadCurrentManager({ (error) in
                block()
            })
        }
        else {
            block()
        }
    }
    
    func connect() {
        let server = textServer.stringValue
        let domain = textDomain.stringValue
        
        let hostname = ((domain == "") ? server : [server, domain].joined(separator: "."))
        let port = UInt16(textPort.stringValue)!
        let username = textUsername.stringValue
        let password = textPassword.stringValue
        
        configureVPN({ (manager) in
//            manager.isOnDemandEnabled = true
//            manager.onDemandRules = [NEOnDemandRuleConnect()]
            
            let endpoint = PIATunnelProvider.AuthenticatedEndpoint(
                hostname: hostname,
                username: username,
                password: password
            )
            
            var builder = PIATunnelProvider.ConfigurationBuilder(appGroup: ViewController.APP_GROUP)
//            let socketType: PIATunnelProvider.SocketType = (self.switchTCP.isOn ? .tcp : .udp)
            let socketType: PIATunnelProvider.SocketType = .udp
            builder.endpointProtocols = [PIATunnelProvider.EndpointProtocol(socketType, port, .vanilla)]
            builder.cipher = ViewController.CIPHER
            builder.digest = ViewController.DIGEST
            builder.handshake = ViewController.HANDSHAKE
            builder.mtu = 1350
            builder.renegotiatesAfterSeconds = ViewController.RENEG
            builder.shouldDebug = true
            builder.debugLogKey = "Log"
            
            let configuration = builder.build()
            return try! configuration.generatedTunnelProtocol(withBundleIdentifier: ViewController.VPN_BUNDLE, endpoint: endpoint)
        }, completionHandler: { (error) in
            if let error = error {
                print("configure error: \(error)")
                return
            }
            let session = self.currentManager?.connection as! NETunnelProviderSession
            do {
                try session.startTunnel()
            } catch let e {
                print("error starting tunnel: \(e)")
            }
        })
    }
    
    func disconnect() {
        configureVPN({ (manager) in
            //            manager.isOnDemandEnabled = false
            return nil
        }, completionHandler: { (error) in
            self.currentManager?.connection.stopVPNTunnel()
        })
    }
    
    func configureVPN(_ configure: @escaping (NETunnelProviderManager) -> NETunnelProviderProtocol?, completionHandler: @escaping (Error?) -> Void) {
        reloadCurrentManager { (error) in
            if let error = error {
                print("error reloading preferences: \(error)")
                completionHandler(error)
                return
            }
            
            let manager = self.currentManager!
            if let protocolConfiguration = configure(manager) {
                manager.protocolConfiguration = protocolConfiguration
            }
            manager.isEnabled = true
            
            manager.saveToPreferences { (error) in
                if let error = error {
                    print("error saving preferences: \(error)")
                    completionHandler(error)
                    return
                }
                print("saved preferences")
                self.reloadCurrentManager(completionHandler)
            }
        }
    }
    
    func reloadCurrentManager(_ completionHandler: ((Error?) -> Void)?) {
        NETunnelProviderManager.loadAllFromPreferences { (managers, error) in
            if let error = error {
                completionHandler?(error)
                return
            }
            
            var manager: NETunnelProviderManager?
            
            for m in managers! {
                if let p = m.protocolConfiguration as? NETunnelProviderProtocol {
                    if (p.providerBundleIdentifier == ViewController.VPN_BUNDLE) {
                        manager = m
                        break
                    }
                }
            }
            
            if (manager == nil) {
                manager = NETunnelProviderManager()
            }
            
            self.currentManager = manager
            self.status = manager!.connection.status
            self.updateButton()
            completionHandler?(nil)
        }
    }
    
    func updateButton() {
        switch status {
        case .connected, .connecting:
            buttonConnection.title = "Disconnect"
            
        case .disconnected:
            buttonConnection.title = "Connect"
            
        case .disconnecting:
            buttonConnection.title = "Disconnecting"
            
        default:
            break
        }
    }
    
    @objc private func VPNStatusDidChange(notification: NSNotification) {
        guard let status = currentManager?.connection.status else {
            print("VPNStatusDidChange")
            return
        }
        print("VPNStatusDidChange: \(status.rawValue)")
        self.status = status
        updateButton()
    }
    
    private func testFetchRef() {
//        let keychain = Keychain(group: ViewController.APP_GROUP)
//        let username = "foo"
//        let password = "bar"
//
//        guard let _ = try? keychain.set(password: password, for: username) else {
//            print("Couldn't set password")
//            return
//        }
//        guard let passwordReference = try? keychain.passwordReference(for: username) else {
//            print("Couldn't get password reference")
//            return
//        }
//        guard let fetchedPassword = try? Keychain.password(for: username, reference: passwordReference) else {
//            print("Couldn't fetch password")
//            return
//        }
//
//        print("\(username) -> \(password)")
//        print("\(username) -> \(fetchedPassword)")
    }
}

