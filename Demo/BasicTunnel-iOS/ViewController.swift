//
//  ViewController.swift
//  BasicTunnel-iOS
//
//  Created by Davide De Rosa on 2/11/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import UIKit
import NetworkExtension
import PIATunnel

class ViewController: UIViewController, URLSessionDataDelegate {
    static let APP_GROUP = "group.com.privateinternetaccess.ios.demo.BasicTunnel"
    
    static let VPN_BUNDLE = "com.privateinternetaccess.ios.demo.BasicTunnel.BasicTunnelExtension"

    static let CIPHER: PIATunnelProvider.Cipher = .aes128cbc

    static let DIGEST: PIATunnelProvider.Digest = .sha1

    static let HANDSHAKE: PIATunnelProvider.Handshake = .rsa2048
    
    static let RENEG: Int? = nil
    
    static let DOWNLOAD_COUNT = 5
    
    @IBOutlet var textUsername: UITextField!
    
    @IBOutlet var textPassword: UITextField!
    
    @IBOutlet var textServer: UITextField!
    
    @IBOutlet var textDomain: UITextField!
    
    @IBOutlet var textPort: UITextField!
    
    @IBOutlet var switchTCP: UISwitch!
    
    @IBOutlet var buttonConnection: UIButton!

    @IBOutlet var textLog: UITextView!

    //
    
    @IBOutlet var buttonDownload: UIButton!

    @IBOutlet var labelDownload: UILabel!
    
    var currentManager: NETunnelProviderManager?
    
    var status = NEVPNStatus.invalid
    
    var downloadTask: URLSessionDataTask!
    
    var downloadCount = 0

    var downloadTimes = [TimeInterval]()

    override func viewDidLoad() {
        super.viewDidLoad()
        
        textServer.text = "germany"
        textDomain.text = "privateinternetaccess.com"
//        textServer.text = "159.122.133.238"
//        textDomain.text = ""
        textPort.text = "8080"
        switchTCP.isOn = false
        textUsername.text = "myusername"
        textPassword.text = "mypassword"
        
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
    
    @IBAction func tcpClicked(_ sender: Any) {
        if switchTCP.isOn {
            textPort.text = "443"
        } else {
            textPort.text = "8080"
        }
    }
    
    func connect() {
        let server = textServer.text!
        let domain = textDomain.text!
        
        let hostname = ((domain == "") ? server : [server, domain].joined(separator: "."))
        let port = UInt16(textPort.text!)!
        let username = textUsername.text!
        let password = textPassword.text!

        configureVPN({ (manager) in
//            manager.isOnDemandEnabled = true
//            manager.onDemandRules = [NEOnDemandRuleConnect()]
            
            let endpoint = PIATunnelProvider.AuthenticatedEndpoint(
                hostname: hostname,
                username: username,
                password: password
            )

            var builder = PIATunnelProvider.ConfigurationBuilder(appGroup: ViewController.APP_GROUP)
            let socketType: PIATunnelProvider.SocketType = (self.switchTCP.isOn ? .tcp : .udp)
            builder.endpointProtocols = [PIATunnelProvider.EndpointProtocol(socketType, port, .pia)]
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

    @IBAction func displayLog() {
        guard let vpn = currentManager?.connection as? NETunnelProviderSession else {
            return
        }
        try? vpn.sendProviderMessage(PIATunnelProvider.Message.requestLog.data) { (data) in
            guard let log = String(data: data!, encoding: .utf8) else {
                return
            }
            self.textLog.text = log
        }
    }

    @IBAction func download() {
        downloadCount = ViewController.DOWNLOAD_COUNT
        downloadTimes.removeAll()
        buttonDownload.isEnabled = false
        labelDownload.text = ""

        doDownload()
    }
    
    func doDownload() {
        let url = URL(string: "https://example.bogus/test/100mb")!
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        let cfg = URLSessionConfiguration.ephemeral
        let sess = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
        
        let start = Date()
        downloadTask = sess.dataTask(with: req) { (data, response, error) in
            if let error = error {
                print("error downloading: \(error)")
                return
            }
            
            let elapsed = -start.timeIntervalSinceNow
            print("download finished: \(elapsed) seconds")
            self.downloadTimes.append(elapsed)
            
            DispatchQueue.main.async {
                self.downloadCount -= 1
                if (self.downloadCount > 0) {
                    self.labelDownload.text = "\(self.labelDownload.text!)\(elapsed) seconds\n"
                    self.doDownload()
                } else {
                    var avg = 0.0
                    for n in self.downloadTimes {
                        avg += n
                    }
                    avg /= Double(ViewController.DOWNLOAD_COUNT)
                    
                    self.labelDownload.text = "\(avg) seconds"
                    self.buttonDownload.isEnabled = true
                }
            }
        }
        downloadTask.resume()
    }
    
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        print("received \(data.count) bytes")
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
            buttonConnection.setTitle("Disconnect", for: .normal)
            
        case .disconnected:
            buttonConnection.setTitle("Connect", for: .normal)
            
        case .disconnecting:
            buttonConnection.setTitle("Disconnecting", for: .normal)
            
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
