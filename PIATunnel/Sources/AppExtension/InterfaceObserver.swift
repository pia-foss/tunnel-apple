//
//  InterfaceObserver.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 6/14/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import SystemConfiguration.CaptiveNetwork
import SwiftyBeaver

private let log = SwiftyBeaver.self

extension NSNotification.Name {
    static let __InterfaceObserverDidDetectWifiChange = NSNotification.Name("__InterfaceObserverDidDetectWifiChange")
}

class InterfaceObserver: NSObject {
    private var queue: DispatchQueue?
    
    private var timer: DispatchSourceTimer?
    
    private var lastWifiName: String?
    
    func start(queue: DispatchQueue) {
        self.queue = queue

        let timer = DispatchSource.makeTimerSource(flags: DispatchSource.TimerFlags(rawValue: UInt(0)), queue: queue)
        timer.schedule(deadline: DispatchTime.now(), repeating: .seconds(1))
        timer.setEventHandler {
            self.fireWifiChangeObserver()
        }
        timer.resume()

        self.timer = timer
    }
    
    func stop() {
        timer?.cancel()
        timer = nil
        queue = nil
    }

    private func fireWifiChangeObserver() {
        let currentWifiName = currentWifiNetworkName()
        if (currentWifiName != lastWifiName) {
            if let current = currentWifiName {
                log.debug("SSID is now '\(current)'")
                if let last = lastWifiName, (current != last) {
                    queue?.async {
                        NotificationCenter.default.post(name: .__InterfaceObserverDidDetectWifiChange, object: nil)
                    }
                }
            } else {
                log.debug("SSID is null")
            }
        }
        lastWifiName = currentWifiName
    }

    func currentWifiNetworkName() -> String? {
        #if os(iOS)
        guard let interfaceNames = CNCopySupportedInterfaces() as? [CFString] else {
            return nil
        }
        for name in interfaceNames {
            guard let iface = CNCopyCurrentNetworkInfo(name) as? [String: Any] else {
                continue
            }
            if let ssid = iface["SSID"] as? String {
                return ssid
            }
        }
        #endif
        return nil
    }
}
