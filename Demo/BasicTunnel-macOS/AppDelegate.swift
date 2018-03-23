//
//  AppDelegate.swift
//  BasicTunnel-macOS
//
//  Created by Davide De Rosa on 10/15/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Cocoa
import SwiftyBeaver

private let log = SwiftyBeaver.self

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {



    func applicationDidFinishLaunching(_ aNotification: Notification) {
        let logDestination = ConsoleDestination()
        logDestination.minLevel = .debug
        logDestination.format = "$DHH:mm:ss$d $L $N.$F:$l - $M"
        log.addDestination(logDestination)

        // Insert code here to initialize your application
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }


}

