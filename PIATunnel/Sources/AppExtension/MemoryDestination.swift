//
//  MemoryDestination.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 7/26/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import SwiftyBeaver

class MemoryDestination: BaseDestination, CustomStringConvertible {
    private let queue = DispatchQueue(label: "MemoryDestination")
    
    private var buffer: [String] = []
    
    var maxLines: Int?
    
    func start(with existing: [String]) {
        queue.sync {
            buffer = existing
        }
    }
    
    func flush(to: UserDefaults, with key: String) {
        queue.sync {
            to.set(buffer, forKey: key)
        }
        to.synchronize()
    }
    
    override func send(_ level: SwiftyBeaver.Level, msg: String, thread: String, file: String, function: String, line: Int, context: Any?) -> String? {
        guard let message = super.send(level, msg: msg, thread: thread, file: file, function: function, line: line) else {
            return nil
        }
        queue.sync {
            buffer.append(message)
        }
        if let maxLines = maxLines {
            while (buffer.count > maxLines) {
                buffer.removeFirst()
            }
        }
        return message
    }

    var description: String {
        return queue.sync {
            return buffer.joined(separator: "\n")
        }
    }
}
