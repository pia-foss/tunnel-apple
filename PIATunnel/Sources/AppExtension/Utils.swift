//
//  Utils.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 5/23/18.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

extension DispatchQueue {
    func schedule(after: DispatchTimeInterval, block: @escaping () -> Void) {
        let deadline = DispatchTime.now() + after
        asyncAfter(deadline: deadline, execute: block)
    }
}
