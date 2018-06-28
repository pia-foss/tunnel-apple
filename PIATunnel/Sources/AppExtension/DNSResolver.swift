//
//  DNSResolver.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 12/15/17.
//  Copyright © 2017 London Trust Media. All rights reserved.
//

import Foundation

class DNSResolver {
    private static let queue = DispatchQueue(label: "DNSResolver")

    static func resolve(_ hostname: String, timeout: Int, completionHandler: @escaping ([String]?, Error?) -> Void) {
        var pendingHandler: (([String]?, Error?) -> Void)? = completionHandler
        let host = CFHostCreateWithName(nil, hostname as CFString).takeRetainedValue()
        DNSResolver.queue.async {
            CFHostStartInfoResolution(host, .addresses, nil)
            guard let handler = pendingHandler else {
                return
            }
            DNSResolver.didResolve(host: host, completionHandler: handler)
            pendingHandler = nil
        }
        DNSResolver.queue.asyncAfter(deadline: .now() + .milliseconds(timeout)) {
            guard let handler = pendingHandler else {
                return
            }
            CFHostCancelInfoResolution(host, .addresses)
            handler(nil, nil)
            pendingHandler = nil
        }
    }
    
    private static func didResolve(host: CFHost, completionHandler: @escaping ([String]?, Error?) -> Void) {
        var success: DarwinBoolean = false
        guard let rawAddresses = CFHostGetAddressing(host, &success)?.takeUnretainedValue() as Array? else {
            completionHandler(nil, nil)
            return
        }
        
        var ipAddresses: [String] = []
        for case var rawAddress as Data in rawAddresses {
            var ipAddress = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = rawAddress.withUnsafeBytes { (addr: UnsafePointer<sockaddr>) in
                return getnameinfo(
                    addr,
                    socklen_t(rawAddress.count),
                    &ipAddress,
                    socklen_t(ipAddress.count),
                    nil,
                    0,
                    NI_NUMERICHOST
                )
            }
            guard result == 0 else {
                continue
            }
            ipAddresses.append(String(cString: ipAddress))
        }
        completionHandler(ipAddresses, nil)
    }

    public static func string(fromIPv4 ipv4: UInt32) -> String {
        let a = UInt8(ipv4 & UInt32(0xff))
        let b = UInt8((ipv4 >> 8) & UInt32(0xff))
        let c = UInt8((ipv4 >> 16) & UInt32(0xff))
        let d = UInt8((ipv4 >> 24) & UInt32(0xff))

        return "\(a).\(b).\(c).\(d)"
    }
    
    private init() {
    }
}
