//
//  TunnelSettings.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/7/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

enum TunnelSettingsError: Error {
    case encoding
}

struct TunnelSettings {
    private static let obfuscationKeyLength = 3
    
    private static let magic = "53eo0rk92gxic98p1asgl5auh59r1vp4lmry1e3chzi100qntd"
    
    private static let encodedFormat = "\(magic)crypto\t%@|%@\tca\t%@"
    
    private let caMd5Digest: String
    
    private let cipherName: String
    
    private let digestName: String

    init(caMd5Digest: String, cipherName: String, digestName: String) {
        self.caMd5Digest = caMd5Digest
        self.cipherName = cipherName
        self.digestName = digestName
    }

    // Ruby: pia_settings
    func encodedData() throws -> Data {
        guard let plainData = String(format: TunnelSettings.encodedFormat, cipherName, digestName, caMd5Digest).data(using: .ascii) else {
            throw TunnelSettingsError.encoding
        }
        let keyBytes = try SecureRandom.data(length: TunnelSettings.obfuscationKeyLength)

        var encodedData = Data(keyBytes)
        for (i, b) in plainData.enumerated() {
            let keyChar = keyBytes[i % keyBytes.count]
            let xorredB = b ^ keyChar
            
            encodedData.append(xorredB)
        }
        return encodedData
    }
}
