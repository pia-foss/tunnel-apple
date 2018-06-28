//
//  LinkInterface+Strategy.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 6/28/18.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

extension LinkInterface {
    func hardReset(with encryption: SessionProxy.EncryptionParameters) -> Data? {
        switch communicationType {
        case .pia:
            let settings = TunnelSettings(
                caMd5Digest: encryption.caDigest,
                cipherName: encryption.cipherName,
                digestName: encryption.digestName
            )
            return (try? settings.encodedData()) ?? Data()
            
        default:
            break
        }
        return nil
    }
}
