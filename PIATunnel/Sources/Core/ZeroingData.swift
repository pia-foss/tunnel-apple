//
//  ZeroingData.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 4/27/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import __PIATunnelNative

func Z() -> ZeroingData {
    return ZeroingData()
}

func Z(count: Int) -> ZeroingData {
    return ZeroingData(count: count)
}

func Z(bytes: UnsafePointer<UInt8>, count: Int) -> ZeroingData {
    return ZeroingData(bytes: bytes, count: count)
}

func Z(_ uint8: UInt8) -> ZeroingData {
    return ZeroingData(uInt8: uint8)
}

func Z(_ uint16: UInt16) -> ZeroingData {
    return ZeroingData(uInt16: uint16)
}

func Z(_ data: Data) -> ZeroingData {
    return ZeroingData(data: data)
}

//func Z(_ data: Data, _ offset: Int, _ count: Int) -> ZeroingData {
//    return ZeroingData(data: data, offset: offset, count: count)
//}

func Z(_ string: String, nullTerminated: Bool = false) -> ZeroingData {
    return ZeroingData(string: string, nullTerminated: nullTerminated)
}
