//
//  Data+Manipulation.swift
//  PIATunnel
//
//  Created by Davide De Rosa on 2/3/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation

// hex -> Data conversion code from: http://stackoverflow.com/questions/32231926/nsdata-from-hex-string
// Data -> hex conversion code from: http://stackoverflow.com/questions/39075043/how-to-convert-data-to-hex-string-in-swift

extension UnicodeScalar {
    var hexNibble: UInt8 {
        let value = self.value
        if 48 <= value && value <= 57 {
            return UInt8(value - 48)
        }
        else if 65 <= value && value <= 70 {
            return UInt8(value - 55)
        }
        else if 97 <= value && value <= 102 {
            return UInt8(value - 87)
        }
        fatalError("\(self) not a legal hex nibble")
    }
}

extension Data {
    init(hex: String) {
        let scalars = hex.unicodeScalars
        var bytes = Array<UInt8>(repeating: 0, count: (scalars.count + 1) >> 1)
        for (index, scalar) in scalars.enumerated() {
            var nibble = scalar.hexNibble
            if index & 1 == 0 {
                nibble <<= 4
            }
            bytes[index >> 1] |= nibble
        }
        self = Data(bytes: bytes)
    }

    func toHex() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    mutating func zero() {
        resetBytes(in: 0..<count)
    }

    mutating func zero(from: Int, to: Int) {
        resetBytes(in: from..<to)
    }
}

extension Data {
    mutating func append(_ value: UInt16) {
        var localValue = value
        let buffer = UnsafeBufferPointer(start: &localValue, count: 1)
        append(buffer)
    }
    
    mutating func append(_ value: UInt32) {
        var localValue = value
        let buffer = UnsafeBufferPointer(start: &localValue, count: 1)
        append(buffer)
    }
    
    mutating func append(nullTerminatedString: String) {
        append(nullTerminatedString.data(using: .ascii)!)
        append(UInt8(0))
    }

    func nullTerminatedString(from: Int) -> String? {
        var nullOffset: Int?
        for i in from..<count {
            if (self[i] == 0) {
                nullOffset = i
                break
            }
        }
        guard let to = nullOffset else {
            return nil
        }
        return String(data: subdata(in: from..<to), encoding: .ascii)
    }

    // best
    func UInt16Value(from: Int) -> UInt16 {
        var value: UInt16 = 0
        for i in 0..<2 {
            let byte = self[from + i]
//            print("byte: \(String(format: "%x", byte))")
            value |= (UInt16(byte) << UInt16(8 * i))
        }
//        print("value: \(String(format: "%x", value))")
        return value
    }
    
    @available(*, deprecated)
    func UInt16ValueFromPointers(from: Int) -> UInt16 {
        return subdata(in: from..<(from + 2)).withUnsafeBytes { $0.pointee }
    }

    @available(*, deprecated)
    func UInt16ValueFromReboundPointers(from: Int) -> UInt16 {
        let data = subdata(in: from..<(from + 2))
//        print("data: \(data.toHex())")
        let value = data.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UInt16 in
            bytes.withMemoryRebound(to: UInt16.self, capacity: 1) {
                $0.pointee
            }
        }
//        print("value: \(String(format: "%x", value))")
        return value
    }
    
    @available(*, deprecated)
    func UInt32ValueFromBuffer(from: Int) -> UInt32 {
        var value: UInt32 = 0
        for i in 0..<4 {
            let byte = self[from + i]
//            print("byte: \(String(format: "%x", byte))")
            value |= (UInt32(byte) << UInt32(8 * i))
        }
//        print("value: \(String(format: "%x", value))")
        return value
    }
    
    // best
    func UInt32Value(from: Int) -> UInt32 {
        return subdata(in: from..<(from + 4)).withUnsafeBytes { $0.pointee }
    }

    @available(*, deprecated)
    func UInt32ValueFromReboundPointers(from: Int) -> UInt32 {
        let data = subdata(in: from..<(from + 4))
//        print("data: \(data.toHex())")
        let value = data.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UInt32 in
            bytes.withMemoryRebound(to: UInt32.self, capacity: 1) {
                $0.pointee
            }
        }
//        print("value: \(String(format: "%x", value))")
        return value
    }
}

extension Data {
    func subdata(offset: Int, count: Int) -> Data {
        return subdata(in: offset..<(offset + count))
    }
}
