//
//  Data+Additions.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation

/**
 `Data` extensions.
 */
extension Data {
    /**
     Prints the `Data` buffer as a hexadecimal string.
     */
    func toHex() -> String {
        map { return String(format:"%02X", $0) }.joined(separator: "").uppercased()
    }
    
    /**
     Converts the `Data` buffer into an array of `UInt8` bytes.
     */
    func toArrayOfBytes() -> [UInt8] {
        return self.withUnsafeBytes { bufferPtr in
            guard let srcPointer = bufferPtr.baseAddress else {
               return [UInt8]()
            }

            let count = bufferPtr.count
            let typedPointer: UnsafePointer<UInt8> = srcPointer.bindMemory(to: UInt8.self, capacity: count)
            let buffer = UnsafeBufferPointer(start: typedPointer, count: count)
            return Array<UInt8>(buffer)
        }
    }
}
