//
//  APDUCommand.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation

/**
 Encapsulates the various `APDU` command bytes used throughout the SDK.
 
 For more information on `APDU` commands, see the ISO7816-3 spec, ISO7816-4 spec, and the APDU Enrollment Device Specification from IDEX.
 */
enum APDUCommand {
    /// Selects the IDEX Enrollment applet (AID 494445585F4C5F0101)
    static let selectEnrollApplet: [UInt8] = [0x00, 0xA4, 0x04, 0x00, 0x09, 0x49, 0x44, 0x45, 0x58, 0x5F, 0x4C, 0x5F, 0x01, 0x01, 0x00]
    
    ///
    static let setPT1: [UInt8] = [0x80, 0xE2, 0x08, 0x00, 0x04, 0x90, 0x08, 0x01, 0x03]
    
    /// Resets enrollment.
    static let setEnroll: [UInt8] = [0x80, 0xE2, 0x08, 0x00, 0x04, 0x90, 0x13, 0x01, 0xCB]
    
    /// Sets enrollment retry count.
    static let setEnrollLimit: [UInt8] = [0x80, 0xE2, 0x08, 0x00, 0x04, 0x90, 0x15, 0x01, 0xFF]
    
    ///
    static let setStore: [UInt8] = [0x80, 0xE2, 0x88, 0x00, 0x00]
    
    /// Gets the enrollment status.
    static let getEnrollStatus: [UInt8] = [0x00, 0x59, 0x04, 0x00, 0x01, 0x00]
    
    /// Verifies that the finger on the sensor matches the one recorded during enrollment.
    static let getFingerprintVerify: [UInt8] = [0xED, 0x56, 0x00, 0x00, 0x01, 0x00]
    
    /// Enrolls a fingerprint.
    static let processFingerprint: [UInt8] = [0x00, 0x59, 0x03, 0x00, 0x02, 0x00, 0x01] // note: the last byte indicates the finger number; this will need updating if/when 2 fingers are supported
    
    /// Verifies fingerprint enrollment.
    static let verifyFingerprintEnrollment: [UInt8] = [0x00, 0x59, 0x00, 0x00, 0x01, 0x00]
    
    /// Verifies the PIN.
    static func verifyPIN(pin: [UInt8]) throws -> [UInt8] {
        var verifyPINCommand: [UInt8] = [0x80, 0x20, 0x00, 0x80, 0x08]
        try verifyPINCommand.append(contentsOf: constructPINBuffer(pin: pin))
        return verifyPINCommand
    }

    /// Sets the PIN.
    static func setPIN(pin: [UInt8]) throws -> [UInt8] {
        var setPINCommand: [UInt8] = [ 0x80, 0xE2, 0x08, 0x00, 0x0B, 0x90, 0x00, 0x08]
        try setPINCommand.append(contentsOf: constructPINBuffer(pin: pin))
        return setPINCommand
    }

    
    // MARK: - Private Methods
    
    /// Returns a padded buffer that contains the indicated PIN digits.
    private static func constructPINBuffer(pin: [UInt8]) throws -> [UInt8] {
        var bufferIndex = 1
        var PINBuffer: [UInt8] = [] // [0x80, 0x20, 0x00, 0x80, 0x08]
        PINBuffer.append(0x20 + UInt8(pin.count))
        PINBuffer.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        
        for index in 0..<pin.count {
            let digit = pin[index]
            if digit > 9 {
                throw SentrySDKError.pinDigitOutOfBounds
            }
            
            if index % 2 == 0 {
                PINBuffer[bufferIndex] &= 0x0F
                PINBuffer[bufferIndex] |= digit << 4
            } else {
                PINBuffer[bufferIndex] &= 0xF0
                PINBuffer[bufferIndex] |= digit
                bufferIndex = bufferIndex + 1
            }
        }

        return PINBuffer
    }
}
