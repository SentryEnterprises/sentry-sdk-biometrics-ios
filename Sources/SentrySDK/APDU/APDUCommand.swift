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
    
    /// Selects the CDCVM applet (AID F04A4E45545F1001)
    static let selectCVMApplet: [UInt8] = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xF0, 0x4A, 0x4E, 0x45, 0x54, 0x5F, 0x10, 0x01, 0x00]
    
    /// Selects the Verify applet (AID 4A4E45545F0102030405)
    static let selectVerifyApplet: [UInt8] = [0x00, 0xA4, 0x04, 0x00, 0x0A, 0x4A, 0x4E, 0x45, 0x54, 0x5F, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00]
    
    // TODO: Note - not removing this just yet
//    static let setPT1: [UInt8] = [0x80, 0xE2, 0x08, 0x00, 0x04, 0x90, 0x08, 0x01, 0x03]
//    
//    /// Resets enrollment.
//    static let setEnroll: [UInt8] = [0x80, 0xE2, 0x08, 0x00, 0x04, 0x90, 0x13, 0x01, 0xCB]
//    
//    /// Sets enrollment retry count.
//    static let setEnrollLimit: [UInt8] = [0x80, 0xE2, 0x08, 0x00, 0x04, 0x90, 0x15, 0x01, 0xFF]
//    
//    ///
//    static let setStore: [UInt8] = [0x80, 0xE2, 0x88, 0x00, 0x00]
    
    /// Gets the enrollment status.
    static let getEnrollStatus: [UInt8] = [0x84, 0x59, 0x04, 0x00, 0x01, 0x00]
    
    /// Verifies that the finger on the sensor matches the one recorded during enrollment.
    static let getFingerprintVerify: [UInt8] = [0xED, 0x56, 0x00, 0x00, 0x01, 0x00]
    
    /// Enrolls a fingerprint.
    static let processFingerprint: [UInt8] = [0x84, 0x59, 0x03, 0x00, 0x02, 0x00, 0x01] // note: the last byte indicates the finger number; this will need updating if/when 2 fingers are supported
    
    /// Verifies fingerprint enrollment.
    static let verifyFingerprintEnrollment: [UInt8] = [0x84, 0x59, 0x00, 0x00, 0x01, 0x00]
    
    /// Retrieves the on-card OS version.
    static let getOSVersion: [UInt8] = [0xB1, 0x05, 0x40, 0x00, 0x00]
    
    /// Retrieves the Verify applet version information.
    static let getVerifyAppletVersion: [UInt8] = [0x80, 0xCA, 0x5F, 0xC1, 0x00]
    
    /// Retrieves the data stored in the Verify applet.
    static let getVerifyAppletStoredData: [UInt8] = [0x80, 0xCA, 0x5F, 0xC2, 0x00]

    /// Resets biometric data. DEVELOPMENT USE ONLY! This command works only on development cards.
    static let resetBiometricData: [UInt8] = [0xED, 0x57, 0xC1, 0x00, 0x01, 0x00]
    
    /// Verifies the enroll code.
    static func verifyEnrollCode(code: [UInt8]) throws -> [UInt8] {
        var verifyCodeCommand: [UInt8] = [0x80, 0x20, 0x00, 0x80, 0x08]
        try verifyCodeCommand.append(contentsOf: constructCodeBuffer(code: code))
        return verifyCodeCommand
    }

    /// Sets the enroll code.
    static func setEnrollCode(code: [UInt8]) throws -> [UInt8] {
        var setCodeCommand: [UInt8] = [ 0x80, 0xE2, 0x08, 0x00, 0x0B, 0x90, 0x00, 0x08]
        try setCodeCommand.append(contentsOf: constructCodeBuffer(code: code))
        return setCodeCommand
    }
    
    // TODO: Restrict this to 255 bytes
    /// Sets the data stored in the Verify applet.
    static func setVerifyAppletStoredData(data: [UInt8]) throws -> [UInt8] {
        var setVerifyAppletStoredData: [UInt8] = [0x80, 0xDA, 0x5F, 0xC2]
        setVerifyAppletStoredData.append(UInt8(data.count))
        setVerifyAppletStoredData.append(contentsOf: data)
        
        return setVerifyAppletStoredData
    }

    
    // MARK: - Private Methods
    
    /// Returns a padded buffer that contains the indicated enroll code digits.
    private static func constructCodeBuffer(code: [UInt8]) throws -> [UInt8] {
        var bufferIndex = 1
        var codeBuffer: [UInt8] = [] // [0x80, 0x20, 0x00, 0x80, 0x08]
        codeBuffer.append(0x20 + UInt8(code.count))
        codeBuffer.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        
        for index in 0..<code.count {
            let digit = code[index]
            if digit > 9 {
                throw SentrySDKError.enrollCodeDigitOutOfBounds
            }
            
            if index % 2 == 0 {
                codeBuffer[bufferIndex] &= 0x0F
                codeBuffer[bufferIndex] |= digit << 4
            } else {
                codeBuffer[bufferIndex] &= 0xF0
                codeBuffer[bufferIndex] |= digit
                bufferIndex = bufferIndex + 1
            }
        }

        return codeBuffer
    }
}
