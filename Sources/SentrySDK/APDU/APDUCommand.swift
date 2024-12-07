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
        
    /// Gets the enrollment status.
    static let getEnrollStatus: [UInt8] = [0x84, 0x59, 0x04, 0x00, 0x01, 0x00]
    
    /// Verifies that the finger on the sensor matches the one recorded during enrollment.
    static let getFingerprintVerify: [UInt8] = [0x80, 0xB6, 0x01, 0x00, 0x00]
    
    /// Verifies fingerprint enrollment.
    static let verifyFingerprintEnrollment: [UInt8] = [0x84, 0x59, 0x00, 0x00, 0x01, 0x00]
    
    /// Retrieves the on-card OS version.
    static let getOSVersion: [UInt8] = [0xB1, 0x05, 0x40, 0x00, 0x00]
    
    /// Retrieves the Verify applet version information.
    static let getVerifyAppletVersion: [UInt8] = [0x80, 0xCA, 0x5F, 0xC1, 0x00]
    
    /// Retrieves the data stored in the huge data slot of the Verify applet (requires biometric verification).
    static let getVerifyAppletStoredDataHugeSecured: [UInt8] = [0x80, 0xCB, 0x01, 0xC2, 0x00, 0x0F, 0xFF]       // up to 2048 bytes
    
    /// Retrieves the data stored in the small data slot of the Verify applet.
    static let getVerifyAppletStoredDataSmallUnsecured: [UInt8] = [0x80, 0xCA, 0x5F, 0xB0, 0xFF]                // up to 255 bytes
    
    /// Retrieves the data stored in the small data slot of the Verify applet (requires biometric verification).
    static let getVerifyAppletStoredDataSmallSecured: [UInt8] = [0x80, 0xCB, 0x01, 0xD0, 0xFF]                  // up to 255 bytes

    /// Resets biometric data. DEVELOPMENT USE ONLY! This command works only on development cards.
    static let resetBiometricData: [UInt8] = [0xED, 0x57, 0xC1, 0x00, 0x01, 0x00]
    
    /// Enrolls a fingerprint.
    static func processFingerprint(fingerIndex: UInt8) -> [UInt8] {
        var processFingerprintCommand: [UInt8] = [0x84, 0x59, 0x03, 0x00, 0x02, 0x00]
        processFingerprintCommand.append(fingerIndex)
        return processFingerprintCommand
    }
    
    /// Enrolls a fingerprint and resets biometric data (used for restarting enrollment process).
    static func restartEnrollAndProcessFingerprint(fingerIndex: UInt8) -> [UInt8] {
        var restartEnrollAndProcessFingerprintCommand: [UInt8] = [0x84, 0x59, 0x03, 0x00, 0x02, 0x06]
        restartEnrollAndProcessFingerprintCommand.append(fingerIndex)
        return restartEnrollAndProcessFingerprintCommand
    }

    /// Verifies the enroll code.
    static func verifyEnrollCode(code: [UInt8]) throws -> [UInt8] {
        var verifyCodeCommand: [UInt8] = [0x80, 0x20, 0x00, 0x80, 0x08]
        try verifyCodeCommand.append(contentsOf: constructCodeBuffer(code: code))
        return verifyCodeCommand
    }
    
    /// Sets the data stored in the huge data slot of the Verify applet.
    /// NOTE: Both the secure and unsecure version of this command write to the same data store slot
    /// NOTE: This command is only included in case we want to reverse some changes to the way the large data slot is used. This command will likely become obsolete.
    static func setVerifyAppletStoredDataHugeUnsecure(data: [UInt8]) throws -> [UInt8] {
        if data.count > SentrySDKConstants.HUGE_MAX_DATA_SIZE {
            throw SentrySDKError.dataSizeNotSupported
        }
            
        var setVerifyAppletStoredData: [UInt8] = [0x80, 0xDA, 0x5F, 0xC2, 0x00]
        setVerifyAppletStoredData.append(UInt8((data.count & 0xFF00) >> 8))
        setVerifyAppletStoredData.append(UInt8(data.count & 0x00FF))
        setVerifyAppletStoredData.append(contentsOf: data)
        
        return setVerifyAppletStoredData
    }
    
    /// Sets the data stored in the huge data slot of the Verify applet (requires biometric verification).
    static func setVerifyAppletStoredDataHugeSecure(data: [UInt8]) throws -> [UInt8] {
        if data.count > SentrySDKConstants.HUGE_MAX_DATA_SIZE {
            throw SentrySDKError.dataSizeNotSupported
        }
            
        var setVerifyAppletStoredData: [UInt8] = [0x80, 0xDB, 0x01, 0xC2, 0x00]
        setVerifyAppletStoredData.append(UInt8((data.count & 0xFF00) >> 8))
        setVerifyAppletStoredData.append(UInt8(data.count & 0x00FF))
        setVerifyAppletStoredData.append(contentsOf: data)
        
        return setVerifyAppletStoredData
    }

    /// Sets the data stored in the small data slot of the Verify applet.
    static func setVerifyAppletStoredDataSmallUnsecure(data: [UInt8]) throws -> [UInt8] {
        if data.count > SentrySDKConstants.SMALL_MAX_DATA_SIZE {
            throw SentrySDKError.dataSizeNotSupported
        }
            
        var setVerifyAppletStoredData: [UInt8] = [0x80, 0xDA, 0x5F, 0xB0]
        setVerifyAppletStoredData.append(UInt8(data.count & 0x00FF))
        setVerifyAppletStoredData.append(contentsOf: data)
        
        return setVerifyAppletStoredData
    }

    /// Sets the data stored in the small data slot of the Verify applet (requires biometric verification).
    static func setVerifyAppletStoredDataSmallSecure(data: [UInt8]) throws -> [UInt8] {
        if data.count > SentrySDKConstants.SMALL_MAX_DATA_SIZE {
            throw SentrySDKError.dataSizeNotSupported
        }
            
        var setVerifyAppletStoredData: [UInt8] = [0x80, 0xDB, 0x01, 0xD0]
        setVerifyAppletStoredData.append(UInt8(data.count & 0x00FF))
        setVerifyAppletStoredData.append(contentsOf: data)
        
        return setVerifyAppletStoredData
    }


    
    // MARK: - Private Methods
    
    /// Returns a padded buffer that contains the indicated enroll code digits.
    private static func constructCodeBuffer(code: [UInt8]) throws -> [UInt8] {
        // sanity check - enroll code must be between 4 and 6 characters
        if code.count < 4 || code.count > 6 {
            throw SentrySDKError.enrollCodeLengthOutOfBounds
        }

        var bufferIndex = 1
        var codeBuffer: [UInt8] = []
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
