//
//  APDUResponseCode.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation

/**
 Common `APDU` command responses.
 
 For more information on `APDU` command response codes, see the ISO7816-3 spec, ISO7816-4 spec, and the APDU Enrollment Device Specification from IDEX.
 */
public enum APDUResponseCode: Int {
    /// Normal operation.
    case operationSuccessful = 0x9000
    
    /// Warning processing - state of non-volatile memory may have changed
    case noMatchFound = 0x6300
    case enrollCodeIncorrectThreeTriesRemain = 0x63C3
    case enrollCodeIncorrectTwoTriesRemain = 0x63C2
    case enrollCodeIncorrectOneTriesRemain = 0x63C1
    case enrollCodeIncorrectZeroTriesRemain = 0x63C0
    
    /// Checking errors - wrong length
    case wrongLength = 0x6700
    case formatNotCompliant = 0x6701
    case lengthValueNotTheOneExpected = 0x6702
    case communicationFailure = 0x6741              // IDEX Enroll applet specific
    case calibrationError = 0x6744
    case fingerRemoved = 0x6745                     // IDEX Enroll applet specific
    case poorImageQuality = 0x6747                  // IDEX Enroll applet specific
    case userTimeoutExpired = 0x6748                // IDEX Enroll applet specific
    case hostInterfaceTimeoutExpired = 0x6749       // IDEX Enroll applet specific
    
    /// Checking errors - command not allowed
    case conditionOfUseNotSatisfied = 0x6985
    
    /// Checking errors - wrong parameters
    case appletNotFound = 0x6A82
    case notEnoughMemory = 0x6A84
    
    /// Checking errors - wrong parameters
    case wrongParameters = 0x6B00
    
    /// Checking errors - INS code not supported
    case instructionByteNotSupported = 0x6D00
    
    /// Checking errors - CLA code not supported
    case classByteNotSupported = 0x6E00
    
    /// Checking errors - no precise diagnosis
    case commandAborted = 0x6F00
    case noPreciseDiagnosis = 0x6F87
    case cardDead = 0x6FFF
}
