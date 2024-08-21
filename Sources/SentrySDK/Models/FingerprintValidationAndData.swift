//
//  FingerprintValidationAndData.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation

/**
 Indicates the results of a fingerprint validation.
 */
public enum FingerprintValidation {
    /// Indicates that the finger on the sensor matches the fingerprints recorded during enrollment.
    case matchValid
    
    /// Indicates that the finger on the sensor does not match the fingerprints recorded during enrollment.
    case matchFailed
    
    /// Indicates that the card is not enrolled and fingerprint verification cannot be performed.
    case notEnrolled
}

/**
 Contains a value indicating if the fingerprint on the sensor matches the one recorded during enrollment, and any data stored on the card during the enrollment process.
 */
public struct FingerprintValidationAndData {
    /// `.matchValid` if the scanned fingerprint matches the one recorded during enrollment; otherwise `.matchFailed` (or `.notEnrolled` if the card is not enrolled and validation cannot be performed).
    public let doesFingerprintMatch: FingerprintValidation
    
    /// Contains any data stored during the enrollment process. If no data was stored during enrollment, this array is empty.
    public let storedData: [UInt8]
}
