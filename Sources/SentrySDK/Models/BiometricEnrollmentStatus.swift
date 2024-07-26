//
//  BiometricEnrollmentStatus.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation

/**
 Indicates the card's biometric mode.
 */
public enum BiometricMode {
    case enrollment                 // the card is in enrollment mode and will accept fingerprint enrollment commands
    case verification               // the card is in verification mode
}

/**
 Encapsulates the information returned from querying the card for its enrollment status.
 */
public struct BiometricEnrollmentStatus {
    /// Usually 1, due to only 1 finger can be saved on the card for now.
    public let maximumFingers: UInt8
    
    /// Indicates the number of currently enrolled touches (in the range 0 - 6).
    public let enrolledTouches: UInt8
    
    /// Indicates the number of touches remaining to be enrolled (in the range 0 - 6).
    public let remainingTouches: UInt8
    
    /// Indicates the card's enrollment mode (either available for enrollment or ready to verify fingerprints).
    public let mode: BiometricMode
}
