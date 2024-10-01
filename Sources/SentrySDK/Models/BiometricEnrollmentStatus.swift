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
 Describes the number of enrolled touches and remaining touches for a finger.
 */
public struct FingerTouches {
    /// Indicates the number of currently enrolled touches (in the range 0 - 6).
    public let enrolledTouches: UInt8
    
    /// Indicates the number of touches remaining to be enrolled (in the range 0 - 6).
    public let remainingTouches: UInt8
}

/**
 Encapsulates the information returned from querying the card for its enrollment status.
 */
public struct BiometricEnrollmentStatus {
    /// One (1) for Enroll applet prior to 2.1, two (2) for Enroll applet 2.1 or later.
    public let maximumFingers: UInt8
    
    /// Enrollment data for each supported finger.
    public let enrollmentByFinger: [FingerTouches]
    
    /// The index of the next finger to enroll, starting at one (1).
    public let nextFingerToEnroll: UInt8
    
    /// Indicates the card's enrollment mode (either available for enrollment or ready to verify fingerprints).
    public let mode: BiometricMode
}
