//
//  SentrySDKDelegate.swift
//
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation
import CoreNFC

/**
 Implement this protocol to detect when an `NFCReaderSession` connects to or disconnects from the Sentry Card.
 */
public protocol SentrySDKConnectionDelegate {
    /**
     Indicates when a Sentry Card is connected or disconnected from the application.
     
     - Parameters:
        - session: The `NFCReaderSession` controlling the communication with the Sentry Card.
        - isConnected: This is `true` when the software can actively communicate with the Sentry Card, and `false` when the software can no longer detect the Sentry Card.
     */
    func connected(session: NFCReaderSession, isConnected: Bool)
}
    
/**
 Implement this protocol to monitor the state of fingerprint enrollment.
 */
public protocol SentrySDKEnrollmentDelegate {
    /**
     Indicates when fingerprint enrollment is fully completed.
     
     - Parameters:
        - session: The `NFCReaderSession` controlling the communication with the Sentry Card.
     */
    func enrollmentComplete(session: NFCReaderSession)
    
    /**
     Indicates when the next finger should be used to touch the sensor (for Sentry Cards that support multi-finger enrollment).
     
     - Parameters:
        - session: The `NFCReaderSession` controlling the communication with the Sentry Card.
        - nextFingerIndex: A count indicating the generic 'index' of the next finger to use. Enrollment always starts with the first finger. This parameter is `2` for the next finger, and continues incrementing if more than two fingers are supported.
     */
    func fingerTransition(session: NFCReaderSession, nextFingerIndex: UInt8)
    
    /**
     Indicates the enrollment status for the finger currently being enrolled.
     
     - Parameters:
        - session: The `NFCReaderSession` controlling the communication with the Sentry Card.
        - currentFingerIndex: The generic 'index' of the finger being enrolled. Starts at `1`.
        - currentStep: The current enrollment step (or touch). Starts at `0`.
        - totalSteps: The total number of steps (or touches) required to enroll the finger.
     */
    func enrollmentStatus(session: NFCReaderSession, currentFingerIndex: UInt8, currentStep: UInt8, totalSteps: UInt8, isNewTouch: Bool)
}
