//
//  FingerprintValidationAndData.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation

/**
 THIS STRUCT IS IN FLUX AND IS SUBJECT TO CHANGE.
 */
public struct FingerprintValidationAndData {
    public let doesFingerprintMatch: Bool
    public let storedData: [UInt8]
}
