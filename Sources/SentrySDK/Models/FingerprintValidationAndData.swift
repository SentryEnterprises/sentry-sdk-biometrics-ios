//
//  FingerprintValidationAndData.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation

/**
 Contains a value indicating if the fingerprint on the sensor matches the one recorded during enrollment, and any data stored on the card during the enrollment process.
 */
public struct FingerprintValidationAndData {
    /// `True` if the scanned fingerprint matches the one recorded during enrollment; otherwise `false`.
    public let doesFingerprintMatch: Bool
    
    /// Contains any data stored during the enrollment process. If no data was stored during enrollment, this array is empty.
    public let storedData: [UInt8]
}
