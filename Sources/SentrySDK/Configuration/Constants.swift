//
//  Constants.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation

/**
 Various constants used throughout the SDK.
 */
enum SentrySDKConstants {
    /// The maximum amount of data (in bytes) that can be stored in the huge slot on the SentryCard.
    static let HUGE_MAX_DATA_SIZE = 2048
    
    /// The maximum amount of data (in bytes) that can be stored in the small slot on the SentryCard.
    static let SMALL_MAX_DATA_SIZE = 255
}
