//
//  SentrySDKDelegate.swift
//
//
//  Copyright © 2024 Sentry Enterprises
//

/**
 
 NOTE: EXPERIMENTAL WORK-IN-PROGRESS
 
 */

import Foundation

/**
 Implement this delegate to receive feedback from the `SentrySDK`.
 
 NOTE: This is currently an experimental work-in-progress that is actively changing. Do not use this in production code (yet). This functionality can be safely ignored by simply
 not setting the delegate on any initialized `SentrySDK` object.
 */
public protocol SentrySDKDelegate {
    func cardDetectionChanged(cardIsDetected: Bool)
}
