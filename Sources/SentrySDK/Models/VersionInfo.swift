//
//  VersionInfo.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation

/**
 Contains version information.
 */
public struct VersionInfo {
    /// Indicates if the queried object is installed on the card
    public let isInstalled: Bool
    
    /// The major version number (increments on major functionality changes).
    public let majorVersion: Int
    
    /// The minor version number (increments on minor functionality changes).
    public let minorVersion: Int
    
    /// The hotfix version number (increments only on emergency bug fixes).
    public let hotfixVersion: Int
    
    /// A textual representation of the data returned by the queried object.
    public let text: String?
}

/**
 Contains version information for the scanned card.
 */
public struct CardVersionInfo {
    /// The java card operating system version.
    public let osVersion: VersionInfo
    
    /// The enrollment applet version.
    public let enrollAppletVersion: VersionInfo
    
    /// The CVM applet version.
    public let cvmAppletVersion: VersionInfo
    
    /// The verify applet version.
    public let verifyAppletVersion: VersionInfo
}
