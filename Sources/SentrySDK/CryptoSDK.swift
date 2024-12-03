//
//  SentrySDK.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation
import CoreNFC
import Security

public class CryptoSDK: NSObject {
    // MARK: - Private Properties
    
    private let enrollCode: [UInt8]
    private let biometricsAPI: BiometricsAPI
    
    private var session: NFCTagReaderSession?
    private var connectedTag: NFCISO7816Tag?
    private var callback: ((Result<NFCISO7816Tag, Error>) -> Void)?
    
    
    // MARK: - Public Properties
    
    /// The object that acts as the connection delegate for the `SentrySDK`.
    public var connectionDelegate: SentrySDKConnectionDelegate?
    
    /// The object that acts as the enrollment delegate for the `SentrySDK`.
    public var enrollmentDelegate: SentrySDKEnrollmentDelegate?
    
    /// The object that acts as the fingerprint verification delegate for the `SentrySDK`.
    public var verificationDelegate: SentrySDKFingerprintVerificationDelegate?
    
    /// Gets or sets the text displayed in the NFC scanning UI when an error occurs while communicating with the SentryCard..
    public var cardCommunicationErrorText = "An error occurred while communicating with the card."
    
    /// Gets or sets the text displayed in the NFC scanning UI when scanning starts.
    public var establishConnectionText = "Place your card under the top of the phone to establish connection."
    
    
    // MARK: - Static Public Properties
    
    /// Returns the SDK version (read-only)
    public static var version: VersionInfo {
        get { return VersionInfo(isInstalled: true, majorVersion: 0, minorVersion: 19, hotfixVersion: 0, text: nil) }
    }
    
    
    // MARK: - Constructors
    
    /**
     Creates a new instance of `SentrySDK`.
     
     - Note: The indicated `enrollCode` MUST be the same code used when the com.idex.enroll.cap applet was installed on the SentryCard. See the installation script for the SentryCard to retrieve the enroll code.
     
     - Parameters:
     - enrollCode: An array of `UInt8` bytes containing the enroll code digits. This array must be 4-6 bytes in length, and each byte must be in the range 0-9.
     - verboseDebugOutput: Indicates if verbose debug information is sent to the standard output log (defaults to `true`).
     - useSecureCommunication: Indicates if communication with the SentryCard is encrypted (defaults to `true`).
     
     - Returns: A newly initialized `SentrySDK` object.
     */
    public init(enrollCode: [UInt8], verboseDebugOutput: Bool = true, useSecureCommunication: Bool = true) {
        // NOTE: Will likely bring this back very soon.
        
        //        // sanity check - enroll code must be between 4 and 6 characters
        //        if enrollCode.count < 4 || enrollCode.count > 6 {
        //            throw SentrySDKError.enrollCodeLengthOutOfBounds
        //        }
        //
        //        // each digit must be in the range 0 - 9
        //        for digit in enrollCode {
        //            if digit > 9 {
        //                throw SentrySDKError.enrollCodeDigitOutOfBounds
        //            }
        //        }
        
        self.enrollCode = enrollCode
        biometricsAPI = BiometricsAPI(verboseDebugOutput: verboseDebugOutput, useSecureCommunication: useSecureCommunication)
    }
    
    
    // MARK: - Public Methods
}
