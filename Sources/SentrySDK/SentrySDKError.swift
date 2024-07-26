//
//  SentrySDKError.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation

/**
 Custom errors thrown by the `SentrySDK`.
 */
public enum SentrySDKError: Error {
    // These errors can occur in production.
    
    /// Individual enroll code digits must be in the range 0 - 9.
    case enrollCodeDigitOutOfBounds
    
    /// The enroll code must be between 4 - 6 characters in length.
    case enrollCodeLengthOutOfBounds
        
    /// We have an NFC connection, but no ISO7816 tag.
    case incorrectTagFormat
    
    /// APDU specific error.
    case apduCommandError(Int)
    
    /// The applets on the SentryCard do not appear to support secure communication.
    case secureCommunicationNotSupported
    
    /// The amount of data the system attempted to store on the SentryCard was too big (maximum size supported is 2048 bytes).
    case dataSizeNotSupported
    
    /// The CVM applet on the SentryCard was unavailable.
    case cvmAppletNotAvailable
    
    /// The CVM applet on the SentryCard is blocked, and the SentryCard will need a reset.
    case cvmAppletBlocked
    
    /// The BioVerify applet is not installed on the SentryCard.
    case bioverifyAppletNotInstalled
    
    /// Indicates that the SentryCard is already enrolled and is in verification state.
    case enrollModeNotAvailable
    
    /// TEMPORARY
    case bioVerifyAppletWrongVersion
        
    
    // The following errors should never occur, and indicate bugs in the code.
    
    /// The buffer returned from querying the card for its biometric enrollment status was unexpectedly too small. This indicates something has changed in either the OS running on the scanned device or the Enroll applet itself.
    case enrollmentStatusBufferTooSmall
    
    /// The buffer used in the `NFCISO7816APDU` constructor was not a valid `APDU` command. This should only occur if CoreNFC changes dramatically, or the APDU command itself is incorrect and was never tested.
    case invalidAPDUCommand
    
    /// We have an NFC connection, but no NFC tag. This should only happen if something has changed in the SentrySDK and the connection logic is incorrect.
    case connectedWithoutTag
    
    /// Indicates that a secure channel with the card could not be created.
    case secureChannelInitializationError
    
    /// Indicates an error in the data buffer returned from querying the SentryCard OS version.
    case cardOSVersionError
    
    /// Indicates an error occurred generating the public/private key pair, or other keys.
    case keyGenerationError
    
    /// Indicates an error extracting the shared secrets data.
    case sharedSecretExtractionError
}
