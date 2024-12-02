//
//  SentrySDK.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation
import CoreNFC
import Security

/**
 Entry point for the `SentrySDK` functionality. Provides methods exposing all available functionality.
 
 This class controls and manages an `NFCReaderSession` to communicate with an `NFCISO7816Tag` via `APDU` commands.
 
 The bioverify.cap, com.idex.enroll.cap, and com.jnet.CDCVM.cap applets must be installed on the SentryCard for full access to all functionality of this SDK.
 */
public class SentrySDK: NSObject {
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
        get { return VersionInfo(isInstalled: true, majorVersion: 0, minorVersion: 18, hotfixVersion: 0, text: nil) }
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
    
    /**
     Retrieves version information for all necessary applets installed on the scanned SentryCard.
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     
     - Note: Applets prior to version 1.32 do not support this functionality and return -1 for all version values. This method is provided for debugging purposes.
     
     - Returns: A `CardVersionInfo` structure containing `VersionInfo` structures for the SentryCard operating system and all required applets, if those applets are installed.
     
     This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.incorrectTagFormat` if an NFC session scanned a tag, but it is not an ISO7816 tag.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).

     */
    public func getCardSoftwareVersions() async throws -> CardVersionInfo {
        var errorDuringSession = false
        defer {
            // closes the NFC reader session
            if errorDuringSession {
                session?.invalidate(errorMessage: cardCommunicationErrorText)
            } else {
                session?.invalidate()
            }
        }
        
        do {
            // establish a connection
            let isoTag = try await establishConnection()
            
            if let session = session {
                connectionDelegate?.connected(session: session, isConnected: true)
            }
            
            // get card OS version
            let osVersion = try await biometricsAPI.getCardOSVersion(tag: isoTag)
            print("OS: \(osVersion)")
            
            // get applet version
            let verifyVersion = try await biometricsAPI.getVerifyAppletVersion(tag: isoTag)
            print("Verify: \(verifyVersion)")

            let enrollVersion = try await biometricsAPI.getEnrollmentAppletVersion(tag: isoTag)
            print("Enroll: \(enrollVersion)")
            
            let cvmVersion = try await biometricsAPI.getCVMAppletVersion(tag: isoTag)
            print("CVM: \(cvmVersion)")
            
            return CardVersionInfo(osVersion: osVersion, enrollAppletVersion: enrollVersion, cvmAppletVersion: cvmVersion, verifyAppletVersion: verifyVersion)
        } catch (let error) {
            errorDuringSession = true
            throw error
        }
    }
    
    /**
     Retrieves the biometric fingerprint enrollment status.
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     
     - Returns: A `BiometricEnrollmentStatus` structure containing information on the fingerprint enrollment status.
     
     This method can throw the following exceptions:
     * `SentrySDKError.enrollCodeLengthOutOfbounds` if `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.enrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.incorrectTagFormat` if an NFC session scanned a tag, but it is not an ISO7816 tag.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).

     */
    public func getEnrollmentStatus() async throws -> BiometricEnrollmentStatus  {
        var errorDuringSession = false
        defer {
            // closes the NFC reader session
            if errorDuringSession {
                session?.invalidate(errorMessage: cardCommunicationErrorText)
            } else {
                session?.invalidate()
            }
        }

        do {
            // establish a connection
            let isoTag = try await establishConnection()
            
            if let session = session {
                connectionDelegate?.connected(session: session, isConnected: true)
            }
            
            // initialize the Enroll applet
            try await biometricsAPI.initializeEnroll(tag: isoTag, enrollCode: enrollCode)
            
            // get and return the enrollment status
            let enrollStatus = try await biometricsAPI.getEnrollmentStatus(tag: isoTag)
            return enrollStatus
        } catch (let error) {
            errorDuringSession = true
            throw error
        }
    }
    
    /**
     Validates that the finger on the fingerprint sensor matches (or does not match) a fingerprint recorded during enrollment.
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     
     This process waits up to five (5) seconds for a finger to be pressed against the sensor. This timeout is (currently) not configurable. If a finger is not detected on the sensor within the
     timeout period, a `SentrySDKError.apduCommandError` is thrown, indicating either a user timeout expiration (0x6748) or a host interface timeout expiration (0x6749).
     
     - Returns: `FingerprintValidation.matchValid` if the scanned fingerprint matches the one recorded during enrollment, `FingerprintValidation.matchFailed` if the scanned fingeprrint does not match, and `FingerprintValidation.notEnrolled` if the card is in verification mode (i.e. the card is not enrolled and thus a fingerprint validation could not be performed).
     
     This method can throw the following exceptions:
     * `SentrySDKError.enrollCodeLengthOutOfbounds` if `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.enrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.incorrectTagFormat` if an NFC session scanned a tag, but it is not an ISO7816 tag.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet on the SentryCard could not be initialized.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet on the SentryCard is blocked (likely requiring a full card reset).
     * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).
    
     */
    public func validateFingerprint() async throws -> FingerprintValidation {
        var errorDuringSession = false
        var isReconnect = false
        var isFinished = false
        var cvmErrorCount = 0
        
        defer {
            // closes the NFC reader session
            if errorDuringSession {
                session?.invalidate(errorMessage: cardCommunicationErrorText)
            } else {
                session?.invalidate()
            }
        }
                
        while !isFinished {
            do {
                // establish a connection
                let isoTag = try await establishConnection(reconnect: isReconnect)
                
                if let session = session {
                    connectionDelegate?.connected(session: session, isConnected: true)
                }
                
                // initialize the Enroll applet
                try await biometricsAPI.initializeEnroll(tag: isoTag, enrollCode: enrollCode)
                
                let status = try await biometricsAPI.getEnrollmentStatus(tag: isoTag)
                
                // if we are in verification mode...
                if status.mode == .verification {
                    // initialize the BioVerify applet
                    try await biometricsAPI.initializeVerify(tag: isoTag)
                    
                    if let session = session {
                        verificationDelegate?.awaitingFingerprint(session: session)
                    }
                    
                    // perform a biometric fingerprint verification
                    let result = try await biometricsAPI.getFingerprintVerification(tag: isoTag)
                    
                    return result ? .matchValid : .matchFailed
                } else {
                    // otherwise, this card isn't enrolled and a validation cannot be performed
                    return .notEnrolled
                }
            } catch SentrySDKError.cvmErrorNoMatchPerformed {
                if cvmErrorCount < 3 {
                    cvmErrorCount += 1
                    isReconnect = true
                } else {
                    if let session = session {
                        connectionDelegate?.connected(session: session, isConnected: false)
                    }
                    
                    errorDuringSession = true
                    isFinished = true
                    throw SentrySDKError.cvmErrorNoMatchPerformed
                }
            } catch {
                var errorCode = 0
                
                if case let SentrySDKError.apduCommandError(code) = error {
                    errorCode = code
                } else {
                    errorCode = (error as NSError).code
                }
                
                if errorCode == APDUResponseCode.hostInterfaceTimeoutExpired.rawValue || 
                    errorCode == APDUResponseCode.noPreciseDiagnosis.rawValue ||
                    errorCode == APDUResponseCode.poorImageQuality.rawValue ||
                    errorCode == 102 ||
                    errorCode == 100 {
                    
                    if let session = session {
                        connectionDelegate?.connected(session: session, isConnected: false)
                    }
                    
                    isReconnect = true
                } else {
                    errorDuringSession = true
                    isFinished = true
                    throw error
                }
            }
        }
    }
    
    /**
     Performs the enrollment process. The user must scan their finger a number of times as dictated by the current enrollment status, typically six (6) times total. If enrollment was
     interrupted, the process starts where it left off (i.e. if six (6) scans are required and three (3) scans were previously completed, only three (3) more will be performed). This method
     updates the user via the NFC scanning UI, but includes callbacks allowing the caller to update additional UI indicating the enrollment progress.
     
     This process waits up to five (5) seconds for a finger to be pressed against the sensor. This timeout is (currently) not configurable. If a finger is not detected on the sensor within the
     timeout period, a `SentrySDKError.apduCommandError` is thrown, indicating either a user timeout expiration (0x6748) or a host interface timeout expiration (0x6749).
     
     One (1) and two (2) finger enrollments are supported. For two finger enrollment, the Sentry Card must contain Enroll applet 2.1 or later. This method automatically detects how many
     fingers are supported by the Sentry Card and behaves accordingly.
     
     During enrollment, this method calls the `connected(session:isConnected)` method of the `connectionDelegate` when a Sentry Card is detected and a connection is
     made with the applets on the card, and when the Sentry Card is moved out of position and the mobile app can no longer communicate with the card. As each finger is enrolled, the
     `enrollmentStatus(session:currentFingerIndex:currentStep:totalSteps)` method of the `enrollmentDelegate` is called so the mobile app can update the UI
     to indicate progress. When enrolling multiple fingers, the `fingerTransition(session:nextFingerIndex)` method of the `enrollmentDelegate` is called once a finger
     is enrolled and the next finger is ready. After all fingers are fully enrolled, the `enrollmentComplete(session)` method of the `enrollmentDelegate` is called to indicate that
     enrollment of all fingers is completed.

     Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     
     - Note: If this method throws the `SentrySDKError.enrollVerificationError`, it means that the card could not verify that the finger on the sensor during the last enrollment
     step matches the fingerprints recorded during the enrollment process (for example, a user presses their thumb on the sensor for 5 touches, and then on the last touch they use their index
     finger). If this happens, the calling application must call this method again, setting the `withReset` parameter to `true`. This deletes all recorded biometric data and performs the
     entire process again from the start.
     
     - Parameters:
        - withReset: `True` to erase all existing biometric data and start the entire enrollment process over, `false` to perform enrollment without resetting biometric data (defaults to `false`).
     
     This method can throw the following exceptions:
     * `SentrySDKError.enrollCodeLengthOutOfbounds` if `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.enrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.incorrectTagFormat` if an NFC session scanned a tag, but it is not an ISO7816 tag.
     * `SentrySDKError.enrollModeNotAvailable` if the SentryCard is already enrolled and is in verification state.
     * `SentrySDKError.enrollVerificationError` if the card could not verify that the last finger touch matches the fingerprints recorded during enrollment (requires a restart of the enrollment process).
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).
    
     */
    public func enrollFingerprint(withReset: Bool = false) async throws {
        var errorDuringSession = false
        var resetOnFirstCall = withReset
        var isFinished = false
        var isReconnect = false
        var currentFinger: UInt8 = 1           // this counts from 1 in the IDEX Eroll applet
        
        defer {
            // closes the NFC reader session
            if errorDuringSession {
                session?.invalidate(errorMessage: cardCommunicationErrorText)
            } else {
                session?.invalidate()
            }
        }
        
        while !isFinished {
            do {
                let isoTag = try await establishConnection(reconnect: isReconnect)
                
                if let session = session {
                    connectionDelegate?.connected(session: session, isConnected: true)
                }
                
                // initialize the Enroll applet
                try await biometricsAPI.initializeEnroll(tag: isoTag, enrollCode: enrollCode)
                
                // get the current enrollment status
                let enrollStatus = try await biometricsAPI.getEnrollmentStatus(tag: isoTag)
                
                // if this card is in verification mode, we cannot enroll fingerprints
                if enrollStatus.mode == .verification {
                    throw SentrySDKError.enrollModeNotAvailable
                }
                
                // the next finger index
                currentFinger = enrollStatus.nextFingerToEnroll
                
                // calculate the required number of steps and update the NFC reader session UI
                let maxStepsForFinger = enrollStatus.enrollmentByFinger[Int(currentFinger) - 1].enrolledTouches + enrollStatus.enrollmentByFinger[Int(currentFinger) - 1].remainingTouches
                
                // if we're resetting, assume we have not yet enrolled anything
                var enrollmentsLeft = resetOnFirstCall ? maxStepsForFinger : enrollStatus.enrollmentByFinger[Int(currentFinger) - 1].remainingTouches
                
                // inform listeners about the current state of enrollment for this finger
                if let session = session {
                    enrollmentDelegate?.enrollmentStatus(session: session, currentFingerIndex: currentFinger, currentStep: maxStepsForFinger - enrollmentsLeft, totalSteps: maxStepsForFinger, isNewTouch: false)
                }
                
                while enrollmentsLeft > 0 {
                    // scan the finger currently on the sensor
                    if resetOnFirstCall {
                        enrollmentsLeft = try await biometricsAPI.resetEnrollAndScanFingerprint(tag: isoTag, fingerIndex: currentFinger)
                    } else {
                        enrollmentsLeft = try await biometricsAPI.enrollScanFingerprint(tag: isoTag, fingerIndex: currentFinger)
                    }
                    
                    resetOnFirstCall = false
                    
                    // inform listeners of the step that just finished
                    if let session = session { //}, enrollmentsLeft > 0 {
                        enrollmentDelegate?.enrollmentStatus(session: session, currentFingerIndex: currentFinger, currentStep: maxStepsForFinger - enrollmentsLeft, totalSteps: maxStepsForFinger, isNewTouch: true)
                    }
                }
                
                // inform listeners about the pending verification step
                if let session = session {
                    enrollmentDelegate?.enrollmentStatus(session: session, currentFingerIndex: currentFinger, currentStep: maxStepsForFinger, totalSteps: maxStepsForFinger, isNewTouch: false)
                }
                
                // after all fingerprints are enrolled, perform a verify
                do {
                    try await biometricsAPI.verifyEnrolledFingerprint(tag: isoTag)
                } catch SentrySDKError.apduCommandError(let errorCode) {
                    if errorCode == (APDUResponseCode.noMatchFound.rawValue) {
                        // expose a custom error if the verify enrolled fingerprint command didn't find a match
                        throw SentrySDKError.enrollVerificationError
                    } else {
                        throw SentrySDKError.apduCommandError(errorCode)
                    }
                }
                
                if let session = session {
                    if currentFinger < enrollStatus.maximumFingers {
                        enrollmentDelegate?.fingerTransition(session: session, nextFingerIndex: currentFinger + 1)
                    } else {
                        enrollmentDelegate?.enrollmentComplete(session: session)
                    }
                }
                isFinished = true
            } catch (let error) {
                
                // TODO: Do not throw an error on poor image quality, or restart polling, simply report it and try again
                
                print("-- Error during enrollment: \(error)")
                
                var errorCode = 0
                
                if let readerError = error as? NFCReaderError {
                    print("===== ReaderError: \(readerError.errorCode)")
                }
                
                if let sdkError = error as? SentrySDKError {
                    print("===== SDKError: \(sdkError)")
                }
                
                if case let SentrySDKError.apduCommandError(code) = error {
                    print("===== SDK Error Code: \(code)")
                    errorCode = code
                } else {
                    errorCode = (error as NSError).code
                    print("===== Error Code: \(errorCode)")
                }
                
                if !(session?.isReady ?? false) {
                    throw NFCReaderError(NFCReaderError.readerSessionInvalidationErrorUserCanceled)
                }
                
                if errorCode == APDUResponseCode.hostInterfaceTimeoutExpired.rawValue ||
                    errorCode == APDUResponseCode.noPreciseDiagnosis.rawValue ||
                    errorCode == APDUResponseCode.poorImageQuality.rawValue ||
                    errorCode == APDUResponseCode.userTimeoutExpired.rawValue ||
                    errorCode == 102 ||
                    errorCode == 100 {
                    
                    print("-- Restarting polling")
                    
                    if let session = session {
                        connectionDelegate?.connected(session: session, isConnected: false)
                    }
                    
                    isReconnect = true
                } else {
                    print("-- Actual error, exiting")
                    errorDuringSession = true
                    isFinished = true
                    throw error
                }
            }
        }
    }
    
    /**
     Performs the enrollment process if the card is not currently enrolled, and stores data securely  in the appropriate data slot for the size of data passed (if any).
     The user must scan their finger a number of times as dictated by the current enrollment status, typically six (6) times total. If enrollment was
     interrupted, the process starts where it left off (i.e. if six (6) scans are required and three (3) scans were previously completed, only three (3) more will be performed). This method
     updates the user via the NFC scanning UI, but includes callbacks allowing the caller to update additional UI indicating the enrollment progress.
     
     This process waits up to five (5) seconds for a finger to be pressed against the sensor. This timeout is (currently) not configurable. If a finger is not detected on the sensor within the
     timeout period, a `SentrySDKError.apduCommandError` is thrown, indicating either a user timeout expiration (0x6748) or a host interface timeout expiration (0x6749).
     
     One (1) and two (2) finger enrollments are supported. For two finger enrollment, the Sentry Card must contain Enroll applet 2.1 or later. This method automatically detects how many
     fingers are supported by the Sentry Card and behaves accordingly.
     
     During enrollment, this method calls the `connected(session:isConnected)` method of the `connectionDelegate` when a Sentry Card is detected and a connection is
     made with the applets on the card, and when the Sentry Card is moved out of position and the mobile app can no longer communicate with the card. As each finger is enrolled, the
     `enrollmentStatus(session:currentFingerIndex:currentStep:totalSteps)` method of the `enrollmentDelegate` is called so the mobile app can update the UI
     to indicate progress. When enrolling multiple fingers, the `fingerTransition(session:nextFingerIndex)` method of the `enrollmentDelegate` is called once a finger
     is enrolled and the next finger is ready. After all fingers are fully enrolled, the `enrollmentComplete(session)` method of the `enrollmentDelegate` is called to indicate that
     enrollment of all fingers is completed.

     Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     
     - Note: If this method throws the `SentrySDKError.enrollVerificationError`, it means that the card could not verify that the finger on the sensor during the last enrollment
     step matches the fingerprints recorded during the enrollment process (for example, a user presses their thumb on the sensor for 5 touches, and then on the last touch they use their index
     finger). If this happens, the calling application must call this method again, setting the `withReset` parameter to `true`. This deletes all recorded biometric data and performs the
     entire process again from the start.
     
     - Parameters:
        - withReset: `True` to erase all existing biometric data and start the entire enrollment process over, `false` to perform enrollment without resetting biometric data (defaults to `false`).
     
     This method can throw the following exceptions:
     * `SentrySDKError.enrollCodeLengthOutOfbounds` if `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.enrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.incorrectTagFormat` if an NFC session scanned a tag, but it is not an ISO7816 tag.
     * `SentrySDKError.enrollModeNotAvailable` if the SentryCard is already enrolled and is in verification state.
     * `SentrySDKError.enrollVerificationError` if the card could not verify that the last finger touch matches the fingerprints recorded during enrollment (requires a restart of the enrollment process).
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).
    
     */
    public func enrollFingerprintIfNotEnrolled(withReset: Bool = false, andStoreData: [UInt8]?) async throws {
        var errorDuringSession = false
        var resetOnFirstCall = withReset
        var isFinished = false
        var isReconnect = false
        var currentFinger: UInt8 = 1           // this counts from 1 in the IDEX Enroll applet
                
        // throw an error if the caller is passing more than the allowed maximum size of stored data
        if let dataToStore = andStoreData, dataToStore.count > SentrySDKConstants.SMALL_MAX_DATA_SIZE {
            throw SentrySDKError.dataSizeNotSupported
        }

        defer {
            // closes the NFC reader session
            if errorDuringSession {
                session?.invalidate(errorMessage: cardCommunicationErrorText)
            } else {
                session?.invalidate()
            }
        }
        
        while !isFinished {
            do {
                let isoTag = try await establishConnection(reconnect: isReconnect)
                
                if let session = session {
                    connectionDelegate?.connected(session: session, isConnected: true)
                }
                
                // initialize the Enroll applet
                try await biometricsAPI.initializeEnroll(tag: isoTag, enrollCode: enrollCode)
                
                // get the current enrollment status
                let enrollStatus = try await biometricsAPI.getEnrollmentStatus(tag: isoTag)
                
                // if this card is in enroll mode, enroll fingerprints
                if enrollStatus.mode == .enrollment {
                    // the next finger index
                    currentFinger = enrollStatus.nextFingerToEnroll
                    
                    while (currentFinger - 1) < enrollStatus.maximumFingers {
                        // calculate the required number of steps and update the NFC reader session UI
                        let maxStepsForFinger = enrollStatus.enrollmentByFinger[Int(currentFinger) - 1].enrolledTouches + enrollStatus.enrollmentByFinger[Int(currentFinger) - 1].remainingTouches
                        
                        // if we're resetting, assume we have not yet enrolled anything
                        var enrollmentsLeft = resetOnFirstCall ? maxStepsForFinger : enrollStatus.enrollmentByFinger[Int(currentFinger) - 1].remainingTouches
                        
                        // inform listeners about the current state of enrollment for this finger
                        if let session = session {
                            enrollmentDelegate?.enrollmentStatus(session: session, currentFingerIndex: currentFinger, currentStep: maxStepsForFinger - enrollmentsLeft, totalSteps: maxStepsForFinger, isNewTouch: false)
                        }
                        
                        while enrollmentsLeft > 0 {
                            // scan the finger currently on the sensor
                            if resetOnFirstCall {
                                enrollmentsLeft = try await biometricsAPI.resetEnrollAndScanFingerprint(tag: isoTag, fingerIndex: currentFinger)
                            } else {
                                enrollmentsLeft = try await biometricsAPI.enrollScanFingerprint(tag: isoTag, fingerIndex: currentFinger)
                            }
                            
                            resetOnFirstCall = false
                            
                            // inform listeners of the step that just finished
                            if let session = session {
                                enrollmentDelegate?.enrollmentStatus(session: session, currentFingerIndex: currentFinger, currentStep: maxStepsForFinger - enrollmentsLeft, totalSteps: maxStepsForFinger, isNewTouch: true)
                            }
                        }
                        
                        // inform listeners about the pending verification step
                        if let session = session {
                            enrollmentDelegate?.enrollmentStatus(session: session, currentFingerIndex: currentFinger, currentStep: maxStepsForFinger, totalSteps: maxStepsForFinger, isNewTouch: false)
                        }
                        
                        // after all fingerprints are enrolled, perform a verify
                        do {
                            try await biometricsAPI.verifyEnrolledFingerprint(tag: isoTag)
                        } catch SentrySDKError.apduCommandError(let errorCode) {
                            if errorCode == (APDUResponseCode.noMatchFound.rawValue) {
                                // expose a custom error if the verify enrolled fingerprint command didn't find a match
                                throw SentrySDKError.enrollVerificationError
                            } else {
                                throw SentrySDKError.apduCommandError(errorCode)
                            }
                        }
                        
                        currentFinger += 1
                    }
                }
                
                // if we're also storing data, store the data securely
                if let dataToStore = andStoreData {
                    let slot: DataSlot = dataToStore.count > 255 ? .huge : .small
                    
                    // initialize the BioVerify applet
                    try await biometricsAPI.initializeVerify(tag: isoTag)
                    
                    if let session = session {
                        verificationDelegate?.awaitingFingerprint(session: session)
                    }

                    // store the data
                    let result = try await biometricsAPI.setVerifyStoredDataSecure(tag: isoTag, data: dataToStore, dataSlot: slot)
                    
                    if !result {
                        throw SentrySDKError.apduCommandError(APDUResponseCode.noMatchFound.rawValue)
                    }
                }
                
                // enrollment is fully completed
                if let session = session {
                    enrollmentDelegate?.enrollmentComplete(session: session)
                }

                isFinished = true
            } catch (let error) {
                
                // TODO: Do not throw an error on poor image quality, or restart polling, simply report it and try again
                
                print("-- Error during enrollment: \(error)")
                
                var errorCode = 0
                
                if let readerError = error as? NFCReaderError {
                    print("===== ReaderError: \(readerError.errorCode)")
                }
                
                if let sdkError = error as? SentrySDKError {
                    print("===== SDKError: \(sdkError)")
                }
                
                if case let SentrySDKError.apduCommandError(code) = error {
                    print("===== SDK Error Code: \(code)")
                    errorCode = code
                } else {
                    errorCode = (error as NSError).code
                    print("===== Error Code: \(errorCode)")
                }
                
                if !(session?.isReady ?? false) {
                    throw NFCReaderError(NFCReaderError.readerSessionInvalidationErrorUserCanceled)
                }
                
                if errorCode == APDUResponseCode.hostInterfaceTimeoutExpired.rawValue ||
                    errorCode == APDUResponseCode.noPreciseDiagnosis.rawValue ||
                    errorCode == APDUResponseCode.poorImageQuality.rawValue ||
                    errorCode == APDUResponseCode.userTimeoutExpired.rawValue ||
                    errorCode == 102 ||
                    errorCode == 100 {
                    
                    print("-- Restarting polling")
                    
                    if let session = session {
                        connectionDelegate?.connected(session: session, isConnected: false)
                    }
                    
                    isReconnect = true
                } else {
                    print("-- Actual error, exiting")
                    errorDuringSession = true
                    isFinished = true
                    throw error
                }
            }
        }
    }
    
    /**
     Writes up to 255 bytes of data to the small data slot on the SentryCard.
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     
     - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.
     
     - Parameters:
        - dataToStore: An array of up to 255 `UInt8` bytes to write to the data slot.
     
     This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.dataSizeNotSupported` if the `data` parameter is larger than 255 bytes in size.
     * `SentrySDKError.bioVerifyAppletNotInstalled` if the BioVerify applet is not installed on the scanned SentryCard.
     * `SentrySDKError.bioVerifyAppletWrongVersion` if the BioVerify applet installed on the SentryCard does not support data storage.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).

     */
    public func storeDataUnsecure(dataToStore: [UInt8]) async throws {
        var errorDuringSession = false
        defer {
            // closes the NFC reader session
            if errorDuringSession {
                session?.invalidate(errorMessage: cardCommunicationErrorText)
            } else {
                session?.invalidate()
            }
        }
        
        // throw an error if the caller is passing more than the allowed maximum size of stored data
        if dataToStore.count > SentrySDKConstants.SMALL_MAX_DATA_SIZE {
            throw SentrySDKError.dataSizeNotSupported
        }
        
        do {
            // establish a connection
            let isoTag = try await establishConnection()
            
            try await biometricsAPI.initializeVerify(tag: isoTag)
            
            try await biometricsAPI.setVerifyStoredDataUnsecure(tag: isoTag, data: dataToStore)
        } catch (let error) {
            errorDuringSession = true
            throw error
        }
    }
    
    /**
     Retrieves the data stored in the small data slot on the SentryCard.
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     
     - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.
          
     - Returns: The data stored in the small data slot on the SentryCard (up to 255 bytes).
     
     This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.bioVerifyAppletNotInstalled` if the BioVerify applet is not installed on the scanned SentryCard.
     * `SentrySDKError.bioVerifyAppletWrongVersion` if the BioVerify applet installed on the SentryCard does not support data storage.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).

     */
    public func retrieveDataUnsecure() async throws -> [UInt8] {
        var errorDuringSession = false
        defer {
            // closes the NFC reader session
            if errorDuringSession {
                session?.invalidate(errorMessage: cardCommunicationErrorText)
            } else {
                session?.invalidate()
            }
        }
        
        do {
            // establish a connection
            let isoTag = try await establishConnection()
            
            try await biometricsAPI.initializeVerify(tag: isoTag)
            
            return try await biometricsAPI.getVerifyStoredDataUnsecure(tag: isoTag)
        } catch (let error) {
            errorDuringSession = true
            throw error
        }
    }

    /**
     Writes data to the indicated data slot on the SentryCard. A biometric verification is performed first before writing the data. The `.small` data slot holds up to 255 bytes of data, and the `.huge` data slot holds up to 2048 bytes of data.
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     
     - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.
     
     - Parameters:
        - dataToStore: An array of `UInt8`bytes to write to the indicated data slot.
        - dataSlot: The data slot to which the data is written.
     
     - Returns: `FingerprintValidation.matchValid` if the scanned fingerprint matches the one recorded during enrollment. If there is a successful match, the indicated data is written to the indicated data slot. Otherwise, returns  `FingerprintValidation.matchFailed` if the scanned fingeprrint does not match, and `FingerprintValidation.notEnrolled` if the card is in verification mode (i.e. the card is not enrolled and thus a fingerprint validation could not be performed).
     
     This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.dataSizeNotSupported` if the `data` parameter is larger than 255 bytes in size for the `.small` data slot, or 2048 bytes for the `.huge` data slot.
     * `SentrySDKError.bioVerifyAppletNotInstalled` if the BioVerify applet is not installed on the scanned SentryCard.
     * `SentrySDKError.bioVerifyAppletWrongVersion` if the BioVerify applet installed on the SentryCard does not support data storage.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet was unavailable for some reason.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet is in a blocked state and can no longer be used.
     * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).

     */
    public func storeDataSecure(dataToStore: [UInt8], dataSlot: DataSlot) async throws -> FingerprintValidation {
        var errorDuringSession = false
        
        defer {
            // closes the NFC reader session
            if errorDuringSession {
                session?.invalidate(errorMessage: cardCommunicationErrorText)
            } else {
                session?.invalidate()
            }
        }
        
        // throw an error if the caller is passing more than the allowed maximum size of stored data
        switch dataSlot {
        case .small:
            if dataToStore.count > SentrySDKConstants.SMALL_MAX_DATA_SIZE {
                throw SentrySDKError.dataSizeNotSupported
            }
        case .huge:
            if dataToStore.count > SentrySDKConstants.HUGE_MAX_DATA_SIZE {
                throw SentrySDKError.dataSizeNotSupported
            }
        }
        
        do {
            // establish a connection
            let isoTag = try await establishConnection()
            
            if let session = session {
                connectionDelegate?.connected(session: session, isConnected: true)
            }

            // initialize the Enroll applet
            try await biometricsAPI.initializeEnroll(tag: isoTag, enrollCode: enrollCode)
            
            let status = try await biometricsAPI.getEnrollmentStatus(tag: isoTag)
            
            // if we are in verification mode...
            if status.mode == .verification {
                // initialize the BioVerify applet
                try await biometricsAPI.initializeVerify(tag: isoTag)

                if let session = session {
                    verificationDelegate?.awaitingFingerprint(session: session)
                }

                // store the data
                let result = try await biometricsAPI.setVerifyStoredDataSecure(tag: isoTag, data: dataToStore, dataSlot: dataSlot)
                
                return result ? .matchValid : .matchFailed
            } else {
                // otherwise, this card isn't enrolled and a validation cannot be performed
                return .notEnrolled
            }
        } catch (let error) {
            errorDuringSession = true
            if let session = session {
                connectionDelegate?.connected(session: session, isConnected: false)
            }
            throw error
        }
    }
    
    /**
     Retrieves the data stored in the indicated data slot on the SentryCard. A biometric verification is performed first before retrieving the data.
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     
     - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.
     
     - Parameters:
        - dataSlot: The data slot from which data is retrieved.
     
     - Returns: A `FingerprintValidationAndData` structure indicating if the finger on the sensor matches the fingerprint recorded during enrollment. If there is a successful match, this structure also contains the data stored in the indicated data slot. The `.small` data slot returns up to 255 bytes of data. The `.huge` data slot returns up to 2048 bytes of data.
     
     This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.bioVerifyAppletNotInstalled` if the BioVerify applet is not installed on the scanned SentryCard.
     * `SentrySDKError.bioVerifyAppletWrongVersion` if the BioVerify applet installed on the SentryCard does not support data storage.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet was unavailable for some reason.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet is in a blocked state and can no longer be used.
     * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).

     */
    public func retrieveDataSecure(dataSlot: DataSlot) async throws -> FingerprintValidationAndData {
        var errorDuringSession = false
        defer {
            // closes the NFC reader session
            if errorDuringSession {
                session?.invalidate(errorMessage: cardCommunicationErrorText)
            } else {
                session?.invalidate()
            }
        }
        
        do {
            // establish a connection
            let isoTag = try await establishConnection()
            
            if let session = session {
                connectionDelegate?.connected(session: session, isConnected: true)
            }

            // initialize the Enroll applet
            try await biometricsAPI.initializeEnroll(tag: isoTag, enrollCode: enrollCode)
            
            let status = try await biometricsAPI.getEnrollmentStatus(tag: isoTag)
            
            // if we are in verification mode...
            if status.mode == .verification {
                // initialize the BioVerify applet
                try await biometricsAPI.initializeVerify(tag: isoTag)

                if let session = session {
                    verificationDelegate?.awaitingFingerprint(session: session)
                }

                // store the data
                return try await biometricsAPI.getVerifyStoredDataSecure(tag: isoTag, dataSlot: dataSlot)
            } else {
                // otherwise, this card isn't enrolled and a validation cannot be performed
                return FingerprintValidationAndData(doesFingerprintMatch: .notEnrolled, storedData: [])
            }
        } catch (let error) {
            errorDuringSession = true
            if let session = session {
                connectionDelegate?.connected(session: session, isConnected: false)
            }
            throw error
        }
    }
    /**
     Resets the biometric data recorded on the card. This effectively erases all fingerprint enrollment and puts the card into an unenrolled state.
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816Tag` through this session, and sends `APDU` commands to a java applet running on the connected SentryCard.
     
     - Warning: This is for development purposes only! This command only works on development cards, and fails when used on production cards.
     
     This method can throw the following exceptions:
     * `SentrySDKError.enrollCodeLengthOutOfbounds` if `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.enrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.incorrectTagFormat` if an NFC session scanned a tag, but it is not an ISO7816 tag.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).

     */
    public func resetCard() async throws {
        var errorDuringSession = false

        defer {
            // closes the NFC reader session
            if errorDuringSession {
                session?.invalidate(errorMessage: cardCommunicationErrorText)
            } else {
                session?.invalidate()
            }
        }
        
        do {
            // establish a connection
            let isoTag = try await establishConnection()
            
            if let session = session {
                connectionDelegate?.connected(session: session, isConnected: true)
            }

            // reset the biometric data, setting the card into an unenrolled state
            try await biometricsAPI.resetBiometricData(tag: isoTag)
       } catch (let error) {
           print("*** Reset Card - Error: \(error)")
            errorDuringSession = true
            throw error
        }
    }

    
    // MARK: - Private Methods

    /// Establishes a connection to the NFC reader and returns a connected ISO7816 tag.
    private func establishConnection(reconnect: Bool = false) async throws -> NFCISO7816Tag {
        print("-- Establishing connection")
        
        if reconnect {
            print("-- RECONNECTING --")
            connectedTag = nil
        } else {
            if session != nil {
                print("-- Session is not nil")
                if let connectedTag, connectedTag.isAvailable {
                    print("-- Tag is still connected and available")
                    return connectedTag
                }
            } else {
                print("-- Session is nil")
            }
        }
        
        /// returns an asynchronous continuation that effectively does not continue until
        /// the tagReaderSession(session:didDetect:) below either connects to an ISO7816
        /// tag or throws an error.
        return try await withCheckedThrowingContinuation { continuation in
            callback = { result in
                switch result {
                case .success(let tag):
                    print("=== CALLBACK SUCCESS")
                    continuation.resume(returning: tag)
                case .failure(let error):
                    print("=== CALLBACK ERROR: \(error)")
                    continuation.resume(throwing: error)
                }
            }

            // start the NFC reader session
            if let session = session, reconnect {
                print("-- Restart Polling")
                session.restartPolling()
            } else {
                print("-- Creating new session")
                session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
                session?.alertMessage = establishConnectionText
                session?.begin()
            }
        }
    }
}


// MARK: - NFCTagReaderSessionDelegate Implementation

extension SentrySDK: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        print("----- Tag Reader Session - Active")
        connectedTag = nil
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        if let selfSession = self.session, selfSession != session {
            print("----- Tag Reader Session - Invalidated different session, self: \(selfSession), invalidate: \(session)")
            return
        }
        
        print("----- Tag Reader Session - Invalidated with error: \(error)")
        
        if let callback = callback {
            print("----- Tag Reader Session - Have callback, sending failure")
            callback(.failure(error))
        } else {
            print("----- Tag Reader Session - NO callback")
        }
        
        callback = nil
        self.session = nil
        connectedTag = nil
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        print("----- Tag Reader Session - Detected Tag")
        
        // find the first ISO7816 tag
        let tag = tags.first(where: {
            switch $0 {
            case .iso7816:
                return true
            default:
                return false
            }
        })
        
        // make sure we have a tag, and that it's the right format
        guard let cardTag = tag, case let .iso7816(isoTag) = cardTag else {
            callback?(.failure(SentrySDKError.incorrectTagFormat))
            callback = nil
            session.invalidate()
            return
        }
        
        // connect to the tag
        session.connect(to: cardTag) { [weak self] error in
            if let error = error {
                print("----- Tag Reader Session - Connection error: \(error)")
                self?.callback?(.failure(error))
                self?.callback = nil
                self?.session?.invalidate()
            } else {
                print("----- Tag Reader Session - Connection Made")
                self?.connectedTag = isoTag
                self?.callback?(.success(isoTag))
                self?.callback = nil
            }
        }
    }
}

