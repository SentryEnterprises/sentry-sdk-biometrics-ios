//
//  SentrySDK.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation
import CoreNFC
import sentry_api_security

/**
 Entry point for the `SentrySDK` functionality. Provides methods exposing all available functionality.
 
 This class controls and manages an `NFCReaderSession` to communicate with an `NFCISO7816Tag` via `APDU` commands.
 
 The bioverify.cap, com.idex.enroll.cap, and com.jnet.CDCVM.cap applets must be installed on the java card for full access to all functionality of this SDK.
 */
public class SentrySDK: NSObject {
    // MARK: - Private Properties
    
    private let enrollCode: [UInt8]
    private let biometricsAPI: BiometricsAPI

    private var session: NFCReaderSession?
    private var connectedTag: NFCISO7816Tag?
    private var callback: ((Result<NFCISO7816Tag, Error>) -> Void)?
    
    
    // MARK: - Public Properties
    
    /// Gets or sets the text displayed in the NFC scanning UI when an error occurs while communicating with the java card.
    public var cardCommunicationErrorText = "An error occurred while communicating with the card."
    
    /// Gets or sets the text displayed in the NFC scanning UI when scanning starts.
    public var establishConnectionText = "Place your card under the top of the phone to establish connection."
    
    
    // MARK: - Static Public Properties
    
    /// Returns the SDK version (read-only)
    public static var version: VersionInfo {
        get { return VersionInfo(isInstalled: true, majorVersion: 0, minorVersion: 5, hotfixVersion: 0, text: nil) }
    }
    
    /// Returns the dependent security api version (read-only). Note: TEMPORARY, soon to be eliminated.
    public static var securityVersion: VersionInfo {
        get {
            let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 3)
            defer {
                pointer.deallocate()
            }
            
            LibSdkGetSdkVersion(pointer)
            
            var result: [UInt8] = []
            
            for i in 0..<3 {
                result.append(pointer.advanced(by: i).pointee)
            }
            
            return VersionInfo(isInstalled: true, majorVersion: Int(result[0]), minorVersion: Int(result[1]), hotfixVersion: Int(result[2]), text: nil)
        }
    }
    
    
    // MARK: - Constructors

    /**
     Creates a new instance of `SentrySDK`.
     
     - Note: The indicated `enrollCode` MUST be the same code used when the com.idex.enroll.cap applet was installed on the java card. See the installation script for the java card to retrieve the enroll code.
     
     - Parameters:
        - enrollCode: An array of `UInt8` bytes containing the enroll code digits. This array must be 4-6 bytes in length, and each byte must be in the range 0-9.
        - verboseDebugOutput: Indicates if verbose debug information is sent to the standard output log (defaults to `true`).
        - useSecureCommunication: Indicates if communication with the java card is encrypted (defaults to `true`).
     
     - Returns: A newly initialized `SentrySDK` object.
     */
    public init(enrollCode: [UInt8], verboseDebugOutput: Bool = true, useSecureCommunication: Bool = true) {
        self.enrollCode = enrollCode
        biometricsAPI = BiometricsAPI(verboseDebugOutput: verboseDebugOutput, useSecureCommunication: useSecureCommunication)
    }
    
    
    // MARK: - Public Methods
    
    /**
     Retrieves version information for all necessary applets installed on the scanned java card.
     
     - Note: Applets prior to version 1.32 do not support this functionality and return -1 for all version values. This method is provided for debugging purposes.
     
     - Returns: A `CardVersionInfo` structure containing `VersionInfo` structures for the java card operating system and all required applets, if those applets are installed.
     
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
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816` through this session, and sends `APDU` commands to a java applet running on the connected tag/java card.
     
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
            
            // initialize the Enroll applet
            try await biometricsAPI.initializeEnroll(enrollCode: enrollCode, tag: isoTag)
            
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
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816` through this session, and sends `APDU` commands to a java applet running on the connected tag/java card.
     
     This process waits up to five (5) seconds for a finger to be pressed against the sensor. This timeout is (currently) not configurable. If a finger is not detected on the sensor within the
     timeout period, a `SentrySDKError.apduCommandError` is thrown, indicating either a user timeout expiration (0x6748) or a host interface timeout expiration (0x6749).
     
     - Returns: `True` if the scanned fingerprint matches the one recorded during enrollment, otherwise `false`.
     
     This method can throw the following exceptions:
     * `SentrySDKError.enrollCodeLengthOutOfbounds` if `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.enrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.incorrectTagFormat` if an NFC session scanned a tag, but it is not an ISO7816 tag.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet on the java card could not be initialized.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet on the java card is blocked (likely requiring a full card reset).
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).
    
     */
    public func validateFingerprint() async throws -> Bool {
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
            
            // initialize the Enroll applet
            try await biometricsAPI.initializeVerify(tag: isoTag)
            
            // perform a biometric fingerprint verification
            let result = try await biometricsAPI.getFingerprintVerification(tag: isoTag)
            
            return result
        } catch (let error) {
            errorDuringSession = true
            throw error
        }
    }
    
    /**
     Performs the enrollment process. The user must scan their finger a number of times as dictated by the current enrollment status, typically six (6) times total. If enrollment was
     interrupted, the process starts where it left off (i.e. if six (6) scans are required and three (3) scans were previously completed, only three (3) more will be performed). This method
     updates the user via the NFC scanning UI, but includes callbacks allowing the caller to update additional UI indicating the enrollment progress.
     
     This process waits up to five (5) seconds for a finger to be pressed against the sensor. This timeout is (currently) not configurable. If a finger is not detected on the sensor within the
     timeout period, a `SentrySDKError.apduCommandError` is thrown, indicating either a user timeout expiration (0x6748) or a host interface timeout expiration (0x6749).

     Opens an `NFCReaderSession`, connects to an `NFCISO7816` through this session, and sends `APDU` commands to a java applet running on the connected tag/java card.
     
     - Note: Assumes that the Enroll applet only supports a single finger for enrollment.
     
     - Parameters:
        - connected: A callback method that receives a boolean value. This is called with `true` when an NFC connection is made and an ISO7816 tag is detected, and `false` when the connection is dropped.
        - stepFinished: A callback method that receives the current enrollment scan step that just finished, and the total number of steps required (i.e. scan two (2) out of the six (6) required). Callers should use this to update UI indicating the percentage completed.
     
     This method can throw the following exceptions:
     * `SentrySDKError.enrollCodeLengthOutOfbounds` if `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.enrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.incorrectTagFormat` if an NFC session scanned a tag, but it is not an ISO7816 tag.
//     * `SentrySDKError.dataSizeNotSupported` if the `dataToStore` array size is > 2048 bytes.
     * `SentrySDKError.bioverifyAppletNotInstalled` if the BioVerify applet is not installed on the java card.
     * `SentrySDKError.enrollModeNotAvailable` if the java card is already enrolled and is in verification state.
     * `NFCReaderError` if an error occurred during the NFC session (includes user cancellation of the NFC session).
    
     */
    public func enrollFingerprint(connected: (_ session: NFCReaderSession, _ isConnected: Bool) -> Void, stepFinished: (_ session: NFCReaderSession, _ currentStep: UInt8, _ totalSteps: UInt8) -> Void) async throws {
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
                connected(session, true)
            }
            
            // initialize the Enroll applet
            try await biometricsAPI.initializeEnroll(enrollCode: enrollCode, tag: isoTag)
            
            // get the current enrollment status
            let enrollStatus = try await biometricsAPI.getEnrollmentStatus(tag: isoTag)
            
            // if this card is in verification mode, we cannot enroll fingerprints
            if enrollStatus.mode == .verification {
                throw SentrySDKError.enrollModeNotAvailable
            }
            
            // calculate the required number of steps and update the NFC reader session UI
            let maximumSteps = enrollStatus.enrolledTouches + enrollStatus.remainingTouches
            var enrollmentsLeft = maximumSteps
            
            while enrollmentsLeft > 0 {
                // scan the finger currently on the sensor
                let remainingEnrollments = try await biometricsAPI.enrollScanFingerprint(tag: isoTag)
                if remainingEnrollments <= 0 {
                    try await biometricsAPI.verifyEnrolledFingerprint(tag: isoTag)
                }
                enrollmentsLeft = remainingEnrollments
                                
                // inform the caller of the step that just finished
                if let session = session {
                    stepFinished(session, maximumSteps - enrollmentsLeft, maximumSteps)
                }
            }
        } catch (let error) {
            errorDuringSession = true
            if let session = session {
                connected(session, false)
            }
            throw error
        }
    }
    
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
            
            try await biometricsAPI.setVerifyStoredDataUnsecure(data: dataToStore, tag: isoTag)
        } catch (let error) {
            errorDuringSession = true
            throw error
        }
    }
    
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

    public func storeDataSecure(dataToStore: [UInt8], dataSlot: DataSlot, connected: (_ session: NFCReaderSession, _ isConnected: Bool) -> Void) async throws -> Bool {
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
            
            // make sure the Verify applet is installed or we cannot store data
            let verifyVersion = try await biometricsAPI.getVerifyAppletVersion(tag: isoTag)
            if !verifyVersion.isInstalled {
                throw SentrySDKError.bioverifyAppletNotInstalled
            }
            
            if let session = session {
                connected(session, true)
            }

            try await biometricsAPI.initializeVerify(tag: isoTag)
            
            return try await biometricsAPI.setVerifyStoredDataSecure(data: dataToStore, tag: isoTag, dataSlot: dataSlot)
        } catch (let error) {
            errorDuringSession = true
            if let session = session {
                connected(session, false)
            }
            throw error
        }
    }
    
    public func retrieveDataSecure(dataSlot: DataSlot, connected: (_ session: NFCReaderSession, _ isConnected: Bool) -> Void) async throws -> FingerprintValidationAndData {
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
            
            // make sure the Verify applet is installed or we cannot retrieve data
            let verifyVersion = try await biometricsAPI.getVerifyAppletVersion(tag: isoTag)
            if !verifyVersion.isInstalled {
                throw SentrySDKError.bioverifyAppletNotInstalled
            }
            
            if let session = session {
                connected(session, true)
            }

            try await biometricsAPI.initializeVerify(tag: isoTag)
            
            return try await biometricsAPI.getVerifyStoredDataSecure(tag: isoTag, dataSlot: dataSlot)
        } catch (let error) {
            errorDuringSession = true
            if let session = session {
                connected(session, false)
            }
            throw error
        }
    }
    /**
     Resets the biometric data recorded on the card. This effectively erases all fingerprint enrollment and puts the card into an unenrolled state.
     
     Opens an `NFCReaderSession`, connects to an `NFCISO7816` through this session, and sends `APDU` commands to a java applet running on the connected tag/java card.
     
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
            
            // reset the biometric data, setting the card into an unenrolled state
            try await biometricsAPI.resetBiometricData(tag: isoTag)
       } catch (let error) {
            errorDuringSession = true
            throw error
        }
    }

    
    // MARK: - Private Methods

    /// Establishes a connection to the NFC reader and returns a connected ISO7816 tag.
    private func establishConnection() async throws -> NFCISO7816Tag {
        // we may be trying to establish a connection when one is already established.
        // if we're already in a session and are already connected to a tag, return
        // the currently connected tag
        if session != nil {
            if let connectedTag {
                return connectedTag
            } else {
                // sanity check - if we have a connected session but no tag, something is seriously wrong
                session?.invalidate()
                throw SentrySDKError.connectedWithoutTag
            }
        }
        
        /// returns an asynchronous continuation that effectively does not continue until
        /// the tagReaderSession(session:didDetect:) below either connects to an ISO7816
        /// tag or throws an error.
        return try await withCheckedThrowingContinuation { continuation in
            callback = { result in
                switch result {
                case .success(let tag):
                    continuation.resume(returning: tag)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }

            // start the NFC reader session
            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
            session?.alertMessage = establishConnectionText
            session?.begin()
        }
    }
}


// MARK: - NFCTagReaderSessionDelegate Implementation

extension SentrySDK: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        print("----- Tag Reader Session - Active")
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        print("----- Tag Reader Session - Invalidated with error: \(error)")
        callback?(.failure(error))
        self.session = nil
        callback = nil
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

