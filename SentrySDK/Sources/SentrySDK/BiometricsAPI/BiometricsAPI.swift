//
//  BiometricsAPI.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation
import CoreNFC

/**
 Communicates with the IDEX Enroll applet by sending various `APDU` commands in the appropriate order.
 
 Note: Do not use this class directly, use `SentrySDK` instead.
 */
final class BiometricsAPI {
    // MARK: - Private Types
    
    /// A `tuple` containing an `APDU` command result data buffer and a status word.
    private typealias APDUReturnResult = (data: Data, statusWord: Int)

    
    // MARK: - Private Properties
    private var isDebugOutputVerbose = true
    
    
    // MARK: - Constructors
    
    /**
     Creates a new instance of `BiometricsAPI`.
     
     - Note: Do not use this class directly, use `SentrySDK` instead.
     
     - Parameters:
        - verboseDebugOutput: Indicates if verbose debug information is sent to the standard output log (defaults to `true`).
     
     - Returns: A newly instantiated `BiometricsAPI` object.
     */
    init(verboseDebugOutput: Bool = true) {
        isDebugOutputVerbose = verboseDebugOutput
    }
    
    
    // MARK: - Methods
    
    /**
     Initializes the Enroll applet by selecting the applet on the java card and verifying the PIN. If no PIN is set, this sets the PIN to the indicated value. Call this
     method before calling other methods in this unit.
     
     - Parameters:
        - pin: An array of `UInt8` bytes containing the PIN digits. This array must be 4-6 bytes in length, and each byte must be in the range 0-9.
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     This method can throw the following exceptions:
     * `SentrySDKError.pinLengthOutOfbounds` if the indicated `pin` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.pinDigitOutOfBounds` if a PIN digit is not in the range 0-9.
     
     */
    func initializeEnroll(pin: [UInt8], tag: NFCISO7816Tag) async throws {
        var debugOutput = "----- BiometricsAPI Initialize Enroll - PIN: \(pin)\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
         
        // sanity check - PIN must be between 4 and 6 characters
        if pin.count < 4 || pin.count > 6 {
            throw SentrySDKError.pinLengthOutOfBounds
        }
        
        debugOutput += "     Selecting Enroll Applet\n"
        try await sendAndConfirm(apduCommand: APDUCommand.selectEnrollApplet, name: "Select", to: tag)

        debugOutput += "     Verifing PIN\n"
        let returnData = try await send(apduCommand: APDUCommand.verifyPIN(pin: pin), name: "Verify PIN", to: tag)
        
        if returnData.statusWord == APDUResponseCode.conditionOfUseNotSatisfied.rawValue {
            debugOutput += "     PIN not set, setting\n"
            try await sendAndConfirm(apduCommand: APDUCommand.setPIN(pin: pin), name: "Set PIN", to: tag)

            debugOutput += "     Sending PT1 command\n"
            try await sendAndConfirm(apduCommand: APDUCommand.setPT1, name: "PT1", to: tag)

            debugOutput += "     Setting enrollment\n"
            try await sendAndConfirm(apduCommand: APDUCommand.setEnroll, name: "Enrollment", to: tag)

            debugOutput += "     Setting enrollment limit\n"
            try await send(apduCommand: APDUCommand.setEnrollLimit, name: "Enrollment Limit", to: tag)

            debugOutput += "     Storing\n"
            try await sendAndConfirm(apduCommand: APDUCommand.setStore, name: "Storing", to: tag)
            
            // after setting the PIN, make sure the enrollment app is selected
            debugOutput += "     Selecting Enroll applet again\n"
            try await sendAndConfirm(apduCommand: APDUCommand.selectEnrollApplet, name: "Select", to: tag)
            
            // verify the PIN again
            debugOutput += "     Reverifying PIN\n"
            try await sendAndConfirm(apduCommand: APDUCommand.verifyPIN(pin: pin), name: "Verify PIN", to: tag)
        } else {
            if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
                throw SentrySDKError.apduCommandError(returnData.statusWord)
            }
        }
        
        debugOutput += "------------------------------\n"
    }

    /**
     Retrieves the biometric enrollment status recorded by the Enrollment applet on the card.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     - Returns: A `BiometricEnrollmentStatus` structure containing information on the fingerprint enrollment status.
     
     This method can throw the following exceptions:
     * `SentrySDKError.enrollmentStatusBufferTooSmall` if the buffer returned from the `APDU` command was unexpectedly too small.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     
     */
    func getEnrollmentStatus(tag: NFCISO7816Tag) async throws -> BiometricEnrollmentStatus {
        var debugOutput = "----- BiometricsAPI Get Enrollment Status\n"

        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        let returnData = try await send(apduCommand: APDUCommand.getEnrollStatus, name: "Get Enrollment Status", to: tag)
                
        // get the data as an array of bytes
        let dataArray = returnData.data.toArrayOfBytes()
        
        // sanity check - this buffer should be at least 40 bytes in length, possibly more
        if dataArray.count < 40 {
            throw SentrySDKError.enrollmentStatusBufferTooSmall
        }
        
        // extract values from specific index in the array
        let maxNumberOfFingers = dataArray[31]
        let enrolledTouches = dataArray[32]
        let remainingTouches = dataArray[33]
        let mode = dataArray[39]
        
        debugOutput += "     # Fingers: \(maxNumberOfFingers)\n     Enrolled Touches: \(enrolledTouches)\n     Remaining Touches: \(remainingTouches)\n     Mode: \(mode)\n"

        let biometricMode: BiometricMode = mode == 0 ? .enrollment : .verification
        
        debugOutput += "------------------------------\n"
        
        return BiometricEnrollmentStatus(
            maximumFingers: maxNumberOfFingers,
            enrolledTouches: enrolledTouches,
            remainingTouches: remainingTouches,
            mode: biometricMode
        )
    }
    
    /**
     Scans the finger currently on the fingerprint sensor, indicating if the scanned fingerprint matches one recorded during enrollment.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     - Returns: `True` if the scanned fingerprint matches one recorded during enrollment, otherwise returns `false`.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     
     */
    func getFingerprintVerification(tag: NFCISO7816Tag) async throws -> Bool {
        var debugOutput = "----- BiometricsAPI Get Fingerprint Verification\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }

        let returnData = try await send(apduCommand: APDUCommand.getFingerprintVerify, name: "Fingerprint Verification", to: tag)
        
        if returnData.statusWord == APDUResponseCode.operationSuccessful.rawValue {
            debugOutput += "     Match\n------------------------------\n"
            return true
        }
        
        if returnData.statusWord == APDUResponseCode.noMatchFound.rawValue {
            debugOutput += "     No match found\n------------------------------\n"
            return false
        }
        
        throw SentrySDKError.apduCommandError(returnData.statusWord)
    }

    /**
     Scans a fingerprint, recording (or enrolling) the fingerprint into the card's internal biometrics database.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     - Returns: The number of required fingerprint scans remaining to complete enrollment.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     
     */
    func enrollScanFingerprint(tag: NFCISO7816Tag) async throws -> UInt8 {
        var debugOutput = "----- BiometricsAPI Get Fingerprint Verification\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }

        try await sendAndConfirm(apduCommand: APDUCommand.processFingerprint, name: "Process Fingerprint", to: tag)
        
        debugOutput += "     Getting enrollment status\n"
        let enrollmentStatus = try await getEnrollmentStatus(tag: tag)
        
        debugOutput += "     Remaining: \(enrollmentStatus.remainingTouches)\n------------------------------\n"
        return enrollmentStatus.remainingTouches
    }
    
    /**
     Verifies the fingerprint just enrolled. Used only after scanning a fingerprint during the enrollment process (after all enrollment steps are completed).
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     
     */
    func verifyEnrolledFingerprint(tag: NFCISO7816Tag) async throws {
        var debugOutput = "----- BiometricsAPI Get Fingerprint Verification\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        try await sendAndConfirm(apduCommand: APDUCommand.verifyFingerprintEnrollment, name: "Verify Fingerprint", to: tag)
        
        debugOutput += "------------------------------\n"
    }

    
    // MARK: - Private Methods
    
    /// Sends an APDU command, throwing an exception if that command does not respond with a successful operation value.
    @discardableResult private func sendAndConfirm(apduCommand: [UInt8], name: String? = nil, to tag: NFCISO7816Tag) async throws -> APDUReturnResult {
        let returnData = try await send(apduCommand: apduCommand, name: name, to: tag)
        
        if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
            throw SentrySDKError.apduCommandError(returnData.statusWord)
        }

        return returnData
    }
    
    /// Sends an APDU command.
    @discardableResult private func send(apduCommand: [UInt8], name: String? = nil, to tag: NFCISO7816Tag) async throws -> APDUReturnResult {
        var debugOutput = "\n---------- Sending \(name ?? "") -----------\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }

        let data = Data(apduCommand)
        debugOutput += "     >>> Sending => \(data.toHex())\n"
        
        guard let command = NFCISO7816APDU(data: data) else {
            throw SentrySDKError.invalidAPDUCommand
        }
        
        let result = try await tag.sendCommand(apdu: command)
        
        let resultData = result.0 + Data([result.1]) + Data([result.2])
        debugOutput += "     <<< Received <= \(resultData.toHex())\n"
        
        let statusWord: Int = Int(result.1) << 8 + Int(result.2)
        return APDUReturnResult(data: result.0, statusWord: statusWord)
    }
}

