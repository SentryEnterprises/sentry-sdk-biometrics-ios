//
//  BiometricsAPI.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import Foundation
import CoreNFC
import SentrySecurity

public enum DataSlot {
    case small
    case huge
}

/**
 Communicates with the IDEX Enroll applet by sending various `APDU` commands in the appropriate order.
 
 Note: Do not use this class directly, use `SentrySDK` instead.
 */
final class BiometricsAPI {
    // MARK: - Private Types
    
    /// A `tuple` containing an `APDU` command result data buffer and a status word.
    private typealias APDUReturnResult = (data: Data, statusWord: Int)

    
    // MARK: - Private Properties
    private let isDebugOutputVerbose: Bool
    private let useSecureChannel: Bool
    
    // Note - This is reset when selecting a new applet (i.e. after initing the secure channel)
    private var encryptionCounter: [UInt8] = .init(repeating: 0, count: 16)
    
    // Note - this changes with every wrap, and resets when initing secure channel
    private var chainingValue: [UInt8] = []
    
    private var privateKey: [UInt8] = []
    private var publicKey: [UInt8] = []
    private var sharedSecret: [UInt8] = []
    private var keyRespt: [UInt8] = []
    private var keyENC: [UInt8] = []
    private var keyCMAC: [UInt8] = []
    private var keyRMAC: [UInt8] = []

    
    // MARK: - Constructors
    
    /**
     Creates a new instance of `BiometricsAPI`.
     
     - Note: Do not use this class directly, use `SentrySDK` instead.
     
     - Parameters:
        - verboseDebugOutput: Indicates if verbose debug information is sent to the standard output log (defaults to `true`).
        - useSecureCommunication: Indicates if communication with the SentryCard is encrypted (defaults to `true`).
     
     - Returns: A newly instantiated `BiometricsAPI` object.
     */
    init(verboseDebugOutput: Bool = true, useSecureCommunication: Bool = true) {
        isDebugOutputVerbose = verboseDebugOutput
        useSecureChannel = useSecureCommunication
    }
    
    
    // MARK: - Methods
    
    /**
     Initializes the BioVerify applet by selecting the applet on the SentryCard. Call this method before calling other methods in this unit that communicate with the BioVerify applet.
     
     - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not setup during initialization.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.secureChannelInitializationError` if `useSecureCommunication` is `true` but an error occurred initializing the secure communication encryption.
     * `SentrySDKError.secureCommunicationNotSupported` if `useSecureCommunication` is `true` but the version of the BioVerify applet on the SentryCard does nto support secure communication (highly unlikely).
     * `SentrySDKError.bioVerifyAppletNotInstalled` if the BioVerify applet is not installed on the scanned SentryCard.
     * `SentrySDKError.bioVerifyAppletWrongVersion` if the BioVerify applet installed on the SentryCard does not support data storage.

     */
    func initializeVerify(tag: NFCISO7816Tag) async throws {
        var debugOutput = "----- BiometricsAPI Initialize Verify\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Insuring Verify Applet is Installed\n"
        
        // make sure the Verify applet is installed or we cannot retrieve data
        let verifyVersion = try await getVerifyAppletVersion(tag: tag)
        if !verifyVersion.isInstalled {
            throw SentrySDKError.bioverifyAppletNotInstalled
        } else if verifyVersion.majorVersion <= 1 && verifyVersion.minorVersion < 3 {
            throw SentrySDKError.bioVerifyAppletWrongVersion
        }

//        // use a secure channel, setup keys
//        debugOutput += "     Initializing Secure Channel\n"
//        
//        encryptionCounter = .init(repeating: 0, count: 16)
//        chainingValue.removeAll(keepingCapacity: true)
//        privateKey.removeAll(keepingCapacity: true)
//        publicKey.removeAll(keepingCapacity: true)
//        sharedSecret.removeAll(keepingCapacity: true)
//        keyRespt.removeAll(keepingCapacity: true)
//        keyENC.removeAll(keepingCapacity: true)
//        keyCMAC.removeAll(keepingCapacity: true)
//        keyRMAC.removeAll(keepingCapacity: true)
//        
//        // initialize the secure channel. this sets up keys and encryption
//        let authInfo = try getAuthInitCommand()
//        privateKey.append(contentsOf: authInfo.privateKey)
//        publicKey.append(contentsOf: authInfo.publicKey)
//        sharedSecret.append(contentsOf: authInfo.sharedSecret)
//        
//        let securityInitResponse = try await sendAndConfirm(apduCommand: authInfo.apduCommand, name: "Auth Init", to: tag)
//        
//        if securityInitResponse.statusWord == APDUResponseCode.operationSuccessful.rawValue {
//            let secretKeys = try calcSecretKeys(receivedPubKey: securityInitResponse.data.toArrayOfBytes(), sharedSecret: sharedSecret, privateKey: privateKey)
//            
//            keyRespt.append(contentsOf: secretKeys.keyRespt)
//            keyENC.append(contentsOf: secretKeys.keyENC)
//            keyCMAC.append(contentsOf: secretKeys.keyCMAC)
//            keyRMAC.append(contentsOf: secretKeys.keyRMAC)
//            chainingValue.append(contentsOf: secretKeys.chainingValue)
//        } else {
//            throw SentrySDKError.secureChannelInitializationError
//        }
        
        debugOutput += "------------------------------\n"
    }
    
    /**
     Retrieves the data stored in the indicated data slot on the SentryCard. A biometric verification is performed first before retrieving the data.
     
     - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
        - dataSlot: The data slot from which data is retrieved.
     
     - Returns: A `FingerprintValidationAndData` structure indicating if the finger on the sensor matches the fingerprint recorded during enrollment. If there is a successful match, this structure also contains the data stored in the indicated data slot. The `.small` data slot returns up to 255 bytes of data. The `.huge` data slot returns up to 2048 bytes of data.
     
     This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet was unavailable for some reason.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet is in a blocked state and can no longer be used.
     * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.

     */
    func getVerifyStoredDataSecure(tag: NFCISO7816Tag, dataSlot: DataSlot) async throws -> FingerprintValidationAndData {
        var debugOutput = "----- BiometricsAPI Get Verify Stored Data Secure, slot: \(dataSlot)\n"

        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Getting verify stored data Secure\n"
        var command: [UInt8]
        
        switch dataSlot {
        case .small: command = APDUCommand.getVerifyAppletStoredDataSmallSecured
        case .huge: command = APDUCommand.getVerifyAppletStoredDataHugeSecured
        }
        
        //let command = try wrapAPDUCommand(apduCommand: APDUCommand.getVerifyAppletStoredData, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
        
        let returnData = try await sendAndConfirm(apduCommand: command, name: "Get Verify Stored Data Secure", to: tag)
        
//        let dataArray = try unwrapAPDUResponse(response: returnData.data.toArrayOfBytes(), statusWord: returnData.statusWord, keyENC: keyENC, keyRMAC: keyRMAC, chainingValue: chainingValue, encryptionCounter: encryptionCounter)
        
        let dataArray = returnData.data.toArrayOfBytes()
        
        if dataArray.count == 1 {
            if returnData.data[0] == 0x00 {
                throw SentrySDKError.cvmAppletNotAvailable
            }
            
            if returnData.data[0] == 0x01 {
                throw SentrySDKError.cvmAppletBlocked
            }
            
            if returnData.data[0] == 0x7D {
                throw SentrySDKError.cvmErrorNoMatchPerformed            }

            
            if returnData.data[0] == 0xA5 {
                debugOutput += "     Match\n------------------------------\n"
                return FingerprintValidationAndData(doesFingerprintMatch: .matchValid, storedData: dataArray)
            }

            if returnData.data[0] == 0x5A {
                debugOutput += "     No match found\n------------------------------\n"
                return FingerprintValidationAndData(doesFingerprintMatch: .matchFailed, storedData: [])
            }
            
            throw SentrySDKError.cvmAppletError(returnData.data[0])
        } else {
            debugOutput += "     Match\n------------------------------\n"
            return FingerprintValidationAndData(doesFingerprintMatch: .matchValid, storedData: dataArray)
        }
    }
    
    /**
     Writes data to the indicated data slot on the SentryCard. A biometric verification is performed first before writing the data. The `.small` data slot holds up to 255 bytes of data, and the `.huge` data slot holds up to 2048 bytes of data.
     
     - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
        - data: An array of `UInt8`bytes to write to the indicated data slot.
        - dataSlot: The data slot to which the data is written.
     
     - Returns: `True`if the finger on the sensor matches the fingerprint recorded during enrollment. If there is a successful match, the indicated data is written to the indicated data slot. Otherwise, returns `false`.
     
     This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.dataSizeNotSupported` if the `data` parameter is larger than 255 bytes in size for the `.small` data slot, or 2048 bytes for the `.huge` data slot.
     * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet was unavailable for some reason.
     * `SentrySDKError.cvmAppletBlocked` if the CVM applet is in a blocked state and can no longer be used.
     * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.

     */
    func setVerifyStoredDataSecure(tag: NFCISO7816Tag, data: [UInt8], dataSlot: DataSlot) async throws -> Bool {
        var debugOutput = "----- BiometricsAPI Set Verify Stored Data Secure, slot: \(dataSlot)\n"

        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Setting verify stored data Secure\n"
        var command: [UInt8]

        switch dataSlot {
        case .small: command = try APDUCommand.setVerifyAppletStoredDataSmallSecure(data: data)
        case .huge:  command = try APDUCommand.setVerifyAppletStoredDataHugeSecure(data: data)
        }
        
        //let command = try wrapAPDUCommand(apduCommand: APDUCommand.setVerifyAppletStoredData, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
        let returnData = try await sendAndConfirm(apduCommand: command, name: "Set Verify Stored Data Secure", to: tag)
        
//        if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
//            throw SentrySDKError.apduCommandError(returnData.statusWord)
//        }
//
//        let dataArray = try unwrapAPDUResponse(response: returnData.data.toArrayOfBytes(), statusWord: returnData.statusWord, keyENC: keyENC, keyRMAC: keyRMAC, chainingValue: chainingValue, encryptionCounter: encryptionCounter)
        
        let dataArray = returnData.data.toArrayOfBytes()
        
        if dataArray.count == 1 {
            if returnData.data[0] == 0x00 {
                throw SentrySDKError.cvmAppletNotAvailable
            }
            
            if returnData.data[0] == 0x01 {
                throw SentrySDKError.cvmAppletBlocked
            }
            
            if returnData.data[0] == 0x7D {
                throw SentrySDKError.cvmErrorNoMatchPerformed
            }

            if returnData.data[0] == 0xA5 {
                debugOutput += "     Match\n------------------------------\n"
                return true
            }

            if returnData.data[0] == 0x5A {
                debugOutput += "     No match found\n------------------------------\n"
                return false
            }
            
            throw SentrySDKError.cvmAppletError(returnData.data[0])
        } else {
            return true
        }
    }

    /**
     Retrieves the data stored in the small, unsecured data slot on the SentryCard.
     
     - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     - Returns: The data stored in the small, unsecured data slot on the SentryCard (up to 255 bytes).
     
     This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.

     */
    func getVerifyStoredDataUnsecure(tag: NFCISO7816Tag) async throws -> [UInt8] {
        var debugOutput = "----- BiometricsAPI Get Verify Stored Data Unsecure\n"

        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Getting verify stored data unsecure\n"
        let command = APDUCommand.getVerifyAppletStoredDataSmallUnsecured
        //let command = try wrapAPDUCommand(apduCommand: APDUCommand.getVerifyAppletStoredData, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
        
        let returnData = try await send(apduCommand: command, name: "Get Verify Stored Data Unsecure", to: tag)
        
        if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
            throw SentrySDKError.apduCommandError(returnData.statusWord)
        }

//        let dataArray = try unwrapAPDUResponse(response: returnData.data.toArrayOfBytes(), statusWord: returnData.statusWord, keyENC: keyENC, keyRMAC: keyRMAC, chainingValue: chainingValue, encryptionCounter: encryptionCounter)
        let dataArray = returnData.data.toArrayOfBytes()
        
        debugOutput += "------------------------------\n"
        return dataArray
    }
    
    /**
     Writes up to 255 bytes of data to the small data slot on the SentryCard.
     
     - Note: The BioVerify applet does not currently support secure communication, so a secure channel is not used.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
        - data: An array of `UInt8` bytes to write to the data slot (up to 255 bytes in size).
     
     This method can throw the following exceptions:
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.dataSizeNotSupported` if the `data` parameter is larger than 255 bytes in size.

     */
    func setVerifyStoredDataUnsecure(tag: NFCISO7816Tag, data: [UInt8]) async throws {
        var debugOutput = "----- BiometricsAPI Set Verify Stored Data Unsecure\n"

        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Setting verify stored data Unsecure\n"
        let command = try APDUCommand.setVerifyAppletStoredDataSmallUnsecure(data: data)

        //let command = try wrapAPDUCommand(apduCommand: APDUCommand.setVerifyAppletStoredData, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
        try await sendAndConfirm(apduCommand: command, name: "Set Verify Stored Data Secure", to: tag)
        
//        if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
//            throw SentrySDKError.apduCommandError(returnData.statusWord)
//        }
//
//        let dataArray = try unwrapAPDUResponse(response: returnData.data.toArrayOfBytes(), statusWord: returnData.statusWord, keyENC: keyENC, keyRMAC: keyRMAC, chainingValue: chainingValue, encryptionCounter: encryptionCounter)
        
        debugOutput += "------------------------------\n"
    }

    /**
     Initializes the Enroll applet by selecting the applet on the SentryCard and verifying the enroll code. If no enroll code is set, this sets the enroll code to the indicated value. Call this method before calling other methods in this unit that communicate with the Enroll applet.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
        - enrollCode: An array of `UInt8` bytes containing the enroll code digits. This array must be 4-6 bytes in length, and each byte must be in the range 0-9.
     
     This method can throw the following exceptions:
     * `SentrySDKError.enrollCodeLengthOutOfbounds` if the indicated `enrollCode` is less than four (4) characters or more than six (6) characters in length.
     * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     * `SentrySDKError.enrollCodeDigitOutOfBounds` if an enroll code digit is not in the range 0-9.
     * `SentrySDKError.secureChannelInitializationError` if `useSecureCommunication` is `true` but an error occurred initializing the secure communication encryption.
     * `SentrySDKError.secureCommunicationNotSupported` if `useSecureCommunication` is `true` but the version of the Enroll applet on the SentryCard does nto support secure communication (highly unlikely).
     
     */
    func initializeEnroll(tag: NFCISO7816Tag, enrollCode: [UInt8]) async throws {
        var debugOutput = "----- BiometricsAPI Initialize Enroll - Enroll Code: \(enrollCode)\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        // sanity check - enroll code must be between 4 and 6 characters
        if enrollCode.count < 4 || enrollCode.count > 6 {
            throw SentrySDKError.enrollCodeLengthOutOfBounds
        }
        
        debugOutput += "     Selecting Enroll Applet\n"
        try await sendAndConfirm(apduCommand: APDUCommand.selectEnrollApplet, name: "Select Enroll Applet", to: tag)
        
        // if using a secure channel, setup keys
        if useSecureChannel {
            debugOutput += "     Initializing Secure Channel\n"
            
            encryptionCounter = .init(repeating: 0, count: 16)
            chainingValue.removeAll(keepingCapacity: true)
            privateKey.removeAll(keepingCapacity: true)
            publicKey.removeAll(keepingCapacity: true)
            sharedSecret.removeAll(keepingCapacity: true)
            keyRespt.removeAll(keepingCapacity: true)
            keyENC.removeAll(keepingCapacity: true)
            keyCMAC.removeAll(keepingCapacity: true)
            keyRMAC.removeAll(keepingCapacity: true)
            
            // initialize the secure channel. this sets up keys and encryption
            let authInfo = try getAuthInitCommand()
            privateKey.append(contentsOf: authInfo.privateKey)
            publicKey.append(contentsOf: authInfo.publicKey)
            sharedSecret.append(contentsOf: authInfo.sharedSecret)
            
            do {
                let securityInitResponse = try await sendAndConfirm(apduCommand: authInfo.apduCommand, name: "Auth Init", to: tag)
                
                if securityInitResponse.statusWord == APDUResponseCode.operationSuccessful.rawValue {
                    let secretKeys = try calcSecretKeys(receivedPubKey: securityInitResponse.data.toArrayOfBytes(), sharedSecret: sharedSecret, privateKey: privateKey)
                    
                    keyRespt.append(contentsOf: secretKeys.keyRespt)
                    keyENC.append(contentsOf: secretKeys.keyENC)
                    keyCMAC.append(contentsOf: secretKeys.keyCMAC)
                    keyRMAC.append(contentsOf: secretKeys.keyRMAC)
                    chainingValue.append(contentsOf: secretKeys.chainingValue)
                } else {
                    throw SentrySDKError.secureChannelInitializationError
                }
            } catch SentrySDKError.apduCommandError(let errorCode) {
                if errorCode == APDUResponseCode.instructionByteNotSupported.rawValue {
                    throw SentrySDKError.secureCommunicationNotSupported    // If we get an 'INS byte not supported', the enrollment applet doesn't support secure communication
                } else {
                    throw SentrySDKError.apduCommandError(errorCode)
                }
            }
            
            debugOutput += "     Getting Enroll Status"
            let enrollStatusCommand = try wrapAPDUCommand(apduCommand: APDUCommand.getEnrollStatus, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
            let returnData = try await send(apduCommand: enrollStatusCommand, name: "Get Enroll Status", to: tag)
            
            // we may need to send the verify enroll code command
            if returnData.statusWord == APDUResponseCode.conditionOfUseNotSatisfied.rawValue {
                debugOutput += "     Verifying Enroll Code\n"
                var enrollCodeCommand = try APDUCommand.verifyEnrollCode(code: enrollCode)
                enrollCodeCommand = try wrapAPDUCommand(apduCommand: enrollCodeCommand, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
                try await sendAndConfirm(apduCommand: enrollCodeCommand, name: "Verify Enroll Code", to: tag)
            } else if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
                throw SentrySDKError.apduCommandError(returnData.statusWord)
            }

        } else {
            debugOutput += "     Getting Enroll Status"
            let returnData = try await send(apduCommand: APDUCommand.getEnrollStatus, name: "Get Enroll Status", to: tag)
            
            // we may need to send the verify enroll code command
            if returnData.statusWord == APDUResponseCode.conditionOfUseNotSatisfied.rawValue {
                debugOutput += "     Verifying Enroll Code\n"
                try await sendAndConfirm(apduCommand: APDUCommand.verifyEnrollCode(code: enrollCode), name: "Verify Enroll Code", to: tag)
            } else if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
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
        var dataArray: [UInt8] = []
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Getting enrollment status\n"
        
        if useSecureChannel {
            let enrollStatusCommand = try wrapAPDUCommand(apduCommand: APDUCommand.getEnrollStatus, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
            let returnData = try await send(apduCommand: enrollStatusCommand, name: "Get Enroll Status", to: tag)
            
            if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
                throw SentrySDKError.apduCommandError(returnData.statusWord)
            }
            
            dataArray = try unwrapAPDUResponse(response: returnData.data.toArrayOfBytes(), statusWord: returnData.statusWord, keyENC: keyENC, keyRMAC: keyRMAC, chainingValue: chainingValue, encryptionCounter: encryptionCounter)
        } else {
            let returnData = try await sendAndConfirm(apduCommand: APDUCommand.getEnrollStatus, name: "Get Enrollment Status", to: tag)
            dataArray = returnData.data.toArrayOfBytes()
        }
        
        // sanity check - this buffer should be at least 40 bytes in length, possibly more
        if dataArray.count < 40 {
            throw SentrySDKError.enrollmentStatusBufferTooSmall
        }
        
        // if we're dealing with Enroll app prior to 2.1
        if dataArray[0] == 0 {
            // extract values from specific index in the array
            let maxNumberOfFingers = dataArray[31]
            let enrolledTouches = dataArray[32]
            let remainingTouches = dataArray[33]
            let mode = dataArray[39]
            
            debugOutput += "     # Fingers: \(maxNumberOfFingers)\n     Enrolled Touches: \(enrolledTouches)\n     Remaining Touches: \(remainingTouches)\n     Mode: \(mode)\n"
            
            let biometricMode: BiometricMode = mode == 0 ? .enrollment : .verification
            
            debugOutput += "------------------------------\n"
            
            return BiometricEnrollmentStatus(
                version: 0,
                maximumFingers: maxNumberOfFingers,
                enrollmentByFinger: [FingerTouches(enrolledTouches: enrolledTouches, remainingTouches: remainingTouches, biometricMode: nil)],
                nextFingerToEnroll: 1,
                mode: biometricMode
            )
        } else if dataArray[0] == 1 {
            let maxNumberOfFingers = dataArray[31]
            let finger1EnrolledTouches = dataArray[32]
            let finger1RemainingTouches = dataArray[33]
            let finger1TopupTouches = dataArray[34]
            let finger1QualTouches = dataArray[35]
            let finger1QualPasses = dataArray[36]
            let finger1BioMode = dataArray[37]
            let finger1TopupRemaining = dataArray[38]
            let finger1TopupAttempts = dataArray[39]
            let finger2EnrolledTouches = dataArray[40]
            let finger2RemainingTouches = dataArray[41]
            let finger2TopupTouches = dataArray[42]
            let finger2QualTouches = dataArray[43]
            let finger2QualPasses = dataArray[44]
            let finger2BioMode = dataArray[45]
            let finger2TopupRemaining = dataArray[46]
            let finger2TopupAttempts = dataArray[47]
            let reenrollAttempts = dataArray[48]
            let nextFingerToEnroll = dataArray[49]
            let mode = dataArray[50]
            
            debugOutput +=  "     # Fingers: \(maxNumberOfFingers)\n" +
                            "     F1 Enrolled Touches: \(finger1EnrolledTouches)\n" +
                            "     F1 Remaining Touches: \(finger1RemainingTouches)\n" +
                            "     F1 Topup Touches: \(finger1TopupTouches)\n" +
                            "     F1 Qual Touches: \(finger1QualTouches)\n" +
                            "     F1 Qual Passed: \(finger1QualPasses)\n" +
                            "     F1 Biometric Mode: \(finger1BioMode)\n" +
                            "     F1 Topup Remaining: \(finger1TopupRemaining)\n" +
                            "     F1 Topup Attempts: \(finger1TopupAttempts)\n" +
                            "     F2 Enrolled Touches: \(finger2EnrolledTouches)\n" +
                            "     F2 Remaining Touches: \(finger2RemainingTouches)\n" +
                            "     F2 Topup Touches: \(finger2TopupTouches)\n" +
                            "     F2 Qual Touches: \(finger2QualTouches)\n" +
                            "     F2 Qual Passed: \(finger2QualPasses)\n" +
                            "     F2 Biometric Mode: \(finger2BioMode)\n" +
                            "     F2 Topup Remaining: \(finger2TopupRemaining)\n" +
                            "     F2 Topup Attempts: \(finger2TopupAttempts)\n" +
                            "     Reenroll Attempts: \(reenrollAttempts)\n" +
                            "     Next Finger: \(nextFingerToEnroll)\n" +
                            "     Mode: \(mode)\n"
            
            // need to check all fingers
            var biometricMode: BiometricMode = .enrollment
            if finger1BioMode > 1 && finger2BioMode > 1 {
                biometricMode = .verification
            }
            
            debugOutput += "------------------------------\n"
            
            return BiometricEnrollmentStatus(
                version: 1,
                maximumFingers: maxNumberOfFingers,
                enrollmentByFinger: [FingerTouches(enrolledTouches: finger1EnrolledTouches, remainingTouches: finger1RemainingTouches, biometricMode: finger1BioMode),
                                     FingerTouches(enrolledTouches: finger2EnrolledTouches, remainingTouches: finger2RemainingTouches, biometricMode: finger2BioMode)],
                nextFingerToEnroll: nextFingerToEnroll,
                mode: biometricMode
            )
        } else {
            // throw unsupported Enroll applet version exception
            throw SentrySDKError.unsupportedEnrollAppletVersion(Int(dataArray[0]))
        }
    }
    
    /**
     Scans the finger currently on the fingerprint sensor, indicating if the scanned fingerprint matches one recorded during enrollment.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     - Returns: `True` if the scanned fingerprint matches one recorded during enrollment, otherwise returns `false`.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
      * `SentrySDKError.cvmAppletNotAvailable` if the CVM applet was unavailable for some reason.
      * `SentrySDKError.cvmAppletBlocked` if the CVM applet is in a blocked state and can no longer be used.
      * `SentrySDKError.cvmAppletError` if the CVM applet returned an unexpected error code.
     
     */
    func getFingerprintVerification(tag: NFCISO7816Tag) async throws -> Bool {
        
        // TODO: !!! implement encryption !!!
        
        var debugOutput = "----- BiometricsAPI Get Fingerprint Verification\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }

        let returnData = try await send(apduCommand: APDUCommand.getFingerprintVerify, name: "Fingerprint Verification", to: tag)
        
        if returnData.statusWord == APDUResponseCode.operationSuccessful.rawValue {
            if returnData.data[3] == 0x00 {
                throw SentrySDKError.cvmAppletNotAvailable
            }
            
            if returnData.data[5] == 0x01 {
                throw SentrySDKError.cvmAppletBlocked
            }
            
            if returnData.data[4] == 0x7D {
                throw SentrySDKError.cvmErrorNoMatchPerformed
            }
            
            if returnData.data[4] == 0xA5 {
                debugOutput += "     Match\n------------------------------\n"
                return true
            }
            
            if returnData.data[4] == 0x5A {
                debugOutput += "     No match found\n------------------------------\n"
                return false
            }
            
            throw SentrySDKError.cvmAppletError(returnData.data[4])
        }

        throw SentrySDKError.apduCommandError(returnData.statusWord)
    }

    /**
     Scans a fingerprint, recording (or enrolling) the fingerprint into the card's internal biometrics database.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
        - fingerIndex: The index of the finger to enroll (must be either 1 or 2).
     
     - Returns: The number of required fingerprint scans remaining to complete enrollment.
     
     - Note: The IDEX Enroll applet tracks the finger index starting at 1.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
      * `SentrySDKError.invalidFingerIndex` if the `fingerIndex` value is not either 1 or 2.
     
     */
    func enrollScanFingerprint(tag: NFCISO7816Tag, fingerIndex: UInt8) async throws -> UInt8 {
        if !(1...2).contains(Int(fingerIndex)) {
            throw SentrySDKError.invalidFingerIndex
        }
        
        var debugOutput = "----- BiometricsAPI Enroll Scan Fingerprint: \(fingerIndex)\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        if useSecureChannel {
            let processFingerprintCommand = try wrapAPDUCommand(apduCommand: APDUCommand.processFingerprint(fingerIndex: fingerIndex), keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
            try await sendAndConfirm(apduCommand: processFingerprintCommand, name: "Enroll Scan Fingerprint", to: tag)
        } else {
            try await sendAndConfirm(apduCommand: APDUCommand.processFingerprint(fingerIndex: fingerIndex), name: "Enroll Scan Fingerprint", to: tag)
        }
        
        debugOutput += "     Getting enrollment status\n"
        let enrollmentStatus = try await getEnrollmentStatus(tag: tag)
        
        debugOutput += "     Remaining: \(enrollmentStatus.enrollmentByFinger[Int(fingerIndex) - 1].remainingTouches)\n------------------------------\n"
        return enrollmentStatus.enrollmentByFinger[Int(fingerIndex) - 1].remainingTouches
    }
    
    /**
     Scans a fingerprint, recording (or enrolling) the fingerprint into the card's internal biometrics database. This is exactly the same call as`enrollScanFingerprint()` except that this method also removes all previoiusly recorded fingerprints,
     effectively resetting enrollment.
     
     - Note: Call this only ONCE to reset enrollment, and only for the first touch. Call `enrollScanFingerprint()` for all subsequent touches.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
        - fingerIndex: The index of the finger to enroll (must be either 1 or 2).

     
     - Returns: The number of required fingerprint scans remaining to complete enrollment.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
      * `SentrySDKError.invalidFingerIndex` if the `fingerIndex` value is not either 1 or 2.
     
     */
    func resetEnrollAndScanFingerprint(tag: NFCISO7816Tag, fingerIndex: UInt8) async throws -> UInt8 {
        if !(1...2).contains(Int(fingerIndex)) {
            throw SentrySDKError.invalidFingerIndex
        }
        
        var debugOutput = "----- BiometricsAPI Reset Enroll and Scan Fingerprint: \(fingerIndex)\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        if useSecureChannel {
            let processFingerprintCommand = try wrapAPDUCommand(apduCommand: APDUCommand.restartEnrollAndProcessFingerprint(fingerIndex: fingerIndex), keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
            try await sendAndConfirm(apduCommand: processFingerprintCommand, name: "Reset And Process Fingerprint", to: tag)
        } else {
            try await sendAndConfirm(apduCommand: APDUCommand.restartEnrollAndProcessFingerprint(fingerIndex: fingerIndex), name: "Reset And Process Fingerprint", to: tag)
        }
        
        debugOutput += "     Getting enrollment status\n"
        let enrollmentStatus = try await getEnrollmentStatus(tag: tag)
        
        debugOutput += "     Remaining: \(enrollmentStatus.enrollmentByFinger[Int(fingerIndex) - 1].remainingTouches)\n------------------------------\n"
        return enrollmentStatus.enrollmentByFinger[Int(fingerIndex) - 1].remainingTouches
    }

    /**
     Verifies the fingerprint just enrolled. Used only after scanning a fingerprint during the enrollment process (after all enrollment steps are completed).
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     
     */
    func verifyEnrolledFingerprint(tag: NFCISO7816Tag) async throws {
        var debugOutput = "----- BiometricsAPI Verify Enrolled Fingerprint\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        if useSecureChannel {
            let verifyEnrollCommand = try wrapAPDUCommand(apduCommand: APDUCommand.verifyFingerprintEnrollment, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
            try await sendAndConfirm(apduCommand: verifyEnrollCommand, name: "Verify Enrolled Fingerprint", to: tag)
        } else {
            try await sendAndConfirm(apduCommand: APDUCommand.verifyFingerprintEnrollment, name: "Verify Enrolled Fingerprint", to: tag)
        }
        
        debugOutput += "------------------------------\n"
    }

    /**
     Resets the biometric data recorded on the card. This effectively erases all fingerprint enrollment and puts the card into an unenrolled state.
     
     - Warning: This is for development purposes only! This command only works on development cards, and fails when used on production cards.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.
     
     */
    func resetBiometricData(tag: NFCISO7816Tag) async throws {
        var debugOutput = "----- BiometricsAPI Reset BiometricData\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        try await sendAndConfirm(apduCommand: APDUCommand.resetBiometricData, name: "Reset Biometric Data", to: tag)
        
        debugOutput += "------------------------------\n"
    }

    /**
     Retrieves the version of the operating system installed on the scanned SentryCard.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     - Returns: A `VersionInfo` structure containing version information.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.

     */
    func getCardOSVersion(tag: NFCISO7816Tag) async throws -> VersionInfo {
        var debugOutput = "----- BiometricsAPI Get Card OS Version\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Getting card OS version\n"
        let returnData = try await sendAndConfirm(apduCommand: APDUCommand.getOSVersion, name: "Get Card OS Version", to: tag)
        
        debugOutput += "     Processing response\n"
        let dataBuffer = returnData.data.toArrayOfBytes()
        
        if dataBuffer.count < 8 {
            throw SentrySDKError.cardOSVersionError
        }
        
        if dataBuffer[0] != 0xFE { throw SentrySDKError.cardOSVersionError }
        if dataBuffer[1]  < 0x40 { throw SentrySDKError.cardOSVersionError }
        if dataBuffer[2] != 0x7f { throw SentrySDKError.cardOSVersionError }
        if dataBuffer[3] != 0x00 { throw SentrySDKError.cardOSVersionError }
        if dataBuffer[4]  < 0x40 { throw SentrySDKError.cardOSVersionError }
        if dataBuffer[5] != 0x9f { throw SentrySDKError.cardOSVersionError }
        if dataBuffer[6] != 0x01 { throw SentrySDKError.cardOSVersionError }
        
        let n = dataBuffer[7]
        
        let stringArray = dataBuffer[8...8 + Int(n)]
        let stringText = String(bytes: Array(stringArray), encoding: .ascii)
        
        var p: Int = 8 + Int(n)
        
        if dataBuffer[p] != 0x9F { throw SentrySDKError.cardOSVersionError }
        p += 1
        if dataBuffer[p] != 0x02 {throw SentrySDKError.cardOSVersionError }
        p += 1
        if dataBuffer[p] != 5 { throw SentrySDKError.cardOSVersionError }
        p += 1
        
        let major = dataBuffer[p] - 0x30
        p += 2
        let minor = dataBuffer[p] - 0x30
        p += 2
        let hotfix = dataBuffer[p] - 0x30
        
        let retVal = VersionInfo(isInstalled: true, majorVersion: Int(major), minorVersion: Int(minor), hotfixVersion: Int(hotfix), text: stringText)
                
        debugOutput += "     Card OS Version: \(retVal.majorVersion).\(retVal.minorVersion).\(retVal.hotfixVersion)\n------------------------------\n"
        return retVal
    }
    
    /**
     Retrieves the version of the Enrollment applet installed on the scanned card (only available on version 2.0 or greater).
     
     - Note: If the Enrollment applet version on the card is earlier than 2.0, this returns -1 for all version values.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     - Returns: A `VersionInfo` structure containing version information.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.

     */
    func getEnrollmentAppletVersion(tag: NFCISO7816Tag) async throws -> VersionInfo {
        var version = VersionInfo(isInstalled: true, majorVersion: -1, minorVersion: -1, hotfixVersion: -1, text: nil)
        var debugOutput = "----- BiometricsAPI Get Enrollment Applet Version\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
         
        debugOutput += "     Selecting Enroll Applet\n"
        
        do {
            let response = try await sendAndConfirm(apduCommand: APDUCommand.selectEnrollApplet, name: "Select Enroll Applet", to: tag)
            
            let responseBuffer = response.data.toArrayOfBytes()
            
            if responseBuffer.count < 16 {
                return VersionInfo(isInstalled: true, majorVersion: -1, minorVersion: -1, hotfixVersion: -1, text: nil)
            } else {
                let string = String(bytes: responseBuffer, encoding: .ascii)
                let majorVersion = Int(responseBuffer[13] - 0x30)
                let minorVersion = Int(responseBuffer[15] - 0x30)
                version = VersionInfo(isInstalled: true, majorVersion: majorVersion, minorVersion: minorVersion, hotfixVersion: 0, text: string)
            }
        } catch {
            if (error as NSError).domain == "NFCError" && (error as NSError).code == 2 {
                version = VersionInfo(isInstalled: false, majorVersion: -1, minorVersion: -1, hotfixVersion: -1, text: nil)
            } else {
                throw error
            }
        }
        
        debugOutput += "     Enrollment Applet Version: \(version.isInstalled) - \(version.majorVersion).\(version.minorVersion).\(version.hotfixVersion)\n------------------------------\n"
        return version
    }
    
    /**
     Retrieves the version of the CDCVM applet installed on the scanned card (only available on version 2.0 or greater).
     
     - Note: If the CDCVM applet version on the card is earlier than 2.0, this returns -1 for all version values.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     - Returns: A `VersionInfo` structure containing version information.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.

     */
    func getCVMAppletVersion(tag: NFCISO7816Tag) async throws -> VersionInfo {
        var version = VersionInfo(isInstalled: true, majorVersion: -1, minorVersion: -1, hotfixVersion: -1, text: nil)
        var debugOutput = "----- BiometricsAPI Get CVM Applet Version\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Selecting CVM Applet\n"
        
        do {
            let response = try await sendAndConfirm(apduCommand: APDUCommand.selectCVMApplet, name: "Select CVM Applet", to: tag)
            
            let responseBuffer = response.data.toArrayOfBytes()
            
            if responseBuffer.count > 11 {
                let string = String(bytes: responseBuffer, encoding: .ascii)
                var versionString = ""
                if let string = string {
                    let allowed = CharacterSet.decimalDigits.union(CharacterSet(charactersIn: "A"..."Z")).union(CharacterSet(charactersIn: "a"..."z")).union(CharacterSet(["-", "."]))
                    versionString = String(string.unicodeScalars.filter(allowed.contains))
                }

                let majorVersion = Int(responseBuffer[10] - 0x30)
                let minorVersion = Int(responseBuffer[12] - 0x30)
                version = VersionInfo(isInstalled: true, majorVersion: majorVersion, minorVersion: minorVersion, hotfixVersion: 0, text: versionString)
            }
        } catch {
            if (error as NSError).domain == "NFCError" && (error as NSError).code == 2 {
                version = VersionInfo(isInstalled: false, majorVersion: -1, minorVersion: -1, hotfixVersion: -1, text: nil)
            } else {
                throw error
            }
        }

        debugOutput += "     CVM Applet Version: \(version.isInstalled) - \(version.majorVersion).\(version.minorVersion).\(version.hotfixVersion)\n------------------------------\n"
        return version
    }
    
    /**
     Retrieves the version of the Verify applet installed on the scanned card.
     
     - Parameters:
        - tag: The `NFCISO7816` tag supplied by an NFC connection to which `APDU` commands are sent.
     
     - Returns: A `VersionInfo` structure containing version information.
     
     This method can throw the following exceptions:
      * `SentrySDKError.apduCommandError` that contains the status word returned by the last failed `APDU` command.

     */
    func getVerifyAppletVersion(tag: NFCISO7816Tag) async throws -> VersionInfo {
        // Note: Due to the way Apple implemented APDU communication, it's possible to send a select command and receive a 9000 response
        // even though the applet isn't actually installed on the card. The BioVerify applet has always supported a versioning command,
        // so here we'll simply check if the command was processed, and if we get an 'instruction byte not supported' response, we assume
        // the BioVerify applet isn't installed.
        
        var version = VersionInfo(isInstalled: false, majorVersion: -1, minorVersion: -1, hotfixVersion: -1, text: nil)
        var debugOutput = "----- BiometricsAPI Get Verify Applet Version\n"
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Selecting Verify Applet\n"
        
        try await send(apduCommand: APDUCommand.selectVerifyApplet, name: "Select Verify Applet", to: tag)
        let response = try await send(apduCommand: APDUCommand.getVerifyAppletVersion, name: "Get Verify Applet Version", to: tag)
        
        if response.statusWord == APDUResponseCode.operationSuccessful.rawValue {
            let responseBuffer = response.data.toArrayOfBytes()
            
            if responseBuffer.count == 5 {
                let majorVersion = Int(responseBuffer[3])
                let minorVersion = Int(responseBuffer[4])
                version = VersionInfo(isInstalled: true, majorVersion: majorVersion, minorVersion: minorVersion, hotfixVersion: 0, text: nil)
            } else if responseBuffer.count == 4 {
                let majorVersion = Int(responseBuffer[2])
                let minorVersion = Int(responseBuffer[3])
                version = VersionInfo(isInstalled: true, majorVersion: majorVersion, minorVersion: minorVersion, hotfixVersion: 0, text: nil)
            } else if responseBuffer.count == 2 {
                let majorVersion = Int(responseBuffer[0])
                let minorVersion = Int(responseBuffer[1])
                version = VersionInfo(isInstalled: true, majorVersion: majorVersion, minorVersion: minorVersion, hotfixVersion: 0, text: nil)
            }
        } else if response.statusWord == APDUResponseCode.instructionByteNotSupported.rawValue {
            version = VersionInfo(isInstalled: false, majorVersion: -1, minorVersion: -1, hotfixVersion: -1, text: nil)
        } else {
            throw SentrySDKError.apduCommandError(response.statusWord)
        }
        
        debugOutput += "     Verify Applet Version: \(version.isInstalled) - \(version.majorVersion).\(version.minorVersion).\(version.hotfixVersion)\n------------------------------\n"
        return version
    }
    
    
    // MARK: - Private Methods
    
    /// Encodes an APDU command.
    private func wrapAPDUCommand(apduCommand: [UInt8], keyENC: [UInt8], keyCMAC: [UInt8], chainingValue: inout [UInt8], encryptionCounter: inout [UInt8]) throws -> [UInt8] {
        let data = Data(apduCommand)
        print("     >>> Wrapping => \(data.toHex())\n")

        let command = UnsafeMutablePointer<UInt8>.allocate(capacity: apduCommand.count)
        let wrappedCommand = UnsafeMutablePointer<UInt8>.allocate(capacity: 300)
        let ENC = UnsafeMutablePointer<UInt8>.allocate(capacity: keyENC.count)
        let CMAC = UnsafeMutablePointer<UInt8>.allocate(capacity: keyCMAC.count)
        let chaining = UnsafeMutablePointer<UInt8>.allocate(capacity: chainingValue.count)
        let counter = UnsafeMutablePointer<UInt8>.allocate(capacity: encryptionCounter.count)
        let wrappedLength =  UnsafeMutablePointer<UInt32>.allocate(capacity: 1)

        defer {
            command.deallocate()
            wrappedCommand.deallocate()
            ENC.deallocate()
            CMAC.deallocate()
            chaining.deallocate()
            counter.deallocate()
            wrappedLength.deallocate()
        }
        
        for i in 0..<apduCommand.count {
            command.advanced(by: i).pointee = apduCommand[i]
        }
        
        for i in 0..<keyENC.count {
            ENC.advanced(by: i).pointee = keyENC[i]
        }

        for i in 0..<keyCMAC.count {
            CMAC.advanced(by: i).pointee = keyCMAC[i]
        }

        for i in 0..<chainingValue.count {
            chaining.advanced(by: i).pointee = chainingValue[i]
        }
        
        for i in 0..<encryptionCounter.count {
            counter.advanced(by: i).pointee = encryptionCounter[i]
        }

        let response = LibAuthWrap(command, UInt32(apduCommand.count), wrappedCommand, wrappedLength, ENC, CMAC, chaining, counter)
        
        if response != SUCCESS {
            if response == ERROR_KEYGENERATION {
                throw SentrySDKError.keyGenerationError
            }
            if response == ERROR_SHAREDSECRETEXTRACTION {
                throw SentrySDKError.sharedSecretExtractionError
            }
            
            // TODO: Fix once we've converted security to pure Swift
            throw NSError(domain: "Unknown return value", code: -1)
        }
        
        for i in 0..<encryptionCounter.count {
            encryptionCounter[i] = counter.advanced(by: i).pointee
        }
        
        for i in 0..<chainingValue.count {
            chainingValue[i] = chaining.advanced(by: i).pointee
        }

        var result: [UInt8] = []
        for i in 0..<wrappedLength.pointee {
            result.append(wrappedCommand.advanced(by: Int(i)).pointee)
        }
        
        return result
    }
    
    /// Decodes an APDU command response.
    private func unwrapAPDUResponse(response: [UInt8], statusWord: Int, keyENC: [UInt8], keyRMAC: [UInt8], chainingValue: [UInt8], encryptionCounter: [UInt8]) throws -> [UInt8] {
        let responseData = UnsafeMutablePointer<UInt8>.allocate(capacity: response.count + 2)
        let unwrappedResponse = UnsafeMutablePointer<UInt8>.allocate(capacity: 300)
        let ENC = UnsafeMutablePointer<UInt8>.allocate(capacity: keyENC.count)
        let RMAC = UnsafeMutablePointer<UInt8>.allocate(capacity: keyRMAC.count)
        let chaining = UnsafeMutablePointer<UInt8>.allocate(capacity: chainingValue.count)
        let counter = UnsafeMutablePointer<UInt8>.allocate(capacity: encryptionCounter.count)
        let unwrappedLength = UnsafeMutablePointer<UInt32>.allocate(capacity: 1)

        defer {
            responseData.deallocate()
            unwrappedResponse.deallocate()
            ENC.deallocate()
            RMAC.deallocate()
            chaining.deallocate()
            counter.deallocate()
            unwrappedLength.deallocate()
        }
        
        for i in 0..<response.count {
            responseData.advanced(by: i).pointee = response[i]
        }
        responseData.advanced(by: response.count).pointee = UInt8(statusWord >> 8)
        responseData.advanced(by: response.count + 1).pointee = UInt8(statusWord & 0x00FF)
        
        for i in 0..<keyENC.count {
            ENC.advanced(by: i).pointee = keyENC[i]
        }

        for i in 0..<keyRMAC.count {
            RMAC.advanced(by: i).pointee = keyRMAC[i]
        }

        for i in 0..<chainingValue.count {
            chaining.advanced(by: i).pointee = chainingValue[i]
        }
        
        for i in 0..<encryptionCounter.count {
            counter.advanced(by: i).pointee = encryptionCounter[i]
        }

        let response = LibAuthUnwrap(responseData, UInt32(response.count + 2), unwrappedResponse, unwrappedLength, ENC, RMAC, chaining, counter)
        
        if response != SUCCESS {
            if response == ERROR_KEYGENERATION {
                throw SentrySDKError.keyGenerationError
            }
            if response == ERROR_SHAREDSECRETEXTRACTION {
                throw SentrySDKError.sharedSecretExtractionError
            }
            
            // TODO: Fix once we've converted security to pure Swift
            throw NSError(domain: "Unknown return value", code: -1)
        }

        var result: [UInt8] = []
        for i in 0..<unwrappedLength.pointee {
            result.append(unwrappedResponse.advanced(by: Int(i)).pointee)
        }
        
        return result
    }
    
    // done after select but before verifying pin
    // returns 5F494104 <keys> 8610 <chaining value> 9000
    // 5F494104 D13CD1EDF0CFDC960CB8CC060DEA15203D6C3D7C81B8DA8D020C012652E8A50CE59D462EEBFBC6A3AF55C47E5DCD897EFD371321389DA2B227EEF48FA6143106 8610 498EDA1B2CDF9E20BEE060BA439FAB20 9000
    // whatever processes the response from this command should check:
    //  starts with 5F494104
    //  calls calcSecretKeys
    //  checks 8610 and extracts the chaining value
    // Note: We may need to call this and calcSecretKeys each time a new applet is selected!
    
    /// Initializes secure communication.
    private func getAuthInitCommand() throws -> AuthInitData {
        let apduCommand = UnsafeMutablePointer<UInt8>.allocate(capacity: 100)
        let apduCommandLen = UnsafeMutablePointer<Int32>.allocate(capacity: 1)
        let privateKey = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
        let publicKey = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
        let secretShses = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
        defer {
            apduCommand.deallocate()
            apduCommandLen.deallocate()
            privateKey.deallocate()
            publicKey.deallocate()
            secretShses.deallocate()
        }
        
        let response = LibSecureChannelInit(apduCommand,apduCommandLen, privateKey, publicKey, secretShses)
        
        if response != SUCCESS {
            if response == ERROR_KEYGENERATION {
                throw SentrySDKError.keyGenerationError
            }
            if response == ERROR_SHAREDSECRETEXTRACTION {
                throw SentrySDKError.sharedSecretExtractionError
            }
            
            // TODO: Fix once we've converted security to pure Swift
            throw NSError(domain: "Unknown return value", code: -1)
        }

        var command: [UInt8] = []
        var privKey: [UInt8] = []
        var pubKey: [UInt8] = []
        var sharedSecret: [UInt8] = []
        
        for i in 0..<apduCommandLen.pointee {
            command.append(apduCommand.advanced(by: Int(i)).pointee)
        }
        
        for i in 0..<32 {
            privKey.append(privateKey.advanced(by: i).pointee)
        }
        
        for i in 0..<64 {
            pubKey.append(publicKey.advanced(by: i).pointee)
        }
        
        for i in 0..<32 {
            sharedSecret.append(secretShses.advanced(by: i).pointee)
        }

        return AuthInitData(apduCommand: command, privateKey: privKey, publicKey: pubKey, sharedSecret: sharedSecret)
    }
    
    /// Calculates secret keys.
    private func calcSecretKeys(receivedPubKey: [UInt8], sharedSecret: [UInt8], privateKey: [UInt8]) throws -> Keys {
        let pubKey = UnsafeMutablePointer<UInt8>.allocate(capacity: receivedPubKey.count)
        let shses = UnsafeMutablePointer<UInt8>.allocate(capacity: sharedSecret.count)
        let privatekey = UnsafeMutablePointer<UInt8>.allocate(capacity: privateKey.count)
        let keyRespt = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        let keyENC = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        let keyCMAC = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        let keyRMAC = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        let chaining = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        
        defer {
            pubKey.deallocate()
            shses.deallocate()
            privatekey.deallocate()
            keyRespt.deallocate()
            keyENC.deallocate()
            keyCMAC.deallocate()
            keyRMAC.deallocate()
            chaining.deallocate()
        }
        
        for i in 0..<receivedPubKey.count {
            pubKey.advanced(by: i).pointee = receivedPubKey[i]
        }
        
        for i in 0..<sharedSecret.count {
            shses.advanced(by: i).pointee = sharedSecret[i]
        }

        for i in 0..<privateKey.count {
            privatekey.advanced(by: i).pointee = privateKey[i]
        }
        
        let response = LibCalcSecretKeys(pubKey, shses, privatekey, keyRespt, keyENC, keyCMAC, keyRMAC, chaining)
        
        if response != SUCCESS {
            if response == ERROR_KEYGENERATION {
                throw SentrySDKError.keyGenerationError
            }
            if response == ERROR_SHAREDSECRETEXTRACTION {
                throw SentrySDKError.sharedSecretExtractionError
            }
            
            // TODO: Fix once we've converted security to pure Swift
            throw NSError(domain: "Unknown return value", code: -1)
        }

        var respt: [UInt8] = []
        var enc: [UInt8] = []
        var cmac: [UInt8] = []
        var rmac: [UInt8] = []
        var chainVal: [UInt8] = []
        
        for i in 0..<16 {
            respt.append(keyRespt.advanced(by: i).pointee)
        }
        
        for i in 0..<16 {
            enc.append(keyENC.advanced(by: i).pointee)
        }

        for i in 0..<16 {
            cmac.append(keyCMAC.advanced(by: i).pointee)
        }

        for i in 0..<16 {
            rmac.append(keyRMAC.advanced(by: i).pointee)
        }
        
        for i in 0..<16 {
            chainVal.append(chaining.advanced(by: i).pointee)
        }

        return Keys(keyRespt: respt, keyENC: enc, keyCMAC: cmac, keyRMAC: rmac, chainingValue: chainVal)
    }
    
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
        print("Immediate >>> Sending => \(data.toHex())\n")
        
        guard let command = NFCISO7816APDU(data: data) else {
            throw SentrySDKError.invalidAPDUCommand
        }
        
        let result = try await tag.sendCommand(apdu: command)
        
        let resultData = result.0 + Data([result.1]) + Data([result.2])
        debugOutput += "     <<< Received <= \(resultData.toHex())\n"
        print("Immediate <<< Received <= \(resultData.toHex())\n")
        
        let statusWord: Int = Int(result.1) << 8 + Int(result.2)
        return APDUReturnResult(data: result.0, statusWord: statusWord)
    }
}

