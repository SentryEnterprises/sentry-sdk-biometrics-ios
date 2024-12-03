//
//  CryptoAPI.swift
//  SentrySDK
//
//  Copyright © 2024 Sentry Enterprises
//

import CoreNFC
import SentrySecurity


/**
 */
final class CryptoAPI {
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
    func initializeWallet(tag: NFCISO7816Tag) async throws {
        var debugOutput = "----- CryptoAPI Initialize Wallet\n"
        var dataArray: [UInt8] = []
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Selecting Wallet Applet\n"
        try await sendAndConfirm(apduCommand: APDUCommand.selectWalletApplet, name: "Select Wallet Applet", to: tag)
        
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
            
            debugOutput += "     Getting Wallet Version"
            let enrollStatusCommand = try wrapAPDUCommand(apduCommand: APDUCommand.getWalletVersion, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
            let returnData = try await send(apduCommand: enrollStatusCommand, name: "Get Wallet Version", to: tag)
            
            if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
                throw SentrySDKError.apduCommandError(returnData.statusWord)
            }
            
            dataArray = try unwrapAPDUResponse(response: returnData.data.toArrayOfBytes(), statusWord: returnData.statusWord, keyENC: keyENC, keyRMAC: keyRMAC, chainingValue: chainingValue, encryptionCounter: encryptionCounter)
        } else {
            debugOutput += "     Getting Wallet Version"
            let returnData = try await sendAndConfirm(apduCommand: APDUCommand.getEnrollStatus, name: "Get Wallet Version", to: tag)
            dataArray = returnData.data.toArrayOfBytes()
        }
        
        // sanity check - this buffer should be 7 bytes long
        if dataArray.count < 7 {
            throw SentrySDKError.walletAppletVersionBufferTooSmall
        }

        // should return 5F C1 02 01 12 90 00
        if dataArray[0] != 0x5F { throw SentrySDKError.cardWalletAppletVersionError }
        if dataArray[1] != 0xC1 { throw SentrySDKError.cardWalletAppletVersionError }
        if dataArray[2] != 0x02 { throw SentrySDKError.cardWalletAppletVersionError }
        if dataArray[3] == 0x00 { throw SentrySDKError.cardWalletAppletVersionError }
        if dataArray[4]  < 0x1C { throw SentrySDKError.cardWalletAppletVersionError }       // TODO: ? 12 is < 1C, is this correct?
                
        debugOutput += "------------------------------\n"
    }
    
    func getWalletCapability(tag: NFCISO7816Tag) async throws -> UInt8 {
        var debugOutput = "----- CryptoAPI Get Wallet Capability\n"
        var dataArray: [UInt8] = []
        
        defer {
            if isDebugOutputVerbose { print(debugOutput) }
        }
        
        debugOutput += "     Get Wallet Capability\n"
        
        if useSecureChannel {
            let enrollStatusCommand = try wrapAPDUCommand(apduCommand: APDUCommand.getWalletCapability, keyENC: keyENC, keyCMAC: keyCMAC, chainingValue: &chainingValue, encryptionCounter: &encryptionCounter)
            let returnData = try await send(apduCommand: enrollStatusCommand, name: "Get Wallet Capability", to: tag)
            
            if returnData.statusWord != APDUResponseCode.operationSuccessful.rawValue {
                throw SentrySDKError.apduCommandError(returnData.statusWord)
            }
            
            dataArray = try unwrapAPDUResponse(response: returnData.data.toArrayOfBytes(), statusWord: returnData.statusWord, keyENC: keyENC, keyRMAC: keyRMAC, chainingValue: chainingValue, encryptionCounter: encryptionCounter)
        } else {
            let returnData = try await sendAndConfirm(apduCommand: APDUCommand.getWalletCapability, name: "Get Wallet Capability", to: tag)
            dataArray = returnData.data.toArrayOfBytes()
        }

        // sanity check - this buffer should be 6 bytes long
        if dataArray.count < 6 {
            throw SentrySDKError.walletCapabilityBufferTooSmall
        }

        // should return 5F 3E 01 01 90 00
        if dataArray[0] != 0x5F { throw SentrySDKError.walletCapabilityError }
        if dataArray[1] != 0x3E { throw SentrySDKError.walletCapabilityError }
        if dataArray[2] != 0x01 { throw SentrySDKError.walletCapabilityError }
        
        debugOutput += "\(dataArray[3])\n------------------------------\n"
        
        return dataArray[3]     // TODO: Can this be an enumeration?
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

