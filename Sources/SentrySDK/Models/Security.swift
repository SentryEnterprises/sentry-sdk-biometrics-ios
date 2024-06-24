//
//  File.swift
//  
//
//  Created by John Ayres on 6/21/24.
//

import Foundation

/**
 Contains internal data necessary to initiate communication with the card over a secure channel.
 */
struct AuthInitData {
    let apduCommand: [UInt8]
    let privateKey: [UInt8]
    let publicKey: [UInt8]
    let sharedSecret: [UInt8]
}

/**
 Security Keys.
 */
struct Keys {
    let keyRespt: [UInt8]
    let keyENC: [UInt8]
    let keyCMAC: [UInt8]
    let keyRMAC: [UInt8]
    let chainingValue: [UInt8]
}
