//
//  BRAddress.h
//
//  Created by Aaron Voisine on 9/18/15.
//  Copyright (c) 2015 breadwallet LLC
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#ifndef BRAddress_h
#define BRAddress_h

#include "BRCrypto.h"


#ifdef __cplusplus
extern "C" {
#endif

// bitcoin address prefixes
#define BITCOIN_PUBKEY_PREFIX       0
#define BITCOIN_SCRIPT_PREFIX       5
#define BITCOIN_PUBKEY_PREFIX_TEST  111
#define BITCOIN_SCRIPT_PREFIX_TEST  196
#define BITCOIN_PRIVKEY_PREFIX      128
#define BITCOIN_PRIVKEY_PREFIX_TEST 239
#define BITCOIN_BECH32_PREFIX       "bc"
#define BITCOIN_BECH32_PREFIX_TEST  "tb"

// bitcoin script opcodes: https://en.bitcoin.it/wiki/Script#Constants
#define OP_0           0x00
#define OP_PUSHDATA1   0x4c
#define OP_PUSHDATA2   0x4d
#define OP_PUSHDATA4   0x4e
#define OP_1NEGATE     0x4f
#define OP_1           0x51
#define OP_16          0x60
#define OP_DUP         0x76
#define OP_EQUAL       0x87
#define OP_EQUALVERIFY 0x88
#define OP_HASH160     0xa9
#define OP_CHECKSIG    0xac


#define BITCOIN_ADDRESS_PARAMS  ((BRAddressParams) { \
    BITCOIN_PUBKEY_PREFIX,  \
    BITCOIN_SCRIPT_PREFIX,  \
    BITCOIN_PRIVKEY_PREFIX, \
    BITCOIN_BECH32_PREFIX })

#define BITCOIN_TEST_ADDRESS_PARAMS  ((BRAddressParams) { \
    BITCOIN_PUBKEY_PREFIX_TEST,  \
    BITCOIN_SCRIPT_PREFIX_TEST,  \
    BITCOIN_PRIVKEY_PREFIX_TEST, \
    BITCOIN_BECH32_PREFIX_TEST })

#define EMPTY_ADDRESS_PARAMS   ((BRAddressParams) { 0, 0, 0, "" })

typedef struct {
    char s[75];
} BRAddress;




#ifdef __cplusplus
}
#endif

#endif // BRAddress_h
