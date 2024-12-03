/*
 * hal_hmac.h
 *
 *  Created on: Feb 12, 2022
 *      Author: YuraDesktop
 */

#ifndef PRELIMINARY_H_
#define PRELIMINARY_H_

#include "stdint.h"

void bip39_pbkdf2_preliminary	(uint8_t* o_hmacKey, uint16_t hmacKeyLen, uint32_t s_iterationCount, uint8_t* passphrase, int len_passphrase, uint8_t* ba_derivedKeyData);

//This function is needed only for tests, for release it should be removed from the project!!!
void bip39_pbkdf2_final			(uint8_t* o_hmacKey, uint16_t hmacKeyLen, uint16_t s_iterationCount, uint8_t* ba_derivedKeyData);


#endif

