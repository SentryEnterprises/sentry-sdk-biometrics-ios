/*
 * hal_hmac.h
 *
 *  Created on: Feb 12, 2022
 *      Author: YuraDesktop
 */

#ifndef HAL_HMAC_H_
#define HAL_HMAC_H_

#include "sha512.h"


void 		hal_hmac_sha512_sign  (uint8_t*  secret, uint16_t secretLen, uint8_t*  msg, uint16_t msgLen, uint8_t*  hash);
uint16_t 	hal_hmac_sha512_verify(uint8_t* secret, uint16_t secretLen, uint8_t* msg, uint16_t msgLen, uint8_t* hash);

void hal_hmac_advance_init_update( uint8_t* secret, uint16_t secretLen, SHA512_ADV* ctx);
void hal_hmac_advance_init_final( uint8_t* secret, uint16_t secretLen, SHA512_ADV* ctx);
void hal_hmac_advance_sign(SHA512_ADV* ctx_update, SHA512_ADV* ctx_final,  uint8_t* msg, uint16_t msgLen, uint8_t* hash);
void hal_hmac_advance_sign_be(SHA512_ADV* ctx_update, SHA512_ADV* ctx_final, uint8_t* msg128, uint16_t msgLen);



#endif /* EXAMPLE_HAL_HMAC_H_ */
