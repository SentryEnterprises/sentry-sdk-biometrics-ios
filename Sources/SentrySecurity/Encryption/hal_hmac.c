/*
 * ------------------------------------------------------------------------------------------------------------------ *
 *                                                                                                                    *
 * Copyright (c) 2022 jNet ThingX Corp. All Rights Reserved.                                                          *
 *                                                                                                                    *
 * This software is the confidential and proprietary information of jNet ThingX Corp. ("Confidential Information").   *
 * Any disclosure of such Confidential Information shall only be done in accordance with the terms of the license     *
 * agreement you entered into with jNet ThingX.                                                                       *
 *                                                                                                                    *
 * jNet ThingX makes no representations or warranties about the suitability of the software, either expressed or      *
 * implied, including but not limited to implied warranties of merchantability, fitness for a particular purpose, or  *
 * non-infringement. jNet ThingX Corp. shall not be liable for any damages suffered by licensee as a result of using, *
 * modifying or distributing this software or its derivatives.                                                        *
 *                                                                                                                    *
 * ------------------------------------------------------------------------------------------------------------------ *
 */

/*
 * hal_hmac.c
 *
 *  Created on: Feb 12, 2022
 *      Author: Yuri Gnatyuk
 */

#include "stdint.h"
#include "string.h"
#include "sha512.h"




static void hmac_update_with_secret(SHA512_CTX *ctx, uint8_t* secret, uint16_t len, uint8_t _xor)
{
	uint16_t i;
	uint8_t v;
	uint8_t hash[64];

	// secret should be no longer than 128 bytes! For longer secrets,
	// pass them through hash function as specified in RFC-2104

	if (len > 128)
	{
		SHA512_Update(ctx, secret, len);
		SHA512_Final(hash, ctx);
		SHA512_Init(ctx);

		for (i = 0; i < 64; i++) {
			v = hash[i] ^ _xor;
			SHA512_Update(ctx, &v, 1);
		}
		for (i = 64; i < 128; i++) {
			v = _xor;
			SHA512_Update(ctx, &v, 1);
		}
		return;

	}


	for (i=0; i<len; i++) {
		v = secret[i] ^ _xor;
		SHA512_Update(ctx, &v, 1);
	}
	for (i=len; i<128; i++) {
		v = _xor;
		SHA512_Update(ctx, &v, 1);
	}

}


void hmac_sha512_init(SHA512_CTX *ctx, uint8_t* secret, uint16_t secretLen)
{
	// inner digest
	SHA512_Init(ctx);
	hmac_update_with_secret(ctx, secret, secretLen, 0x36);
}

void hmac_sha512_update(SHA512_CTX *ctx, uint8_t* msg, uint16_t msgLen)
{
	SHA512_Update(ctx, (uint8_t *)msg, msgLen);
}

void hmac_sha512_final(SHA512_CTX *ctx, uint8_t* secret, uint16_t secretLen, uint8_t* hash)
{
	SHA512_Final(hash, ctx );

	// outer digest
	SHA512_Init(ctx);
	hmac_update_with_secret(ctx, secret, secretLen, 0x5c);
	SHA512_Update(ctx, hash, SHA512_DIGEST_LENGTH);
	SHA512_Final(hash,ctx);
}


void hal_hmac_sha512_sign(uint8_t*  secret, uint16_t secretLen, uint8_t*  msg, uint16_t msgLen, uint8_t*  hash)
{

	SHA512_CTX _hmacctx_;
	// inner digest
	hmac_sha512_init(&_hmacctx_, secret, secretLen);
	hmac_sha512_update(&_hmacctx_, msg, msgLen);
	hmac_sha512_final(&_hmacctx_, secret, secretLen, hash);
}


void hal_hmac_advance_init_update( uint8_t* secret, uint16_t secretLen, SHA512_ADV* ctx_adv)
{
	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	hmac_update_with_secret(&ctx, secret, secretLen, 0x36);
	memcpy(&ctx_adv->state, &ctx.state, sizeof(ctx.state));
	memcpy(&ctx_adv->bitcount, &ctx.bitcount, sizeof(ctx.bitcount));
}


void hal_hmac_advance_init_final( uint8_t* secret, uint16_t secretLen, SHA512_ADV* ctx_adv)
{
	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	hmac_update_with_secret(&ctx, secret, secretLen, 0x5c);
	memcpy(&ctx_adv->state, &ctx.state, sizeof(ctx.state));
	memcpy(&ctx_adv->bitcount, &ctx.bitcount, sizeof(ctx.bitcount));

}

void hal_hmac_advance_sign(SHA512_ADV* ctx_update, SHA512_ADV* ctx_final,  uint8_t* msg, uint16_t msgLen, uint8_t* hash)
{
	SHA512_CTX ctx;
	ctx.bitcount = ctx_update->bitcount;
	memcpy(&ctx.state, ctx_update->state, sizeof(ctx.state));
	SHA512_Update(&ctx, msg, msgLen);
	SHA512_Final(hash, &ctx);

	ctx.bitcount = ctx_final->bitcount;
	memcpy(&ctx.state, ctx_final->state, sizeof(ctx.state));
	SHA512_Update(&ctx, hash, SHA512_DIGEST_LENGTH);
	//SHA512_Final(hash, &ctx);
	SHA512_Last(&ctx);
	memcpy(hash, &ctx.state, 64);
}


void hal_hmac_advance_sign_be(SHA512_ADV* ctx_update, SHA512_ADV* ctx_final, uint8_t* msg128, uint16_t msgLen)
{
	uint32_t bits = (ctx_update->bitcount + msgLen)*8;
	memset(msg128 + 64, 0, 64);
	msg128[64 + 7] = 0x80;
	msg128[120] = (uint8_t)bits;
	msg128[121] = (uint8_t)(bits>>8);
	msg128[122] = (uint8_t)(bits >> 16);
	SHA512_Transform_BE(ctx_update, msg128);
	memset(msg128 + 64, 0, 64);
	msg128[64 + 7] = 0x80;
	msg128[120] = (uint8_t)bits;
	msg128[121] = (uint8_t)(bits >> 8);
	msg128[122] = (uint8_t)(bits >> 16);
	SHA512_Transform_BE(ctx_final, msg128);
}



