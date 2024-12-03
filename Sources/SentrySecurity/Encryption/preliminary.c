
/*
 *-------------------------------------------------------------------------------
 *                                                                              *
 * Copyright (c) 2023 jNet ThingX Corp. All Rights Reserved.                    *
 *                                                                              *
 * This software is the confidential and proprietary information of             *
 * jNet ThingX Corp. ("Confidential Information"). Any disclosure of such       *
 * Confidential Information shall only be done in accordance with the terms of  *
 * the license agreement you entered into with jNet ThingX.                     *
 *                                                                              *
 * jNet ThingX makes no representations or warranties about the suitability of  *
 * the software, either expressed or implied, including but not limited to      *
 * implied warranties of merchantability, fitness for a particular purpose, or  *
 * non-infringement. jNet ThingX Corp. shall not be liable for any damages      *
 * suffered by licensee as a result of using, modifying or distributing this    *
 * software or its derivatives.                                                 *
 *                                                                              *
 *-------------------------------------------------------------------------------
 */



#include "stdint.h"
#include "string.h"
#include "sha512.h"
#include "hal_hmac.h"

 /**
  *
  * Performs the RFC2898 PBKDF2 Key Derivation Function.
  *
  * Input Parameters (from Java):
  *   - Key o_hmacKey : HMAC Key Object
  *   - int32_t s_iterationCount : Number of Iteration in KDF
  *   - byte[] ba_derivedKeyData : the Derived Key Generated Data
  *
  * Return:
  *   - None (void)
  *
  */
void bip39_pbkdf2_preliminary(uint8_t* o_hmacKey, uint16_t hmacKeyLen, uint32_t s_iterationCount, uint8_t* passphrase, int len_passphrase,uint8_t* ba_derivedKeyData)
{
		uint8_t		ba_saltData[]= { 0x04,0x07,0x0C,0x04,0x06,0x07,0x00,0x0A}; //
		uint16_t	s_saltLength = 8;

		// Allocate Working Buffer
		uint8_t hash_out[128+128];
		uint8_t hash_tmp128[128];

		SHA512_ADV ctx_update;
		SHA512_ADV ctx_final;

		// Retrieve HMAC Hash Algorithm Parameters
		uint16_t u2HashLength = 64;
		// Retrieve Count Value
		uint32_t u2Count = s_iterationCount;

		
		uint32_t j;
		
		for (j = 0; j < 8; j++) ba_saltData[j] = ba_saltData[j] ^ 0x69;

		hal_hmac_advance_init_update(o_hmacKey, hmacKeyLen, &ctx_update);
		hal_hmac_advance_init_final(o_hmacKey, hmacKeyLen, &ctx_final);

		// Copy the Salt in Working Buffer at Offset 0
		memcpy(hash_out, ba_saltData, s_saltLength);
		if (len_passphrase > 0)
		{
			memcpy(hash_out+ s_saltLength, passphrase, len_passphrase);
			s_saltLength += (uint16_t)len_passphrase;

		}

			// Add Block Number (4 Bytes) at the end of the Salt in the Working Buffer ("SALT | BLOCK NUMBER")
			hash_out[(short)(s_saltLength + 0)] = 0;
			hash_out[(short)(s_saltLength + 1)] = 0;
			hash_out[(short)(s_saltLength + 2)] = 0;
			hash_out[(short)(s_saltLength + 3)] = 1;

			// Compute HMAC(SALT | INDEX) -> Intermediate Hash U1
			hal_hmac_advance_sign(&ctx_update, &ctx_final, hash_out, s_saltLength + 4, hash_tmp128);

			// Saving U1 into a Working Buffer at Derived Data Offset (T)
			memcpy(hash_out, hash_tmp128, u2HashLength);

			// XORING U1, U2...Uc
			for (j = 1; j < u2Count; j++)
			{
				hal_hmac_advance_sign_be(&ctx_update, &ctx_final, hash_tmp128, u2HashLength);
				// XOR U{i} and U{i-1}
				for (short k = 0; k < u2HashLength; k++)
				{
					hash_out[k] = hash_out[k] ^ hash_tmp128[k];
				}
			}

			
			//Get preDK into Output Buffer
			memcpy(ba_derivedKeyData+0,				hash_tmp128,	u2HashLength);
			memcpy(ba_derivedKeyData+ u2HashLength, hash_out,		u2HashLength);

	return ;
}



//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//This function is needed only for tests, for release it should be removed from the project!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


//---------------------------------------------------------------------------------------
/**
  *
  * Performs the RFC2898 PBKDF2 Key Derivation Function.
  *
  * Input Parameters (from Java):
  *   - Key o_hmacKey : HMAC Key Object
  *   - short s_iterationCount : Number of Iteration in KDF
  *   - byte[] ba_derivedKeyData : the Derived Key Generated Data
  *
  * Return:
  *   - None (void)
  *
  */
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//This function is needed only for tests, for release it should be removed from the project!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

void bip39_pbkdf2_final(uint8_t* o_hmacKey, uint16_t hmacKeyLen, uint16_t s_iterationCount, uint8_t* ba_derivedKeyData)
{
	// Allocate Working Buffer
	uint8_t hash_out[128];
	uint8_t hash_tmp128[128];
	SHA512_ADV ctx_update;
	SHA512_ADV ctx_final;
	// Retrieve HMAC Hash Algorithm Parameters
	uint16_t u2HashLength = 64;
	// Retrieve Count Value
	uint16_t u2Count = s_iterationCount;
	uint16_t j;
	hal_hmac_advance_init_update(o_hmacKey, hmacKeyLen, &ctx_update);
	hal_hmac_advance_init_final(o_hmacKey, hmacKeyLen, &ctx_final);

	// Saving U1 into a Working Buffer at Derived Data Offset (T)
	memcpy(hash_tmp128,	 ba_derivedKeyData+0,				u2HashLength);
	memcpy(hash_out,	 ba_derivedKeyData+ u2HashLength,	u2HashLength);

	// XORING U1, U2...Uc
	for (j = 0; j < u2Count; j++)
	{
		hal_hmac_advance_sign_be(&ctx_update, &ctx_final, hash_tmp128, u2HashLength);
		// XOR U{i} and U{i-1}
		for (short k = 0; k < u2HashLength; k++)
		{
			hash_out[k] = hash_out[k] ^ hash_tmp128[k];
		}
	}

	for (j = 0; j < 8; j++)
	{
		hash_tmp128[j * 8 + 0] = hash_out[j * 8 + 7];
		hash_tmp128[j * 8 + 1] = hash_out[j * 8 + 6];
		hash_tmp128[j * 8 + 2] = hash_out[j * 8 + 5];
		hash_tmp128[j * 8 + 3] = hash_out[j * 8 + 4];
		hash_tmp128[j * 8 + 4] = hash_out[j * 8 + 3];
		hash_tmp128[j * 8 + 5] = hash_out[j * 8 + 2];
		hash_tmp128[j * 8 + 6] = hash_out[j * 8 + 1];
		hash_tmp128[j * 8 + 7] = hash_out[j * 8 + 0];
	}

	//Get DK into Output Buffer
	memcpy(ba_derivedKeyData, hash_tmp128, u2HashLength);

	return;
}