/*
 * sha512.h
 *
 *  Created on: Feb 12, 2022
 *      Author: YuraDesktop
 */

#ifndef EXAMPLE_SHA512_H_
#define EXAMPLE_SHA512_H_

#include "stdint.h"



//typedef unsigned long long uint64_t ;
/* do we have sha512 header defs */
#ifndef SHA512_DIGEST_LENGTH
#define SHA512_BLOCK_LENGTH		128
#define SHA512_DIGEST_LENGTH		64
#define SHA512_DIGEST_STRING_LENGTH	(SHA512_DIGEST_LENGTH * 2 + 1)

typedef struct _SHA512_CTX {
	uint64_t	state[8];
	uint8_t		buffer[SHA512_BLOCK_LENGTH];
	uint16_t	bitcount;
} SHA512_CTX;


typedef struct _SHA512_ADV {
	uint64_t	state[8];
	uint16_t	bitcount;
} SHA512_ADV;


#endif /* do we have sha512 header defs */


void SHA512_Init(SHA512_CTX*);
void SHA512_Update(SHA512_CTX*, uint8_t*, uint16_t);
void SHA512_Final(uint8_t* data, SHA512_CTX *);
void SHA512_Last(SHA512_CTX* context);
void SHA512_Transform_BE(SHA512_ADV* context, uint8_t* _data);


void SHA512(uint8_t *data, uint16_t data_len, uint8_t *digest);

#endif /* EXAMPLE_SHA512_H_ */
