/*
 * FILE:	sha2.c
 * AUTHOR:	Aaron D. Gifford - http://www.aarongifford.com/
 *
 * Copyright (c) 2000-2001, Aaron D. Gifford
 * All rights reserved.
 *
 * Modified by Jelte Jansen to fit in ldns, and not clash with any
 * system-defined SHA code.
 * Changes:
 * - Renamed (external) functions and constants to fit ldns style
 * - Removed _End and _Data functions
 * - Added ldns_shaX(data, len, digest) convenience functions
 * - Removed prototypes of _Transform functions and made those static
 * Modified by Wouter, and trimmed, to provide SHA512 for getentropy_fallback.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: sha2.c,v 1.1 2001/11/08 00:01:51 adg Exp adg $
 */


/* sha512.c
 *
 *  Created on: Feb 12, 2022
 *      Author: YuraDesktop
 */

#include "stdint.h"
#include "string.h"
#include "sha512.h"




/*** SHA-256/384/512 Machine Architecture Definitions *****************/
/*
 * BYTE_ORDER NOTE:
 *
 * Please make sure that your system defines BYTE_ORDER.  If your
 * architecture is little-endian, make sure it also defines
 * LITTLE_ENDIAN and that the two (BYTE_ORDER and LITTLE_ENDIAN) are
 * equivilent.
 *
 * If your system does not define the above, then you can do so by
 * hand like this:
 *
 *   #define LITTLE_ENDIAN 1234
 *   #define BIG_ENDIAN    4321
 *
 * And for little-endian machines, add:
 *
 *   #define BYTE_ORDER LITTLE_ENDIAN
 *
 * Or for big-endian machines:
 *
 *   #define BYTE_ORDER BIG_ENDIAN
 *
 * The FreeBSD machine this was written on defines BYTE_ORDER
 * appropriately by including <sys/types.h> (which in turn includes
 * <machine/endian.h> where the appropriate definitions are actually
 * made).
 */



#define BYTE_ORDER LITTLE_ENDIAN

typedef uint8_t  sha2_byte;	/* Exactly 1 byte */
typedef uint32_t sha2_word32;	/* Exactly 4 bytes */
#ifdef S_SPLINT_S
typedef unsigned long long sha2_word64; /* lint 8 bytes */
#else
typedef uint64_t sha2_word64;	/* Exactly 8 bytes */
#endif

/*** SHA-256/384/512 Various Length Definitions ***********************/
#define SHA512_SHORT_BLOCK_LENGTH	(SHA512_BLOCK_LENGTH - 16)


/*** ENDIAN REVERSAL MACROS *******************************************/
#if BYTE_ORDER == LITTLE_ENDIAN
#define REVERSE32(w,x)	{ \
	sha2_word32 tmp = (w); \
	tmp = (tmp >> 16) | (tmp << 16); \
	(x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
}
#ifndef S_SPLINT_S

#define REVERSE64(w,x)	{ \
	sha2_word64 tmp = (w); \
	tmp = (tmp >> 32) | (tmp << 32); \
	tmp = ((tmp & 0xff00ff00ff00ff00ULL) >> 8) | \
	      ((tmp & 0x00ff00ff00ff00ffULL) << 8); \
	(x) = ((tmp & 0xffff0000ffff0000ULL) >> 16) | \
	      ((tmp & 0x0000ffff0000ffffULL) << 16); \
}

#else /* splint */
#define REVERSE64(w,x) /* splint */
#endif /* splint */
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

/*** THE SIX LOGICAL FUNCTIONS ****************************************/
/*
 * Bit shifting and rotation (used by the six SHA-XYZ logical functions:
 *
 *   NOTE:  The naming of R and S appears backwards here (R is a SHIFT and
 *   S is a ROTATION) because the SHA-256/384/512 description document
 *   (see http://csrc.nist.gov/cryptval/shs/sha256-384-512.pdf) uses this
 *   same "backwards" definition.
 */
/* Shift-right (used in SHA-256, SHA-384, and SHA-512): */
#define R(b,x) 		((x) >> (b))
/* 64-bit Rotate-right (used in SHA-384 and SHA-512): */
#define S64(b,x)	(((x) >> (b)) | ((x) << (64 - (b))))

/* Two of six logical functions used in SHA-256, SHA-384, and SHA-512: */
#define Ch(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* Four of six logical functions used in SHA-384 and SHA-512: */
#define Sigma0_512(x)	(S64(28, (x)) ^ S64(34, (x)) ^ S64(39, (x)))
#define Sigma1_512(x)	(S64(14, (x)) ^ S64(18, (x)) ^ S64(41, (x)))
#define sigma0_512(x)	(S64( 1, (x)) ^ S64( 8, (x)) ^ R( 7,   (x)))
#define sigma1_512(x)	(S64(19, (x)) ^ S64(61, (x)) ^ R( 6,   (x)))

/*** SHA-XYZ INITIAL HASH VALUES AND CONSTANTS ************************/
/* Hash constant words K for SHA-384 and SHA-512: */
static const sha2_word64 K512[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/* initial hash value H for SHA-512 */
static const sha2_word64 sha512_initial_hash_value[8] = {
	0x6a09e667f3bcc908ULL,
	0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL,
	0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL,
	0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL,
	0x5be0cd19137e2179ULL
};

typedef union _ldns_sha2_buffer_union {
        uint8_t*  theChars;
        uint64_t* theLongs;
} ldns_sha2_buffer_union;

/*** SHA-512: *********************************************************/
void SHA512_Init(SHA512_CTX* context) {
	if (context == (SHA512_CTX*)0) {
		return;
	}
	memcpy(context->state, (void *)sha512_initial_hash_value, SHA512_DIGEST_LENGTH);
	//MEMSET_BZERO(context->buffer, SHA512_BLOCK_LENGTH);
	context->bitcount=  0;
}

static void SHA512_Transform(SHA512_CTX* context, uint8_t* _data) 
{

	uint64_t a0[4];
	uint64_t a4[4];

	uint64_t	T1, T2;

	uint64_t* data = (uint64_t*)_data;
	uint64_t* W512 = (uint64_t*)context->buffer;
	uint8_t	j;

	{
		REVERSE64(*data++, W512[0]);
		REVERSE64(*data++, W512[1]);
		REVERSE64(*data++, W512[2]);
		REVERSE64(*data++, W512[3]);
		REVERSE64(*data++, W512[4]);
		REVERSE64(*data++, W512[5]);
		REVERSE64(*data++, W512[6]);
		REVERSE64(*data++, W512[7]);
		REVERSE64(*data++, W512[8]);
		REVERSE64(*data++, W512[9]);
		REVERSE64(*data++, W512[10]);
		REVERSE64(*data++, W512[11]);
		REVERSE64(*data++, W512[12]);
		REVERSE64(*data++, W512[13]);
		REVERSE64(*data++, W512[14]);
		REVERSE64(*data++, W512[15]);
	}

	a0[0] = context->state[3];
	a0[1] = context->state[2];
	a0[2] = context->state[1];
	a0[3] = context->state[0];

	a4[0] = context->state[7];
	a4[1] = context->state[6];
	a4[2] = context->state[5];
	a4[3] = context->state[4];
	
	j = 0;
	
		do
		{
			T1 = Sigma1_512(a4[(3 + j) & 3]) + Ch( a4[(3 + j) & 3], a4[(2 + j) & 3], a4[(1 + j) & 3]) + a4[(0 + j) & 3] + K512[j] + W512[j];
			T2 = Sigma0_512(a0[(3 + j) & 3]) + Maj(a0[(3 + j) & 3], a0[(2 + j) & 3], a0[(1 + j) & 3]);
			a4[j & 3] = a0[j & 3] + T1;
			a0[j & 3] = T1 + T2;			
			j += 1;			
		} while (j < 16);

	
	do {
		W512[j & 0x0f] += sigma0_512(W512[(j + 1) & 0x0f]) + W512[(j + 9) & 0x0f] + sigma1_512(W512[(j + 14) & 0x0f]);
		/* Apply the SHA-512 compression function to update a..h */
		T1 = Sigma1_512(a4[(3 + j) & 3]) + Ch(a4[(3 + j) & 3], a4[(2 + j) & 3], a4[(1 + j) & 3]) + a4[(0 + j) & 3] + K512[j] + W512[j & 0x0f];
		T2 = Sigma0_512(a0[(3 + j) & 3]) + Maj(a0[(3 + j) & 3], a0[(2 + j) & 3], a0[(1 + j) & 3]);
		a4[j & 3] = a0[j & 3] + T1;
		a0[j & 3] = T1 + T2;
		j += 1;
	} while (j < 80);

	/* Compute the current intermediate hash value */
	context->state[0] += a0[3];
	context->state[1] += a0[2];
	context->state[2] += a0[1];
	context->state[3] += a0[0];
	context->state[4] += a4[3];
	context->state[5] += a4[2];
	context->state[6] += a4[1];
	context->state[7] += a4[0];

	/* Clean up */
	//a = b = c = d = e = f = g = h = T1 = T2 = 0;

}


void SHA512_Transform_BE(SHA512_ADV* context, uint8_t* _data)
{

	uint64_t a0[4];
	uint64_t a4[4];

	uint64_t	T1, T2;

	uint64_t* data = (uint64_t*)_data;

	uint8_t	j;


	a0[0] = context->state[3];
	a0[1] = context->state[2];
	a0[2] = context->state[1];
	a0[3] = context->state[0];

	a4[0] = context->state[7];
	a4[1] = context->state[6];
	a4[2] = context->state[5];
	a4[3] = context->state[4];

	j = 0;

	do
	{
		T1 = Sigma1_512(a4[(3 + j) & 3]) + Ch(a4[(3 + j) & 3], a4[(2 + j) & 3], a4[(1 + j) & 3]) + a4[(0 + j) & 3] + K512[j] + data[j];
		T2 = Sigma0_512(a0[(3 + j) & 3]) + Maj(a0[(3 + j) & 3], a0[(2 + j) & 3], a0[(1 + j) & 3]);
		a4[j & 3] = a0[j & 3] + T1;
		a0[j & 3] = T1 + T2;
		j += 1;
	} while (j < 16);


	do {
		data[j & 0x0f] += sigma0_512(data[(j + 1) & 0x0f]) + data[(j + 9) & 0x0f] + sigma1_512(data[(j + 14) & 0x0f]);
		/* Apply the SHA-512 compression function to update a..h */
		T1 = Sigma1_512(a4[(3 + j) & 3]) + Ch(a4[(3 + j) & 3], a4[(2 + j) & 3], a4[(1 + j) & 3]) + a4[(0 + j) & 3] + K512[j] + data[j & 0x0f];
		T2 = Sigma0_512(a0[(3 + j) & 3]) + Maj(a0[(3 + j) & 3], a0[(2 + j) & 3], a0[(1 + j) & 3]);
		a4[j & 3] = a0[j & 3] + T1;
		a0[j & 3] = T1 + T2;
		j += 1;
	} while (j < 80);

	/* Compute the current intermediate hash value */
	data[0] = context->state[0] + a0[3];
	data[1] = context->state[1] + a0[2];
	data[2] = context->state[2] + a0[1];
	data[3] = context->state[3] + a0[0];
	data[4] = context->state[4] + a4[3];
	data[5] = context->state[5] + a4[2];
	data[6] = context->state[6] + a4[1];
	data[7] = context->state[7] + a4[0];

	/* Clean up */
	//a = b = c = d = e = f = g = h = T1 = T2 = 0;

}


void SHA512_Update(SHA512_CTX* context, uint8_t *datain, uint16_t len) 
{
	uint16_t freespace, usedspace;
	uint16_t pos=0;

	if (len == 0) {
		/* Calling with no data is valid - we do nothing */
		return;
	}

	usedspace = context->bitcount % SHA512_BLOCK_LENGTH;
	if (usedspace > 0) {
		/* Calculate how much free space is available in the buffer */
		freespace = SHA512_BLOCK_LENGTH - usedspace;

		if (len >= freespace) {
			/* Fill the buffer completely and process it */
			memcpy(&context->buffer[usedspace], (void *)datain, freespace);
			context->bitcount+= freespace;
			len -= freespace;
			pos = freespace;
			SHA512_Transform(context, context->buffer);
		} else {
			/* The buffer is not yet full */
			memcpy(&context->buffer[usedspace], (void *)datain, len);
			context->bitcount+=len ;
			/* Clean up: */
			usedspace = freespace = 0;
			return;
		}
	}
	while (len >= SHA512_BLOCK_LENGTH) {
		/* Process as many complete blocks as we can */
		SHA512_Transform(context, datain+pos);
		context->bitcount+= SHA512_BLOCK_LENGTH;
		len-= SHA512_BLOCK_LENGTH;
		pos+= SHA512_BLOCK_LENGTH;

	}
	if (len > 0) {
		/* There's left-overs, so save 'em */
		memcpy(context->buffer, datain+pos, len);
		context->bitcount+= len;
	}
	/* Clean up: */
	usedspace = freespace = 0;
}

void SHA512_Last(SHA512_CTX* context) 
{
	uint16_t usedspace;
	uint32_t bits;
	
	usedspace = (context->bitcount) % SHA512_BLOCK_LENGTH;
	if (usedspace > 0) {
		/* Begin padding with a 1 bit: */
		context->buffer[usedspace++] = 0x80;

		if (usedspace <= SHA512_SHORT_BLOCK_LENGTH) {
			/* Set-up for the last transform: */
			memset(&context->buffer[usedspace],0, 128 - usedspace);
		} else {
			if (usedspace < SHA512_BLOCK_LENGTH) {
				memset(&context->buffer[usedspace],0, SHA512_BLOCK_LENGTH - usedspace);
			}
			/* Do second-to-last transform: */
			SHA512_Transform(context, context->buffer);

			/* And set-up for the last transform: */
			memset(context->buffer, 0,SHA512_BLOCK_LENGTH - 2);
		}
	} else {
		/* Prepare for final transform: */
		memset(context->buffer,0, 128);

		/* Begin padding with a 1 bit: */
		*context->buffer = 0x80;
	}
	/* Store the length of input data (in bits): */
	bits = context->bitcount * 8;
	*(context->buffer + 127) = (uint8_t)bits;
	*(context->buffer + 126) = (uint8_t)(bits >> 8);
	*(context->buffer + 125) = (uint8_t)(bits >> 16);;
	*(context->buffer + 124) = 0;

	/* final transform: */
	SHA512_Transform(context, context->buffer);
}

void SHA512_Final(uint8_t *digest, SHA512_CTX* context) 
{
	/* If no digest buffer is passed, we don't bother doing this: */
	{
		SHA512_Last(context);

		/* Save the hash data for output: */
#if BYTE_ORDER == LITTLE_ENDIAN
		{
			{
				uint8_t* pData = (uint8_t *)context->state;
				for (uint8_t j = 0; j < 8; j++)
				{
					digest[j * 8 + 0] = pData[j * 8 + 7];
					digest[j * 8 + 1] = pData[j * 8 + 6];
					digest[j * 8 + 2] = pData[j * 8 + 5];
					digest[j * 8 + 3] = pData[j * 8 + 4];
					digest[j * 8 + 4] = pData[j * 8 + 3];
					digest[j * 8 + 5] = pData[j * 8 + 2];
					digest[j * 8 + 6] = pData[j * 8 + 1];
					digest[j * 8 + 7] = pData[j * 8 + 0];
				}
			}
		}
#else
		MEMCPY_BCOPY(d, context->state, SHA512_DIGEST_LENGTH);
#endif
	}
}

void SHA512(uint8_t *data, uint16_t data_len, uint8_t *digest)
{
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, data, data_len);
    SHA512_Final(digest, &ctx);
}




