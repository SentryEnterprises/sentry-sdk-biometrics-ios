
#include "stdint.h"
#include "string.h"
#include "sha3.h"



// zeros out memory in a way that can't be optimized out by the compiler
inline static void mem_clean(void* ptr, size_t len)
{    
    memset(ptr, 0, len);
}

#define le64(x) (x)


// bitwise left rotation
#define rol32(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

// bitwise left rotation
#define rol64(a, b) ((a) << (b) ^ ((a) >> (64 - (b))))

static void _BRSHA3Compress(uint64_t* r, const uint64_t* x, size_t blockSize)
{
    static const uint64_t k[] = { // keccak round constants
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b,
        0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088,
        0x0000000080008009, 0x000000008000000a, 0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };

    size_t i, j;
    uint64_t a[5], b[5], r0, r1;

    for (i = 0; i < blockSize / sizeof(uint64_t); i++) r[i] ^= le64(x[i]);

    for (i = 0; i < 24; i++) { // permute r
        // theta(r)
        for (j = 0; j < 5; j++) a[j] = r[j] ^ r[j + 5] ^ r[j + 10] ^ r[j + 15] ^ r[j + 20];
        b[0] = rol64(a[1], 1) ^ a[4], b[1] = rol64(a[2], 1) ^ a[0], b[2] = rol64(a[3], 1) ^ a[1];
        b[3] = rol64(a[4], 1) ^ a[2], b[4] = rol64(a[0], 1) ^ a[3];
        for (j = 0; j < 5; j++) r[j] ^= b[j], r[j + 5] ^= b[j], r[j + 10] ^= b[j], r[j + 15] ^= b[j], r[j + 20] ^= b[j];

        // rho(r)
        r[1] = rol64(r[1], 1), r[2] = rol64(r[2], 62), r[3] = rol64(r[3], 28), r[4] = rol64(r[4], 27);
        r[5] = rol64(r[5], 36), r[6] = rol64(r[6], 44), r[7] = rol64(r[7], 6), r[8] = rol64(r[8], 55);
        r[9] = rol64(r[9], 20), r[10] = rol64(r[10], 3), r[11] = rol64(r[11], 10), r[12] = rol64(r[12], 43);
        r[13] = rol64(r[13], 25), r[14] = rol64(r[14], 39), r[15] = rol64(r[15], 41), r[16] = rol64(r[16], 45);
        r[17] = rol64(r[17], 15), r[18] = rol64(r[18], 21), r[19] = rol64(r[19], 8), r[20] = rol64(r[20], 18);
        r[21] = rol64(r[21], 2), r[22] = rol64(r[22], 61), r[23] = rol64(r[23], 56), r[24] = rol64(r[24], 14);

        // pi(r)
        r1 = r[1], r[1] = r[6], r[6] = r[9], r[9] = r[22], r[22] = r[14], r[14] = r[20], r[20] = r[2], r[2] = r[12],
            r[12] = r[13], r[13] = r[19], r[19] = r[23], r[23] = r[15], r[15] = r[4], r[4] = r[24], r[24] = r[21];
        r[21] = r[8], r[8] = r[16], r[16] = r[5], r[5] = r[3], r[3] = r[18], r[18] = r[17], r[17] = r[11], r[11] = r[7];
        r[7] = r[10], r[10] = r1; // r[0] left as is

        for (j = 0; j < 25; j += 5) { // chi(r)
            r0 = r[0 + j], r1 = r[1 + j], r[0 + j] ^= ~r1 & r[2 + j], r[1 + j] ^= ~r[2 + j] & r[3 + j];
            r[2 + j] ^= ~r[3 + j] & r[4 + j], r[3 + j] ^= ~r[4 + j] & r0, r[4 + j] ^= ~r0 & r1;
        }

        *r ^= k[i]; // iota(r, i)
    }

    mem_clean(a, sizeof(a));
    mem_clean(b, sizeof(b));
    //var_clean(&r0, &r1);
}

// sha3-256: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
void BRSHA3_256(void* md32, const void* data, size_t dataLen)
{
    size_t i;
    uint64_t x[17], buf[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };


    for (i = 0; i <= dataLen; i += 136) { // process data in 136 byte blocks
        memcpy(x, (const uint8_t*)data + i, (i + 136 < dataLen) ? 136 : dataLen - i);
        if (i + 136 > dataLen) break;
        _BRSHA3Compress(buf, x, 136);
    }

    memset((uint8_t*)x + (dataLen - i), 0, 136 - (dataLen - i)); // clear remainder of x
    ((uint8_t*)x)[dataLen - i] |= 0x06; // append padding
    ((uint8_t*)x)[135] |= 0x80;
    _BRSHA3Compress(buf, x, 136); // finalize
    for (i = 0; i < 4; i++) buf[i] = le64(buf[i]); // endian swap
    memcpy(md32, buf, 32); // write to md
    mem_clean(x, sizeof(x));
    mem_clean(buf, sizeof(buf));
}

// keccak-256: https://keccak.team/files/Keccak-submission-3.pdf
void BRKeccak256(uint8_t * md32, uint8_t* data, size_t dataLen)
{
    size_t i;
    uint64_t x[17], buf[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };


    for (i = 0; i <= dataLen; i += 136) { // process data in 136 byte blocks
        memcpy(x, (const uint8_t*)data + i, (i + 136 < dataLen) ? 136 : dataLen - i);
        if (i + 136 > dataLen) break;
        _BRSHA3Compress(buf, x, 136);
    }

    memset((uint8_t*)x + (dataLen - i), 0, 136 - (dataLen - i)); // clear remainder of x
    ((uint8_t*)x)[dataLen - i] |= 0x01; // append padding
    ((uint8_t*)x)[135] |= 0x80;
    _BRSHA3Compress(buf, x, 136); // finalize
    for (i = 0; i < 4; i++) buf[i] = le64(buf[i]); // endian swap
    memcpy(md32, buf, 32); // write to md
    mem_clean(x, sizeof(x));
    mem_clean(buf, sizeof(buf));
}


