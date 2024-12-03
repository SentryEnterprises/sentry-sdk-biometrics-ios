#ifndef __SHA3_h
#define __SHA3_h

void ripemd160(uint8_t* msg, uint32_t msg_len, uint8_t* hash);
void BRKeccak256(uint8_t* md32, uint8_t* data, size_t dataLen);


#endif





