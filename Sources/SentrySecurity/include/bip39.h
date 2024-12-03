#ifndef ___BLOCK_CHAIN_BIP39___
#include "stdint.h"

int BIP39_getMnemonicSentence(int set_lang, uint16_t* wordsIdxList, uint16_t wordListLength, uint8_t* outBuf);
int BIP39_areMnemonicValid(uint8_t* mnemonicSentence, uint16_t mnemonicOffset, uint16_t mnemnicLength, uint16_t numberOfWords);


#endif // !___BLOCK_CHAIN_BIP39___


