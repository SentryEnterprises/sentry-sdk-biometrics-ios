#ifndef __Support__

#include "stdint.h"
#define  __Support__

int lib_address_to_script(uint8_t* Address, int Len, uint8_t* Script, uint32_t* ScriptLen);
int lib_script0_to_address_test(uint8_t* script, int len, uint8_t* address, uint32_t* addresslen);
int lib_script0_to_address(uint8_t* script, int len, uint8_t* address, uint32_t* addresslen);
int lib_script_legacy_to_address(uint8_t* script, int len, uint8_t* address, uint32_t* addresslen, uint8_t format, uint8_t pur);
int lib_bip143(uint8_t* Inputs, int InputCount, uint8_t* Outputs, int OutputCount, uint32_t LockTime,  uint8_t* Trx, uint32_t* TrxLen, uint8_t* TrxHash);
int lib_bip143Sign(uint8_t* Inputs, int InputCount, uint8_t* Outputs, int OutputCount, uint32_t LockTime, uint8_t* Sign, uint32_t* SignLen);
int lib_bip143MultiSign(uint8_t* Inputs, int InputCount, uint8_t* Outputs, int OutputCount, uint32_t LockTime, uint8_t* Sign, uint8_t* SignLen, uint8_t* Script, int ScriptLen, uint8_t* Trx, uint32_t* TrxLen, uint8_t* TrxHash);
int lib_eip1559(
    uint8_t* chain_id,
    uint8_t* nonce,
    uint8_t* max_priority_fee_per_gas,
    uint8_t* max_fee_per_gas,
    uint8_t* gas_limit,
    uint8_t* destination,
    uint8_t* amount,
    uint8_t* data,
    uint8_t* access_list,
    uint8_t* Trx, uint32_t* TrxLen, uint8_t* TrxHash);


#endif // !__Support__

