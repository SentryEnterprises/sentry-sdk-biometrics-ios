
#ifndef __lib_sdk_wallet

#include "stdint.h"
#include "string.h"

int lib_secure_channel_init(void);
int            lib_check_sw_err(uint8_t* pout, int len);
uint16_t    lib_get_sw    (uint8_t* pout, int len);

int lib_sdk_get_version(uint8_t* version);

int  lib_wallet_init(int sc);
void lib_wallet_deinit(void);

int lib_sdk_get_capability(uint8_t* capability);

int lib_wallet_select_wallet(void);
int lib_wallet_select_wallet_sc(void);

int lib_wallet_store_pin(uint8_t* pin, int len);
int lib_wallet_verify_pin(uint8_t* pin, int len);

int lib_wallet_get_gguid(uint8_t* gguid);

int lib_wallet_get_version(uint8_t* version);
int lib_os_get_version(uint8_t* version);
int lib_wallet_get_status(uint8_t* GWS, uint8_t* WPSM, uint8_t* WSSM);
int lib_wallet_get_accounts(uint8_t* NumberAccounts, uint8_t* AccountInfo);

int lib_wallet_create    (int iteration, int set_words, int set_lang, uint8_t* passphrase, int len_passphrase, uint8_t* mnemonics, int* len_mnemonic);
int lib_wallet_recovery    (int iteration, uint8_t* mnemonics, int len_mnemonics, uint8_t* passphrase, int len_passphrase);
int lib_wallet_account_create(uint32_t currID, uint8_t netID, uint8_t accountID, uint8_t chain, uint8_t bip, uint8_t* nickname, int len_nick);
int lib_wallet_select_account(int index);
int lib_wallet_get_status_account(uint8_t* ALC, uint8_t* WSSM);
int lib_wallet_get_publickey_account(uint8_t* AccountPublicKey, uint8_t* AccountChainCodeKey, uint8_t* PublicKeyParent);
int lib_wallet_get_receive_publickey_account(uint8_t* AccountPublicKey);
int lib_wallet_get_address_index(uint16_t* AddressIndex);
int lib_wallet_get_chain_index(uint8_t* ChainIndex);

int lib_wallet_set_address_index(uint16_t AddressIndex);
int lib_wallet_set_chain_index(uint8_t ChainIndex);
int lib_wallet_sign_hash( uint8_t* Hash, int len_hash, uint8_t* R, uint8_t* S, uint8_t* V);

int lib_wallet_reset(void);
int lib_wallet_select_wallet(void);

int lib_wallet_get_cvm_status(uint8_t *CVM, uint8_t *WSSM);
int lib_wallet_get_cvm_verify(uint8_t* CVM, uint8_t* WSSM);
int lib_wallet_cvm_disable_pin(void);

int lib_wallet_get_address(uint8_t* Address, uint32_t* AddressLen);
int lib_wallet_script0_to_address(int pur, uint8_t* script, int len, uint8_t* Address, uint32_t* AddressLen);


#define _SDK_ERROR_INVALID_INPUT_    (-1)
#define _SDK_ERROR_STATUS_            (-2)
#define _SDK_ERROR_UNKNOWN_            (-3)
#define _SDK_ERROR_CRITICAL_        (-4)
#define _SDK_ERROR_CRITERION_        (-5)
#define _SDK_ERROR_STATE_            (-6)
#define _SDK_ERROR_EXCHANGE_        (-100)


#endif // !__lib_sdk_wallet

