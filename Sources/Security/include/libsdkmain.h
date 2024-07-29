#ifndef __lib_main_header__

#include "stdint.h"

#ifdef _WINDOWS
#define DllExport   __declspec( dllexport )
#define  _Export_ DllExport
#endif

#ifdef __ANDROID__
#define  _Export_ extern
#endif

#ifdef __APPLE__
#define  _Export_ extern
#endif

//#include "wrapper.h"

//_Export_ int LibSdkWalletInit(int SecureChannel, SmartCardApduCallBack callback);
//_Export_ int LibSdkWalletDeinit(void);
//_Export_ int LibSdkGetSdkVersion(uint8_t* version);
//_Export_ int LibSdkGetWalletVersion(uint8_t* version);
//_Export_ int LibSdkGetCapability(uint8_t* capability);
//_Export_ int LibSdkStorePin(uint8_t* pin, int len);
//_Export_ int LibSdkVerifyPin(uint8_t* pin, int len);
//_Export_ int LibSdkGetGGUID(uint8_t* gguid);
//_Export_ int LibSdkGetOSVersion(uint8_t* version);
//_Export_ int LibSdkGetStatus(uint8_t* GWLCS, uint8_t* WPSM, uint8_t* WSSM);
//_Export_ int LibSdkGetAccounts(uint8_t* NumberAccounts, uint8_t* AccountInfo);
//_Export_ int LibSdkCreateWallet(int Iteration, int Words, int Lang, uint8_t* passphrase, int len_passphrase, uint8_t* mnemonics, int* len_mnemonic);
//_Export_ int LibSdkRecoveryWallet(int Iteration, uint8_t* mnemonics, int len_mnemonics, uint8_t* passphrase, int len_passphrase);
//_Export_ int LibSdkAccountCreate(uint32_t currID, uint8_t netID, uint8_t accountID, uint8_t chain, uint8_t bip, uint8_t* nickname, int len_nick);
//_Export_ int LibSdkSelectAccount(int account_index);
//_Export_ int LibSdkAccountGetStatus(uint8_t* ALC, uint8_t* WSSM);
//_Export_ int LibSdkAccountGetPublicKey(uint8_t* AccountPublicKey, uint8_t* AccountChainCodeKey, uint8_t* PublicKeyParent);
//_Export_ int LibSdkAccountGetReceivePublicKey(uint8_t* AccountPublicKey);
//_Export_ int LibSdkAccountGetAddressIndex(uint16_t* AddressIndex);
//_Export_ int LibSdkAccountGetChainIndex(uint8_t* ChainIndex);
//_Export_ int LibSdkAccountSetAddressIndex(uint16_t AddressIndex);
//_Export_ int LibSdkAccountSetChainIndex(uint8_t ChainIndex);
//_Export_ int LibSdkAccountSignHash(uint8_t* Hash, int len_hash, uint8_t* R, uint8_t* S, uint8_t* V);
//_Export_ int LibSdkResetWallet(void);
//_Export_ int LibSdkSelectWallet(void);
//_Export_ int LibSdkWalletGetCVMStatus(uint8_t* CVM, uint8_t* WSSM);
//_Export_ int LibSdkWalletCVMVerify(uint8_t* CVM, uint8_t* WSSM);
//_Export_ int LibSdkWalletCVMDisablePin(void);

//------------------------------------------------------------------------------------
//_Export_ int LibSdkEnrollInit(int SecureChannel, uint8_t* pin, int len, SmartCardApduCallBack callback);
//_Export_ int LibSdkEnrollDeinit(void);
//_Export_ int LibSdkGetEnrollStatus(uint8_t* max_num_fingers, uint8_t* enrolled_touches, uint8_t* remaining_touches, uint8_t* biometric_mode);
//_Export_ int LibSdkEnrollProcess(int num_finger, uint8_t* enrolled_touches, uint8_t* remaining_touches, uint8_t* biometric_mode);
//_Export_ int LibSdkEnrollReprocess(int num_finger, uint8_t* enrolled_touches, uint8_t* remaining_touches, uint8_t* biometric_mode);
//_Export_ int LibSdkEnrollVerify(void);

_Export_ int LibSdkGetSdkVersion(uint8_t* version);

_Export_ int LibSecureChannelInit(uint8_t* out_apduCommand, int *out_commandLen, uint8_t* out_private_key, uint8_t* out_public_key, uint8_t* out_secret_shses);

_Export_ int LibCalcSecretKeys(uint8_t* pubKey, uint8_t* shses, uint8_t* privateKey, uint8_t* out_KeyRespt, uint8_t* out_KeyENC, uint8_t* out_KeyCMAC, uint8_t* out_KeyRMAC, uint8_t* out_chaining);

_Export_ int LibAuthWrap(uint8_t* apdu_in, uint32_t in_len, uint8_t* apdu_out, uint32_t* out_len, uint8_t* keyENC, uint8_t* keyCMAC, uint8_t* inout_chaining_value, uint8_t* inout_encryption_counter);

_Export_ int LibAuthUnwrap(uint8_t* wrapped_apdu_in, uint32_t in_len, uint8_t* unwrapped_apdu_out, uint32_t* out_len, uint8_t* keyENC, uint8_t* keyRMAC, uint8_t* chaining_value, uint8_t* encryption_counter);

//------------------------------------------------------------------------------------
//// HASH
//_Export_ int LibSdkPublicKeyDecompress(uint8_t* compress_pub, uint8_t* decompress_pub);
//_Export_ int LibSdkVerifyPublicSignHash(uint8_t* Compress, uint8_t* Hash, uint8_t* Sign);
//_Export_ int LibSdkAddressToScript(uint8_t* Address, int Len, uint8_t* Script, uint32_t* ScriptLen);
//_Export_ int LibSdkHash160(uint8_t* Data, int DataLen, uint8_t* SHA160);
//_Export_ int LibSdkRipemd160(uint8_t* Data, int DataLen, uint8_t* SHA160);
//_Export_ int LibSdkKeccak256(uint8_t* Data, int DataLen, uint8_t* _SHA256);
//_Export_ int LibSdkSha256(uint8_t* Data, int DataLen, uint8_t* _SHA256);
//_Export_ int LibSdkSha256D(uint8_t* Data, int DataLen, uint8_t* _SHA256);
//_Export_ int LibSdkWalletGetAddress(uint8_t* Address, uint32_t* AddressLen);
//_Export_ int LibSdkWalletScript0ToAddress(int currID, uint8_t* script, int len, uint8_t* Address, uint32_t* AddressLen);
//------------------------------------------------------------------------------------
//_Export_ int LibSdkBip143(
//    uint8_t* Inputs,
//    int InputCount,
//    uint8_t* Outputs,
//    int OutputCount,
//    uint32_t LockTime,
//    uint8_t*Trx,
//    uint32_t *TrxLen,
//    uint8_t* TrxHash);
//------------------------------------------------------------------------------------
//_Export_ int LibSdkBip143Sign(
//    uint8_t* Inputs,
//    int InputCount,
//    uint8_t* Outputs,
//    int OutputCount,
//    uint32_t LockTime,
//    uint8_t* Sign,
//    uint32_t* SignLen);

//------------------------------------------------------------------------------------
//_Export_ int LibSdkBip143MultiSign(
//    uint8_t* Inputs,
//    int InputCount,
//    uint8_t* Outputs,
//    int OutputCount,
//    uint32_t LockTime,
//    uint8_t* Sign,
//    uint8_t* SignLen,
//    uint8_t* Script,
//    int ScriptLen,
//    uint8_t* Trx,
//    uint32_t* TrxLen,
//    uint8_t* TrxHash);
//------------------------------------------------------------------------------------
//_Export_ int LibSdkEip1559(
//    uint8_t* chain_id,
//    uint8_t* nonce,
//    uint8_t* max_priority_fee_per_gas,
//    uint8_t* max_fee_per_gas,
//    uint8_t* gas_limit,
//    uint8_t* destination,
//    uint8_t* amount,
//    uint8_t* data,
//    uint8_t* access_list,
//    uint8_t* Trx,
//    uint32_t* TrxLen,
//    uint8_t* TrxHash);
//------------------------------------------------------------------------------------

#endif // !__lib_main_header__



