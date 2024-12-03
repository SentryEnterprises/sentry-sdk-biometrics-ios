

#include "stdio.h"
#include "lib_wallet.h"
#include "secure.h"
#include "preliminary.h"
#include "bip39.h"
#include "wrapper.h"
#include "support.h"

//----------------------------------------------------------------------------------------------------------------------
#define SDK_VERSION_H 0
#define SDK_VERSION_L 24
//----------------------------------------------------------------------------------------------------------------------

uint8_t            apdu_out[300];
uint32_t        apdu_out_len = 0;

//----------------------------------------------------------------------------------------------------------------------
volatile    int        SelectWallet = -1;
//----------------------------------------------------------------------------------------------------------------------

//uint8_t        WalletVersion[4];//Retrieve Current Wallet Version

uint8_t        WalletGGID[40];//Retrieve the Unique ID of the Card

uint8_t        WalletStatus5F36[4]; //Global Wallet Life Cycle (GWS)
uint8_t        WalletStatus5F37[4]; //Wallet Personalization State Machine (WPSM)
uint8_t        WalletStatus5F39[4]; //Wallet Security State Machine (WSSM)
uint8_t        WalletStatus5F3A[4]; //Account Life Cycle

uint8_t        WalletGGUID[16]; //Retrieve the Unique ID of the Card

//uint8_t        WalletCapability[1];

uint8_t        account_info[10];

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
//int lib_sdk_get_version(uint8_t* version)
//{
//    version[0] = 2;
//    version[1] = SDK_VERSION_H;
//    version[2] = SDK_VERSION_L;
//    return 0;
//}
////----------------------------------------------------------------------------------------------------------------------
//int lib_secure_channel_init(void)
//{
//    uint8_t apdu_int[250];
//    int len_apdu = 0;
//    int p;
//    int ret = lib_auth_init(apdu_int, &len_apdu);
//    if (ret != 0) return ret;
//    apdu_out_len = 0;
//    ret = apdu_secure_channel(apdu_int, len_apdu, apdu_out, &apdu_out_len);
//    if (ret != 0) return _SDK_ERROR_EXCHANGE_;
//    p = 0;
//    if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
//    if (apdu_out[p++] != 0x49) return _SDK_ERROR_CRITERION_;
//    if (apdu_out[p++] != 65) return _SDK_ERROR_CRITERION_;
//    ret = lib_auth_ecdh_kdf(apdu_out + p);
//    if (ret != 0) return _SDK_ERROR_EXCHANGE_;
//    p += 65;
//    if (apdu_out[p++] != 0x86) return _SDK_ERROR_CRITERION_;
//    if (apdu_out[p++] != 0x10) return _SDK_ERROR_CRITERION_;
//    lib_auth_wrapper_init(apdu_out + p);
//    return ret;
//}
////----------------------------------------------------------------------------------------------------------------------
//int lib_wallet_init(int sc)
//{
//    int ret = lib_wallet_select_wallet();
//    if (ret != 0) return ret;
//    if (sc > 0)
//    {
//        ret = lib_secure_channel_init();
//    }
//
//    return ret;
//}
////----------------------------------------------------------------------------------------------------------------------
//void lib_wallet_deinit(void)
//{
//    SelectWallet = -1;
//}
//----------------------------------------------------------------------------------------------------------------------
//int lib_check_sw_err(uint8_t* pout, int len)
//{
//    uint16_t sw;
//    if (len < 2) return _SDK_ERROR_EXCHANGE_;
//    sw = (pout[len - 2] << 8) + (pout[len - 1] << 0);
//    if (sw == 0x9000) return 0;
//    if (sw == 0x6985) return _SDK_ERROR_STATE_;
//    if (sw == 0x6986) return _SDK_ERROR_STATE_;
//    if (sw == 0x6982) return _SDK_ERROR_STATE_;
//
//    if (sw == 0x6980) return _SDK_ERROR_INVALID_INPUT_;
//    if (sw == 0x6983) return _SDK_ERROR_INVALID_INPUT_;
//    if (sw == 0x6A82) return _SDK_ERROR_INVALID_INPUT_;
//    if (sw == 0x6984) return _SDK_ERROR_INVALID_INPUT_;
//        
//    return _SDK_ERROR_CRITERION_;
//}
////----------------------------------------------------------------------------------------------------------------------
//uint16_t lib_get_sw(uint8_t* pout, int len)
//{
//    uint16_t sw;
//    if (len < 2) return 0;
//    sw = (pout[len - 2] << 8) + (pout[len - 1] << 0);
//    return sw;
//}
////----------------------------------------------------------------------------------------------------------------------
//int lib_wallet_select_wallet(void)
//{
//    uint8_t apdu_select[] = { 0x00, 0xA4, 0x04, 0x00, 0x0A, 0x4A, 0x4E, 0x45, 0x54, 0x5F, 0x4C, 0x5F, 0x01, 0x01, 0x57, 0x00 };
//    apdu_out_len = 0;
//    int Ret = apdu_secure_channel(apdu_select, sizeof(apdu_select), apdu_out, &apdu_out_len);
//    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
//    
//    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
//    if (Ret != 0) return Ret;
//
//    if (Ret == 0) SelectWallet = 1;
//    return Ret;
//}
////----------------------------------------------------------------------------------------------------------------------
//int lib_wallet_select_wallet_sc(void)
//{
//    uint8_t apdu_select[] = { 0x80, 0xA4, 0x04, 0x00, 0x0A, 0x4A, 0x4E, 0x45, 0x54, 0x5F, 0x4C, 0x5F, 0x01, 0x01, 0x57, 0x00 };
//    apdu_out_len = 0;
//    int Ret = apdu_secure_channel(apdu_select, sizeof(apdu_select), apdu_out, &apdu_out_len);
//    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
//    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
//    if (Ret != 0) return Ret;
//
//    if (Ret == 0) SelectWallet = 1;
//    return Ret;
//}
//----------------------------------------------------------------------------------------------------------------------
//int lib_wallet_get_version(uint8_t *version)
//{
//    int p = 0;
//    uint8_t apdu_get_data[] = { 0x80, 0xCA, 0x5F, 0xC1, 0x00};
//    apdu_out_len = 0;
//    int Ret;
//    Ret=lib_wallet_select_wallet_sc();
//    if (Ret != 0) return Ret;
//    Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
//    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
//    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
//    if (Ret != 0) return Ret;
//    if (Ret == 0 && apdu_out_len==7)//5F C1 02 01 12 90 00
//    {
//        int n;
//        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
//        if (apdu_out[p++] != 0xC1) return _SDK_ERROR_CRITERION_;
//        
//        n = apdu_out[p];
//        
//        for (int i = 0; i < (n+1); i++)
//        {
//            WalletVersion[i] = apdu_out[p];
//            version[i]= apdu_out[p++];
//        }
//
//    }
//    return Ret;
//}
////----------------------------------------------------------------------------------------------------------------------
//int lib_os_get_version(uint8_t* version)
//{
//    int p = 0;
//    uint8_t apdu_get_data[] = { 0xb1, 0x05, 0x40, 0x00, 0x00 };
//    apdu_out_len = 0;
//    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
//    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
//    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
//    if (Ret != 0) return Ret;
//
//    if (Ret == 0 && apdu_out_len > 7)
//    {
//        int n;
//        if (apdu_out[p++] != 0xFE) return _SDK_ERROR_CRITERION_;
//        if (apdu_out[p++] < 0x40) return _SDK_ERROR_CRITERION_;
//        if (apdu_out[p++] != 0x7F) return _SDK_ERROR_CRITERION_;
//        if (apdu_out[p++] != 0x00) return _SDK_ERROR_CRITERION_;
//        if (apdu_out[p++] <  0x40) return _SDK_ERROR_CRITERION_;
//        if (apdu_out[p++] != 0x9F) return _SDK_ERROR_CRITERION_;
//        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
//        n = apdu_out[p++];
//        p += n;
//        if (apdu_out[p++] != 0x9F) return _SDK_ERROR_CRITERION_;
//        if (apdu_out[p++] != 0x02) return _SDK_ERROR_CRITERION_;
//        n = apdu_out[p++];
//        if (n != 5) return -1;
//
//        version[0] = 3;
//        version[1] = apdu_out[p++]-0x30; p++; //.
//        version[2] = apdu_out[p++]-0x30; p++; //.
//        version[3] = apdu_out[p++]-0x30; p++; //.
//    }
//    return Ret;
//}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_get_gguid(uint8_t* gguid)
{
    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xCA, 0x5F, 0x40, 0x00 };
    if (lib_wallet_select_wallet_sc() != 0) return -1;
    apdu_out_len = 0;
    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;
    if (Ret == 0 )//5F 40 20
    {
        int n;
        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x40) return _SDK_ERROR_CRITERION_;

        n = apdu_out[p];
        
        for (int i = 0; i < n; i++)
        {
            WalletGGID[i] = apdu_out[p];
            gguid[i] = apdu_out[p++];
        }

    }
    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_sdk_get_capability(uint8_t* capability)
{
    int p = 0;
    uint8_t apdu_get_cap[] = { 0x80, 0xB8, 0x00, 0x00, 0x00 };
    apdu_out_len = 0;
    int Ret = apdu_secure_channel(apdu_get_cap, sizeof(apdu_get_cap), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0 && apdu_out_len == 6)//5F 3E 01 01 90 00
    {
        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x3E) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
            
        WalletCapability[0] = apdu_out[p++];
        capability[0] = WalletCapability[0];
    }
    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_get_status(uint8_t *GWLC, uint8_t* WPSM, uint8_t* WSSM)
{
    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xCA, 0xBF, 0xC3, 0x00 };
    //if (lib_wallet_select_wallet_sc() != 0) return -1;
    apdu_out_len = 0;
    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0 && apdu_out_len == 17)//BF C3 0C 5F 36 01 [54] 5F 37 01 10 5F 39 01 00 90 00
    {
        if (apdu_out[p++] != 0xBF) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0xC3) return _SDK_ERROR_CRITERION_;

        if (apdu_out[p++] != 0x0C) return _SDK_ERROR_CRITERION_;

        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x36) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
        WalletStatus5F36[0] = apdu_out[p++];
        GWLC[0] = WalletStatus5F36[0];

        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x37) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
        WalletStatus5F37[0] = apdu_out[p++];
        WPSM[0] = WalletStatus5F37[0];

        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x39) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
        WalletStatus5F39[0] = apdu_out[p++];
        WSSM[0] = WalletStatus5F39[0];

    }
    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_get_status_account(uint8_t* ALC, uint8_t* WSSM)
{
    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xCA, 0xBF, 0xD3, 0x00 };
    apdu_out_len = 0;
    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0 && apdu_out_len >= 11)//BF D3 08 5F 3A 01 [11] 5F 39 01 00 90 00
    {
        if (apdu_out[p++] != 0xBF) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0xD3) return _SDK_ERROR_CRITERION_;

        if (apdu_out[p++] != 0x08) return _SDK_ERROR_CRITERION_;

        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x3A) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
        WalletStatus5F3A[0] = apdu_out[p++];
        ALC[0] = WalletStatus5F3A[0];

        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x39) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
        WalletStatus5F39[0] = apdu_out[p++];
        WSSM[0] = WalletStatus5F39[0];

    }
    return Ret;

}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_get_accounts(uint8_t *NumberAccounts, uint8_t *AccountInfo)
{
    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xCA, 0xBF, 0xC4, 0x00 };
    uint8_t apdu_get_info[] = { 0x80, 0xCA, 0xBF, 0xD4, 0x01, 0x00 };
    apdu_out_len = 0;
    int Ret = lib_wallet_select_wallet_sc();
    if (Ret != 0) return Ret;
    Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0 )//BF C4 04 9F 30 01 00 90 00  or
    {
        int len_tag, n, acc;
        if (apdu_out[p++] != 0xBF) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0xC4) return _SDK_ERROR_CRITERION_;

        len_tag = apdu_out[p++];
        if((len_tag & 0x80)>0) len_tag = apdu_out[p++];

        if (apdu_out[p++] != 0x9F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x30) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
        n = apdu_out[p++];
        NumberAccounts[0] = (uint8_t)n;
        if (n == 0) return Ret;
        acc = 0;
        for (int i = 0; i < n; i++)
        {
            apdu_get_info[5] = (uint8_t)i;
            Ret = apdu_secure_channel(apdu_get_info, sizeof(apdu_get_info), apdu_out, &apdu_out_len);
            if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
            Ret = lib_check_sw_err(apdu_out, apdu_out_len);
            if (Ret != 0) return Ret;
            p = 0;

            if (apdu_out[p++] != 0xBF) return _SDK_ERROR_CRITERION_;
            if (apdu_out[p++] != 0xD4) return _SDK_ERROR_CRITERION_;

            len_tag = apdu_out[p++];
            if ((len_tag & 0x80) > 0) len_tag = apdu_out[p++];


            if (apdu_out[p++] != 0xBF) return _SDK_ERROR_CRITERION_;
            if (apdu_out[p++] != 0x31) return _SDK_ERROR_CRITERION_;
            len_tag = apdu_out[p++];

            if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
            if (apdu_out[p++] != 0x32) return _SDK_ERROR_CRITERION_;
            len_tag = apdu_out[p++];
            memcpy(AccountInfo + acc, apdu_out + p, len_tag);
            p += len_tag;
            acc+= len_tag;

            if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
            if (apdu_out[p++] != 0x33) return _SDK_ERROR_CRITERION_;
            len_tag = apdu_out[p++];
            memcpy(AccountInfo + acc, apdu_out + p, len_tag);
            p += len_tag;
            acc += len_tag;

            if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
            if (apdu_out[p++] != 0x38) return _SDK_ERROR_CRITERION_;
            len_tag = apdu_out[p++];
            AccountInfo[acc++] = (uint8_t)len_tag;
            memcpy(AccountInfo + acc, apdu_out + p, len_tag);
            p += len_tag;
            acc += len_tag;
        }

    }
    return Ret;
}
////----------------------------------------------------------------------------------------------------------------------
//int lib_wallet_store_pin(uint8_t* pin, int len)
//{
//    int p = 5, Ret=0;
//    uint8_t b;
//    uint8_t apdu_store_pin[] = { 0x80,0xD2,0x00,0x00,0x08,0x2F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
//    if (len < 4) return -1;
//    if (len > 8) return -1;
//    apdu_store_pin[p++] = (uint8_t)(0x20 + len);
//    for (int i = 0; i < len; i++)
//    {
//        b = pin[i];
//        if (b > 0x09) return -1;
//        if ((i & 0x01) == 0)
//        {
//            apdu_store_pin[p] &= 0x0F;
//            apdu_store_pin[p] |= (b << 4);
//        }
//        else
//        {
//            apdu_store_pin[p] &= 0xF0;
//            apdu_store_pin[p++] |= (b << 0);
//
//        }
//    }
//
//    if (SelectWallet != 1) Ret=lib_wallet_select_wallet_sc();
//    if (Ret != 0) return Ret;
//
//
//    apdu_out_len = 0;
//    Ret = apdu_secure_channel(apdu_store_pin, sizeof(apdu_store_pin), apdu_out, &apdu_out_len);
//    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
//    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
//    if (Ret != 0) return Ret;
//
//
//    return Ret;
//
//}
//----------------------------------------------------------------------------------------------------------------------
//int lib_wallet_verify_pin(uint8_t* pin, int len)
//{
//    int p = 5,Ret=0;
//    uint8_t b;
//    uint8_t apdu_verify_pin[] = { 0x80,0x20,0x00,0x80,0x08,0x2F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
//    if (len < 4) return -1;
//    if (len > 8) return -1;
//    apdu_verify_pin[p++] = (uint8_t)(0x20 + len);
//    for (int i = 0; i < len; i++)
//    {
//        b = pin[i];
//        if (b > 0x09) return -2;
//        if ((i & 0x01) == 0)
//        {
//            apdu_verify_pin[p]&=0x0F;
//            apdu_verify_pin[p] |= (b << 4);
//        }
//        else
//        {
//            apdu_verify_pin[p] &= 0xF0;
//            apdu_verify_pin[p++] |= (b << 0);
//
//        }
//    }
//
//    if (SelectWallet != 1) Ret=lib_wallet_select_wallet_sc();
//    if (Ret != 0) return Ret;
//
//
//    apdu_out_len = 0;
//    Ret = apdu_secure_channel(apdu_verify_pin, sizeof(apdu_verify_pin), apdu_out, &apdu_out_len);
//    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
//    if (apdu_out_len != 2) return _SDK_ERROR_UNKNOWN_;
//    if (apdu_out[0] == 0x90 && apdu_out[1] == 0x00) return 0;
//
//    if (apdu_out[0] != 0x69 && apdu_out[0] != 0x61) return _SDK_ERROR_STATE_;
//    if ((apdu_out[1] & 0xF0) != 0xC0) return _SDK_ERROR_STATE_;
//    return (apdu_out[1]);
//}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_create(int iteration,  int set_words, int set_lang, uint8_t* passphrase, int len_passphrase, uint8_t* mnemonics, int* len_mnemonic)
{
    uint16_t index_mnemonics[250];
    uint8_t p1_word = (uint8_t)set_words;
    uint8_t apdu_create[] = { 0x80,0xE2,p1_word,0x00,0x00};

    if (iteration !=2048 && iteration != 1000000) return -1;
    if (set_words < 12) return -1;

    apdu_out_len = 0;
    len_mnemonic[0] = 0;
    int Ret = apdu_secure_channel(apdu_create, sizeof(apdu_create), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;
    if (((int)apdu_out_len - 2) < (set_words * 2)) return  _SDK_ERROR_STATE_;
    memcpy(index_mnemonics, apdu_out, apdu_out_len - 2);
    Ret=BIP39_getMnemonicSentence(set_lang, index_mnemonics, (uint16_t)set_words, mnemonics);
    if (Ret < 0) return Ret;
    len_mnemonic[0] = Ret;
    Ret = lib_wallet_recovery(iteration, mnemonics, len_mnemonic[0], passphrase, len_passphrase);
    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_recovery(int iteration, uint8_t* mnemonics, int len_mnemonics, uint8_t* passphrase, int len_passphrase)
{
    int Ret, i;
    uint8_t amax = 232;
    int remaining_number = 7;
    uint8_t apdu_init_recovery[260] =    { 0x80,0xF2,0x00,0x00};
    uint8_t apdu_recovery[260] =        { 0x80,0xF4,0x00,0x00, 0x88};
    uint8_t ba_derivedKeyData[128];
    uint8_t len_send;
    uint8_t len_mnem = (uint8_t)len_mnemonics;
    //uint8_t len_pass = (uint8_t)len_passphrase;
    int block_240, block_241, block_pos;
    block_240 = len_mnemonics / amax;
    block_241 = len_mnemonics % amax;
    block_pos = 0;
    int p = 5;
    
    //check mnemonics
    if (len_mnemonics < 48) return -1;
    len_send = 0;
    for (i = 0; i < len_mnemonics; i++)
    {
        if (i > 0 && mnemonics[i] == 0x20 && mnemonics[i - 1] != 0x20) len_send++;
    }
    if (len_send < 11) return -1;

    for (i = 0; i < block_240; i++)
    {
        len_mnem = amax;
        p = 5;
        apdu_init_recovery[2]    =    0x00;
        apdu_init_recovery[3]    =    (uint8_t)i;
        apdu_init_recovery[p++] =    0x9F;
        apdu_init_recovery[p++] =    0xF1;
        apdu_init_recovery[p++] = len_mnem;
        memcpy(apdu_init_recovery + p, mnemonics+ block_pos, len_mnem);
        p += len_mnem;
        len_send = (uint8_t)p;
        apdu_init_recovery[4] = len_send - 5;

        apdu_out_len = 0;
        Ret = apdu_secure_channel(apdu_init_recovery, len_send, apdu_out, &apdu_out_len);
        if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
        Ret = lib_check_sw_err(apdu_out, apdu_out_len);
        if (Ret != 0) return Ret;

        block_pos += len_mnem;
    }
    
    {
        len_mnem = (uint8_t)block_241;
        p = 5;
        apdu_init_recovery[2]    = 0x01;
        apdu_init_recovery[p++] = 0x9F;
        apdu_init_recovery[p++] = 0xF1;
        apdu_init_recovery[p++] = len_mnem;
        memcpy(apdu_init_recovery + p, mnemonics + block_pos, len_mnem);
        p += len_mnem;
        len_send = (uint8_t)p;
        apdu_init_recovery[4] = len_send - 5;

        apdu_out_len = 0;
        Ret = apdu_secure_channel(apdu_init_recovery, len_send, apdu_out, &apdu_out_len);
        if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
        Ret = lib_check_sw_err(apdu_out, apdu_out_len);
        if (Ret != 0) return Ret;

        block_pos += len_mnem;
    }

    bip39_pbkdf2_preliminary(mnemonics, (uint16_t)len_mnemonics, (iteration-remaining_number), passphrase, len_passphrase,ba_derivedKeyData);

    p = 5;
    apdu_recovery[p++] = 0x9F;
    apdu_recovery[p++] = 0xF2;
    apdu_recovery[p++] = 0x80;
    memcpy(apdu_recovery + p, ba_derivedKeyData, 0x80);
    p += 0x80;
    apdu_recovery[p++] = 0x9F;
    apdu_recovery[p++] = 0xF3;
    apdu_recovery[p++] = 0x02;
    apdu_recovery[p++] = 0x00;
    apdu_recovery[p++] = (uint8_t)remaining_number;

    len_send = (uint8_t)p;
    apdu_recovery[4] = len_send - 5;

    apdu_out_len = 0;
    Ret = apdu_secure_channel(apdu_recovery, len_send, apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    return Ret;

}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_account_create(uint32_t currID, uint8_t netID, uint8_t accountID, uint8_t chain, uint8_t bip, uint8_t *nickname, int len_nick  )
{
    uint8_t apdu_account[250] = { 0x80,0xE3,0x00,0x00};
    uint8_t len_send=0;
    int Ret;
    
    int p = 5;
    apdu_account[p++] = (uint8_t)currID;
    apdu_account[p++] = (uint8_t)(currID>>8);
    apdu_account[p++] = (uint8_t)(currID>>16);
    apdu_account[p++] = (uint8_t)(currID>>24);
    apdu_account[p++] = netID;
    apdu_account[p++] = accountID;
    apdu_account[p++] = chain;
    apdu_account[p++] = bip;
    apdu_account[p++] = 0x00;//BRD
    apdu_account[p++] = 0x9F;//tag
    apdu_account[p++] = 0x01;//tag
    apdu_account[p++] = (uint8_t)len_nick;
    memcpy(apdu_account + p, nickname, len_nick);
    p += len_nick;
    len_send = (uint8_t)p;
    apdu_account[4] = len_send - 5;
    apdu_out_len = 0;
    Ret = apdu_secure_channel(apdu_account, len_send, apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_select_account(int index)
{
    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xCA, 0xBF, 0xC4, 0x00 };
    uint8_t apdu_get_info[] = { 0x80, 0xCA, 0xBF, 0xD4, 0x01, 0x00 };
    uint8_t apdu_account[] = { 0x80,0xBC,0x00,0x00,0x04,0x9F,0x30,0x01, (uint8_t)index };
    uint8_t len_send = 0;
    apdu_out_len = 0;
    int Ret = lib_wallet_select_wallet_sc();
    if (Ret != 0) return Ret;
    if (index < 0) return -1;
    Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    
    if (Ret != 0) return Ret;
    {
        int len_tag, n;
        if (apdu_out[p++] != 0xBF) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0xC4) return _SDK_ERROR_CRITERION_;

        len_tag = apdu_out[p++];
        if ((len_tag & 0x80) > 0) len_tag = apdu_out[p++];

        if (apdu_out[p++] != 0x9F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x30) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
        n = apdu_out[p++];
        if (n == 0) return _SDK_ERROR_CRITERION_;
        if (index >= n) return _SDK_ERROR_CRITERION_;

        apdu_get_info[5] = (uint8_t)index;
        Ret = apdu_secure_channel(apdu_get_info, sizeof(apdu_get_info), apdu_out, &apdu_out_len);
        if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
        Ret = lib_check_sw_err(apdu_out, apdu_out_len);
        if (Ret != 0) return Ret;
        p = 0;

        if (apdu_out[p++] != 0xBF) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0xD4) return _SDK_ERROR_CRITERION_;

        len_tag = apdu_out[p++];
        if ((len_tag & 0x80) > 0) len_tag = apdu_out[p++];

        if (apdu_out[p++] != 0xBF) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x31) return _SDK_ERROR_CRITERION_;
        len_tag = apdu_out[p++];

        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x32) return _SDK_ERROR_CRITERION_;
        len_tag = apdu_out[p++];
        //AccountInfo[acc++] = (uint8_t)len_tag;
        memset(account_info, 0, 9);
        memcpy(account_info, apdu_out + p, len_tag);
    }
    
    len_send = (uint8_t)sizeof(apdu_account);
    apdu_out_len = 0;
    Ret = apdu_secure_channel(apdu_account, len_send, apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_get_publickey_account(uint8_t* AccountPublicKey,  uint8_t* AccountChainCodeKey, uint8_t* PublicKeyParent)
{

    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xCA, 0xBF, 0xD5, 0x00 };
    apdu_out_len = 0;
    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0)//BF D5 47 5F 34 21 02 D4 16 791CC97E1E7F63011D36D2
    {
        int len_tag;
        if (apdu_out[p++] != 0xBF) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0xD5) return _SDK_ERROR_CRITERION_;
        len_tag= apdu_out[p++];
        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x34) return _SDK_ERROR_CRITERION_;
        len_tag = apdu_out[p++];
        if( len_tag!=33) return _SDK_ERROR_CRITERION_;
        memcpy(AccountPublicKey, apdu_out + p, len_tag);

        p += len_tag;
        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x35) return _SDK_ERROR_CRITERION_;
        len_tag = apdu_out[p++];
        if (len_tag != 32) return -1;
        memcpy(AccountChainCodeKey, apdu_out + p, len_tag);

        p += len_tag;
        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x36) return _SDK_ERROR_CRITERION_;
        len_tag = apdu_out[p++];
        if (len_tag != 33) return _SDK_ERROR_CRITERION_;
        memcpy(PublicKeyParent, apdu_out + p, len_tag);
    }
    return Ret;

}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_get_receive_publickey_account(uint8_t* AccountPublicKey)
{

    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xCA, 0x5F, 0xD0, 0x00 };
    apdu_out_len = 0;
    
    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0)//
    {
        int len_tag;
        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0xD0) return _SDK_ERROR_CRITERION_;
        len_tag = apdu_out[p++];
        if(len_tag!=33) return _SDK_ERROR_CRITERION_;
        memcpy(AccountPublicKey, apdu_out + p, len_tag);
    }
    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_get_address_index(uint16_t* AddressIndex)
{

    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xCA, 0x5F, 0x3B, 0x00 };
    apdu_out_len = 0;
    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0)//5F3B 02 0019
    {
        uint16_t index = 0;
        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x3B) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x02) return _SDK_ERROR_CRITERION_;
        index = (apdu_out[p++]<<8);
        index += apdu_out[p++];
        AddressIndex[0] = index;
    }
    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_get_chain_index(uint8_t* ChainIndex)
{

    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xCA, 0x5F, 0xF1, 0x00 };
    apdu_out_len = 0;
    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0)//5F3B 02 0019
    {
        uint8_t index = 0;
        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0xF1) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
        index = apdu_out[p++];
        ChainIndex[0] = index;
    }
    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_set_address_index(uint16_t AddressIndex)
{
    uint8_t apdu_get_data[] = { 0x80, 0xDA, 0x5F, 0xF0, 0x02, (uint8_t)(AddressIndex>>8), (uint8_t)AddressIndex};
    apdu_out_len = 0;
    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_set_chain_index(uint8_t ChainIndex)
{
    uint8_t apdu_get_data[] = { 0x80, 0xDA, 0x5F, 0xF1, 0x01, ChainIndex };
    apdu_out_len = 0;
    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_sign_hash( uint8_t* Hash, int len_hash, uint8_t* R, uint8_t* S, uint8_t* V)
{
    uint8_t apdu_sign_hash[250] = { 0x80,0xB4,0x01,0x01, 0x26};
    uint8_t len_send = 0;
    int p = 5;
    int Ret;
    if (len_hash != 0x20) return -1;
    apdu_sign_hash[p++] = 0xBF;
    apdu_sign_hash[p++] = 0xB4;
    apdu_sign_hash[p++] = 0x23;
    apdu_sign_hash[p++] = 0x9F;
    apdu_sign_hash[p++] = 0x41;
    apdu_sign_hash[p++] = 0x20;
    memcpy(apdu_sign_hash + p, Hash, len_hash);
    p += len_hash;
    len_send = (uint8_t)p;
    apdu_out_len = 0;
    Ret = apdu_secure_channel(apdu_sign_hash, len_send, apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0)
    {
        uint8_t len = 0, len_sig;
        p = 0;
        if (apdu_out[p++] != 0x9F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0xB4) return _SDK_ERROR_CRITERION_;
        len = apdu_out[p++];
        if (apdu_out[p++] != 0x30) return _SDK_ERROR_CRITERION_;
        len_sig = apdu_out[p++];//47 48
        if (apdu_out[p++] != 0x02) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x01) return _SDK_ERROR_CRITERION_;
        V[0] = apdu_out[p++];//1b 1c
        if (apdu_out[p++] != 0x02) return _SDK_ERROR_CRITERION_;
        len_sig = apdu_out[p++];//20 21
        if(len_sig==33) apdu_out[p++];
        memcpy(R, apdu_out + p, 32);
        p += 32;
        if (apdu_out[p++] != 0x02) return _SDK_ERROR_CRITERION_;
        len_sig = apdu_out[p++];//20 21
        if (len_sig == 33) apdu_out[p++];
        memcpy(S, apdu_out + p, 32);
    }
    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_reset(void)
{
    uint8_t apdu_reset_data[] = { 0x80, 0xB2, 0x00, 0x00, 0x00};
    
    int Ret = lib_wallet_select_wallet_sc();
    if (Ret != 0) return -1;

    apdu_out_len = 0;
    Ret = apdu_secure_channel(apdu_reset_data, sizeof(apdu_reset_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_get_cvm_status(uint8_t* CVM, uint8_t* WSSM)
{

    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xB6, 0x00, 0x00, 0x00 };
    apdu_out_len = 0;

    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0)//
    {
        int len_tag;
        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x3C) return _SDK_ERROR_CRITERION_;
        len_tag = apdu_out[p++];
        if (len_tag != 2) return -1;
        memcpy(CVM, apdu_out + p, len_tag);
        p += len_tag;

        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x39) return _SDK_ERROR_CRITERION_;
        len_tag = apdu_out[p++];
        if (len_tag != 1) return -1;
        memcpy(WSSM, apdu_out + p, len_tag);
    }
    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_get_cvm_verify(uint8_t* CVM, uint8_t* WSSM)
{

    int p = 0;
    uint8_t apdu_get_data[] = { 0x80, 0xB6, 0x01, 0x00, 0x00 };
    apdu_out_len = 0;

    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    if (Ret == 0)//
    {
        int len_tag;
        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x3C) return _SDK_ERROR_CRITERION_;
        len_tag = apdu_out[p++];
        if (len_tag != 2) return _SDK_ERROR_CRITERION_;
        memcpy(CVM, apdu_out + p, len_tag);
        p += len_tag;

        if (apdu_out[p++] != 0x5F) return _SDK_ERROR_CRITERION_;
        if (apdu_out[p++] != 0x39) return _SDK_ERROR_CRITERION_;
        len_tag = apdu_out[p++];
        if (len_tag != 1) return _SDK_ERROR_CRITERION_;
        memcpy(WSSM, apdu_out + p, len_tag);
    }
    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_cvm_disable_pin(void)
{
    uint8_t apdu_get_data[] = { 0x80, 0xBA, 0x00, 0x00, 0x00 };
    apdu_out_len = 0;
    int Ret = apdu_secure_channel(apdu_get_data, sizeof(apdu_get_data), apdu_out, &apdu_out_len);
    if (Ret != 0) return _SDK_ERROR_EXCHANGE_;
    Ret = lib_check_sw_err(apdu_out, apdu_out_len);
    if (Ret != 0) return Ret;

    return Ret;
}
//----------------------------------------------------------------------------------------------------------------------
static uint8_t tolowercase(uint8_t input)
{
    return input;
}
static uint8_t touppercase(uint8_t input)
{
    char c_input = (char)input;
    switch (c_input)
    {
    case 'a': c_input = 'A'; break;
    case 'b': c_input = 'B'; break;
    case 'c': c_input = 'C'; break;
    case 'd': c_input = 'D'; break;
    case 'e': c_input = 'E'; break;
    case 'f': c_input = 'F'; break;
    }

    return (uint8_t)c_input;
}


//----------------------------------------------------------------------------------------------------------------------
int lib_wallet_script0_to_address(int pur, uint8_t *script, int len, uint8_t* Address, uint32_t* AddressLen)
{
    if (pur == 0) return lib_script0_to_address(script, len, Address, AddressLen);
    if (pur == 1) return lib_script0_to_address_test(script, len, Address, AddressLen);
    return -1;
}


//----------------------------------------------------------------------------------------------------------------------


int lib_wallet_get_address(uint8_t* Address, uint32_t* AddressLen)
{
    int ret;
    uint8_t rp_key[33];
    uint8_t  SHA160[20];
    uint8_t script[33+10];
    ret = lib_wallet_get_receive_publickey_account(rp_key);
    if (ret != 0) return ret;
    lib_sha160(rp_key, 33, SHA160);

    if (account_info[7] == 84)
    {
        script[0] = 0x00;
        script[1] = 0x14;
        memcpy(script + 2, SHA160, 20);
        if (account_info[0] == 0) return lib_script0_to_address     (script, 0x16, Address, AddressLen);
        if (account_info[0] == 1) return lib_script0_to_address_test(script, 0x16, Address, AddressLen);

        return -1;
    }
    if (account_info[7] == 44)
    {
        uint8_t decomp[64];
        uint8_t keccak[32];
        uint8_t str[128];
        if (account_info[0] == 60)
        {
            ret = lib_public_decompress(rp_key, decomp);
            if (ret != 0) return ret;
            lib_sha3_256(decomp, 64, keccak);
            memcpy(SHA160, keccak + 12, 20);

            int p = 0;
            str[p++] = '0';
            str[p++] = 'x';
            for (int i = 0; i < 20; i++)
            {
                sprintf((char*)(str + p), "%02x", SHA160[i]); p += 2;
            }

            lib_sha3_256(str+2, 40, keccak);

            for (int i = 0; i < 40; i++) {
                // We should hex-encode the hash and then look character by character.  Instead
                // we'll extract 4 bits as the upper or lower nibble and compare to 8.  This is the
                // same extracting that hexEncode performs, ultimately.
                int value = 0x0f & (keccak[i / 2] >> ((0 == i % 2) ? 4 : 0));
                str[i+2] = (value < 8
                    ? tolowercase(str[i+2])
                    : touppercase(str[i+2]));
            }

            memcpy(Address, str, p);
            AddressLen[0] = p;
            return 0;
        }
        else
        if (account_info[0] == 0 )
        {
            uint8_t format = 44;
            lib_sha160(rp_key, 33, SHA160);
            return lib_script_legacy_to_address(SHA160, 33, Address, AddressLen, format, 0 );
        }
        else
        if (account_info[0] == 1)
        {
            uint8_t format = 44;
            lib_sha160(rp_key, 33, SHA160);
            return lib_script_legacy_to_address(SHA160, 33, Address, AddressLen, format, 1);
        }

        
        return -1;
    }
    if (account_info[7] == 49)
    {
        if (account_info[0] == 0)
        {
            uint8_t format = 49;
            lib_sha160(rp_key, 33, SHA160);
            return lib_script_legacy_to_address(SHA160, 33, Address, AddressLen, format, 0);
        }
        else
        if (account_info[0] == 1)
        {
            uint8_t format = 49;
            lib_sha160(rp_key, 33, SHA160);
            return lib_script_legacy_to_address(SHA160, 33, Address, AddressLen, format, 1);
        }
    }
        
    return - 1;
    
}
//----------------------------------------------------------------------------------------------------------------------
