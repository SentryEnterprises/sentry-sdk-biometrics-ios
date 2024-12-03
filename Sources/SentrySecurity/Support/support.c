
#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "secure.h"
#include "lib_wallet.h"
#include "BRBech32.h"
#include "BRBase58.h"

//-----------------------------------------------------------------------------------------------------------
static int findhexsym(char hsym1, char hsym2)
{
    char* hexc = { "0123456789ABCDEF" };
    char* hexl = { "0123456789abcdef" };
    uint8_t ll=255, hh=255;
    for (int i = 0; i < 16; i++)
    {
        if (hexc[i] == hsym1) hh = (uint8_t)i;
        if (hexl[i] == hsym1) hh = (uint8_t)i;
        if (hexc[i] == hsym2) ll = (uint8_t)i;
        if (hexl[i] == hsym2) ll = (uint8_t)i;
    }
    if (hh == 255) return -1;
    if (ll == 255) return -2;

    return (int)((hh<<4)|ll);
}

//-----------------------------------------------------------------------------------------------------------
static int toneedlowercase(char symb, int is_lower)
{
    char* hexc = { "0123456789ABCDEF" };
    char* hexl = { "0123456789abcdef" };

    int ll = 255;
    for (int i = 0; i < 16; i++)
    {
        if (is_lower == 0)
        {
            if (symb == hexc[i])  ll = 0;
        }
        else
        {
            if (symb == hexl[i])  ll = 0;
        }

    }
    return ll;
}
//-----------------------------------------------------------------------------------------------------------
//-----------------------------------------------------------------------------------------------------------
int EthDecode(uint8_t* Address, int Len, uint8_t* Script, uint32_t* ScriptLen)
{
    uint8_t        code[20];
    uint8_t        keccak[32];
    uint8_t        str[64];
    int err = 0;
    int p = 0;
    if (Len < (2 + 40)) return 0;
    for (int i = 2; i < 42; i += 2)
    {
        char hsym1 = (char)Address[i];
        char hsym2 = (char)Address[i+1];
        int hex=findhexsym(hsym1, hsym2);
        if (hex < 0) return 0;
        code[p++] = (uint8_t)hex;
    }

    
    p = 0;
    str[p++] = '0';
    str[p++] = 'x';
    for (int i = 0; i < 20; i++)
    {
        sprintf((char*)(str + p), "%02x", code[i]); p += 2;
    }
    lib_sha3_256(str + 2, 40, keccak);

    for (int i = 0; i < 40; i++) {
        // We should hex-encode the hash and then look character by character.  Instead
        // we'll extract 4 bits as the upper or lower nibble and compare to 8.  This is the
        // same extracting that hexEncode performs, ultimately.
        int value = 0x0f & (keccak[i / 2] >> ((0 == i % 2) ? 4 : 0));
        err += (value < 8
            ? toneedlowercase(Address[i + 2], 1)
            : toneedlowercase(Address[i + 2], 0));
    }

    if (err == 0)
    {
        memcpy(Script, code, 20);
        ScriptLen[0] = 20;
        return 20;
    }
    return 0;
}

//-----------------------------------------------------------------------------------------------------------
int lib_address_to_script(uint8_t* Address, int Len, uint8_t* Script, uint32_t* ScriptLen)
{
    char prefixETH[3] = "0x";
    char prefix1[0x84] = BITCOIN_BECH32_PREFIX;
    char prefix2[0x84] = BITCOIN_BECH32_PREFIX_TEST;
    
    
    ScriptLen[0] = 0;
    if (Len == 0) return -1;
    
    if (memcmp(Address, prefixETH, 2) == 0)
    {
        ScriptLen[0] = EthDecode(Address, Len, Script, ScriptLen);
    }
    else
    if (memcmp(Address, prefix1, 2) == 0)
    {
        ScriptLen[0] = Bech32Decode(prefix1, Script, Address);
    }
    else
    if (memcmp(Address, prefix2, 2) == 0)
    {
        ScriptLen[0] = Bech32Decode(prefix2, Script, Address);
    }
    else
    {
        uint8_t scr[32];
        uint8_t sha256d[32];
        int len;
        int p = 0;

        len = Base58Decode(scr, 32, (const char*)Address);
        lib_sha2_256D(scr, 21, sha256d);
        if (memcmp(sha256d, scr + 1 + 20, 4) != 0)
        {
            return -2;
        }
        if (scr[0] == 0x00 || scr[0] == 0x6f)
        {
            //bip44
            Script[p++] = 0x76;
            Script[p++] = 0xa9;
            Script[p++] = 0x14;
            memcpy(Script + p, scr + 1, 20); p += 20;
            Script[p++] = 0x88;
            Script[p++] = 0xac;
            ScriptLen[0] = p;

        }
        else
        if (scr[0] == 0x05 || scr[0] == 0xC4)
        {
            //bip49
            Script[p++] = 0xa9;
            Script[p++] = 0x14;
            memcpy(Script + p, scr + 1, 20); p += 20;
            Script[p++] = 0x87;
            ScriptLen[0] = p;
        }




        if(ScriptLen[0]==0)    return -1;
    }
    return 0;
}
//-----------------------------------------------------------------------------------------------------------
int lib_script0_to_address_test(uint8_t *script, int len, uint8_t *address, uint32_t* addresslen)
{
    int size;
    char prefix2[0x84] = BITCOIN_BECH32_PREFIX_TEST;
    if (len == 0) return -1;
    size = Bech32Encode(address, prefix2, script);
    if (size == 0) return -1;
    addresslen[0] = size-1;
    return 0;
}
//-----------------------------------------------------------------------------------------------------------
int lib_script0_to_address(uint8_t* script, int len, uint8_t* address, uint32_t* addresslen)
{
    int size;
    if (len == 0) return -1;
    char prefix2[0x84] = BITCOIN_BECH32_PREFIX;
    size = Bech32Encode(address, prefix2, script);
    if (size == 0) return -1;
    addresslen[0] = size-1;
    return 0;
}
//-----------------------------------------------------------------------------------------------------------
int lib_script_legacy_to_address(uint8_t* script, int len, uint8_t* address, uint32_t* addresslen, uint8_t format, uint8_t pur)
{
    
    uint8_t data[32];
    uint8_t sha256d[32];
    int size;
    if (len == 0) return -1;
    if (format == 44)
    {
        data[0] = pur == 0 ? 0 : 0x6f;
    }
    else
        if (format == 44)
        {
            data[0] = pur == 0 ? 5 : 0xc4;
        }
        else return -2;

    memcpy(data + 1, script, 20);
    lib_sha2_256D(data, 21, sha256d);
    memcpy(data + 1+20, sha256d, 4);
    size = Base58Encode((char *)address, 40, data, 25);
    if (size == 0) return -1;
    addresslen[0] = size - 1;
    return 0;
}
//-----------------------------------------------------------------------------------------------------------

#define _MAX_COUNT_ 128

typedef struct
{
    uint8_t PrevOuts[36 * _MAX_COUNT_];
    int        pPrevOuts;
    uint8_t PrevOutsSha256d[32];

    uint8_t Sequence[4 * _MAX_COUNT_];
    int        pSequence;
    uint8_t SequenceSha256d[32];

    uint8_t Output[24 * _MAX_COUNT_];
    int        pOutput;
    uint8_t OutputSha256d[32];

    uint8_t Tmp[32 * _MAX_COUNT_];
    uint8_t TmpSha256d[32 * _MAX_COUNT_];

} sHashBIP143;

static sHashBIP143 HashBIP143;
static uint8_t TrHash[32];

//-----------------------------------------------------------------------------------------------------------
static void lib_reverse_bytes(uint8_t *inb, int len, uint8_t *outb)
{
    uint8_t tmp[128];
    for (int i = 0; i < len; i++)
    {
        tmp[len - 1 - i] = inb[i];
    }
    memcpy(outb, tmp, len);
}
//-----------------------------------------------------------------------------------------------------------
static void lib_bip143_hash(uint8_t* Inputs, int InputCount, uint8_t* Outputs, int OutputCount, uint32_t LockTime, uint8_t* Trx)
{
    uint8_t s_nLockTime[4] = { (uint8_t)LockTime,(uint8_t)(LockTime >> 8),(uint8_t)(LockTime >> 16),(uint8_t)(LockTime >> 24) };

    HashBIP143.pPrevOuts = 0;
    HashBIP143.pSequence = 0;
    HashBIP143.pOutput = 0;
    memset(HashBIP143.PrevOuts, 0, sizeof(HashBIP143.pPrevOuts));
    memset(HashBIP143.Sequence, 0, sizeof(HashBIP143.Sequence));
    memset(HashBIP143.Output, 0, sizeof(HashBIP143.Output));

    int p = 1;
    int pTrx = 0;
    uint8_t len;
    Trx[pTrx++] = 0x02;
    Trx[pTrx++] = 0x00;
    Trx[pTrx++] = 0x00;
    Trx[pTrx++] = 0x00;
    Trx[pTrx++] = Inputs[0];

    for (int i = 0; i < InputCount; i++)
    {
        
        memcpy(Trx + pTrx, Inputs + p, (32 + 4));
        lib_reverse_bytes(Trx + pTrx, 32, Trx + pTrx);
        p += (32 + 4);         pTrx += (32 + 4);
        len = Inputs[p++]; p += len;  //+ input script ->
        Trx[pTrx++] = 0;
        memcpy(Trx + pTrx, Inputs + p, 4); p += 4; pTrx += 4;
        p += 8;//+ Amount ->
    }

    Trx[pTrx++] = Outputs[0];
    p = 1;
    for (int i = 0; i < OutputCount; i++)
    {
        memcpy(Trx + pTrx, Outputs + p, 8); p += 8; pTrx += 8;
        len = Outputs[p];
        len++;
        memcpy(Trx + pTrx, Outputs + p, len); p += len; pTrx += len;
    }
    //s_nLockTime
    memcpy(Trx + pTrx, s_nLockTime, 4);  pTrx += 4;
    lib_sha2_256D(Trx, pTrx, TrHash);
    lib_reverse_bytes(TrHash, 32, TrHash);


    HashBIP143.pPrevOuts = 0;
    HashBIP143.pSequence = 0;
    HashBIP143.pOutput = 0;
    memset(HashBIP143.PrevOuts, 0, sizeof(HashBIP143.pPrevOuts));
    memset(HashBIP143.Sequence, 0, sizeof(HashBIP143.Sequence));
    memset(HashBIP143.Output, 0, sizeof(HashBIP143.Output));

    p = 1;
    for (int i = 0; i < InputCount; i++)
    {
        //s_PrevOuts = s_PrevOuts + Inputs_List.InputPreviousOutputHash[i] + Inputs_List.InputPreviousOutputIndex[i];
        memcpy(HashBIP143.PrevOuts + HashBIP143.pPrevOuts, Inputs + p, (32 + 4));
        lib_reverse_bytes(HashBIP143.PrevOuts + HashBIP143.pPrevOuts, 32, HashBIP143.PrevOuts + HashBIP143.pPrevOuts);
        p += (32 + 4);         HashBIP143.pPrevOuts += (32 + 4);
        
        len = Inputs[p++]; p += len;
        //s_Sequence = s_Sequence + Inputs_List.InputSequence[i];
        memcpy(HashBIP143.Sequence + HashBIP143.pSequence, Inputs + p, 4); p += 4; HashBIP143.pSequence += 4;
        p += 8;
    }

    p = 1;
    for (int i = 0; i < OutputCount; i++)
    {
        //UInt64 btc = UInt64.Parse(Outputs_List.OutputValue[i]);
        //s_output = s_output + Int64ToStr(btc) + "160014" + Outputs_List.OutputPublicKeyScript[i];
        memcpy(HashBIP143.Output + HashBIP143.pOutput, Outputs + p, 8); p += 8; HashBIP143.pOutput += 8;
        len = Outputs[p];
        len++;
        memcpy(HashBIP143.Output + HashBIP143.pOutput, Outputs + p, len); p += len; HashBIP143.pOutput += len;
    }



    lib_sha2_256D(HashBIP143.PrevOuts, HashBIP143.pPrevOuts, HashBIP143.PrevOutsSha256d);
    lib_sha2_256D(HashBIP143.Sequence, HashBIP143.pSequence, HashBIP143.SequenceSha256d);
    lib_sha2_256D(HashBIP143.Output, HashBIP143.pOutput, HashBIP143.OutputSha256d);

    p = 1;
    for (int i = 0; i < InputCount; i++)
    {
        uint8_t s_outpoint[32 + 4];
        uint8_t s_scriptCode[26];
        uint8_t s_amount[8];
        uint8_t s_nSequence[4];
        uint8_t s_nVersion[4] = { 0x02, 0x00,0x00,0x00 };
        uint8_t s_nHashType[4] = { 0x01, 0x00,0x00,0x00 };

        memcpy(s_outpoint, Inputs + p, (32 + 4));
        lib_reverse_bytes(s_outpoint, 32, s_outpoint);
        p += (32 + 4);
        s_scriptCode[0] = 0x19;
        s_scriptCode[1] = 0x76;
        s_scriptCode[2] = 0xa9;
        s_scriptCode[3] = 0x14;
        memcpy(s_scriptCode + 4, Inputs + p + 3, 0x14);
        s_scriptCode[24] = 0x88;
        s_scriptCode[25] = 0xac;

        len = Inputs[p++]; p += len;
        memcpy(s_nSequence, Inputs + p, 4);  p += 4;
        memcpy(s_amount, Inputs + p, 8);  p += 8;

        int t = 0;
        memcpy(HashBIP143.Tmp + t, s_nVersion, 4); t += 4;
        memcpy(HashBIP143.Tmp + t, HashBIP143.PrevOutsSha256d, 32); t += 32;
        memcpy(HashBIP143.Tmp + t, HashBIP143.SequenceSha256d, 32); t += 32;
        memcpy(HashBIP143.Tmp + t, s_outpoint, 36); t += 36;
        memcpy(HashBIP143.Tmp + t, s_scriptCode, 26); t += 26;
        memcpy(HashBIP143.Tmp + t, s_amount, 8); t += 8;
        memcpy(HashBIP143.Tmp + t, s_nSequence, 4); t += 4;
        memcpy(HashBIP143.Tmp + t, HashBIP143.OutputSha256d, 32); t += 32;
        memcpy(HashBIP143.Tmp + t, s_nLockTime, 4); t += 4;
        memcpy(HashBIP143.Tmp + t, s_nHashType, 4); t += 4;
        lib_sha2_256D(HashBIP143.Tmp, t, HashBIP143.TmpSha256d + (i * 32));
    }



}
//-----------------------------------------------------------------------------------------------------------
static void lib_bip143_multisign_hash(uint8_t* Inputs, int InputCount, uint8_t* Outputs, int OutputCount, uint32_t LockTime, uint8_t* Trx)
{
    int ScriptLen = 0;
    uint8_t s_nLockTime[4] = { (uint8_t)LockTime,(uint8_t)(LockTime >> 8),(uint8_t)(LockTime >> 16),(uint8_t)(LockTime >> 24) };

    HashBIP143.pPrevOuts = 0;
    HashBIP143.pSequence = 0;
    HashBIP143.pOutput = 0;
    memset(HashBIP143.PrevOuts, 0, sizeof(HashBIP143.pPrevOuts));
    memset(HashBIP143.Sequence, 0, sizeof(HashBIP143.Sequence));
    memset(HashBIP143.Output, 0, sizeof(HashBIP143.Output));

    int p = 1;
    int pTrx = 0;
    uint8_t len;
    Trx[pTrx++] = 0x02;
    Trx[pTrx++] = 0x00;
    Trx[pTrx++] = 0x00;
    Trx[pTrx++] = 0x00;
    Trx[pTrx++] = Inputs[0];

    for (int i = 0; i < InputCount; i++)
    {

        memcpy(Trx + pTrx, Inputs + p, (32 + 4));
        lib_reverse_bytes(Trx + pTrx, 32, Trx + pTrx);
        p += (32 + 4);         pTrx += (32 + 4);
        len = Inputs[p++]; p += len;  //+ input script ->
        Trx[pTrx++] = 0;
        memcpy(Trx + pTrx, Inputs + p, 4); p += 4; pTrx += 4;
        p += 8;//+ Amount ->
    }

    Trx[pTrx++] = Outputs[0];
    p = 1;
    for (int i = 0; i < OutputCount; i++)
    {
        memcpy(Trx + pTrx, Outputs + p, 8); p += 8; pTrx += 8;
        len = Outputs[p];
        len++;
        memcpy(Trx + pTrx, Outputs + p, len); p += len; pTrx += len;
    }
    //s_nLockTime
    memcpy(Trx + pTrx, s_nLockTime, 4);  pTrx += 4;
    lib_sha2_256D(Trx, pTrx, TrHash);
    lib_reverse_bytes(TrHash, 32, TrHash);


    HashBIP143.pPrevOuts = 0;
    HashBIP143.pSequence = 0;
    HashBIP143.pOutput = 0;
    memset(HashBIP143.PrevOuts, 0, sizeof(HashBIP143.pPrevOuts));
    memset(HashBIP143.Sequence, 0, sizeof(HashBIP143.Sequence));
    memset(HashBIP143.Output, 0, sizeof(HashBIP143.Output));

    p = 1;
    for (int i = 0; i < InputCount; i++)
    {
        //s_PrevOuts = s_PrevOuts + Inputs_List.InputPreviousOutputHash[i] + Inputs_List.InputPreviousOutputIndex[i];
        memcpy(HashBIP143.PrevOuts + HashBIP143.pPrevOuts, Inputs + p, (32 + 4));
        lib_reverse_bytes(HashBIP143.PrevOuts + HashBIP143.pPrevOuts, 32, HashBIP143.PrevOuts + HashBIP143.pPrevOuts);
        p += (32 + 4);         HashBIP143.pPrevOuts += (32 + 4);

        len = Inputs[p++]; p += len;
        //s_Sequence = s_Sequence + Inputs_List.InputSequence[i];
        memcpy(HashBIP143.Sequence + HashBIP143.pSequence, Inputs + p, 4); p += 4; HashBIP143.pSequence += 4;
        p += 8;
    }

    p = 1;
    for (int i = 0; i < OutputCount; i++)
    {
        //UInt64 btc = UInt64.Parse(Outputs_List.OutputValue[i]);
        //s_output = s_output + Int64ToStr(btc) + "160014" + Outputs_List.OutputPublicKeyScript[i];
        memcpy(HashBIP143.Output + HashBIP143.pOutput, Outputs + p, 8); p += 8; HashBIP143.pOutput += 8;
        len = Outputs[p];
        len++;
        memcpy(HashBIP143.Output + HashBIP143.pOutput, Outputs + p, len); p += len; HashBIP143.pOutput += len;
    }



    lib_sha2_256D(HashBIP143.PrevOuts, HashBIP143.pPrevOuts, HashBIP143.PrevOutsSha256d);
    lib_sha2_256D(HashBIP143.Sequence, HashBIP143.pSequence, HashBIP143.SequenceSha256d);
    lib_sha2_256D(HashBIP143.Output, HashBIP143.pOutput, HashBIP143.OutputSha256d);

    p = 1;
    for (int i = 0; i < InputCount; i++)
    {
        uint8_t s_outpoint[32 + 4];
        uint8_t s_scriptCode[260];
        uint8_t s_amount[8];
        uint8_t s_nSequence[4];
        uint8_t s_nVersion[4] = { 0x02, 0x00,0x00,0x00 };
        uint8_t s_nHashType[4] = { 0x01, 0x00,0x00,0x00 };

        memcpy(s_outpoint, Inputs + p, (32 + 4));
        lib_reverse_bytes(s_outpoint, 32, s_outpoint);
        p += (32 + 4);
        
        /*
        s_scriptCode[0] = 0x19;
        s_scriptCode[1] = 0x76;
        s_scriptCode[2] = 0xa9;
        s_scriptCode[3] = 0x14;
        memcpy(s_scriptCode + 4, Inputs + p + 3, 0x14);
        s_scriptCode[24] = 0x88;
        s_scriptCode[25] = 0xac;
        */

        len = Inputs[p];
        len++;
        memcpy(s_scriptCode + 0, Inputs + p, len); ScriptLen = len;
        p += len;
        memcpy(s_nSequence, Inputs + p, 4);  p += 4;
        memcpy(s_amount, Inputs + p, 8);  p += 8;

        int t = 0;
        memcpy(HashBIP143.Tmp + t, s_nVersion, 4); t += 4;
        memcpy(HashBIP143.Tmp + t, HashBIP143.PrevOutsSha256d, 32); t += 32;
        memcpy(HashBIP143.Tmp + t, HashBIP143.SequenceSha256d, 32); t += 32;
        memcpy(HashBIP143.Tmp + t, s_outpoint, 36); t += 36;
        memcpy(HashBIP143.Tmp + t, s_scriptCode, ScriptLen); t += ScriptLen;
        memcpy(HashBIP143.Tmp + t, s_amount, 8); t += 8;
        memcpy(HashBIP143.Tmp + t, s_nSequence, 4); t += 4;
        memcpy(HashBIP143.Tmp + t, HashBIP143.OutputSha256d, 32); t += 32;
        memcpy(HashBIP143.Tmp + t, s_nLockTime, 4); t += 4;
        memcpy(HashBIP143.Tmp + t, s_nHashType, 4); t += 4;
        lib_sha2_256D(HashBIP143.Tmp, t, HashBIP143.TmpSha256d + (i * 32));
    }



}
//-----------------------------------------------------------------------------------------------------------
static int  lib_sign_rs_to_der(uint8_t *bR, uint8_t *bS, uint8_t *der)
{
    uint8_t pR1[6] = { 0x48,0x30,0x45,0x02,0x21,0x00 };
    uint8_t pR2[5] = { 0x47,0x30,0x44,0x02,0x20 };
    int pder = 0;

    if (bR[0] > 0x7F)
    {
        //pR = "483045022100";
        memcpy(der + pder, pR1, 6); pder += 6;
    }
    else
    {
        //pR = "4730440220";
        memcpy(der + pder, pR2, 5); pder += 5;
    }

    //Sign = pR + R + "0220" + S;
    memcpy(der + pder, bR, 32); pder += 32;
    der[pder++] = 0x02;
    der[pder++] = 0x20;
    memcpy(der + pder, bS, 32); pder += 32;
    return pder;
}
//-----------------------------------------------------------------------------------------------------------

int lib_bip143(uint8_t* Inputs, int InputCount, uint8_t* Outputs, int OutputCount, uint32_t LockTime, uint8_t* Trx, uint32_t* TrxLen, uint8_t* TrxHash)
{
    int pTrx = 0;
    int p = 0;
    int ret;
    uint8_t len;
    uint8_t  RPublicKey[33];
    uint8_t  SHA160[20];
    uint8_t  Script[32];
    uint8_t  s_transaction[6] = { 0x02,0x00,0x00,0x00,0x00,0x01};
    uint8_t  s_nLockTime[4] = { (uint8_t)LockTime,(uint8_t)(LockTime >> 8),(uint8_t)(LockTime >> 16),(uint8_t)(LockTime >> 24) };
    TrxLen[0] = 0;
    if (InputCount > _MAX_COUNT_) return -1;
    if (OutputCount > _MAX_COUNT_) return -1;

    if (InputCount <= 0) return -1;
    if (OutputCount <= 0) return -1;
    if (Inputs[p]!= InputCount) return -1;
    if (Outputs[p] != OutputCount) return -1;

    ret = lib_wallet_get_receive_publickey_account(RPublicKey);
    if (ret != 0) return ret;
    lib_sha160(RPublicKey, 33, SHA160);

    lib_bip143_hash(Inputs, InputCount, Outputs, OutputCount, LockTime, Trx);

    p++;
    memcpy(Trx + pTrx, s_transaction, 6);
    pTrx += 6;

    Trx[pTrx++] = (uint8_t)InputCount;
    for (int i = 0; i < InputCount; i++)
    {
        //Transaction = Transaction + Inputs_List.InputPreviousOutputHash[i] + Inputs_List.InputPreviousOutputIndex[i];
        memcpy(Trx + pTrx, Inputs + p, 32+4);
        lib_reverse_bytes(Trx + pTrx, 32, Trx + pTrx);
        pTrx += 36; p += 36;
        len = Inputs[p]; len++;
        memcpy(Script, Inputs + p, len);
        {
            if (Script[2] == 0x14)
            {
                if (memcmp(SHA160, Script + 3, 20) != 0)
                {
                    return -1;
                }
            }
            else
                if (Script[3] == 0x14)
                {
                    if (memcmp(SHA160, Script + 4, 20) != 0)
                    {
                        return -1;
                    }
                }
            else
            {
                return -1;
            }

        }
        
        p += len;
        
        //Transaction = Transaction + "00";
        Trx[pTrx++] = 0;
        //Transaction = Transaction + Inputs_List.InputSequence[i];
        memcpy(Trx + pTrx, Inputs + p, 4);
        p += 4; pTrx += 4;
        p += 8;//amount
    }

    Trx[pTrx++] = (uint8_t)OutputCount;
    p = 1;
    for (int i = 0; i < OutputCount; i++)
    {

        memcpy(Trx + pTrx, Outputs + p, 8);  p += 8; pTrx += 8;
        len = Outputs[p]; len++;
        memcpy(Trx + pTrx, Outputs + p, len);  p += len; pTrx += len;
    }

    for (int i = 0; i < InputCount; i++)
    {
        uint8_t R[32];
        uint8_t S[32];
        uint8_t V[32];
        uint8_t Der[128];
        int pDer = 0;
        //int lib_wallet_sign_hash( uint8_t* Hash, int len_hash, uint8_t* R, uint8_t* S, uint8_t* V)
        ret = lib_wallet_sign_hash(HashBIP143.TmpSha256d + (i * 32), 32, R, S, V);
        if (ret != 0) return ret;

        Trx[pTrx++] = 2; //2 struct
        pDer = lib_sign_rs_to_der(R, S, Der);
        memcpy(Trx + pTrx, Der, pDer); pTrx += pDer;
        Trx[pTrx++] = 0x01;
        Trx[pTrx++] = 0x21;
        memcpy(Trx + pTrx, RPublicKey, 33); pTrx += 33;
    }

    memcpy(Trx + pTrx, s_nLockTime, 4); pTrx += 4;


    TrxLen[0] = pTrx;
    memcpy(TrxHash, TrHash, 32);
    return 0;


}
//-----------------------------------------------------------------------------------------------------------
int lib_bip143Sign(uint8_t* Inputs, int InputCount, uint8_t* Outputs, int OutputCount, uint32_t LockTime, uint8_t* Sign, uint32_t* SignLen)
{
    int pTrx = 0;
    int p = 0;
    int ret;
    SignLen[0] = 0;
    if (InputCount > _MAX_COUNT_) return -1;
    if (OutputCount > _MAX_COUNT_) return -1;

    if (InputCount <= 0) return -1;
    if (OutputCount <= 0) return -1;
    if (Inputs[p] != InputCount) return -1;
    if (Outputs[p] != OutputCount) return -1;


    lib_bip143_multisign_hash(Inputs, InputCount, Outputs, OutputCount, LockTime, Sign);

    for (int i = 0; i < InputCount; i++)
    {
        uint8_t R[32];
        uint8_t S[32];
        uint8_t V[32];
        uint8_t Der[128];
        int pDer = 0;
        //int lib_wallet_sign_hash( uint8_t* Hash, int len_hash, uint8_t* R, uint8_t* S, uint8_t* V)
        ret = lib_wallet_sign_hash(HashBIP143.TmpSha256d + (i * 32), 32, R, S, V);
        if (ret != 0) return ret;

        //Trx[pTrx++] = 2; //2 struct
        pDer = lib_sign_rs_to_der(R, S, Der);
        memcpy(Sign + pTrx, Der, pDer); pTrx += pDer;
        Sign[pTrx++] = 0x01;
    }

    SignLen[0] = pTrx;
    return 0;
}
//-----------------------------------------------------------------------------------------------------------

int lib_bip143MultiSign(uint8_t* Inputs, int InputCount, uint8_t* Outputs, int OutputCount, uint32_t LockTime, uint8_t* Sign, uint8_t* SignLen, uint8_t* Script, int ScriptLen, uint8_t* Trx, uint32_t* TrxLen, uint8_t* TrxHash)
{
    int pTrx = 0;
    int p = 0;
    uint8_t len;
    uint8_t  s_transaction[6] = { 0x02,0x00,0x00,0x00,0x00,0x01 };
    uint8_t  s_nLockTime[4] = { (uint8_t)LockTime,(uint8_t)(LockTime >> 8),(uint8_t)(LockTime >> 16),(uint8_t)(LockTime >> 24) };
    TrxLen[0] = 0;
    if (InputCount > _MAX_COUNT_) return -1;
    if (OutputCount > _MAX_COUNT_) return -1;

    if (InputCount <= 0) return -1;
    if (OutputCount <= 0) return -1;
    if (Inputs[p] != InputCount) return -1;
    if (Outputs[p] != OutputCount) return -1;

    lib_bip143_hash(Inputs, InputCount, Outputs, OutputCount, LockTime, Trx);

    p++;
    memcpy(Trx + pTrx, s_transaction, 6);
    pTrx += 6;

    Trx[pTrx++] = (uint8_t)InputCount;
    for (int i = 0; i < InputCount; i++)
    {
        //Transaction = Transaction + Inputs_List.InputPreviousOutputHash[i] + Inputs_List.InputPreviousOutputIndex[i];
        memcpy(Trx + pTrx, Inputs + p, 32 + 4);
        lib_reverse_bytes(Trx + pTrx, 32, Trx + pTrx);
        pTrx += 36; p += 36;
        len = Inputs[p]; len++;
        p += len;

        //Transaction = Transaction + "00";
        Trx[pTrx++] = 0;
        //Transaction = Transaction + Inputs_List.InputSequence[i];
        memcpy(Trx + pTrx, Inputs + p, 4);
        p += 4; pTrx += 4;
        p += 8;//amount
    }

    Trx[pTrx++] = (uint8_t)OutputCount;
    p = 1;
    for (int i = 0; i < OutputCount; i++)
    {

        memcpy(Trx + pTrx, Outputs + p, 8);  p += 8; pTrx += 8;
        len = Outputs[p]; len++;
        memcpy(Trx + pTrx, Outputs + p, len);  p += len; pTrx += len;
    }

    
    int pDer = 0;

    for (int i = 0; i < InputCount; i++)
    {

        Trx[pTrx++] = 4; //4 struct
        Trx[pTrx++] = 0;
        
        
        memcpy(Trx + pTrx, Sign+ pDer, SignLen[i]); pTrx += SignLen[i]; pDer+= SignLen[i];
        Trx[pTrx++] = (uint8_t)ScriptLen;
        
        memcpy(Trx + pTrx, Script, ScriptLen); pTrx += ScriptLen;
    }

    memcpy(Trx + pTrx, s_nLockTime, 4); pTrx += 4;


    TrxLen[0] = pTrx;
    memcpy(TrxHash, TrHash, 32);
    return 0;


}
//-----------------------------------------------------------------------------------------------------------

typedef struct
{
    int size;
    uint8_t buf[64];
}t_RLP;

typedef struct
{
    int size;
    uint8_t buf[1024 * 4];
}t_Data_RLP;

typedef struct
{
    int size;
    uint8_t buf[1024 * 4];
}t_List_RLP;

typedef struct
{
    int size;
    int pos;
    uint8_t buf[1024 * 8];
}t_Buffer;


static t_List_RLP    payload_rlp;
static t_RLP        chain_id_rlp;
static t_RLP        nonce_rlp;
static t_RLP        max_priority_fee_per_gas_rlp;
static t_RLP        max_fee_per_gas_rlp;
static t_RLP        gas_limit_rlp;
static t_RLP        destination_rlp;
static t_RLP        amount_rlp;
static t_Data_RLP    data_rlp;
static t_List_RLP    access_list_rlp;

static t_Buffer eip;

static t_RLP        V_rlp;
static t_RLP        R_rlp;
static t_RLP        S_rlp;

//-----------------------------------------------------------------------------------------------------------
static int load_int_rlp(t_RLP* rlp, uint8_t* data)
{
    int p = 0;
    if (data[p] >  0xb7) return -1;

    if (data[p] < 0x81)
    {
        rlp->size = 1;
        rlp->buf[0] = data[p];
        return 0;
    }
    rlp->size = (data[p] - 0x80)+1;
    memcpy(rlp->buf, data, rlp->size);
    return 0;
}

//-----------------------------------------------------------------------------------------------------------
static int load_data_rlp(t_Data_RLP* rlp, uint8_t* data)
{
    int p = 0;
    if (data[p] < 0x80) return -1;

    if (data[p] < 0xb8)
    {
        rlp->size = (data[p] - 0x80) + 1;
        memcpy(rlp->buf, data, rlp->size);
        return 0;
    }

    if (data[p] > 0xb7)
    {
        int len_bytes = (data[p++] - 0xb7);
        if (len_bytes > 2) return -1;
        uint32_t len = 0;
        if (len_bytes == 1)
        {
            len = data[p++];
        }
        else
        {
            len = (data[p++]<<8);
            len+= (data[p++]);
        }
        
        rlp->size = len + len_bytes + 1;
        
        memcpy(rlp->buf, data, rlp->size);
        return 0;
    }

    return -1;
}

//-----------------------------------------------------------------------------------------------------------
static int load_list_rlp(t_List_RLP* rlp, uint8_t* data)
{
    int p = 0;
    if (data[p] == 0xC0)
    {
        rlp->size = 1;
        rlp->buf[0] = data[p];
        return 0;
    }

    if (data[p] > 0xf7)
    {

        int len_bytes = (data[p++] - 0xf7);
        if (len_bytes > 2) return -1;
        uint32_t len = 0;
        if (len_bytes == 1)
        {
            len = data[p++];
        }
        else
        {
            len = (data[p++] << 8);
            len += (data[p++]);
        }

        rlp->size = len + len_bytes +1;

        memcpy(rlp->buf, data, rlp->size);
        return 0;

    }

    return -1;


}

//-----------------------------------------------------------------------------------------------------------

static int load_pre_rlp(t_List_RLP* rlp, uint8_t* data)
{
    int p = 0;
    
    if (data[p] > 0xf7)
    {

        int len_bytes = (data[p++] - 0xf7);
        if (len_bytes > 2) return -1;
        uint32_t len = 0;
        if (len_bytes == 1)
        {
            len = data[p++];
        }
        else
        {
            len = (data[p++] << 8);
            len += (data[p++]);
        }

        rlp->size = len_bytes +1;

        memcpy(rlp->buf, data, rlp->size);
        return 0;

    }

    return -1;


}

//-----------------------------------------------------------------------------------------------------------

static void append_init(int size)
{
    eip.buf[0] = 0x02;
    if (size < 56)
    {
        eip.buf[1] = (uint8_t)(0xC0+size);
        eip.pos = 2;
    }
    else
    if (size < 256)
    {
        eip.buf[1] = 0xf8;
        eip.buf[2] = (uint8_t)size;
        eip.pos = 3;
    }
    else
    {
        eip.buf[1] = 0xf9;
        eip.buf[2] = (uint8_t)(size >> 8);
        eip.buf[3] = (uint8_t)(size >> 0);;
        eip.pos = 4;
    }
    eip.size= 0;
}
//-----------------------------------------------------------------------------------------------------------
static void append_int_rlp(t_RLP* rlp)
{
    memcpy(eip.buf + eip.pos, rlp->buf, rlp->size);
    eip.pos += rlp->size;
    eip.size += rlp->size;
}
//-----------------------------------------------------------------------------------------------------------
static void append_data_rlp(t_Data_RLP* rlp)
{
    memcpy(eip.buf + eip.pos, rlp->buf, rlp->size);
    eip.pos += rlp->size;
    eip.size += rlp->size;
}
//-----------------------------------------------------------------------------------------------------------
static void append_list_rlp(t_List_RLP* rlp)
{
    memcpy(eip.buf + eip.pos, rlp->buf, rlp->size);
    eip.pos += rlp->size;
    eip.size += rlp->size;
}
//-----------------------------------------------------------------------------------------------------------

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
    uint8_t* Trx, uint32_t* TrxLen, uint8_t* TrxHash)

{
    int p = 0;
    int ret=0;
    uint8_t        Keccak[32];
    TrxLen[0] = 0x00;
    
    if (load_int_rlp(&chain_id_rlp, chain_id) != 0)                                    return -1;
    if (load_int_rlp(&nonce_rlp, nonce) != 0)                                        return -1;
    if (load_int_rlp(&max_priority_fee_per_gas_rlp, max_priority_fee_per_gas) != 0) return -1;
    if (load_int_rlp(&max_fee_per_gas_rlp, max_fee_per_gas) != 0)                    return -1;
    if (load_int_rlp(&gas_limit_rlp, gas_limit) != 0)                                return -1;
    if (load_int_rlp(&destination_rlp, destination) != 0)                            return -1;
    if (destination_rlp.size != 21)                                                    return -1;
    if (load_int_rlp(&amount_rlp, amount) != 0)                                        return -1;
    if (load_data_rlp(&data_rlp, data) != 0)                                        return -1;
    if (load_list_rlp(&access_list_rlp, access_list) != 0)                            return -1;

    int size =
        chain_id_rlp.size +
        nonce_rlp.size +
        max_priority_fee_per_gas_rlp.size +
        max_fee_per_gas_rlp.size +
        gas_limit_rlp.size +
        destination_rlp.size +
        amount_rlp.size +
        data_rlp.size +
        access_list_rlp.size;


    if (size > 8096) return -1;

    append_init(size);

    append_int_rlp(&chain_id_rlp);
    append_int_rlp(&nonce_rlp);
    append_int_rlp(&max_priority_fee_per_gas_rlp);
    append_int_rlp(&max_fee_per_gas_rlp);
    append_int_rlp(&gas_limit_rlp);
    append_int_rlp(&destination_rlp);
    append_int_rlp(&amount_rlp);
    append_data_rlp(&data_rlp);
    append_list_rlp(&access_list_rlp);

    if (size != eip.size) return -1;

    lib_sha3_256(eip.buf, eip.pos, Keccak);
    
    

    {
        uint8_t R[33];
        uint8_t S[33];
        uint8_t V[32];
        
        ret = lib_wallet_sign_hash(Keccak, 32, R+1, S+1, V);
        if (ret != 0) return ret;

        R[0] = 0xa0;
        S[0] = 0xa0;
        if (V[0] == 0x1B) V[0] = 0x80;
            else
        if (V[0] == 0x1C) V[0] = 0x01;
            else return -100;

        if (load_int_rlp(&V_rlp, V) != 0)                                        return -1;
        if (load_int_rlp(&R_rlp, R) != 0)                                        return -1;
        if (load_int_rlp(&S_rlp, S) != 0)                                        return -1;
    }

    size =
        chain_id_rlp.size +
        nonce_rlp.size +
        max_priority_fee_per_gas_rlp.size +
        max_fee_per_gas_rlp.size +
        gas_limit_rlp.size +
        destination_rlp.size +
        amount_rlp.size +
        data_rlp.size +
        access_list_rlp.size +
        V_rlp.size +
        R_rlp.size +
        S_rlp.size;


    append_init(size);

    append_int_rlp(&chain_id_rlp);
    append_int_rlp(&nonce_rlp);
    append_int_rlp(&max_priority_fee_per_gas_rlp);
    append_int_rlp(&max_fee_per_gas_rlp);
    append_int_rlp(&gas_limit_rlp);
    append_int_rlp(&destination_rlp);
    append_int_rlp(&amount_rlp);
    append_data_rlp(&data_rlp);
    append_list_rlp(&access_list_rlp);
    append_int_rlp(&V_rlp);
    append_int_rlp(&R_rlp);
    append_int_rlp(&S_rlp);

    if (size != eip.size) return -1;

    p = 0;

    lib_sha3_256(eip.buf, eip.pos, TrxHash);
    
    memcpy(Trx + p, eip.buf, eip.pos);
    p += eip.pos;
    TrxLen[0] = p;

    return 0;
}

//-----------------------------------------------------------------------------------------------------------
