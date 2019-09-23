

#define ECB 1
#define CBC 0
#define CTR 0

#include "ccrypto.h"
#include "aes.h"


void
aes_xtsn_decrypt(u8 *buffer, u64 len, u8 *key, u8 *tweakin, u64 sectoroffsethi, u64 sectoroffsetlo, u32 sector_size) {
    u64 i;
    struct AES_ctx _key, _tweak;
    AES_init_ctx(&_key, key);
    AES_init_ctx(&_tweak, tweakin);
    u64 position[2] = {sectoroffsetlo, sectoroffsethi};

    for (i = 0; i < (len / (u64) sector_size); i++) {
        union bigint128 tweak = geniv(position);
        AES_ECB_encrypt(&_tweak, tweak.value8);
        unsigned int j;
        for (j = 0; j < sector_size / 16; j++) {
            xor128((u64 *) buffer, tweak.value64);
            AES_ECB_decrypt(&_key, buffer);
            xor128((u64 *) buffer, tweak.value64);
            int flag = tweak.value8[15] & 0x80;
            shift128(tweak.value8);
            if (flag) tweak.value8[0] ^= 0x87;
            buffer += 16;
        }
        if (position[0] > (position[0] + 1LLU)) position[1] += 1LLU; //if overflow, we gotta
        position[0] += 1LLU;
    }
}

void
aes_xtsn_encrypt(u8 *buffer, u64 len, u8 *key, u8 *tweakin, u64 sectoroffsethi, u64 sectoroffsetlo, u32 sector_size) {
    u64 i;
    struct AES_ctx _key, _tweak;
    AES_init_ctx(&_key, key);
    AES_init_ctx(&_tweak, tweakin);
    u64 position[2] = {sectoroffsetlo, sectoroffsethi};

    for (i = 0; i < (len / (u64) sector_size); i++) {
        union bigint128 tweak = geniv(position);
        AES_ECB_encrypt(&_tweak, tweak.value8);
        unsigned int j;
        for (j = 0; j < sector_size / 16; j++) {
            xor128((u64 *) buffer, tweak.value64);
            AES_ECB_encrypt(&_key, buffer);
            xor128((u64 *) buffer, tweak.value64);
            int flag = tweak.value8[15] & 0x80;
            shift128(tweak.value8);
            if (flag) tweak.value8[0] ^= 0x87;
            buffer += 16;
        }
        if (position[0] > (position[0] + 1LLU)) position[1] += 1LLU; //if overflow, we gotta
        position[0] += 1LLU;
    }
}
