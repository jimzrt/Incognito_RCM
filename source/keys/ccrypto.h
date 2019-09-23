#ifndef _CCRYPTO_H_
#define _CCRYPTO_H_

//#include <stdlib.h>
//#include <stdio.h>
// #include <inttypes.h>
// #include <stdlib.h>
// #include <string.h>
// #include <stdbool.h>
#include "../utils/types.h"

// typedef uint8_t u8;
// typedef uint16_t u16;
// typedef uint32_t u32;
// typedef uint64_t u64;

// union {
//     u16 foo;
//     u8 islittle;
// } endian = {.foo = 1};

union bigint128 {
    u8 value8[16];
    u64 value64[2];
};

inline static union bigint128 geniv(u64 *pos) {
    union bigint128 out;
   // if (endian.islittle) {
        //sacrifice code size for possible speed up
        out.value8[15] = ((u8 *) pos)[0];
        out.value8[14] = ((u8 *) pos)[1];
        out.value8[13] = ((u8 *) pos)[2];
        out.value8[12] = ((u8 *) pos)[3];
        out.value8[11] = ((u8 *) pos)[4];
        out.value8[10] = ((u8 *) pos)[5];
        out.value8[9] = ((u8 *) pos)[6];
        out.value8[8] = ((u8 *) pos)[7];
        out.value8[7] = ((u8 *) pos)[8];
        out.value8[6] = ((u8 *) pos)[9];
        out.value8[5] = ((u8 *) pos)[10];
        out.value8[4] = ((u8 *) pos)[11];
        out.value8[3] = ((u8 *) pos)[12];
        out.value8[2] = ((u8 *) pos)[13];
        out.value8[1] = ((u8 *) pos)[14];
        out.value8[0] = ((u8 *) pos)[15];
    // } else {
    //     out.value64[1] = pos[0];
    //     out.value64[0] = pos[1];
    // }
    return out;
}

inline static void xor128(u64 *foo, u64 *bar) {
    foo[0] ^= bar[0];
    foo[1] ^= bar[1];
}

inline static void shift128(u8 *foo) {
  //  if (endian.islittle) {
        //due to little endian order, we can do this
        ((u64 *) foo)[1] = (((u64 *) foo)[1] << 1) | (((u64 *) foo)[0] >> 63);
        ((u64 *) foo)[0] = (((u64 *) foo)[0] << 1);
    // } else {
    //     //sacrifice code size for possible speed up
    //     foo[15] = (foo[15] << 1) | (foo[14] >> 7);
    //     foo[14] = (foo[14] << 1) | (foo[13] >> 7);
    //     foo[13] = (foo[13] << 1) | (foo[12] >> 7);
    //     foo[12] = (foo[12] << 1) | (foo[11] >> 7);
    //     foo[11] = (foo[11] << 1) | (foo[10] >> 7);
    //     foo[10] = (foo[10] << 1) | (foo[9] >> 7);
    //     foo[9] = (foo[9] << 1) | (foo[8] >> 7);
    //     foo[8] = (foo[8] << 1) | (foo[7] >> 7);
    //     foo[7] = (foo[7] << 1) | (foo[6] >> 7);
    //     foo[6] = (foo[6] << 1) | (foo[5] >> 7);
    //     foo[5] = (foo[5] << 1) | (foo[4] >> 7);
    //     foo[4] = (foo[4] << 1) | (foo[3] >> 7);
    //     foo[3] = (foo[3] << 1) | (foo[2] >> 7);
    //     foo[2] = (foo[2] << 1) | (foo[1] >> 7);
    //     foo[1] = (foo[1] << 1) | (foo[0] >> 7);
    //     foo[0] = (foo[0] << 1);
    // }
}

void
aes_xtsn_decrypt(u8 *buffer, u64 len, u8 *key, u8 *tweakin, u64 sectoroffsethi, u64 sectoroffsetlo, u32 sector_size);

void
aes_xtsn_encrypt(u8 *buffer, u64 len, u8 *key, u8 *tweakin, u64 sectoroffsethi, u64 sectoroffsetlo, u32 sector_size);


#endif