/*
 * Copyright (c) 2012 by naehrwert
 * This file is released under the GPLv2.
 */

#include "../utils/types.h"
#include "aes.h"
#include "aes_xts.h"

int aes_xts_init(aes_xts_ctxt_t *ctxt, int mode, const u8 *data_key, const u8 *tweak_key, int keybits) {
    ctxt->mode = mode;
    ctxt->keybits = keybits;
    aes_setkey_enc(&ctxt->twk_ctxt, tweak_key, keybits);

    if (mode == AES_ENCRYPT)
        aes_setkey_enc(&ctxt->aes_ctxt, data_key, keybits);
    else if (mode == AES_DECRYPT)
        aes_setkey_dec(&ctxt->aes_ctxt, data_key, keybits);
    else
        return -1;

    return 0;
}

int aes_xts_crypt(aes_xts_ctxt_t *ctxt, u64 seqno, u32 sector_size, const u8 *in, u8 *out) {
    u32 i = 0, j = 0;
    u8 tweak[0x10], buf[0x10];
    u8 carry_in, carry_out;

    //Check alignment.
    if (!(sector_size % 0x10 == 0))
        return -1;

    //Init tweak.
    ((u64 *) tweak)[0] = seqno; //_ES64(seqno);
    ((u64 *) tweak)[1] = 0;
    aes_crypt_ecb(&ctxt->twk_ctxt, AES_ENCRYPT, tweak, tweak);

    //En-/decrypt sector.
    for (i = 0; i < sector_size; i += 0x10) {
        for (j = 0; j < 0x10; j++)
            buf[j] = in[i + j] ^ tweak[j];

        //En-/decrypt 0x10 bytes.
        aes_crypt_ecb(&ctxt->aes_ctxt, ctxt->mode, buf, buf);

        for (j = 0; j < 0x10; j++)
            out[i + j] = buf[j] ^ tweak[j];

        //Update tweak (GF MUL).
        carry_in = 0;
        for (j = 0; j < 0x10; j++) {
            carry_out = (tweak[j] >> 7) & 1;
            tweak[j] = ((tweak[j] << 1) + carry_in) & 0xFF;
            carry_in = carry_out;
        }
        if (carry_out)
            tweak[0] ^= 0x87;
    }

    return 0;
}
