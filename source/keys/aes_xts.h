/*
 * Copyright (c) 2012 by naehrwert
 * This file is released under the GPLv2.
 */

#ifndef _AES_XTS_H_
#define _AES_XTS_H_

#include "../utils/types.h"

//Using polarssl.
#include "aes.h"

/*! AES-XTS context. */
typedef struct _aes_xts_ctxt {
    aes_context twk_ctxt;
    aes_context aes_ctxt;
    int mode;
    int keybits;
} aes_xts_ctxt_t;

/*! Initialize AES-XTS context. */
int aes_xts_init(aes_xts_ctxt_t *ctxt, int mode, const u8 *data_key, const u8 *tweak_key, int keybits);
/*! Crypt buffer (must be aligned to 0x10). */
int aes_xts_crypt(aes_xts_ctxt_t *ctxt, u64 seqno, u32 sector_size, const u8 *in, u8 *out);

#endif
