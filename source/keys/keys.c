/*
 * Copyright (c) 2019 shchmue
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keys.h"

#include "../config/config.h"
#include "../gfx/di.h"
#include "../gfx/gfx.h"
#include "../gfx/tui.h"
#include "../hos/pkg1.h"
#include "../hos/pkg2.h"
#include "../hos/sept.h"
#include "../libs/fatfs/ff.h"
#include "../mem/heap.h"
#include "../mem/mc.h"
#include "../mem/sdram.h"
#include "../sec/se.h"
#include "../sec/se_t210.h"
#include "../sec/tsec.h"
#include "../soc/fuse.h"
#include "../soc/smmu.h"
#include "../soc/t210.h"
#include "../storage/emummc.h"
#include "../storage/nx_emmc.h"
#include "../storage/sdmmc.h"
#include "../utils/btn.h"
#include "../utils/list.h"
#include "../utils/sprintf.h"
#include "../utils/util.h"

#include "key_sources.inl"

#include "../libs/fatfs/diskio.h"
#include <string.h>
#include "sha256.h"

#include "aes_xts.h"

extern bool sd_mount();
extern void sd_unmount();
extern int sd_save_to_file(void *buf, u32 size, const char *filename);

extern hekate_config h_cfg;

u32 _key_count = 0;
sdmmc_storage_t storage;
emmc_part_t *system_part;
emmc_part_t *prodinfo_part;
u32 start_time, end_time;

#define TPRINTF(text)                                           \
    end_time = get_tmr_us();                                    \
    gfx_printf(text " done in %d us\n", end_time - start_time); \
    start_time = get_tmr_us()
#define TPRINTFARGS(text, args...)                                    \
    end_time = get_tmr_us();                                          \
    gfx_printf(text " done in %d us\n", args, end_time - start_time); \
    start_time = get_tmr_us()
#define SAVE_KEY(name, src, len) _save_key(name, src, len, text_buffer)
#define SAVE_KEY_FAMILY(name, src, count, len) _save_key_family(name, src, count, len, text_buffer)

static u8 temp_key[0x10],
    bis_key[4][0x20] = {0},
    device_key[0x10] = {0},
    new_device_key[0x10] = {0},
    keyblob[KB_FIRMWARE_VERSION_600 + 1][0x90] = {0},
    keyblob_key[KB_FIRMWARE_VERSION_600 + 1][0x10] = {0},
    keyblob_mac_key[KB_FIRMWARE_VERSION_600 + 1][0x10] = {0},
    package1_key[KB_FIRMWARE_VERSION_600 + 1][0x10] = {0},
    // master key-derived families
    master_kek[KB_FIRMWARE_VERSION_MAX + 1][0x10] = {0},
    master_key[KB_FIRMWARE_VERSION_MAX + 1][0x10] = {0};

// key functions
static bool _key_exists(const void *data) { return memcmp(data, zeros, 0x10); };
static void _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed, const void *key_seed);

bool dump_keys()
{
    display_backlight_brightness(100, 1000);
    gfx_clear_partial_grey(0x1B, 0, 1256);
    gfx_con_setpos(0, 0);

    gfx_print_header();

    // gfx_printf("[%kLo%kck%kpi%kck%k_R%kCM%k v%d.%d.%d%k]\n\n",
    //            colors[0], colors[1], colors[2], colors[3], colors[4], colors[5], 0xFFFF00FF, LP_VER_MJ, LP_VER_MN, LP_VER_BF, 0xFFCCCCCC);

    start_time = get_tmr_us();
    //u32 begin_time = get_tmr_us();
    u32 retries = 0;
    u32 color_idx = 0;

    tsec_ctxt_t tsec_ctxt;
    sdmmc_t sdmmc;

    emummc_storage_init_mmc(&storage, &sdmmc);
    TPRINTFARGS("%kMMC init...     ", colors[(color_idx++) % 6]);

    // Read package1.
    u8 *pkg1 = (u8 *)malloc(0x40000);
    emummc_storage_set_mmc_partition(&storage, 1);
    emummc_storage_read(&storage, 0x100000 / NX_EMMC_BLOCKSIZE, 0x40000 / NX_EMMC_BLOCKSIZE, pkg1);
    const pkg1_id_t *pkg1_id = pkg1_identify(pkg1);
    if (!pkg1_id)
    {
        EPRINTF("Unknown pkg1 version.");
        return false;
    }

    bool found_tsec_fw = false;
    for (const u32 *pos = (const u32 *)pkg1; (u8 *)pos < pkg1 + 0x40000; pos += 0x100 / sizeof(u32))
    {
        if (*pos == 0xCF42004D)
        {
            tsec_ctxt.fw = (u8 *)pos;
            found_tsec_fw = true;
            break;
        }
    }
    if (!found_tsec_fw)
    {
        EPRINTF("Failed to locate TSEC firmware.");
        return false;
    }

    tsec_key_data_t *key_data = (tsec_key_data_t *)(tsec_ctxt.fw + TSEC_KEY_DATA_ADDR);
    tsec_ctxt.pkg1 = pkg1;
    tsec_ctxt.size = 0x100 + key_data->blob0_size + key_data->blob1_size + key_data->blob2_size + key_data->blob3_size + key_data->blob4_size;

    // u32 MAX_KEY = 6;
    // if (pkg1_id->kb >= KB_FIRMWARE_VERSION_620)
    // {
    //     MAX_KEY = pkg1_id->kb + 1;
    // }

    if (pkg1_id->kb >= KB_FIRMWARE_VERSION_700)
    {
        se_aes_key_read(12, master_key[KB_FIRMWARE_VERSION_MAX], 0x10);
    }

    //get_tsec: ;
    u8 tsec_keys[0x10 * 2] = {0};

    if (pkg1_id->kb == KB_FIRMWARE_VERSION_620)
    {
        u8 *tsec_paged = (u8 *)page_alloc(3);
        memcpy(tsec_paged, (void *)tsec_ctxt.fw, tsec_ctxt.size);
        tsec_ctxt.fw = tsec_paged;
    }

    int res = 0;

    mc_disable_ahb_redirect();

    while (tsec_query(tsec_keys, pkg1_id->kb, &tsec_ctxt) < 0)
    {
        memset(tsec_keys, 0x00, 0x20);
        retries++;
        if (retries > 15)
        {
            res = -1;
            break;
        }
    }
    free(pkg1);

    mc_enable_ahb_redirect();

    if (res < 0)
    {
        EPRINTFARGS("ERROR %x dumping TSEC.\n", res);
       return false;
    }

    TPRINTFARGS("%kTSEC key(s)...  ", colors[(color_idx++) % 6]);

    // Master key derivation
    if (pkg1_id->kb == KB_FIRMWARE_VERSION_620 && _key_exists(tsec_keys + 0x10))
    {
        se_aes_key_set(8, tsec_keys + 0x10, 0x10); // mkek6 = unwrap(mkeks6, tsecroot)
        se_aes_crypt_block_ecb(8, 0, master_kek[6], master_kek_sources[0]);
        se_aes_key_set(8, master_kek[6], 0x10); // mkey = unwrap(mkek, mks)
        se_aes_crypt_block_ecb(8, 0, master_key[6], master_key_source);
    }

    u8 *keyblob_block = (u8 *)calloc(NX_EMMC_BLOCKSIZE, 1);
    u8 keyblob_mac[0x10] = {0};
    u32 sbk[4] = {FUSE(FUSE_PRIVATE_KEY0), FUSE(FUSE_PRIVATE_KEY1),
                  FUSE(FUSE_PRIVATE_KEY2), FUSE(FUSE_PRIVATE_KEY3)};
    se_aes_key_set(8, tsec_keys, 0x10);
    se_aes_key_set(9, sbk, 0x10);
    for (u32 i = 0; i <= KB_FIRMWARE_VERSION_600; i++)
    {
        se_aes_crypt_block_ecb(8, 0, keyblob_key[i], keyblob_key_source[i]); // temp = unwrap(kbks, tsec)
        se_aes_crypt_block_ecb(9, 0, keyblob_key[i], keyblob_key[i]);        // kbk = unwrap(temp, sbk)
        se_aes_key_set(7, keyblob_key[i], 0x10);
        se_aes_crypt_block_ecb(7, 0, keyblob_mac_key[i], keyblob_mac_key_source); // kbm = unwrap(kbms, kbk)
        if (i == 0)
        {
            se_aes_crypt_block_ecb(7, 0, device_key, per_console_key_source); // devkey = unwrap(pcks, kbk0)
            se_aes_crypt_block_ecb(7, 0, new_device_key, per_console_key_source_4x);
        }

        // verify keyblob is not corrupt
        emummc_storage_read(&storage, 0x180000 / NX_EMMC_BLOCKSIZE + i, 1, keyblob_block);
        se_aes_key_set(3, keyblob_mac_key[i], 0x10);
        se_aes_cmac(3, keyblob_mac, 0x10, keyblob_block + 0x10, 0xa0);
        if (memcmp(keyblob_block, keyblob_mac, 0x10))
        {
            EPRINTFARGS("Keyblob %x corrupt.", i);
            gfx_hexdump(i, keyblob_block, 0x10);
            gfx_hexdump(i, keyblob_mac, 0x10);
            continue;
        }

        // decrypt keyblobs
        se_aes_key_set(2, keyblob_key[i], 0x10);
        se_aes_crypt_ctr(2, keyblob[i], 0x90, keyblob_block + 0x20, 0x90, keyblob_block + 0x10);

        memcpy(package1_key[i], keyblob[i] + 0x80, 0x10);
        memcpy(master_kek[i], keyblob[i], 0x10);
        se_aes_key_set(7, master_kek[i], 0x10);
        se_aes_crypt_block_ecb(7, 0, master_key[i], master_key_source);
    }
    free(keyblob_block);

    TPRINTFARGS("%kMaster keys...  ", colors[(color_idx++) % 6]);

    u32 key_generation = 0;
    if (pkg1_id->kb >= KB_FIRMWARE_VERSION_500)
    {
        if ((fuse_read_odm(4) & 0x800) && fuse_read_odm(0) == 0x8E61ECAE && fuse_read_odm(1) == 0xF2BA3BB2)
        {
            key_generation = fuse_read_odm(2) & 0x1F;
        }
    }
    if (_key_exists(device_key))
    {
        if (key_generation)
        {
            se_aes_key_set(8, new_device_key, 0x10);
            se_aes_crypt_block_ecb(8, 0, temp_key, new_device_key_sources[pkg1_id->kb - KB_FIRMWARE_VERSION_400]);
            se_aes_key_set(8, master_key[0], 0x10);
            se_aes_unwrap_key(8, 8, new_device_keygen_sources[pkg1_id->kb - KB_FIRMWARE_VERSION_400]);
            se_aes_crypt_block_ecb(8, 0, temp_key, temp_key);
        }
        else
            memcpy(temp_key, device_key, 0x10);
        se_aes_key_set(8, temp_key, 0x10);
        se_aes_unwrap_key(8, 8, retail_specific_aes_key_source);                   // kek = unwrap(rsaks, devkey)
        se_aes_crypt_block_ecb(8, 0, bis_key[0] + 0x00, bis_key_source[0] + 0x00); // bkey = unwrap(bkeys, kek)
        se_aes_crypt_block_ecb(8, 0, bis_key[0] + 0x10, bis_key_source[0] + 0x10);
        // kek = generate_kek(bkeks, devkey, aeskek, aeskey)
        _generate_kek(8, bis_kek_source, temp_key, aes_kek_generation_source, aes_key_generation_source);
        se_aes_crypt_block_ecb(8, 0, bis_key[1] + 0x00, bis_key_source[1] + 0x00); // bkey = unwrap(bkeys, kek)
        se_aes_crypt_block_ecb(8, 0, bis_key[1] + 0x10, bis_key_source[1] + 0x10);
        se_aes_crypt_block_ecb(8, 0, bis_key[2] + 0x00, bis_key_source[2] + 0x00);
        se_aes_crypt_block_ecb(8, 0, bis_key[2] + 0x10, bis_key_source[2] + 0x10);
        memcpy(bis_key[3], bis_key[2], 0x20);
    }

    emummc_storage_set_mmc_partition(&storage, 0);
    // Parse eMMC GPT.
    LIST_INIT(gpt);
    nx_emmc_gpt_parse(&gpt, &storage);

    // Find PRODINFO partition.
    prodinfo_part = nx_emmc_part_find(&gpt, "PRODINFO");
    if (!prodinfo_part)
    {
        EPRINTF("Failed to locate PRODINFO.");
       return false;
    }

    // Read in package2 header and get package2 real size.

    //  u8 *tmp_copy = (u8 *)malloc(NX_EMMC_BLOCKSIZE*2);

    // nx_emmc_part_read(&storage, prodinfo_part, 0, 2, tmp);

    // memcpy(tmp_copy, tmp, NX_EMMC_BLOCKSIZE*2);
    // gfx_hexdump(0, tmp + 0x250, 0x18);

    // aes_xtsn_decrypt(tmp_copy, NX_EMMC_BLOCKSIZE*2, bis_key[0], bis_key[0] + 0x10,  pkg2_part->lba_end, pkg2_part->lba_start, NX_EMMC_BLOCKSIZE);

    //  gfx_hexdump(0, tmp_copy + 0x250, 0x18);
    //  memcpy(tmp_copy, tmp, NX_EMMC_BLOCKSIZE*2);

    se_aes_key_set(8, bis_key[0] + 0x00, 0x10);
    se_aes_key_set(9, bis_key[0] + 0x10, 0x10);

    //u32 length = 0x18;
    // u8* buffer = (u8 *)malloc(NX_EMMC_BLOCKSIZE);
    // readData(buffer, 0, NX_EMMC_BLOCKSIZE);
    // gfx_hexdump(0, buffer, 0x08);

    // readData(buffer, NX_EMMC_BLOCKSIZE, NX_EMMC_BLOCKSIZE);
    // gfx_hexdump(0, buffer, 100);

    // free(buffer);

    //verify();

    // const char junkSerial[] = "XAJ40030771137";
    // // gfx_hexdump(0, (u8 *)junkSerial, strlen(junkSerial));
    // writeData((u8 *)junkSerial, 0x250, strlen(junkSerial));

    // writeClientCertHash();
    // writeCal0Hash();

    // //  gfx_hexdump(0, buffer, sizeof(buffer));
    // //free(buffer);

    // // restore();

    // // verify();

    // //  u8 *tmp = (u8 *)malloc(NX_EMMC_BLOCKSIZE);
    // u8 *tmp_dec = (u8 *)malloc(NX_EMMC_BLOCKSIZE);
    // //   nx_emmc_part_read(&storage, prodinfo_part, 1, 1, tmp);

    // //  gfx_hexdump(0, tmp, 0x100);
    // //  aes_xts_ctxt_t context;
    // //  aes_xts_init(&context, AES_DECRYPT, bis_key[0], bis_key[0] + 0x10, 128);
    // // //  aes_xts_crypt(&context, 0, NX_EMMC_BLOCKSIZE, tmp, tmp_dec);

    // // // gfx_hexdump(0, tmp_dec, 0x100);

    // //  aes_xts_crypt(&context, 1, NX_EMMC_BLOCKSIZE, tmp, tmp_dec);

    // // gfx_hexdump(0, tmp_dec, 0x100);

    // disk_read_prod(tmp_dec, 1, 1);
    // //readData(tmp_dec, NX_EMMC_BLOCKSIZE, NX_EMMC_BLOCKSIZE);

    // gfx_hexdump(0, tmp_dec, 0x100);

    // // disk_write_prod(tmp_dec, 1, 1);
    // // gfx_hexdump(0, tmp_dec, 0x100);

    // //se_aes_xts_crypt_sec(9, 8, 1, 1, tmp, tmp_dec, NX_EMMC_BLOCKSIZE);

    // //gfx_hexdump(0, tmp, 0x100);

    // // se_aes_xts_crypt_sec(9, 8, 1, 0, tmp, tmp_dec, NX_EMMC_BLOCKSIZE);

    // // se_aes_xts_crypt_sec(9, 8, 0, 0, tmp_dec, tmp, NX_EMMC_BLOCKSIZE);

    // // gfx_hexdump(0, tmp_dec, 0x10);

    // //  free(tmp);
    // free(tmp_dec);

    // // writeClientCertHash();
    // //  writeCal0Hash();

    // verify();

    // // verify();
    // // free(tmp_copy);

    // //   pkg2_done:
    // //     // free(pkg2);
    // //     // free(ki);

    // //     TPRINTFARGS("%kFS keys...      ", colors[(color_idx++) % 6]);

    // //     // DIR dir;
    // //     // FILINFO fno;
    // //     // FIL fp;

    // //    // f_closedir(&dir);

    // //    // f_close(&fp);

    // //     TPRINTFARGS("%kSD Seed...      ", colors[(color_idx++) % 6]);

// dismount:
//     nx_emmc_gpt_free(&gpt);
//     emummc_storage_end(&storage);

//     end_time = get_tmr_us();
//     gfx_printf("\n%kFound %d keys.", colors[(color_idx++) % 6], _key_count);
//     _key_count = 0;
//     gfx_printf("\n%kLockpick totally done in %d us", colors[(color_idx++) % 6], end_time - begin_time);
//     gfx_printf("\n%kFound through master_key_%02x\n", colors[(color_idx++) % 6], MAX_KEY - 1);

//     // f_mkdir("sd:/switch");
//     // char keyfile_path[30] = "sd:/switch/";
//     // if (!(fuse_read_odm(4) & 3))
//     //     sprintf(&keyfile_path[11], "prod.keys");
//     // else
//     //     sprintf(&keyfile_path[11], "dev.keys");
//     // if (sd_mount() && !sd_save_to_file(text_buffer, strlen(text_buffer), keyfile_path) && !f_stat(keyfile_path, &fno)) {
//     //     gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, keyfile_path);
//     // } else
//     //     EPRINTF("Failed to save keys to SD.");
     h_cfg.emummc_force_disable = emummc_load_cfg();

// out_wait:
//     // sd_unmount();
//     gfx_printf("\n%kPress any key to return to the main menu.", colors[(color_idx) % 6], colors[(color_idx + 1) % 6], colors[(color_idx + 2) % 6]);

//     btn_wait();
   // nx_emmc_gpt_free(&gpt);
    gfx_printf("\n%kFound keys.\n\n", colors[(color_idx++) % 6]);
    return true;
}


void cleanUp(){
    
    emummc_storage_end(&storage);
}

static void _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed, const void *key_seed)
{
    if (!_key_exists(key_source) || !_key_exists(master_key) || !_key_exists(kek_seed))
        return;

    se_aes_key_set(ks, master_key, 0x10);
    se_aes_unwrap_key(ks, ks, kek_seed);
    se_aes_unwrap_key(ks, ks, key_source);
    if (key_seed && _key_exists(key_seed))
        se_aes_unwrap_key(ks, ks, key_seed);
}

static inline u32 _read_le_u32(const void *buffer, u32 offset)
{
    return (*(u8 *)(buffer + offset + 0)) |
           (*(u8 *)(buffer + offset + 1) << 0x08) |
           (*(u8 *)(buffer + offset + 2) << 0x10) |
           (*(u8 *)(buffer + offset + 3) << 0x18);
}

bool readData(u8 *buffer, u32 offset, u32 length)
{

    // u8 *tmp = (u8 *)malloc(NX_EMMC_BLOCKSIZE);
    // u32 sector = (offset / NX_EMMC_BLOCKSIZE);
    // u32 newOffset = offset % NX_EMMC_BLOCKSIZE;
    // u32 read = 0;

    // if (newOffset > 0 && length >= NX_EMMC_BLOCKSIZE)
    // {
    //     u32 toRead = NX_EMMC_BLOCKSIZE - newOffset;
    //     disk_read_prod(tmp, sector, 1);
    //     memcpy(buffer, tmp + newOffset, toRead);

    //     length -= toRead;
    //     read += toRead;
    //     sector++;
    // }

    // while (length > NX_EMMC_BLOCKSIZE)
    // {

    //     disk_read_prod(tmp, sector, 1);
    //     memcpy(buffer + read, tmp, NX_EMMC_BLOCKSIZE);

    //     length -= NX_EMMC_BLOCKSIZE;
    //     read += NX_EMMC_BLOCKSIZE;
    //     sector++;
    // }

    // if (length > 0)
    // {
    //     disk_read_prod(tmp, sector, 1);
    //     memcpy(buffer + read, tmp, length);
    // }

    // free(tmp);

    u32 sector = (offset / NX_EMMC_BLOCKSIZE);
    u32 newOffset = (offset % NX_EMMC_BLOCKSIZE);

    u32 sectorCount = ((newOffset + length - 1) / (NX_EMMC_BLOCKSIZE)) + 1;

    u8 *tmp = (u8 *)malloc(sectorCount * NX_EMMC_BLOCKSIZE);

    disk_read_prod(tmp, sector, sectorCount);

    memcpy(buffer, tmp + newOffset, length);

    free(tmp);

     return true;
}

bool writeData(u8 *buffer, u32 offset, u32 length)
{

    // u8 *tmp = (u8 *)malloc(NX_EMMC_BLOCKSIZE);
    // u32 sector = (offset / NX_EMMC_BLOCKSIZE);
    // u32 newOffset = offset % NX_EMMC_BLOCKSIZE;
    // u32 read = 0;

    // if (newOffset > 0 && length >= NX_EMMC_BLOCKSIZE)
    // {
    //     u32 toRead = NX_EMMC_BLOCKSIZE - newOffset;
    //     disk_read_prod(tmp, sector, 1);
    //     memcpy(tmp + newOffset, buffer, toRead);
    //     disk_write_prod(tmp, sector, 1);
    //     length -= toRead;
    //     read += toRead;
    //     sector++;
    // }

    // while (length > NX_EMMC_BLOCKSIZE)
    // {

    //     disk_write_prod(buffer + read, sector, 1);

    //     length -= NX_EMMC_BLOCKSIZE;
    //     read += NX_EMMC_BLOCKSIZE;
    //     sector++;
    // }

    // if (length > 0)
    // {
    //     disk_read_prod(tmp, sector, 1);
    //     memcpy(tmp, buffer + read, length);
    //     disk_write_prod(buffer + read, sector, 1);
    // }

    // free(tmp);




    u32 sector = (offset / NX_EMMC_BLOCKSIZE);
    u32 newOffset = (offset % NX_EMMC_BLOCKSIZE);

    u8 sectorCount = ((newOffset + length - 1) / (NX_EMMC_BLOCKSIZE)) + 1;

    u8 *tmp = (u8 *)malloc(sectorCount * NX_EMMC_BLOCKSIZE);

    disk_read_prod(tmp, sector, sectorCount);

    memcpy(tmp + newOffset, buffer, length);

    disk_write_prod(tmp, sector, sectorCount);

    free(tmp);

     return true;
}

bool writeHash(u32 hashOffset, u32 offset, u32 sz)
{

    u8 *buffer = (u8 *)malloc(NX_EMMC_BLOCKSIZE);

    SHA256_CTX ctx;
    sha256_init(&ctx);

    u32 newOffset = offset % NX_EMMC_BLOCKSIZE;

    if (newOffset > 0 && newOffset + sz >= NX_EMMC_BLOCKSIZE)
    {
        u32 toRead = NX_EMMC_BLOCKSIZE - newOffset;
        readData(buffer, offset, toRead);
        sha256_update(&ctx, buffer, toRead);

        sz -= toRead;
        offset += toRead;
    }

    while (sz > NX_EMMC_BLOCKSIZE)
    {

        readData(buffer, offset, NX_EMMC_BLOCKSIZE);
        sha256_update(&ctx, buffer, NX_EMMC_BLOCKSIZE);

        sz -= NX_EMMC_BLOCKSIZE;
        offset += NX_EMMC_BLOCKSIZE;
    }

    if (sz > 0)
    {

        readData(buffer, offset, sz);
        sha256_update(&ctx, buffer, sz);
    }
    u8 hash[0x20];
    sha256_final(&ctx, hash);

    writeData(hash, hashOffset, 0x20);

    free(buffer);
    return true;
}

bool verifyHash(u32 hashOffset, u32 offset, u32 sz)
{
    bool result = false;
    u8 *buffer = (u8 *)malloc(NX_EMMC_BLOCKSIZE);

    SHA256_CTX ctx;
    sha256_init(&ctx);

    u32 newOffset = offset % NX_EMMC_BLOCKSIZE;

    if (newOffset > 0 && sz >= NX_EMMC_BLOCKSIZE)
    {
        u32 toRead = NX_EMMC_BLOCKSIZE - newOffset;
        readData(buffer, offset, toRead);
        sha256_update(&ctx, buffer, toRead);

        sz -= toRead;
        offset += toRead;
    }

    while (sz > NX_EMMC_BLOCKSIZE)
    {

        readData(buffer, offset, NX_EMMC_BLOCKSIZE);
        sha256_update(&ctx, buffer, NX_EMMC_BLOCKSIZE);

        sz -= NX_EMMC_BLOCKSIZE;
        offset += NX_EMMC_BLOCKSIZE;
    }

    if (sz > 0)
    {

        readData(buffer, offset, sz);
        sha256_update(&ctx, buffer, sz);
    }
    u8 hash1[0x20];
    sha256_final(&ctx, hash1);

    u8 hash2[0x20];

    readData(hash2, hashOffset, 0x20);

    if (memcmp(hash1, hash2, 0x20))
    {
        EPRINTF("error: hash verification failed\n");
    }
    else
    {
        result = true;
    }

    gfx_hexdump(0, hash1, 0x20);
    gfx_hexdump(0, hash2, 0x20);

    free(buffer);
    return result;
}

u32 certSize()
{
    u32 buffer;
    readData((u8 *)&buffer, 0x0AD0, sizeof(buffer));
    return buffer;
}

u32 calibrationDataSize()
{
    u32 buffer;
    readData((u8 *)&buffer, 0x08, sizeof(buffer));
    return buffer;
}

bool writeCal0Hash()
{
    return writeHash(0x20, 0x40, calibrationDataSize());
}

bool writeClientCertHash()
{
    return writeHash(0x12E0, 0xAE0, certSize());
}

bool verifyCal0Hash()
{
    return verifyHash(0x20, 0x40, calibrationDataSize());
}

bool verifyClientCertHash()
{

    return verifyHash(0x12E0, 0xAE0, certSize());
}

bool verifyProdinfo()
{
    return verifyClientCertHash() && verifyCal0Hash();
    // bool r = verifyHash(0x12E0, 0xAE0, certSize());      // client cert hash
    // r &= verifyHash(0x20, 0x40, calibrationDataSize()); // calibration hash

    // return r;
}

bool backupProdinfo()
{
    sd_mount();
     char* name;
    if (!emu_cfg.enabled || h_cfg.emummc_force_disable){
        name = "sd:/prodinfo_sysnand.bin";
    } else {
       
         name = "sd:/prodinfo_emunand.bin";
    }

    if (f_stat(name, NULL))
    {
        f_unlink(name);
    }
    FIL fp;
    f_open(&fp, name, FA_CREATE_ALWAYS | FA_WRITE);
    u8 bufferNX[NX_EMMC_BLOCKSIZE];
    u32 size = 0x3FBC00;
    u32 offset = 0;
    while (size > NX_EMMC_BLOCKSIZE)
    {
        readData(bufferNX, offset, NX_EMMC_BLOCKSIZE);
        f_write(&fp, bufferNX, NX_EMMC_BLOCKSIZE, NULL);
        f_sync(&fp);
        offset += NX_EMMC_BLOCKSIZE;
        size -= NX_EMMC_BLOCKSIZE;
    }
    if (size > 0)
    {
        readData(bufferNX, offset, size);
        f_write(&fp, bufferNX, size, NULL);
        f_sync(&fp);

    }

    f_close(&fp);

    gfx_printf("%kBackup %s done!\n\n", COLOR_GREEN, name);

    // if (f_stat("sd:/prodinfoENC.bin", NULL))
    // {
    //     f_unlink("sd:/prodinfoENC.bin");
    // }

    // f_open(&fp, "sd:/prodinfoENC.bin", FA_CREATE_NEW | FA_WRITE);
    // size = 0x3FBC00;
    // offset = 0;
    // while (size > 0)
    // {
    //     nx_emmc_part_read(&storage, prodinfo_part, offset, 1, bufferNX);
    //     f_write(&fp, bufferNX, NX_EMMC_BLOCKSIZE, NULL);
    //     offset++;
    //     size -= NX_EMMC_BLOCKSIZE;
    // }

    // f_close(&fp);

    // gfx_printf("\n%kBackup encrypted done!", colors[4]);
    return true;
}

bool restoreProdinfo()
{
    sd_mount();

     char* name;
    if (!emu_cfg.enabled || h_cfg.emummc_force_disable){
        name = "sd:/prodinfo_sysnand.bin";
    } else {
       
         name = "sd:/prodinfo_emunand.bin";
    }


    FIL fp;
    if (f_open(&fp, name, FA_READ) != FR_OK)
    {
        gfx_printf("\nCannot open%s!\n", name);
        return false;
    }
    u8 bufferNX[NX_EMMC_BLOCKSIZE];

    u32 size = 0x3FBC00;
    u32 offset = 0;
    while (size > 0)
    {
        f_read(&fp, bufferNX, NX_EMMC_BLOCKSIZE, NULL);
        writeData(bufferNX,offset,NX_EMMC_BLOCKSIZE);
        //nx_emmc_part_write(&storage, prodinfo_part, offset, 1, bufferNX);
        offset+= NX_EMMC_BLOCKSIZE;
        size -= NX_EMMC_BLOCKSIZE;
    }
    //  if(size > 0){
    //      f_read(&fp, bufferNX, size, NULL);
    //      nx_emmc_part_write(&storage, prodinfo_part, offset, 1, bufferNX);
    //      f_write(&fp, bufferNX, size, NULL);
    //  }

    f_close(&fp);

     gfx_printf("%kRestore %s done!\n\n", COLOR_GREEN, name);
    return true;
}

// bool erase(u32 offset, u32 sz)
// 	{
// 		u8 zero = 0;

// 		for (u64 i = 0; i < sz; i++)
// 		{
// 			fsStorageWrite(&m_sh, offset + i, &zero, 1);
// 		}

// 		return true;
// 	}
