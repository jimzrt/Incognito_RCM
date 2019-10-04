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

extern bool sd_mount();
extern void sd_unmount();
extern int sd_save_to_file(void *buf, u32 size, const char *filename);

extern hekate_config h_cfg;

u32 _key_count = 0;
sdmmc_storage_t storage;
sdmmc_t sdmmc;
emmc_part_t *system_part;
emmc_part_t *prodinfo_part;
u32 start_time, end_time;

#define ENCRYPTED 1
#define DECRYPTED 0
#define SECTORS_IN_CLUSTER 32

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

LIST_INIT(gpt);

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

    gfx_printf("%kGetting bis_keys...\n", COLOR_YELLOW);

    start_time = get_tmr_us();
    //u32 begin_time = get_tmr_us();
    u32 retries = 0;
    // u32 color_idx = 0;

    tsec_ctxt_t tsec_ctxt;

    emummc_storage_init_mmc(&storage, &sdmmc);
    //  TPRINTFARGS("%kMMC init...     ", colors[(color_idx++) % 6]);

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

    //TPRINTFARGS("%kTSEC key(s)...  ", colors[(color_idx++) % 6]);

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

    //TPRINTFARGS("%kMaster keys...  ", colors[(color_idx++) % 6]);

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

    nx_emmc_gpt_parse(&gpt, &storage);

    // Find PRODINFO partition.
    prodinfo_part = nx_emmc_part_find(&gpt, "PRODINFO");
    if (!prodinfo_part)
    {
        EPRINTF("Failed to locate PRODINFO.");
        return false;
    }

    se_aes_key_set(8, bis_key[0] + 0x00, 0x10);
    se_aes_key_set(9, bis_key[0] + 0x10, 0x10);

    gfx_printf("%kGot keys!\n", COLOR_GREEN);
    char serial[15];
    readData((u8 *)serial, 0x250, 15, ENCRYPTED);

    gfx_printf("%kCurrent serial:%s\n\n", COLOR_BLUE, serial);

    return true;
}

void erase(u32 offset, u32 length)
{

    u8 *tmp = (u8 *)calloc(length, sizeof(u8));
    writeData(tmp, offset, length, ENCRYPTED);
    free(tmp);
}

void writeSerial()
{
    const char *junkSerial;
    if (!emu_cfg.enabled || h_cfg.emummc_force_disable)
    {
        junkSerial = "XAW00000000000";
    }
    else
    {
        junkSerial = "XAW00000000001";
    }

    writeData((u8 *)junkSerial, 0x250, 14, ENCRYPTED);
}

void incognito()
{

    gfx_printf("%kWriting junk serial...\n", COLOR_YELLOW);

    writeSerial();
    gfx_printf("%kErasing client cert...\n", COLOR_YELLOW);
    erase(0x0AE0, 0x800); // client cert
    gfx_printf("%kErasing private key...\n", COLOR_YELLOW);
    erase(0x3AE0, 0x130); // private key
    gfx_printf("%kErasing deviceId 1/2...\n", COLOR_YELLOW);
    erase(0x35E1, 0x006); // deviceId
    gfx_printf("%kErasing deviceId 2/2...\n", COLOR_YELLOW);
    erase(0x36E1, 0x006); // deviceId
    gfx_printf("%kErasing device cert 1/2...\n", COLOR_YELLOW);
    erase(0x02B0, 0x180); // device cert
    gfx_printf("%kErasing device cert 2/2...\n", COLOR_YELLOW);
    erase(0x3D70, 0x240); // device cert
    gfx_printf("%kErasing device key...\n", COLOR_YELLOW);

    erase(0x3FC0, 0x240); // device key

    gfx_printf("%kWriting client cert hash...\n", COLOR_YELLOW);

    writeClientCertHash();
    gfx_printf("%kWriting CAL0 hash...\n", COLOR_YELLOW);

    writeCal0Hash();

    gfx_printf("\n%kIncognito done!\n\n", COLOR_GREEN);
}

u32 divideCeil(u32 x, u32 y)
{
    return 1 + ((x - 1) / y);
}

void cleanUp()
{

    h_cfg.emummc_force_disable = emummc_load_cfg();
    //nx_emmc_gpt_free(&gpt);
    //   emummc_storage_end(&storage);
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

bool readData(u8 *buffer, u32 offset, u32 length, u8 enc)
{
    bool result = false;
    u32 sector = (offset / NX_EMMC_BLOCKSIZE);
    u32 newOffset = (offset % NX_EMMC_BLOCKSIZE);

    u32 sectorCount = divideCeil(newOffset + length - 1, NX_EMMC_BLOCKSIZE) + 1;
    //u32 sectorCount = ((newOffset + length - 1) / (NX_EMMC_BLOCKSIZE)) + 1;

    u8 *tmp = (u8 *)malloc(sectorCount * NX_EMMC_BLOCKSIZE);

    u32 clusterOffset = sector % SECTORS_IN_CLUSTER;
    u32 sectorOffset = 0;
    while (clusterOffset + sectorCount > SECTORS_IN_CLUSTER)
    {
        u32 sectorsToRead = SECTORS_IN_CLUSTER - clusterOffset;
        if (disk_read_prod(tmp + (sectorOffset * NX_EMMC_BLOCKSIZE), sector, sectorsToRead, enc) != RES_OK)
        {
            goto out;
        }
        sector += sectorsToRead;
        sectorCount -= sectorsToRead;
        clusterOffset = 0;
        sectorOffset += sectorsToRead;
    }
    if(sectorCount == 0) goto done;

    if (disk_read_prod(tmp + (sectorOffset * NX_EMMC_BLOCKSIZE), sector, sectorCount, enc) != RES_OK)
    {
        goto out;
    }

    memcpy(buffer, tmp + newOffset, length);
done:
    result = true;
out:
    free(tmp);
    return result;
}

bool writeData(u8 *buffer, u32 offset, u32 length, u8 enc)
{
    bool result = false;

    u8 *tmp_sec = (u8 *)malloc(NX_EMMC_BLOCKSIZE);
    u8 *tmp = NULL;

    u32 sector = (offset / NX_EMMC_BLOCKSIZE);
    u32 newOffset = (offset % NX_EMMC_BLOCKSIZE);

    // if there is a sector offset, read involved sector, write data to it with offset and write back whole sector to be sector aligned
    if(newOffset > 0){
        
        u32 bytesToRead;
        if(length  > NX_EMMC_BLOCKSIZE){
            bytesToRead = NX_EMMC_BLOCKSIZE - newOffset;
        } else {
            bytesToRead = length - newOffset;
        }
        if(disk_read_prod(tmp_sec, sector, 1, enc) != RES_OK){
            goto out; 
        }
        memcpy(tmp_sec + newOffset, buffer, bytesToRead);
        if(disk_write_prod(tmp_sec, sector, 1, enc) != RES_OK){
            goto out;
        }
        sector++;
        length -= bytesToRead;
        newOffset = bytesToRead;

        // are we done?
        if(length == 0) goto done;
    }
    
    // write whole sectors in chunks while being cluster aligned
    u32 sectorCount = (length - 1 / NX_EMMC_BLOCKSIZE) + 1;
    tmp = (u8 *)malloc(sectorCount * NX_EMMC_BLOCKSIZE);

    u32 clusterOffset = sector % SECTORS_IN_CLUSTER;
    u32 sectorOffset = 0;
    while (clusterOffset + sectorCount > SECTORS_IN_CLUSTER)
    {
        u32 sectorsToRead = SECTORS_IN_CLUSTER - clusterOffset;
        if(disk_write_prod(buffer + newOffset + (sectorOffset * NX_EMMC_BLOCKSIZE), sector, sectorsToRead, enc) != RES_OK){
            goto out;
        }
        sector += sectorsToRead;
        sectorOffset += sectorsToRead;
        sectorCount -= sectorsToRead;
        clusterOffset = 0;
        length -= sectorsToRead * NX_EMMC_BLOCKSIZE;
    }

    // write remaining sectors
    if(sectorCount > 0){
        if(disk_write_prod(buffer + newOffset + (sectorOffset * NX_EMMC_BLOCKSIZE), sector, sectorCount, enc) != RES_OK){
            goto out;
        }
        length -= sectorCount * NX_EMMC_BLOCKSIZE;
        sector += sectorCount;
        sectorOffset += sectorCount;
    }
    
    // if there is data remaining that is smaller than a sector, read that sector, write remaining data to it and write back whole sector 
    if(length == 0) goto done;
    if(length >= NX_EMMC_BLOCKSIZE){
        gfx_printf("\n%kERROR, ERROR!! remaining length: %d\n", COLOR_RED, length);
        goto out;
    }
    if(disk_read_prod(tmp_sec, sector, 1, enc) != RES_OK){
        goto out;
    }
    memcpy(tmp, buffer + newOffset + (sectorOffset * NX_EMMC_BLOCKSIZE), length);
    if(disk_write_prod(tmp_sec, sector, 1, enc) != RES_OK){
        goto out;
    }


done:   
    result = true;
out:
    free(tmp_sec);
    free(tmp);
    return result;


    // u32 sector = (offset / NX_EMMC_BLOCKSIZE);
    // u32 newOffset = (offset % NX_EMMC_BLOCKSIZE);

    // u8 sectorCount = ((newOffset + length - 1) / (NX_EMMC_BLOCKSIZE)) + 1;

    // u8 *tmp = (u8 *)malloc(sectorCount * NX_EMMC_BLOCKSIZE);

    // disk_read_prod(tmp, sector, sectorCount, 1);

    // memcpy(tmp + newOffset, buffer, length);

    // disk_write_prod(tmp, sector, sectorCount, enc);

    // free(tmp);

    // return true;
}

bool writeHash(u32 hashOffset, u32 offset, u32 sz)
{

    u8 *buffer = (u8 *)malloc(sz);
    readData(buffer, offset, sz, ENCRYPTED);
    u8 hash[0x20];
    se_calc_sha256(hash, buffer, sz);

    writeData(hash, hashOffset, 0x20, ENCRYPTED);

    free(buffer);
    return true;
}

// void test(){
//     u32 size = 32768;
//     u8 *buffer = (u8 *)malloc(NX_EMMC_BLOCKSIZE);
//     u8* bigBuffer = (u8 *)malloc(size);
//     u32 offset = 0;
//     readData(bigBuffer, 0, size, ENCRYPTED);
//     while(size > NX_EMMC_BLOCKSIZE){
//         readData(buffer, offset, NX_EMMC_BLOCKSIZE, ENCRYPTED);
//         if(memcmp(buffer, bigBuffer + offset, NX_EMMC_BLOCKSIZE) != 0){
//             gfx_printf("arry mismatch on offset %d", offset);

//         }
//         size -= NX_EMMC_BLOCKSIZE;
//         offset += NX_EMMC_BLOCKSIZE;
//     }
// }

bool verifyHash(u32 hashOffset, u32 offset, u32 sz)
{
    bool result = false;
    u8 *buffer = (u8 *)malloc(sz);
    readData(buffer, offset, sz, ENCRYPTED);
    u8 hash1[0x20];
    se_calc_sha256(hash1, buffer, sz);

    u8 hash2[0x20];

    readData(hash2, hashOffset, 0x20, ENCRYPTED);

    if (memcmp(hash1, hash2, 0x20))
    {
        EPRINTF("error: hash verification failed\n");
        gfx_hexdump(0, hash1, 0x20);
        gfx_hexdump(0, hash2, 0x20);
    }
    else
    {
        result = true;
    }

    free(buffer);
    return result;
}

u32 certSize()
{
    u32 buffer;
    readData((u8 *)&buffer, 0x0AD0, sizeof(buffer), ENCRYPTED);
    return buffer;
}

u32 calibrationDataSize()
{
    u32 buffer;
    readData((u8 *)&buffer, 0x08, sizeof(buffer), ENCRYPTED);
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

    gfx_printf("%kVerifying client cert hash and CAL0 hash...\n", COLOR_YELLOW);

    if (verifyClientCertHash() && verifyCal0Hash())
    {
        char serial[15];
        readData((u8 *)serial, 0x250, 15, ENCRYPTED);
        gfx_printf("%kVerification successful!\n%kNew Serial:%s\n", COLOR_GREEN, COLOR_BLUE, serial);
        return true;
    }
    gfx_printf("%kVerification not successful!\nPlease restore backup!\n", COLOR_RED);
    return false;
}

void print_progress(size_t count, size_t max)
{
    const char prefix[] = "Progress: [";
    const char suffix[] = "]";
    const size_t prefix_length = sizeof(prefix) - 1;
    const size_t suffix_length = sizeof(suffix) - 1;
    char *buffer = calloc(max + prefix_length + suffix_length + 1, 1); // +1 for \0
    size_t i = 0;

    strcpy(buffer, prefix);
    for (; i < max; ++i)
    {
        buffer[prefix_length + i] = i < count ? '#' : ' ';
    }

    strcpy(&buffer[prefix_length + i], suffix);
    gfx_printf("%k%s %d%%\n", COLOR_BLUE, buffer, (100 / max) * count);
    free(buffer);
}

bool backupProdinfo()
{
    char *name;
    if (!emu_cfg.enabled || h_cfg.emummc_force_disable)
    {
        name = "sd:/prodinfo_sysnand.bin";
    }
    else
    {

        name = "sd:/prodinfo_emunand.bin";
    }

    gfx_printf("%kBacking up %s...\n", COLOR_YELLOW, name);

    if (f_stat(name, NULL))
    {
        f_unlink(name);
    }
    FIL fp;
    f_open(&fp, name, FA_CREATE_ALWAYS | FA_WRITE);
    u8 *bufferNX = (u8 *)malloc(NX_EMMC_BLOCKSIZE);
    u32 size = 0x3FBC00;

    u8 percentDone = 0;
    u32 offset = 0;
    const u8 step = 5;

    u32 iterations = size / NX_EMMC_BLOCKSIZE;
    u32 printCount = iterations / (100 / step);

    u32 x = gfx_con.x;
    u32 y = gfx_con.y;

    while (size > NX_EMMC_BLOCKSIZE)
    {
        readData(bufferNX, offset, NX_EMMC_BLOCKSIZE, ENCRYPTED);
        f_write(&fp, bufferNX, NX_EMMC_BLOCKSIZE, NULL);
        f_sync(&fp);

        offset += NX_EMMC_BLOCKSIZE;
        size -= NX_EMMC_BLOCKSIZE;
        if (iterations % printCount == 0)
        {
            print_progress(percentDone / step, 100 / step);
            gfx_con.x = x;
            gfx_con.y = y;
            percentDone += step;
        }
        iterations--;
    }
    if (size > 0)
    {
        readData(bufferNX, offset, size, ENCRYPTED);
        f_write(&fp, bufferNX, size, NULL);
        f_sync(&fp);
    }

    print_progress(100 / step, 100 / step);

    f_close(&fp);
    free(bufferNX);
    gfx_printf("%k\nBackup %s done!\n\n", COLOR_GREEN, name);

    return true;
}

bool restoreProdinfo()
{
    sd_mount();

    char *name;
    if (!emu_cfg.enabled || h_cfg.emummc_force_disable)
    {
        name = "sd:/prodinfo_sysnand.bin";
    }
    else
    {

        name = "sd:/prodinfo_emunand.bin";
    }

    gfx_printf("%kRestoring %s...\n", COLOR_YELLOW, name);

    FIL fp;
    if (f_open(&fp, name, FA_READ) != FR_OK)
    {
        gfx_printf("\nCannot open%s!\n", name);
        return false;
    }
    u8 bufferNX[NX_EMMC_BLOCKSIZE];

    u32 size = 0x3FBC00;

    u8 percentDone = 0;
    u32 offset = 0;
    const u8 step = 5;

    u32 iterations = size / NX_EMMC_BLOCKSIZE;
    u32 printCount = iterations / (100 / step);

    u32 x = gfx_con.x;
    u32 y = gfx_con.y;

    while (size > NX_EMMC_BLOCKSIZE)
    {
        f_read(&fp, bufferNX, NX_EMMC_BLOCKSIZE, NULL);
        writeData(bufferNX, offset, NX_EMMC_BLOCKSIZE, ENCRYPTED);
        offset += NX_EMMC_BLOCKSIZE;
        size -= NX_EMMC_BLOCKSIZE;
        if (iterations % printCount == 0)
        {
            print_progress(percentDone / step, 100 / step);
            gfx_con.x = x;
            gfx_con.y = y;
            percentDone += step;
        }
        iterations--;
    }
    if (size > 0)
    {
        f_read(&fp, bufferNX, size, NULL);
        writeData(bufferNX, offset, size, ENCRYPTED);
    }
    print_progress(100 / step, 100 / step);

    f_close(&fp);

    gfx_printf("%kRestore %s done!\n\n", COLOR_GREEN, name);
    return true;
}
