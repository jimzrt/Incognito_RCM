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

#include "incognito.h"

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
#include "../utils/list.h"
#include "../utils/sprintf.h"
#include "../utils/util.h"

#include "key_sources.inl"

#include "io/io.h"
#include <string.h>

#define RETRY_COUNT 5
#define RETRY(exp)                                                                              \
    ({                                                                                          \
        u8 _attemptc_ = RETRY_COUNT;                                                            \
        bool _resultb_ = false;                                                                 \
        while (_attemptc_--)                                                                    \
        {                                                                                       \
            if ((_resultb_ = exp))                                                              \
                break;                                                                          \
            gfx_printf("%kretry %d/%d...\n", COLOR_RED, RETRY_COUNT - _attemptc_, RETRY_COUNT); \
        }                                                                                       \
        _resultb_;                                                                              \
    })

extern bool sd_mount();
extern void sd_unmount();
extern int sd_save_to_file(void *buf, u32 size, const char *filename);

extern hekate_config h_cfg;

u32 _key_count = 0;
sdmmc_storage_t storage;
sdmmc_t sdmmc;
emmc_part_t *system_part;
emmc_part_t *prodinfo_part;

#define SECTORS_IN_CLUSTER 32
#define PRODINFO_SIZE 0x3FBC00

#define BACKUP_NAME_EMUNAND "sd:/prodinfo_emunand.bin"
#define BACKUP_NAME_SYSNAND "sd:/prodinfo_sysnand.bin"

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

    gfx_printf("%kGetting bis_keys...\n", COLOR_YELLOW);

    u32 retries = 0;

    tsec_ctxt_t tsec_ctxt;

    if (!emummc_storage_init_mmc(&storage, &sdmmc))
    {
        EPRINTF("Unable to init MMC.");
        return false;
    }

    // Read package1.
    u8 *pkg1 = (u8 *)malloc(0x40000);
    emummc_storage_set_mmc_partition(&storage, 1);
    emummc_storage_read(&storage, 0x100000 / NX_EMMC_BLOCKSIZE, 0x40000 / NX_EMMC_BLOCKSIZE, pkg1);
    const pkg1_id_t *pkg1_id = pkg1_identify(pkg1);
    if (!pkg1_id)
    {
        EPRINTF("Unknown pkg1 version.");
        free(pkg1);
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
        free(pkg1);
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
            // gfx_hexdump(i, keyblob_block, 0x10);
            // gfx_hexdump(i, keyblob_mac, 0x10);
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

    gfx_printf("%kGot keys!\n%kValidate...", COLOR_GREEN, COLOR_YELLOW);
    const char magic[4] = "CAL0";
    char buffer[4];
    readData((u8 *)buffer, 0, 4, NULL);
    if (memcmp(magic, buffer, 4) == 0)
    {
        gfx_printf("%kOK!\n", COLOR_GREEN);
    }
    else
    {
        gfx_printf("%kError!\n", COLOR_RED);
        return false;
    }

    char serial[15] = "";
    readData((u8 *)serial, 0x250, 14, NULL);

    gfx_printf("%kCurrent serial:%s\n\n", COLOR_BLUE, serial);

    return true;
}

bool erase(u32 offset, u32 length)
{

    u8 *tmp = (u8 *)calloc(length, sizeof(u8));
    bool result = writeData(tmp, offset, length, NULL);
    free(tmp);
    return result;
}

bool writeSerial()
{
    const char *junkSerial;
    if (isSysNAND())
    {
        junkSerial = "XAW00000000000";
    }
    else
    {
        junkSerial = "XAW00000000001";
    }

    return writeData((u8 *)junkSerial, 0x250, 14, NULL);
}

bool incognito()
{
    gfx_printf("%kChecking if backup exists...\n", COLOR_YELLOW);
    if (!checkBackupExists())
    {
        gfx_printf("%kI'm sorry Dave, I'm afraid I can't do that..\n%kWill make a backup first...\n", COLOR_RED, COLOR_YELLOW);
        if (!backupProdinfo())
            return false;
    }

    gfx_printf("%kWriting junk serial...\n", COLOR_YELLOW);
    if (!writeSerial())
        return false;

    gfx_printf("%kErasing client cert...\n", COLOR_YELLOW);
    if (!erase(0x0AE0, 0x800)) // client cert
        return false;

    gfx_printf("%kErasing private key...\n", COLOR_YELLOW);
    if (!erase(0x3AE0, 0x130)) // private key
        return false;

    gfx_printf("%kErasing deviceId 1/2...\n", COLOR_YELLOW);
    if (!erase(0x35E1, 0x006)) // deviceId
        return false;

    gfx_printf("%kErasing deviceId 2/2...\n", COLOR_YELLOW);
    if (!erase(0x36E1, 0x006)) // deviceId
        return false;

    gfx_printf("%kErasing device cert 1/2...\n", COLOR_YELLOW);
    if (!erase(0x02B0, 0x180)) // device cert
        return false;

    gfx_printf("%kErasing device cert 2/2...\n", COLOR_YELLOW);
    if (!erase(0x3D70, 0x240)) // device cert
        return false;

    gfx_printf("%kErasing device key...\n", COLOR_YELLOW);
    if (!erase(0x3FC0, 0x240)) // device key
        return false;

    gfx_printf("%kWriting client cert hash...\n", COLOR_YELLOW);
    if (!writeClientCertHash())
        return false;

    gfx_printf("%kWriting CAL0 hash...\n", COLOR_YELLOW);
    if (!writeCal0Hash())
        return false;

    gfx_printf("\n%kIncognito done!\n", COLOR_GREEN);
    return true;
}

u32 divideCeil(u32 x, u32 y)
{
    return 1 + ((x - 1) / y);
}

void cleanUp()
{

    h_cfg.emummc_force_disable = emummc_load_cfg();
    //nx_emmc_gpt_free(&gpt);
    //emummc_storage_end(&storage);
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

bool readData(u8 *buffer, u32 offset, u32 length, void (*progress_callback)(u32, u32))
{
    if (progress_callback != NULL)
    {
        (*progress_callback)(0, length);
    }
    bool result = false;
    u32 sector = (offset / NX_EMMC_BLOCKSIZE);
    u32 newOffset = (offset % NX_EMMC_BLOCKSIZE);

    u32 sectorCount = divideCeil(newOffset + length, NX_EMMC_BLOCKSIZE);

    u8 *tmp = (u8 *)malloc(sectorCount * NX_EMMC_BLOCKSIZE);

    u32 clusterOffset = sector % SECTORS_IN_CLUSTER;
    u32 sectorOffset = 0;
    while (clusterOffset + sectorCount > SECTORS_IN_CLUSTER)
    {
        u32 sectorsToRead = SECTORS_IN_CLUSTER - clusterOffset;
        if (!RETRY(prodinfo_read(tmp + (sectorOffset * NX_EMMC_BLOCKSIZE), sector, sectorsToRead)))
            goto out;

        sector += sectorsToRead;
        sectorCount -= sectorsToRead;
        clusterOffset = 0;
        sectorOffset += sectorsToRead;
        if (progress_callback != NULL)
        {
            (*progress_callback)(sectorOffset * NX_EMMC_BLOCKSIZE, length);
        }
    }
    if (sectorCount == 0)
        goto done;

    if (!RETRY(prodinfo_read(tmp + (sectorOffset * NX_EMMC_BLOCKSIZE), sector, sectorCount)))
        goto out;

    memcpy(buffer, tmp + newOffset, length);
done:
    result = true;
    if (progress_callback != NULL)
    {
        (*progress_callback)(length, length);
    }
out:
    free(tmp);
    return result;
}

bool writeData(u8 *buffer, u32 offset, u32 length, void (*progress_callback)(u32, u32))
{
    if (progress_callback != NULL)
    {
        (*progress_callback)(0, length);
    }
    bool result = false;

    u32 initialLength = length;

    u8 *tmp_sec = (u8 *)malloc(NX_EMMC_BLOCKSIZE);
    u8 *tmp = NULL;

    u32 sector = (offset / NX_EMMC_BLOCKSIZE);
    u32 newOffset = (offset % NX_EMMC_BLOCKSIZE);

    // if there is a sector offset, read involved sector, write data to it with offset and write back whole sector to be sector aligned
    if (newOffset > 0)
    {
        u32 bytesToRead = NX_EMMC_BLOCKSIZE - newOffset;
        u32 bytesToWrite;
        if (length >= bytesToRead)
        {
            bytesToWrite = bytesToRead;
        }
        else
        {
            bytesToWrite = length;
        }
        if (!RETRY(prodinfo_read(tmp_sec, sector, 1)))
            goto out;

        memcpy(tmp_sec + newOffset, buffer, bytesToWrite);
        if (!RETRY(prodinfo_write(tmp_sec, sector, 1)))
            goto out;

        sector++;
        length -= bytesToWrite;
        newOffset = bytesToWrite;

        if (progress_callback != NULL)
        {
            (*progress_callback)(initialLength - length, initialLength);
        }
        // are we done?
        if (length == 0)
            goto done;
    }

    // write whole sectors in chunks while being cluster aligned
    u32 sectorCount = length / NX_EMMC_BLOCKSIZE;
    tmp = (u8 *)malloc(sectorCount * NX_EMMC_BLOCKSIZE);

    u32 clusterOffset = sector % SECTORS_IN_CLUSTER;
    u32 sectorOffset = 0;
    while (clusterOffset + sectorCount >= SECTORS_IN_CLUSTER)
    {
        u32 sectorsToRead = SECTORS_IN_CLUSTER - clusterOffset;
        if (!RETRY(prodinfo_write(buffer + newOffset + (sectorOffset * NX_EMMC_BLOCKSIZE), sector, sectorsToRead)))
            goto out;

        sector += sectorsToRead;
        sectorOffset += sectorsToRead;
        sectorCount -= sectorsToRead;
        clusterOffset = 0;
        length -= sectorsToRead * NX_EMMC_BLOCKSIZE;

        if (progress_callback != NULL)
        {
            (*progress_callback)(initialLength - length, initialLength);
        }
    }

    // write remaining sectors
    if (sectorCount > 0)
    {
        if (!RETRY(prodinfo_write(buffer + newOffset + (sectorOffset * NX_EMMC_BLOCKSIZE), sector, sectorCount)))
            goto out;

        length -= sectorCount * NX_EMMC_BLOCKSIZE;
        sector += sectorCount;
        sectorOffset += sectorCount;

        if (progress_callback != NULL)
        {
            (*progress_callback)(initialLength - length, initialLength);
        }
    }

    // if there is data remaining that is smaller than a sector, read that sector, write remaining data to it and write back whole sector
    if (length == 0)
        goto done;

    if (length > NX_EMMC_BLOCKSIZE)
    {
        gfx_printf("%kERROR, ERRO! Length is %d!\n", COLOR_RED, length);
        goto out;
    }

    if (!RETRY(prodinfo_read(tmp_sec, sector, 1)))
        goto out;

    memcpy(tmp_sec, buffer + newOffset + (sectorOffset * NX_EMMC_BLOCKSIZE), length);
    if (!RETRY(prodinfo_write(tmp_sec, sector, 1)))
        goto out;

done:
    result = true;
    if (progress_callback != NULL)
    {
        (*progress_callback)(initialLength, initialLength);
    }
out:
    free(tmp_sec);
    free(tmp);
    return result;
}

bool writeHash(u32 hashOffset, u32 offset, u32 sz)
{
    bool result = false;
    u8 *buffer = (u8 *)malloc(sz);
    if (!readData(buffer, offset, sz, NULL))
    {
        goto out;
    }
    u8 hash[0x20];
    se_calc_sha256(hash, buffer, sz);

    if (!writeData(hash, hashOffset, 0x20, NULL))
    {
        goto out;
    }
    result = true;
out:
    free(buffer);
    return result;
}

#ifdef DEBUG
void screenshot(const char *filename)
{
    sd_mount();

    FIL fp;
    if (f_open(&fp, filename, FA_CREATE_ALWAYS | FA_WRITE) != FR_OK)
    {
        gfx_printf("\n%kCannot write image!\n", COLOR_RED);
        return;
    }
    u32 size;
    u8 *buffer = gfx_bmp_screenshot(&size);

    f_write(&fp, buffer, size, NULL);
    f_close(&fp);
    free(buffer);
}
#endif

bool verifyHash(u32 hashOffset, u32 offset, u32 sz, u8 *blob)
{
    bool result = false;
    u8 *buffer = (u8 *)malloc(sz);
    if (blob == NULL)
    {
        if (!readData(buffer, offset, sz, NULL))
            goto out;
    }
    else
    {
        memcpy(buffer, blob + offset, sz);
    }
    u8 hash1[0x20];
    se_calc_sha256(hash1, buffer, sz);

    u8 hash2[0x20];

    if (blob == NULL)
    {
        if (!readData(hash2, hashOffset, 0x20, NULL))
            goto out;
    }
    else
    {
        memcpy(hash2, blob + hashOffset, 0x20);
    }

    if (memcmp(hash1, hash2, 0x20))
    {
        EPRINTF("error: hash verification failed\n");
        // gfx_hexdump(0, hash1, 0x20);
        // gfx_hexdump(0, hash2, 0x20);
        goto out;
    }

    result = true;
out:
    free(buffer);
    return result;
}

s32 getClientCertSize(u8 *blob)
{
    s32 buffer;
    if (blob == NULL)
    {
        if (!RETRY(readData((u8 *)&buffer, 0x0AD0, sizeof(buffer), NULL)))
        {
            return -1;
        }
    }
    else
    {
        memcpy(&buffer, blob + 0x0AD0, sizeof(buffer));
    }
    return buffer;
}

s32 getCalibrationDataSize(u8 *blob)
{
    s32 buffer;
    if (blob == NULL)
    {
        if (!RETRY(readData((u8 *)&buffer, 0x08, sizeof(buffer), NULL)))
        {
            return -1;
        }
    }
    else
    {
        memcpy(&buffer, blob + 0x08, sizeof(buffer));
    }

    return buffer;
}

bool writeCal0Hash()
{
    s32 calibrationSize = getCalibrationDataSize(NULL);
    if (calibrationSize == -1)
        return false;

    return writeHash(0x20, 0x40, calibrationSize);
}

bool writeClientCertHash()
{
    s32 certSize = getClientCertSize(NULL);
    if (certSize == -1)
        return false;

    return writeHash(0x12E0, 0xAE0, certSize);
}

bool verifyCal0Hash(u8 *blob)
{
    s32 calibrationSize = getCalibrationDataSize(blob);
    if (calibrationSize == -1)
        return false;

    return verifyHash(0x20, 0x40, calibrationSize, blob);
}

bool verifyClientCertHash(u8 *blob)
{
    s32 certSize = getClientCertSize(blob);
    if (certSize == -1)
        return false;

    return verifyHash(0x12E0, 0xAE0, certSize, blob);
}

bool verifyProdinfo(u8 *blob)
{
    gfx_printf("%kVerifying client cert hash and CAL0 hash%s...\n", COLOR_YELLOW, blob != NULL ? "\nfrom backup" : "");

    if (verifyClientCertHash(blob) && verifyCal0Hash(blob))
    {
        char serial[15] = "";
        if (blob == NULL)
        {
            readData((u8 *)serial, 0x250, 14, NULL);
        }
        else
        {
            memcpy(serial, blob + 0x250, 14);
        }

        gfx_printf("%kVerification successful!\n%kSerial:%s\n", COLOR_GREEN, COLOR_BLUE, serial);
        return true;
    }
    gfx_printf("%kVerification not successful!\n", COLOR_RED);
    return false;
}

void print_progress(u32 count, u32 max)
{
    tui_pbar(0, gfx_con.y + 1, (int)(count * 100 / (float)max), COLOR_BLUE, COLOR_ORANGE);
}

// bool getLastBackup()
// {
//     DIR dir;
//     //char* path = "sd:/incognito";
//     char path[255];
//     strcpy(path, "sd:/incognito");
//     FILINFO fno;
//     FRESULT res;

//     res = f_opendir(&dir, path); /* Open the directory */
//     if (res == FR_OK)
//     {
//         for (;;)
//         {
//             res = f_readdir(&dir, &fno); /* Read a directory item */
//             if (res != FR_OK || fno.fname[0] == 0)
//                 break; /* Break on error or end of dir */
//             if ((fno.fattrib & AM_DIR) == 0)
//             { /* It is not a directory */
//                 gfx_printf("%s/%s\n", path, fno.fname);
//             }
//         }
//         f_closedir(&dir);
//     }

//     return res;
// }

bool isSysNAND()
{
    return (!emu_cfg.enabled || h_cfg.emummc_force_disable);
}

bool checkBackupExists()
{
    char *name;
    if (isSysNAND())
    {
        name = BACKUP_NAME_SYSNAND;
    }
    else
    {
        name = BACKUP_NAME_EMUNAND;
    }
    return f_stat(name, NULL) == FR_OK;
}

bool backupProdinfo()
{
    bool result = false;
    char *name;
    if (isSysNAND())
    {
        name = BACKUP_NAME_SYSNAND;
    }
    else
    {
        name = BACKUP_NAME_EMUNAND;
    }

    gfx_printf("%kBacking up %s...\n", COLOR_YELLOW, name);
    if (checkBackupExists())
    {
        gfx_printf("%kBackup already exists!\nWill rename old backup.\n", COLOR_ORANGE);
        u32 filenameSuffix = 0;
        char newName[255];
        do
        {
            sprintf(newName, "%s.%d", name, filenameSuffix);
            filenameSuffix++;
        } while (f_stat(newName, NULL) == FR_OK);
        f_rename(name, newName);
        gfx_printf("%kOld backup renamed to:\n%s\n", COLOR_YELLOW, newName);
    }

    FIL fp;
    if (f_open(&fp, name, FA_CREATE_ALWAYS | FA_WRITE) != FR_OK)
    {
        gfx_printf("\n%kCannot write to %s!\n", COLOR_RED, name);
        return false;
    }

    u8 *bufferNX = (u8 *)malloc(PRODINFO_SIZE);
    gfx_printf("%kReading from NAND...\n", COLOR_YELLOW);
    if (!readData(bufferNX, 0, PRODINFO_SIZE, print_progress))
    {
        gfx_printf("\n%kError reading from NAND!\n", COLOR_RED);
        goto out;
    }
    gfx_putc('\n');
    if (!verifyProdinfo(bufferNX))
    {
        goto out;
    }
    gfx_printf("%k\nWriting to file...\n", COLOR_YELLOW);
    u32 bytesWritten;
    if (f_write(&fp, bufferNX, PRODINFO_SIZE, &bytesWritten) != FR_OK || bytesWritten != PRODINFO_SIZE)
    {
        gfx_printf("\n%kError writing to file!\nPlease try again. If this doesn't work, you don't have a working backup!\n", COLOR_RED);
        goto out;
    }
    f_sync(&fp);

    result = true;
    gfx_printf("\n%kBackup to %s done!\n", COLOR_GREEN, name);

out:
    f_close(&fp);
    free(bufferNX);

    return result;
}

bool restoreProdinfo()
{
    bool result = false;
    sd_mount();

    const char *name;
    if (isSysNAND())
    {
        name = BACKUP_NAME_SYSNAND;
    }
    else
    {
        name = BACKUP_NAME_EMUNAND;
    }

    gfx_printf("%kRestoring from %s...\n", COLOR_YELLOW, name);

    FIL fp;
    if (f_open(&fp, name, FA_READ) != FR_OK)
    {
        gfx_printf("\n%kCannot open %s!\n", COLOR_RED, name);
        return false;
    }

    u8 *bufferNX = (u8 *)malloc(PRODINFO_SIZE);
    u32 bytesRead;
    gfx_printf("%kReading from file...\n", COLOR_YELLOW);
    if (f_read(&fp, bufferNX, PRODINFO_SIZE, &bytesRead) != FR_OK || bytesRead != PRODINFO_SIZE)
    {
        gfx_printf("\n%kError reading from file!\n", COLOR_RED);
        goto out;
    }
    if (!verifyProdinfo(bufferNX))
    {
        goto out;
    }
    gfx_printf("%kWriting to NAND...\n", COLOR_YELLOW);
    if (!writeData(bufferNX, 0, PRODINFO_SIZE, print_progress))
    {
        gfx_printf("\n%kError writing to NAND!\nThis is bad. Try again, because your switch probably won't boot.\n"
                   "If you see this error again, you should restore via NAND backup in hekate.\n",
                   COLOR_RED);
        goto out;
    }

    result = true;
    gfx_printf("\n%kRestore from %s done!\n\n", COLOR_GREEN, name);
out:
    f_close(&fp);
    free(bufferNX);

    return result;
}
