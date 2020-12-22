/*
 * Copyright (c) 2019-2020 shchmue
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

/*-----------------------------------------------------------------------*/
/* Low level disk I/O module skeleton for FatFs     (C)ChaN, 2016        */
/*-----------------------------------------------------------------------*/
/* If a working storage control module is available, it should be        */
/* attached to the FatFs via a glue function rather than modifying it.   */
/* This is an example of glue functions to attach various exsisting      */
/* storage control modules to the FatFs module with a defined API.       */
/*-----------------------------------------------------------------------*/

#include <string.h>

#include "../../../common/memory_map.h"

#include "diskio.h"		/* FatFs lower layer API */
#include "../../mem/heap.h"
#include "../../sec/se.h"
#include "../../storage/nx_emmc.h"
#include "../../storage/sdmmc.h"

extern sdmmc_storage_t sd_storage;
extern sdmmc_storage_t storage;
extern emmc_part_t *system_part;

#define MAX_CLUSTER_CACHE_ENTRIES 128
#define CLUSTER_LOOKUP_EMPTY_ENTRY 0xFFFFFFFF
#define XTS_CLUSTER_SIZE 0x4000
#define SECTORS_PER_CLUSTER 0x20

typedef struct {
    u32 cluster_num;        // index of the cluster in the partition
    u32 visit_count;        // used for debugging/access analysis
    u8  dirty;              // has been modified without writeback flag
    u8  align[7];
    u8  cluster[XTS_CLUSTER_SIZE];    // the cached cluster itself
} cluster_cache_t;

static cluster_cache_t *cluster_cache = (cluster_cache_t *)RAM_DISK_ADDR;
u32 cluster_cache_index = 0;
u32 *cluster_lookup = (u32 *)(RAM_DISK_ADDR + MAX_CLUSTER_CACHE_ENTRIES * sizeof(cluster_cache_t));
u8 *emmc_buffer = (u8 *)(MIXD_BUF_ALIGNED + 0x100000);

bool clear_cluster_cache = false;
bool lock_cluster_cache = false;

DSTATUS disk_status (
    BYTE pdrv /* Physical drive number to identify the drive */
)
{
    return 0;
}

DSTATUS disk_initialize (
    BYTE pdrv /* Physical drive number to identify the drive */
)
{
    return 0;
}

static inline void _gf256_mul_x_le(void *block)
{
    u32 *pdata = (u32 *)block;
    u32 carry = 0;

    for (u32 i = 0; i < 4; i++) {
        u32 b = pdata[i];
        pdata[i] = (b << 1) | carry;
        carry = b >> 31;
    }

    if (carry)
        pdata[0x0] ^= 0x87;
}

static inline int _emmc_xts(u32 ks1, u32 ks2, u32 enc, u8 *tweak, bool regen_tweak, u32 tweak_exp, u64 sec, void *dst, void *src, u32 secsize)
{
    int res = 0;
    u8 *temptweak = (u8 *)malloc(0x10);
	u32 *pdst = (u32 *)dst;
    u32 *psrc = (u32 *)src;
    u32 *ptweak = (u32 *)tweak;

    if (regen_tweak) {
        for (int i = 0xF; i >= 0; i--) {
            tweak[i] = sec & 0xFF;
            sec >>= 8;
        }
        if (!se_aes_crypt_block_ecb(ks1, 1, tweak, tweak))
            goto out;
    }

    // tweak_exp allows us to use a saved tweak to reduce _gf256_mul_x_le calls
    for (u32 i = 0; i < tweak_exp * SECTORS_PER_CLUSTER; i++)
        _gf256_mul_x_le(tweak);

    memcpy(temptweak, tweak, 0x10);

    // The reference implementation in IEEE P1619 encrypts once per AES block
    // In this environment, doing so produces a lot of overhead
    // Instead, we perform one single AES-ECB operation between the sector xors

    // We are assuming a 0x10-aligned sector size in this implementation.
    for (u32 i = 0; i < secsize / 0x10; i++)
    {
        for (u32 j = 0; j < 4; j++)
            pdst[j] = psrc[j] ^ ptweak[j];
        _gf256_mul_x_le(tweak);
        psrc += 4;
        pdst += 4;
    }

    se_aes_crypt_ecb(ks2, enc, dst, secsize, dst, secsize);

    pdst = (u32 *)dst;

    memcpy(tweak, temptweak, 0x10);
    for (u32 i = 0; i < secsize / 0x10; i++)
	{
        for (u32 j = 0; j < 4; j++)
            pdst[j] = pdst[j] ^ ptweak[j];
        _gf256_mul_x_le(tweak);
        pdst += 4;
    }

    res = 1;

out:;
    free(temptweak);
    return res;
}

DRESULT disk_read (
    BYTE pdrv,		/* Physical drive number to identify the drive */
    BYTE *buff,		/* Data buffer to store read data */
    DWORD sector,	/* Start sector in LBA */
    UINT count		/* Number of sectors to read */
)
{
    switch (pdrv)
    {
    case 0:
        return sdmmc_storage_read(&sd_storage, sector, count, buff) ? RES_OK : RES_ERROR;

    case 1:;
        __attribute__ ((aligned (16))) static u8 tweak[0x10];
        __attribute__ ((aligned (16))) static u64 prev_cluster = -1;
        __attribute__ ((aligned (16))) static u32 prev_sector = 0;

        if (cluster_cache_index == 0 || clear_cluster_cache)
        {
            // memset gets optimized out...
            // for (u32 i = 0; i < (system_part->lba_end - system_part->lba_start + 1) / SECTORS_PER_CLUSTER; i++)
            //     cluster_lookup[i] = CLUSTER_LOOKUP_EMPTY_ENTRY;
            memset(cluster_lookup, -1, (system_part->lba_end - system_part->lba_start + 1) / SECTORS_PER_CLUSTER * 4);
            cluster_cache_index = 0;
            clear_cluster_cache = false;
            lock_cluster_cache = false;
        }

        u32 cluster = sector / SECTORS_PER_CLUSTER;
        u32 aligned_sector = cluster * SECTORS_PER_CLUSTER;
        u32 sector_index_in_cluster = sector % SECTORS_PER_CLUSTER;
        u32 cluster_lookup_index = cluster_lookup[cluster];

        if (cluster_lookup_index != CLUSTER_LOOKUP_EMPTY_ENTRY)
        {
            memcpy(buff, cluster_cache[cluster_lookup_index].cluster + sector_index_in_cluster * NX_EMMC_BLOCKSIZE, count * NX_EMMC_BLOCKSIZE);
            cluster_cache[cluster_lookup_index].visit_count++;
            prev_sector = sector + count - 1;
            prev_cluster = cluster;
            return RES_OK;
        }

        // Only cache single-sector reads as these are most likely to be repeated (eg. boot block, FAT directory tables)
        if (count == 1 &&
            !lock_cluster_cache &&
            cluster_cache_index < MAX_CLUSTER_CACHE_ENTRIES &&
            cluster_lookup_index == CLUSTER_LOOKUP_EMPTY_ENTRY)
        {
            cluster_cache[cluster_cache_index].cluster_num = cluster;
            cluster_cache[cluster_cache_index].visit_count = 1;
            cluster_cache[cluster_cache_index].dirty = 0;
            cluster_lookup[cluster] = cluster_cache_index;

            // Read and decrypt the whole cluster the sector resides in
            if (!nx_emmc_part_read(&storage, system_part, aligned_sector, SECTORS_PER_CLUSTER, emmc_buffer))
                return RES_ERROR;
            _emmc_xts(9, 8, 0, tweak, true, 0, cluster, emmc_buffer, emmc_buffer, XTS_CLUSTER_SIZE);
            memcpy(cluster_cache[cluster_cache_index].cluster, emmc_buffer, XTS_CLUSTER_SIZE);
            memcpy(buff, emmc_buffer + sector_index_in_cluster * NX_EMMC_BLOCKSIZE, NX_EMMC_BLOCKSIZE);
            prev_cluster = -1;
            prev_sector = 0;
            cluster_cache_index++;
            return RES_OK;
        }

        if (!nx_emmc_part_read(&storage, system_part, sector, count, buff))
            return RES_ERROR;
        u32 tweak_exp = 0;
        bool regen_tweak = true;
        if (prev_cluster != cluster)
        { // Sector is in different cluster than last read
            prev_cluster = cluster;
            tweak_exp = sector_index_in_cluster;
        }
        else if (sector > prev_sector)
        { // Sector is in same cluster and past last sector
            // Calculates the new tweak using the saved one, reducing expensive _gf256_mul_x_le calls
            tweak_exp = sector - prev_sector - 1;
            regen_tweak = false;
        }
        else
        { // Sector is in same cluster and before or same as last sector
            tweak_exp = sector_index_in_cluster;
        }

        // FatFs will never pull more than one 4K cluster, which is the same as the crypto 'sector' size
        _emmc_xts(9, 8, 0, tweak, regen_tweak, tweak_exp, prev_cluster, buff, buff, count * NX_EMMC_BLOCKSIZE);
        prev_sector = sector + count - 1;
        return RES_OK;
    }

    return RES_ERROR;
}

DRESULT disk_write (
    BYTE pdrv,			/* Physical drive number to identify the drive */
    const BYTE *buff,	/* Data to be written */
    DWORD sector,		/* Start sector in LBA */
    UINT count			/* Number of sectors to write */
)
{
    switch (pdrv)
    {
    case 0:
        return sdmmc_storage_write(&sd_storage, sector, count, (void *)buff) ? RES_OK : RES_ERROR;

    case 1:
        return RES_WRPRT;
	}

    return RES_ERROR;
}

DRESULT disk_ioctl (
    BYTE pdrv,		/* Physical drive number (0..) */
    BYTE cmd,		/* Control code */
    void *buff		/* Buffer to send/receive control data */
)
{
    return RES_OK;
}
