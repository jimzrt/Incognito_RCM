#include "io.h"

#include "../../storage/sdmmc.h"
#include "../../storage/nx_emmc.h"

#include <string.h>
#include "../../sec/se.h"

extern sdmmc_storage_t storage;
extern emmc_part_t *prodinfo_part;

static inline void _gf256_mul_x_le(void *block)
{
    u8 *pdata = (u8 *)block;
    u32 carry = 0;

    for (u32 i = 0; i < 0x10; i++)
    {
        u8 b = pdata[i];
        pdata[i] = (b << 1) | carry;
        carry = b >> 7;
    }

    if (carry)
        pdata[0x0] ^= 0x87;
}

static inline int _emmc_xts(u32 ks1, u32 ks2, u32 enc, u8 *tweak, bool regen_tweak, u32 tweak_exp, u64 sec, void *dst, void *src, u32 secsize)
{
    int res = 0;
    u8 *pdst = (u8 *)dst;
    u8 *psrc = (u8 *)src;

    if (regen_tweak)
    {
        for (int i = 0xF; i >= 0; i--)
        {
            tweak[i] = sec & 0xFF;
            sec >>= 8;
        }
        if (!se_aes_crypt_block_ecb(ks1, 1, tweak, tweak))
            goto out;
    }

    for (u32 i = 0; i < tweak_exp * 0x20; i++)
        _gf256_mul_x_le(tweak);

    u8 temptweak[0x10];
    memcpy(temptweak, tweak, 0x10);

    //We are assuming a 0x10-aligned sector size in this implementation.
    for (u32 i = 0; i < secsize / 0x10; i++)
    {
        for (u32 j = 0; j < 0x10; j++)
            pdst[j] = psrc[j] ^ tweak[j];
        _gf256_mul_x_le(tweak);
        psrc += 0x10;
        pdst += 0x10;
    }

    se_aes_crypt_ecb(ks2, enc, dst, secsize, src, secsize);

    pdst = (u8 *)dst;

    memcpy(tweak, temptweak, 0x10);
    for (u32 i = 0; i < secsize / 0x10; i++)
    {
        for (u32 j = 0; j < 0x10; j++)
            pdst[j] = pdst[j] ^ tweak[j];
        _gf256_mul_x_le(tweak);
        pdst += 0x10;
    }

    res = 1;

out:;
    return res;
}


bool prodinfo_read(
    u8 *buff,   /* Data buffer to store read data */
    u32 sector, /* Start sector in LBA */
    u32 count   /* Number of sectors to read */
    )
{
    bool result = false;
    __attribute__((aligned(16))) static u8 tweak[0x10];
    __attribute__((aligned(16))) static u64 prev_cluster = -1;
    __attribute__((aligned(16))) static u32 prev_sector = 0;
    u32 tweak_exp = 0;
    bool regen_tweak = true;

    if (nx_emmc_part_read(&storage, prodinfo_part, sector, count, buff))
    {
        if (prev_cluster != sector / 0x20)
        { // sector in different cluster than last read
            prev_cluster = sector / 0x20;
            tweak_exp = sector % 0x20;
        }
        else if (sector > prev_sector)
        { // sector in same cluster and past last sector
            tweak_exp = sector - prev_sector - 1;
            regen_tweak = false;
        }
        else
        { // sector in same cluster and before or same as last sector
            tweak_exp = sector % 0x20;
        }

        // fatfs will never pull more than a cluster
        result = _emmc_xts(9, 8, 0, tweak, regen_tweak, tweak_exp, prev_cluster, buff, buff, count * 0x200);

        prev_sector = sector + count - 1;
        return result;
    }

    return result;
}

bool prodinfo_write(
    u8 *buff,   /* Data buffer to store read data */
    u32 sector, /* Start sector in LBA */
    u32 count   /* Number of sectors to read */
    )
{
    __attribute__((aligned(16))) static u8 tweak[0x10];
    __attribute__((aligned(16))) static u64 prev_cluster = -1;
    __attribute__((aligned(16))) static u32 prev_sector = 0;
    u32 tweak_exp = 0;
    bool regen_tweak = true;

    if (prev_cluster != sector / 0x20)
    { // sector in different cluster than last read
        prev_cluster = sector / 0x20;
        tweak_exp = sector % 0x20;
    }
    else if (sector > prev_sector)
    { // sector in same cluster and past last sector
        tweak_exp = sector - prev_sector - 1;
        regen_tweak = false;
    }
    else
    { // sector in same cluster and before or same as last sector
        tweak_exp = sector % 0x20;
    }

    // fatfs will never pull more than a cluster
    if(!_emmc_xts(9, 8, 1, tweak, regen_tweak, tweak_exp, prev_cluster, buff, buff, count * 0x200)){
        return false;
    }
    if (nx_emmc_part_write(&storage, prodinfo_part, sector, count, buff))
    {
        prev_sector = sector + count - 1;
        return true;
    }

    return false;
}