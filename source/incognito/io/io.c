#include "io.h"

#include <storage/sdmmc.h>
#include "../../storage/nx_emmc.h"
#include "../../storage/emummc.h"

#include <string.h>
#include <sec/se.h>

extern sdmmc_storage_t storage;
extern emmc_part_t *prodinfo_part;

static inline void _gf256_mul_x_le(void *block)
{
    u32 *pdata = (u32 *)block;
    u32 carry = 0;

    for (u32 i = 0; i < 4; i++)
    {
        u32 b = pdata[i];
        pdata[i] = (b << 1) | carry;
        carry = b >> 31;
    }

    if (carry)
        pdata[0x0] ^= 0x87;
}

static int _nx_aes_xts_crypt_sec(u32 tweak_ks, u32 crypt_ks, u32 enc, u8 *tweak, bool regen_tweak, u32 tweak_exp, u32 sec, void *dst, const void *src, u32 sec_size)
{
	u32 *pdst = (u32 *)dst;
	u32 *psrc = (u32 *)src;
	u32 *ptweak = (u32 *)tweak;

	if (regen_tweak)
	{
		for (int i = 0xF; i >= 0; i--)
		{
			tweak[i] = sec & 0xFF;
			sec >>= 8;
		}
		if (!se_aes_crypt_block_ecb(tweak_ks, 1, tweak, tweak))
			return 0;
	}

	// tweak_exp allows us to use a saved tweak to reduce _gf256_mul_x_le calls.
	for (u32 i = 0; i < (tweak_exp << 5); i++)
		_gf256_mul_x_le(tweak);

	u8 orig_tweak[0x10];
	memcpy(orig_tweak, tweak, 0x10);

	// We are assuming a 0x10-aligned sector size in this implementation.
	for (u32 i = 0; i < (sec_size >> 4); i++)
	{
		for (u32 j = 0; j < 4; j++)
			pdst[j] = psrc[j] ^ ptweak[j];

		_gf256_mul_x_le(tweak);
		psrc += 4;
		pdst += 4;
	}

	if (!se_aes_crypt_ecb(crypt_ks, enc, dst, sec_size, dst, sec_size))
		return 0;

	pdst = (u32 *)dst;
	ptweak = (u32 *)orig_tweak;
	for (u32 i = 0; i < (sec_size >> 4); i++)
	{
		for (u32 j = 0; j < 4; j++)
			pdst[j] = pdst[j] ^ ptweak[j];

		_gf256_mul_x_le(orig_tweak);
		pdst += 4;
	}

	return 1;
}

// replacement for nx_emmc_part_write in storage/nx_emmc, which uses sdmmc_storage_write
int nx_emummc_part_write(sdmmc_storage_t *storage, emmc_part_t *part, u32 sector_off, u32 num_sectors, void *buf)
{
	// The last LBA is inclusive.
	if (part->lba_start + sector_off > part->lba_end)
		return 0;
	return emummc_storage_write(storage, part->lba_start + sector_off, num_sectors, buf);
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

    if (nx_emmc_part_read(&emmc_storage, prodinfo_part, sector, count, buff))
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
        result = _nx_aes_xts_crypt_sec(9, 8, 0, tweak, regen_tweak, tweak_exp, prev_cluster, buff, buff, count * 0x200);

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
    if(!_nx_aes_xts_crypt_sec(9, 8, 1, tweak, regen_tweak, tweak_exp, prev_cluster, buff, buff, count * 0x200)){
        return false;
    }
    if (nx_emummc_part_write(&emmc_storage, prodinfo_part, sector, count, buff))
    {
        prev_sector = sector + count - 1;
        return true;
    }

    return false;
}
