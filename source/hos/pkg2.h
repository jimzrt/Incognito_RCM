/*
 * Copyright (c) 2018 naehrwert
 * Copyright (c) 2018-2020 CTCaer
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

#ifndef _PKG2_H_
#define _PKG2_H_

#include <utils/types.h>
#include <utils/list.h>

#define PKG2_MAGIC 0x31324B50
#define PKG2_SEC_BASE 0x80000000
#define PKG2_SEC_KERNEL 0
#define PKG2_SEC_INI1 1

#define PKG2_NEWKERN_GET_INI1_HEURISTIC 0xD2800015 // Offset of OP + 12 is the INI1 offset.

extern u32 pkg2_newkern_ini1_val;
extern u32 pkg2_newkern_ini1_start;
extern u32 pkg2_newkern_ini1_end;

typedef struct _kernel_patch_t
{
	u32 id;
	u32 off;
	u32 val;
	u32 *ptr;
} kernel_patch_t;

typedef struct _pkg2_hdr_t
{
	u8 ctr[0x10];
	u8 sec_ctr[0x40];
	u32 magic;
	u32 base;
	u32 pad0;
	u8  pkg2_ver;
	u8  bl_ver;
	u16 pad1;
	u32 sec_size[4];
	u32 sec_off[4];
	u8 sec_sha256[0x80];
	u8 data[];
} pkg2_hdr_t;

typedef struct _pkg2_ini1_t
{
	u32 magic;
	u32 size;
	u32 num_procs;
	u32 pad;
} pkg2_ini1_t;

typedef struct _pkg2_kip1_sec_t
{
	u32 offset;
	u32 size_decomp;
	u32 size_comp;
	u32 attrib;
} pkg2_kip1_sec_t;

#define KIP1_NUM_SECTIONS 6

typedef struct _pkg2_kip1_t
{
	u32 magic;
	u8 name[12];
	u64 tid;
	u32 proc_cat;
	u8 main_thrd_prio;
	u8 def_cpu_core;
	u8 res;
	u8 flags;
	pkg2_kip1_sec_t sections[KIP1_NUM_SECTIONS];
	u32 caps[0x20];
	u8 data[];
} pkg2_kip1_t;

typedef struct _pkg2_kip1_info_t
{
	pkg2_kip1_t *kip1;
	u32 size;
	link_t link;
} pkg2_kip1_info_t;

typedef struct _pkg2_kernel_id_t
{
	u8 hash[8];
	kernel_patch_t *kernel_patchset;
} pkg2_kernel_id_t;

bool pkg2_parse_kips(link_t *info, pkg2_hdr_t *pkg2, bool *new_pkg2);
int pkg2_decompress_kip(pkg2_kip1_info_t* ki, u32 sectsToDecomp);
pkg2_hdr_t *pkg2_decrypt(void *data);

#endif
