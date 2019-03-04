/*
 * Copyright (c) 2018 naehrwert
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

#ifndef _PKG1_H_
#define _PKG1_H_

#include "../utils/types.h"

typedef struct _pkg1_id_t
{
	const char *id;
	u32 kb;
	u32 tsec_off;
	u32 pkg11_off;
	u32 sec_map[3];
	u32 secmon_base;
	u32 warmboot_base;
	bool set_warmboot;
	u32 *secmon_patchset;
	u32 *warmboot_patchset;
} pkg1_id_t;

const pkg1_id_t *pkg1_identify(u8 *pkg1);

#endif
