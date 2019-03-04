/*
 * Copyright (c) 2018 naehrwert
 * Copyright (c) 2018 st4rk
 * Copyright (c) 2018-2019 CTCaer
 * Copyright (c) 2018 balika011
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

#include <string.h>

#include "pkg1.h"
#include "../sec/se.h"

#define SM_100_ADR 0x4002B020

/*
 * package1.1 header: <wb, ldr, sm>
 * package1.1 layout:
 * 1.0: {sm, ldr, wb} { 2, 1, 0 }
 * 2.0: {wb, ldr, sm} { 0, 1, 2 }
 * 3.0: {wb, ldr, sm} { 0, 1, 2 }
 * 3.1: {wb, ldr, sm} { 0, 1, 2 }
 * 4.0: {ldr, sm, wb} { 1, 2, 0 }
 * 5.0: {ldr, sm, wb} { 1, 2, 0 }
 * 6.0: {ldr, sm, wb} { 1, 2, 0 }
 * 6.2: {ldr, sm, wb} { 1, 2, 0 }
 * 7.0: {ldr, sm, wb} { 1, 2, 0 }
 */

static const pkg1_id_t _pkg1_ids[] = {
	{ "20161121183008", 0, 0x1900, 0x3FE0, { 2, 1, 0 }, SM_100_ADR, 0x8000D000, true,  NULL, NULL },   //1.0.0 (Patched relocator)
	{ "20170210155124", 0, 0x1900, 0x3FE0, { 0, 1, 2 }, 0x4002D000, 0x8000D000, true,  NULL, NULL },   //2.0.0 - 2.3.0
	{ "20170519101410", 1, 0x1A00, 0x3FE0, { 0, 1, 2 }, 0x4002D000, 0x8000D000, true,  NULL, NULL },   //3.0.0
	{ "20170710161758", 2, 0x1A00, 0x3FE0, { 0, 1, 2 }, 0x4002D000, 0x8000D000, true,  NULL, NULL },   //3.0.1 - 3.0.2
	{ "20170921172629", 3, 0x1800, 0x3FE0, { 1, 2, 0 }, 0x4002B000, 0x4003B000, false, NULL, NULL },   //4.0.0 - 4.1.0
	{ "20180220163747", 4, 0x1900, 0x3FE0, { 1, 2, 0 }, 0x4002B000, 0x4003B000, false, NULL, NULL },   //5.0.0 - 5.1.0
	{ "20180802162753", 5, 0x1900, 0x3FE0, { 1, 2, 0 }, 0x4002B000, 0x4003D800, false, NULL, NULL },   //6.0.0 - 6.1.0
	{ "20181107105733", 6, 0x0E00, 0x6FE0, { 1, 2, 0 }, 0x4002B000, 0x4003D800, false, NULL, NULL }, //6.2.0
	{ "20181218175730", 7, 0x0F00, 0x6FE0, { 1, 2, 0 }, 0x40030000, 0x4003E000, false, NULL, NULL },                 //7.0.0
	{ "20190208150037", 7, 0x0F00, 0x6FE0, { 1, 2, 0 }, 0x40030000, 0x4003E000, false, NULL, NULL },                 //7.0.1
	{ NULL } //End.
};

const pkg1_id_t *pkg1_identify(u8 *pkg1)
{
	for (u32 i = 0; _pkg1_ids[i].id; i++)
		if (!memcmp(pkg1 + 0x10, _pkg1_ids[i].id, 12))
			return &_pkg1_ids[i];
	return NULL;
}
