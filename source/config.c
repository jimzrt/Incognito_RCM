/*
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

#include <string.h>
#include <stdlib.h>

#include "config.h"
#include <utils/ini.h>
#include <gfx_utils.h>
#include "gfx/tui.h"
#include <libs/fatfs/ff.h>
#include <soc/fuse.h>
#include <soc/t210.h>
#include <storage/nx_sd.h>
#include <storage/sdmmc.h>
#include <utils/btn.h>
#include <utils/list.h>
#include <utils/util.h>

extern hekate_config h_cfg;

void set_default_configuration()
{
	h_cfg.autoboot = 0;
	h_cfg.autoboot_list = 0;
	h_cfg.bootwait = 3;
	h_cfg.se_keygen_done = 0;
	h_cfg.backlight = 100;
	h_cfg.autohosoff = 0;
	h_cfg.autonogc = 1;
	h_cfg.updater2p = 0;
	h_cfg.brand = NULL;
	h_cfg.tagline = NULL;
	h_cfg.errors = 0;
	h_cfg.sept_run = EMC(EMC_SCRATCH0) & EMC_SEPT_RUN;
	h_cfg.rcm_patched = fuse_check_patched_rcm();
	h_cfg.emummc_force_disable = false;

	sd_power_cycle_time_start = 0;
}
