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

#ifndef _KEYS_H_
#define _KEYS_H_

#include "../utils/types.h"


//testing
void screenshot(const char* suffix);
//testing

bool isSysNAND();
bool dump_keys();
bool incognito();
void cleanUp();
bool readData(u8 *buffer, u32 offset, u32 length, void (*progress_callback)(u32, u32));
bool writeData(u8 *buffer, u32 offset, u32 length, void (*progress_callback)(u32, u32));
bool writeClientCertHash();
bool writeCal0Hash();
bool verifyProdinfo(u8 *blob);
bool backupProdinfo();
bool restoreProdinfo();
bool checkBackupExists();
void print_progress(u32 count, u32 max);

#endif
