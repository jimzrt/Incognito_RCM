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
#include "../gfx/di.h"
#include "../gfx/gfx.h"
#include "../hos/pkg1.h"
#include "../hos/pkg2.h"
#include "../hos/sept.h"
#include "../libs/fatfs/ff.h"
#include "../mem/heap.h"
#include "../rtc/max77620-rtc.h"
#include "../sec/se.h"
#include "../sec/se_t210.h"
#include "../sec/tsec.h"
#include "../soc/fuse.h"
#include "../soc/smmu.h"
#include "../soc/t210.h"
#include "../storage/nx_emmc.h"
#include "../storage/sdmmc.h"
#include "../utils/btn.h"
#include "../utils/list.h"
#include "../utils/util.h"

#include <string.h>
#include <stdarg.h>

extern gfx_ctxt_t gfx_ctxt;
extern gfx_con_t gfx_con;

extern bool sd_mount();
extern void sd_unmount();
extern void *sd_file_read(char *path);
extern int  sd_save_to_file(void *buf, u32 size, const char *filename);
extern void power_off();
extern void reboot_normal();
extern void reboot_rcm();

u32 _key_count = 0;
sdmmc_storage_t storage;
emmc_part_t *system_part;

#define EPRINTF(text) gfx_printf(&gfx_con, "%k"text"%k\n", 0xFFCCCCCC, 0xFFCCCCCC)
#define EPRINTFARGS(text, args...) gfx_printf(&gfx_con, "%k"text"%k\n", 0xFFCCCCCC, args, 0xFFCCCCCC)
#define TPRINTF(text) \
    end_time = get_tmr_ms(); \
    gfx_printf(&gfx_con, text" done @ %d.%03ds\n", (end_time - start_time) / 1000, (end_time - start_time) % 1000)
#define TPRINTFARGS(text, args...) \
    end_time = get_tmr_ms(); \
    gfx_printf(&gfx_con, text" done @ %d.%03ds\n", args, (end_time - start_time) / 1000, (end_time - start_time) % 1000)
#define SAVE_KEY(name, src, len) _save_key(name, src, len, text_buffer, &buf_index)
#define SAVE_KEY_FAMILY(name, src, count, len) _save_key_family(name, src, count, len, text_buffer, &buf_index)

static const u8 zeros[0x10] = {0};

static const u8 keyblob_key_source[][0x10] = {
    {0xDF, 0x20, 0x6F, 0x59, 0x44, 0x54, 0xEF, 0xDC, 0x70, 0x74, 0x48, 0x3B, 0x0D, 0xED, 0x9F, 0xD3}, //1.0.0
    {0x0C, 0x25, 0x61, 0x5D, 0x68, 0x4C, 0xEB, 0x42, 0x1C, 0x23, 0x79, 0xEA, 0x82, 0x25, 0x12, 0xAC}, //3.0.0
    {0x33, 0x76, 0x85, 0xEE, 0x88, 0x4A, 0xAE, 0x0A, 0xC2, 0x8A, 0xFD, 0x7D, 0x63, 0xC0, 0x43, 0x3B}, //3.0.1
    {0x2D, 0x1F, 0x48, 0x80, 0xED, 0xEC, 0xED, 0x3E, 0x3C, 0xF2, 0x48, 0xB5, 0x65, 0x7D, 0xF7, 0xBE}, //4.0.0
    {0xBB, 0x5A, 0x01, 0xF9, 0x88, 0xAF, 0xF5, 0xFC, 0x6C, 0xFF, 0x07, 0x9E, 0x13, 0x3C, 0x39, 0x80}, //5.0.0
    {0xD8, 0xCC, 0xE1, 0x26, 0x6A, 0x35, 0x3F, 0xCC, 0x20, 0xF3, 0x2D, 0x3B, 0x51, 0x7D, 0xE9, 0xC0}  //6.0.0
};

static const u8 master_kek_sources[KB_FIRMWARE_VERSION_MAX - KB_FIRMWARE_VERSION_600][0x10] = {
    {0x37, 0x4B, 0x77, 0x29, 0x59, 0xB4, 0x04, 0x30, 0x81, 0xF6, 0xE5, 0x8C, 0x6D, 0x36, 0x17, 0x9A},
    {0x9A, 0x3E, 0xA9, 0xAB, 0xFD, 0x56, 0x46, 0x1C, 0x9B, 0xF6, 0x48, 0x7F, 0x5C, 0xFA, 0x09, 0x5C}
};

static const u8 mkey_vectors[KB_FIRMWARE_VERSION_MAX+1][0x10] =
{
    {0x0C, 0xF0, 0x59, 0xAC, 0x85, 0xF6, 0x26, 0x65, 0xE1, 0xE9, 0x19, 0x55, 0xE6, 0xF2, 0x67, 0x3D}, /* Zeroes encrypted with Master Key 00. */
    {0x29, 0x4C, 0x04, 0xC8, 0xEB, 0x10, 0xED, 0x9D, 0x51, 0x64, 0x97, 0xFB, 0xF3, 0x4D, 0x50, 0xDD}, /* Master key 00 encrypted with Master key 01. */
    {0xDE, 0xCF, 0xEB, 0xEB, 0x10, 0xAE, 0x74, 0xD8, 0xAD, 0x7C, 0xF4, 0x9E, 0x62, 0xE0, 0xE8, 0x72}, /* Master key 01 encrypted with Master key 02. */
    {0x0A, 0x0D, 0xDF, 0x34, 0x22, 0x06, 0x6C, 0xA4, 0xE6, 0xB1, 0xEC, 0x71, 0x85, 0xCA, 0x4E, 0x07}, /* Master key 02 encrypted with Master key 03. */
    {0x6E, 0x7D, 0x2D, 0xC3, 0x0F, 0x59, 0xC8, 0xFA, 0x87, 0xA8, 0x2E, 0xD5, 0x89, 0x5E, 0xF3, 0xE9}, /* Master key 03 encrypted with Master key 04. */
    {0xEB, 0xF5, 0x6F, 0x83, 0x61, 0x9E, 0xF8, 0xFA, 0xE0, 0x87, 0xD7, 0xA1, 0x4E, 0x25, 0x36, 0xEE}, /* Master key 04 encrypted with Master key 05. */
    {0x1E, 0x1E, 0x22, 0xC0, 0x5A, 0x33, 0x3C, 0xB9, 0x0B, 0xA9, 0x03, 0x04, 0xBA, 0xDB, 0x07, 0x57}, /* Master key 05 encrypted with Master key 06. */
    {0xA4, 0xD4, 0x52, 0x6F, 0xD1, 0xE4, 0x36, 0xAA, 0x9F, 0xCB, 0x61, 0x27, 0x1C, 0x67, 0x65, 0x1F}, /* Master key 06 encrypted with Master key 07. */
};

//======================================Keys======================================//
// from Package1 -> Secure_Monitor
static const u8 aes_kek_generation_source[0x10] = {
    0x4D, 0x87, 0x09, 0x86, 0xC4, 0x5D, 0x20, 0x72, 0x2F, 0xBA, 0x10, 0x53, 0xDA, 0x92, 0xE8, 0xA9};
static const u8 aes_kek_seed_01[0x10] = {
    0xA2, 0xAB, 0xBF, 0x9C, 0x92, 0x2F, 0xBB, 0xE3, 0x78, 0x79, 0x9B, 0xC0, 0xCC, 0xEA, 0xA5, 0x74};
static const u8 aes_kek_seed_03[0x10] = {
    0xE5, 0x4D, 0x9A, 0x02, 0xF0, 0x4F, 0x5F, 0xA8, 0xAD, 0x76, 0x0A, 0xF6, 0x32, 0x95, 0x59, 0xBB};
static const u8 package2_key_source[0x10] = {
    0xFB, 0x8B, 0x6A, 0x9C, 0x79, 0x00, 0xC8, 0x49, 0xEF, 0xD2, 0x4D, 0x85, 0x4D, 0x30, 0xA0, 0xC7};
static const u8 titlekek_source[0x10] = {
    0x1E, 0xDC, 0x7B, 0x3B, 0x60, 0xE6, 0xB4, 0xD8, 0x78, 0xB8, 0x17, 0x15, 0x98, 0x5E, 0x62, 0x9B};
static const u8 retail_specific_aes_key_source[0x10] = {
    0xE2, 0xD6, 0xB8, 0x7A, 0x11, 0x9C, 0xB8, 0x80, 0xE8, 0x22, 0x88, 0x8A, 0x46, 0xFB, 0xA1, 0x95};

// from Package1ldr (or Secure_Monitor on 6.2.0)
static const u8 keyblob_mac_key_source[0x10] = {
    0x59, 0xC7, 0xFB, 0x6F, 0xBE, 0x9B, 0xBE, 0x87, 0x65, 0x6B, 0x15, 0xC0, 0x53, 0x73, 0x36, 0xA5};
static const u8 master_key_source[0x10] = {
    0xD8, 0xA2, 0x41, 0x0A, 0xC6, 0xC5, 0x90, 0x01, 0xC6, 0x1D, 0x6A, 0x26, 0x7C, 0x51, 0x3F, 0x3C};
static const u8 per_console_key_source[0x10] = {
    0x4F, 0x02, 0x5F, 0x0E, 0xB6, 0x6D, 0x11, 0x0E, 0xDC, 0x32, 0x7D, 0x41, 0x86, 0xC2, 0xF4, 0x78};

// from SPL
static const u8 aes_key_generation_source[0x10] = {
    0x89, 0x61, 0x5E, 0xE0, 0x5C, 0x31, 0xB6, 0x80, 0x5F, 0xE5, 0x8F, 0x3D, 0xA2, 0x4F, 0x7A, 0xA8};

// from FS
static const u8 bis_kek_source[0x10] = {
    0x34, 0xC1, 0xA0, 0xC4, 0x82, 0x58, 0xF8, 0xB4, 0xFA, 0x9E, 0x5E, 0x6A, 0xDA, 0xFC, 0x7E, 0x4F};
static const u8 bis_key_source[3][0x20] = {
    {
        0xF8, 0x3F, 0x38, 0x6E, 0x2C, 0xD2, 0xCA, 0x32, 0xA8, 0x9A, 0xB9, 0xAA, 0x29, 0xBF, 0xC7, 0x48,
        0x7D, 0x92, 0xB0, 0x3A, 0xA8, 0xBF, 0xDE, 0xE1, 0xA7, 0x4C, 0x3B, 0x6E, 0x35, 0xCB, 0x71, 0x06},
    {
        0x41, 0x00, 0x30, 0x49, 0xDD, 0xCC, 0xC0, 0x65, 0x64, 0x7A, 0x7E, 0xB4, 0x1E, 0xED, 0x9C, 0x5F,
        0x44, 0x42, 0x4E, 0xDA, 0xB4, 0x9D, 0xFC, 0xD9, 0x87, 0x77, 0x24, 0x9A, 0xDC, 0x9F, 0x7C, 0xA4},
    {
        0x52, 0xC2, 0xE9, 0xEB, 0x09, 0xE3, 0xEE, 0x29, 0x32, 0xA1, 0x0C, 0x1F, 0xB6, 0xA0, 0x92, 0x6C,
        0x4D, 0x12, 0xE1, 0x4B, 0x2A, 0x47, 0x4C, 0x1C, 0x09, 0xCB, 0x03, 0x59, 0xF0, 0x15, 0xF4, 0xE4}
};

static const u8 fs_hashes_sha256[10][0x20] = {
    { // header_kek_source
        0x18, 0x88, 0xca, 0xed, 0x55, 0x51, 0xb3, 0xed, 0xe0, 0x14, 0x99, 0xe8, 0x7c, 0xe0, 0xd8, 0x68,
        0x27, 0xf8, 0x08, 0x20, 0xef, 0xb2, 0x75, 0x92, 0x10, 0x55, 0xaa, 0x4e, 0x2a, 0xbd, 0xff, 0xc2},
    { // header_key_source
        0x8f, 0x78, 0x3e, 0x46, 0x85, 0x2d, 0xf6, 0xbe, 0x0b, 0xa4, 0xe1, 0x92, 0x73, 0xc4, 0xad, 0xba,
        0xee, 0x16, 0x38, 0x00, 0x43, 0xe1, 0xb8, 0xc4, 0x18, 0xc4, 0x08, 0x9a, 0x8b, 0xd6, 0x4a, 0xa6},
    { // key_area_key_application_source
        0x04, 0xad, 0x66, 0x14, 0x3c, 0x72, 0x6b, 0x2a, 0x13, 0x9f, 0xb6, 0xb2, 0x11, 0x28, 0xb4, 0x6f,
        0x56, 0xc5, 0x53, 0xb2, 0xb3, 0x88, 0x71, 0x10, 0x30, 0x42, 0x98, 0xd8, 0xd0, 0x09, 0x2d, 0x9e},
    { // key_area_key_ocean_source
        0xfd, 0x43, 0x40, 0x00, 0xc8, 0xff, 0x2b, 0x26, 0xf8, 0xe9, 0xa9, 0xd2, 0xd2, 0xc1, 0x2f, 0x6b,
        0xe5, 0x77, 0x3c, 0xbb, 0x9d, 0xc8, 0x63, 0x00, 0xe1, 0xbd, 0x99, 0xf8, 0xea, 0x33, 0xa4, 0x17},
    { // key_area_key_system_source
        0x1f, 0x17, 0xb1, 0xfd, 0x51, 0xad, 0x1c, 0x23, 0x79, 0xb5, 0x8f, 0x15, 0x2c, 0xa4, 0x91, 0x2e,
        0xc2, 0x10, 0x64, 0x41, 0xe5, 0x17, 0x22, 0xf3, 0x87, 0x00, 0xd5, 0x93, 0x7a, 0x11, 0x62, 0xf7},
    { // save_mac_kek_source
        0x3D, 0xCB, 0xA1, 0x00, 0xAD, 0x4D, 0xF1, 0x54, 0x7F, 0xE3, 0xC4, 0x79, 0x5C, 0x4B, 0x22, 0x8A,
        0xA9, 0x80, 0x38, 0xF0, 0x7A, 0x36, 0xF1, 0xBC, 0x14, 0x8E, 0xEA, 0xF3, 0xDC, 0xD7, 0x50, 0xF4},
    { // save_mac_key_source
        0xB4, 0x7B, 0x60, 0x0B, 0x1A, 0xD3, 0x14, 0xF9, 0x41, 0x14, 0x7D, 0x8B, 0x39, 0x1D, 0x4B, 0x19,
        0x87, 0xCC, 0x8C, 0x88, 0x4A, 0xC8, 0x9F, 0xFC, 0x91, 0xCA, 0xE2, 0x21, 0xC5, 0x24, 0x51, 0xF7},
    { // sd_card_kek_source
        0x6B, 0x2E, 0xD8, 0x77, 0xC2, 0xC5, 0x23, 0x34, 0xAC, 0x51, 0xE5, 0x9A, 0xBF, 0xA7, 0xEC, 0x45,
        0x7F, 0x4A, 0x7D, 0x01, 0xE4, 0x62, 0x91, 0xE9, 0xF2, 0xEA, 0xA4, 0x5F, 0x01, 0x1D, 0x24, 0xB7},
    { // sd_card_nca_key_source
        0x2E, 0x75, 0x1C, 0xEC, 0xF7, 0xD9, 0x3A, 0x2B, 0x95, 0x7B, 0xD5, 0xFF, 0xCB, 0x08, 0x2F, 0xD0,
        0x38, 0xCC, 0x28, 0x53, 0x21, 0x9D, 0xD3, 0x09, 0x2C, 0x6D, 0xAB, 0x98, 0x38, 0xF5, 0xA7, 0xCC},
    { // sd_card_save_key_source
        0xD4, 0x82, 0x74, 0x35, 0x63, 0xD3, 0xEA, 0x5D, 0xCD, 0xC3, 0xB7, 0x4E, 0x97, 0xC9, 0xAC, 0x8A,
        0x34, 0x21, 0x64, 0xFA, 0x04, 0x1A, 0x1D, 0xC8, 0x0F, 0x17, 0xF6, 0xD3, 0x1E, 0x4B, 0xC0, 0x1C}
};

static const u8 es_hashes_sha256[3][0x20] = {
    { // eticket_rsa_kek
        0xB7, 0x1D, 0xB2, 0x71, 0xDC, 0x33, 0x8D, 0xF3, 0x80, 0xAA, 0x2C, 0x43, 0x35, 0xEF, 0x88, 0x73,
        0xB1, 0xAF, 0xD4, 0x08, 0xE8, 0x0B, 0x35, 0x82, 0xD8, 0x71, 0x9F, 0xC8, 0x1C, 0x5E, 0x51, 0x1C},
    { // eticket_rsa_kekek
        0xE8, 0x96, 0x5A, 0x18, 0x7D, 0x30, 0xE5, 0x78, 0x69, 0xF5, 0x62, 0xD0, 0x43, 0x83, 0xC9, 0x96,
        0xDE, 0x48, 0x7B, 0xBA, 0x57, 0x61, 0x36, 0x3D, 0x2D, 0x4D, 0x32, 0x39, 0x18, 0x66, 0xA8, 0x5C},
    { // ssl_rsa_kek_source_x
        0x69, 0xA0, 0x8E, 0x62, 0xE0, 0xAE, 0x50, 0x7B, 0xB5, 0xDA, 0x0E, 0x65, 0x17, 0x9A, 0xE3, 0xBE,
        0x05, 0x1F, 0xED, 0x3C, 0x49, 0x94, 0x1D, 0xF4, 0xEF, 0x29, 0x56, 0xD3, 0x6D, 0x30, 0x11, 0x0C}
};

static const u8 ssl_hashes_sha256[2][0x20] = {
    { // ssl_rsa_kek_source_x
        0x69, 0xA0, 0x8E, 0x62, 0xE0, 0xAE, 0x50, 0x7B, 0xB5, 0xDA, 0x0E, 0x65, 0x17, 0x9A, 0xE3, 0xBE,
        0x05, 0x1F, 0xED, 0x3C, 0x49, 0x94, 0x1D, 0xF4, 0xEF, 0x29, 0x56, 0xD3, 0x6D, 0x30, 0x11, 0x0C},
    { // ssl_rsa_kek_source_y
        0x1C, 0x86, 0xF3, 0x63, 0x26, 0x54, 0x17, 0xD4, 0x99, 0x22, 0x9E, 0xB1, 0xC4, 0xAD, 0xC7, 0x47,
        0x9B, 0x2A, 0x15, 0xF9, 0x31, 0x26, 0x1F, 0x31, 0xEE, 0x67, 0x76, 0xAE, 0xB4, 0xC7, 0x65, 0x42}
};

static u8 temp_key[0x10],
          bis_key[4][0x20] = {0},
          device_key[0x10] = {0},
          sd_seed[0x10] = {0},
          // FS-related keys
          fs_keys[10][0x20] = {0},
          header_key[0x20] = {0},
          save_mac_key[0x10] = {0},
          // other sysmodule sources
          es_keys[3][0x10] = {0},
          eticket_rsa_kek[0x10] = {0},
          ssl_keys[2][0x10] = {0},
          ssl_rsa_kek[0x10] = {0},
          // keyblob-derived families
          keyblob[KB_FIRMWARE_VERSION_600+1][0x90] = {0},
          keyblob_key[KB_FIRMWARE_VERSION_600+1][0x10] = {0},
          keyblob_mac_key[KB_FIRMWARE_VERSION_600+1][0x10] = {0},
          package1_key[KB_FIRMWARE_VERSION_600+1][0x10] = {0},
          // master key-derived families
          key_area_key[3][KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
          master_kek[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
          master_key[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
          package2_key[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
          titlekek[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0};

static const u32 colors[6] = {COLOR_RED, COLOR_ORANGE, COLOR_YELLOW, COLOR_GREEN, COLOR_BLUE, COLOR_VIOLET};

// key functions
static bool   _key_exists(const void *data) { return memcmp(data, zeros, 0x10); };
static void   _save_key(const char *name, const void *data, const u32 len, char *outbuf, u32 *buf_index);
static void   _save_key_family(const char *name, const void *data, const u32 num_keys, const u32 len, char *outbuf, u32 *buf_index);
static void   _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed, const void *key_seed);
// nca functions
static void  *_nca_process(u32 hk_ks1, u32 hk_ks2, FIL *fp, u32 key_offset, u32 len);
static u32    _nca_fread_ctr(u32 ks, FIL *fp, void *buffer, u32 offset, u32 len, u8 *ctr);
static void   _update_ctr(u8 *ctr, u32 ofs);
// output functions
static void _putc(char *buffer, const char c);
static u32  _puts(char *buffer, const char *s);
static u32  _putn(char *buffer, u32 v, int base, char fill, int fcnt);
static u32  _sprintf(char *buffer, const char *fmt, ...);

void dump_keys() {
    display_backlight_brightness(100, 1000);
    gfx_clear_partial_grey(&gfx_ctxt, 0x1B, 0, 1256);
    gfx_con_setpos(&gfx_con, 0, 0);

    gfx_printf(&gfx_con, "[%kLo%kck%kpi%kck%k-R%kCM%k]\n\n",
        colors[0], colors[1], colors[2], colors[3], colors[4], colors[5], 0xFFCCCCCC);

    u32 start_time = get_tmr_ms(),
        end_time,
        retries = 0;

    tsec_ctxt_t tsec_ctxt;
    sdmmc_t sdmmc;

    sdmmc_storage_init_mmc(&storage, &sdmmc, SDMMC_4, SDMMC_BUS_WIDTH_8, 4);

    // Read package1.
    u8 *pkg1 = (u8 *)malloc(0x40000);
    sdmmc_storage_set_mmc_partition(&storage, 1);
    sdmmc_storage_read(&storage, 0x100000 / NX_EMMC_BLOCKSIZE, 0x40000 / NX_EMMC_BLOCKSIZE, pkg1);
    const pkg1_id_t *pkg1_id = pkg1_identify(pkg1);
    if (!pkg1_id) {
        EPRINTF("Unknown pkg1 version.");
        goto out_wait;
    }

    if (pkg1_id->kb >= KB_FIRMWARE_VERSION_700) {
        if (!f_stat("sd:/sept/payload.bak", NULL)) {
            f_unlink("sd:/sept/payload.bin");
            f_rename("sd:/sept/payload.bak", "sd:/sept/payload.bin");
        }

        if (!(EMC(EMC_SCRATCH0) & EMC_SEPT_RUN)) {
            FIL fp;
            if (f_stat("sd:/sept/sept-primary.bin", NULL) || f_stat("sd:/sept/sept-secondary.enc", NULL)) {
                EPRINTF("On firmware 7.x but no sept payload present\nSkipping new key derivation...");
                goto get_tsec;
            }
            // backup post-reboot payload
            if (!f_stat("sd:/sept/payload.bin", NULL))
                f_rename("sd:/sept/payload.bin", "sd:/sept/payload.bak");
            // write self to payload.bin to run again when sept finishes
            f_open(&fp, "sd:/sept/payload.bin", FA_CREATE_NEW | FA_WRITE);
            u32 payload_size = *(u32 *)(IPL_LOAD_ADDR + 0x84) - IPL_LOAD_ADDR;
            f_write(&fp, (u8 *)IPL_LOAD_ADDR, payload_size, NULL);
            f_close(&fp);
            gfx_printf(&gfx_con, "%kFirmware 7.x detected.\n%kRenamed /sept/payload.bin", colors[0], colors[1]);
            gfx_printf(&gfx_con, "\n%k     to /sept/payload.bak\n%kCopied self to /sept/payload.bin",colors[2], colors[3]);
            sdmmc_storage_end(&storage);
            if (!reboot_to_sept((u8 *)pkg1 + pkg1_id->tsec_off))
                goto out_wait;
        } else {
            se_aes_key_read(12, master_key[pkg1_id->kb], 0x10);
        }
    }

get_tsec: ;
    u8 tsec_keys[0x10 * 2] = {0};

    tsec_ctxt.fw = (u8 *)pkg1 + pkg1_id->tsec_off;
    tsec_ctxt.pkg1 = pkg1;
    tsec_ctxt.pkg11_off = pkg1_id->pkg11_off;
    tsec_ctxt.secmon_base = pkg1_id->secmon_base;

    if (pkg1_id->kb <= KB_FIRMWARE_VERSION_600)
        tsec_ctxt.size = 0xF00;
    else if (pkg1_id->kb == KB_FIRMWARE_VERSION_620)
        tsec_ctxt.size = 0x2900;
    else {
        tsec_ctxt.size = 0x3000;
        // Exit after TSEC key generation.
        *((vu16 *)((u32)tsec_ctxt.fw + 0x2DB5)) = 0x02F8;
    }

    if (pkg1_id->kb == KB_FIRMWARE_VERSION_620) {
        u8 *tsec_paged = (u8 *)page_alloc(3);
        memcpy(tsec_paged, (void *)tsec_ctxt.fw, tsec_ctxt.size);
        tsec_ctxt.fw = tsec_paged;
    }

    int res = 0;

    while (tsec_query(tsec_keys, pkg1_id->kb, &tsec_ctxt) < 0) {
        memset(tsec_keys, 0x00, 0x20);
        retries++;
        if (retries > 3) {
            res = -1;
            break;
        }
    }
    free(pkg1);

    if (res < 0) {
        EPRINTFARGS("ERROR %x dumping TSEC.\n", res);
        goto out_wait;
    }

    TPRINTFARGS("%kTSEC key(s)...  ", colors[0]);

    // Master key derivation
    if (pkg1_id->kb == KB_FIRMWARE_VERSION_620 && _key_exists(tsec_keys + 0x10)) {
        se_aes_key_set(8, tsec_keys + 0x10, 0x10); // mkek6 = unwrap(mkeks6, tsecroot)
        se_aes_crypt_block_ecb(8, 0, master_kek[6], master_kek_sources[0]);
        se_aes_key_set(8, master_kek[6], 0x10); // mkey = unwrap(mkek, mks)
        se_aes_crypt_block_ecb(8, 0, master_key[6], master_key_source);
    }

    if (pkg1_id->kb >= KB_FIRMWARE_VERSION_620 && _key_exists(master_key[pkg1_id->kb])) {
        // derive all lower master keys in the event keyblobs are bad
        for (u32 i = pkg1_id->kb; i > 0; i--) {
            se_aes_key_set(8, master_key[i], 0x10);
            se_aes_crypt_block_ecb(8, 0, master_key[i-1], mkey_vectors[i]);
        }
    }

    u8 *keyblob_block = (u8 *)calloc(NX_EMMC_BLOCKSIZE, 1);
    u8 keyblob_mac[0x10] = {0};
    u32 sbk[4] = {FUSE(FUSE_PRIVATE_KEY0), FUSE(FUSE_PRIVATE_KEY1),
                  FUSE(FUSE_PRIVATE_KEY2), FUSE(FUSE_PRIVATE_KEY3)};
    se_aes_key_set(8, tsec_keys, 0x10);
    se_aes_key_set(9, sbk, 0x10);
    for (u32 i = 0; i <= KB_FIRMWARE_VERSION_600; i++) {
        se_aes_crypt_block_ecb(8, 0, keyblob_key[i], keyblob_key_source[i]); // temp = unwrap(kbks, tsec)
        se_aes_crypt_block_ecb(9, 0, keyblob_key[i], keyblob_key[i]); // kbk = unwrap(temp, sbk)
        se_aes_key_set(7, keyblob_key[i], 0x10);
        se_aes_crypt_block_ecb(7, 0, keyblob_mac_key[i], keyblob_mac_key_source); // kbm = unwrap(kbms, kbk)
        if (i == 0)
            se_aes_crypt_block_ecb(7, 0, device_key, per_console_key_source); // devkey = unwrap(pcks, kbk0)

        // verify keyblob is not corrupt
        sdmmc_storage_read(&storage, 0x180000 / NX_EMMC_BLOCKSIZE + i, 1, keyblob_block);
        se_aes_key_set(3, keyblob_mac_key[i], 0x10);
        se_aes_cmac(3, keyblob_mac, 0x10, keyblob_block + 0x10, 0xa0);
        if (memcmp(keyblob_block, keyblob_mac, 0x10)) {
            EPRINTFARGS("Keyblob %x corrupt.", i);
            gfx_hexdump(&gfx_con, i, keyblob_block, 0x10);
            gfx_hexdump(&gfx_con, i, keyblob_mac, 0x10);
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

    TPRINTFARGS("%kMaster keys...  ", colors[1]);

    /*  key = unwrap(source, wrapped_key):
        key_set(ks, wrapped_key), block_ecb(ks, 0, key, source) -> final key in key
    */
    if (_key_exists(device_key)) {
        se_aes_key_set(8, device_key, 0x10);
        se_aes_unwrap_key(8, 8, retail_specific_aes_key_source); // kek = unwrap(rsaks, devkey)
        se_aes_crypt_block_ecb(8, 0, bis_key[0] + 0x00, bis_key_source[0] + 0x00); // bkey = unwrap(bkeys, kek)
        se_aes_crypt_block_ecb(8, 0, bis_key[0] + 0x10, bis_key_source[0] + 0x10);
        // kek = generate_kek(bkeks, devkey, aeskek, aeskey)
        _generate_kek(8, bis_kek_source, device_key, aes_kek_generation_source, aes_key_generation_source);
        se_aes_crypt_block_ecb(8, 0, bis_key[1] + 0x00, bis_key_source[1] + 0x00); // bkey = unwrap(bkeys, kek)
        se_aes_crypt_block_ecb(8, 0, bis_key[1] + 0x10, bis_key_source[1] + 0x10);
        se_aes_crypt_block_ecb(8, 0, bis_key[2] + 0x00, bis_key_source[2] + 0x00);
        se_aes_crypt_block_ecb(8, 0, bis_key[2] + 0x10, bis_key_source[2] + 0x10);
        memcpy(bis_key[3], bis_key[2], 0x20);
    }

    // Dump package2.
    u8 *pkg2 = NULL;
    pkg2_kip1_info_t *ki = NULL;
    if (!_key_exists(master_key[pkg1_id->kb])) {
        EPRINTF("Current master key not found.\nUnable to decrypt Package2.");
        goto pkg2_done;
    }

    sdmmc_storage_set_mmc_partition(&storage, 0);
    // Parse eMMC GPT.
    LIST_INIT(gpt);
    nx_emmc_gpt_parse(&gpt, &storage);
    
    // Find package2 partition.
    emmc_part_t *pkg2_part = nx_emmc_part_find(&gpt, "BCPKG2-1-Normal-Main");
    if (!pkg2_part) {
        EPRINTF("Failed to locate Package2.");
        goto pkg2_done;
    }

    // Read in package2 header and get package2 real size.
    u8 *tmp = (u8 *)malloc(NX_EMMC_BLOCKSIZE);
    nx_emmc_part_read(&storage, pkg2_part, 0x4000 / NX_EMMC_BLOCKSIZE, 1, tmp);
    u32 *hdr_pkg2_raw = (u32 *)(tmp + 0x100);
    u32 pkg2_size = hdr_pkg2_raw[0] ^ hdr_pkg2_raw[2] ^ hdr_pkg2_raw[3];
    free(tmp);

    if (pkg2_size > 0x7FC000) {
        EPRINTF("Invalid Package2 header.");
        goto pkg2_done;
    }
    // Read in package2.
    u32 pkg2_size_aligned = ALIGN(pkg2_size, NX_EMMC_BLOCKSIZE);
    pkg2 = malloc(pkg2_size_aligned);
    nx_emmc_part_read(&storage, pkg2_part, 0x4000 / NX_EMMC_BLOCKSIZE, pkg2_size_aligned / NX_EMMC_BLOCKSIZE, pkg2);
    
    // Decrypt package2 and parse KIP1 blobs in INI1 section.
    se_aes_key_set(8, master_key[pkg1_id->kb], 0x10);
    se_aes_unwrap_key(8, 8, package2_key_source);
    pkg2_hdr_t *pkg2_hdr = pkg2_decrypt(pkg2);

    TPRINTFARGS("%kDecrypt pkg2... ", colors[2]);

    LIST_INIT(kip1_info);
    pkg2_parse_kips(&kip1_info, pkg2_hdr);
    LIST_FOREACH_ENTRY(pkg2_kip1_info_t, ki_tmp, &kip1_info, link) {
        if(ki_tmp->kip1->tid == 0x0100000000000000ULL) {
            ki = malloc(sizeof(pkg2_kip1_info_t));
            memcpy(ki, ki_tmp, sizeof(pkg2_kip1_info_t));
            break;
        }
    }
    LIST_FOREACH_SAFE(iter, &kip1_info)
        free(CONTAINER_OF(iter, pkg2_kip1_info_t, link));

    if (!ki) {
        EPRINTF("Failed to parse INI1.");
        goto pkg2_done;
    }

    pkg2_decompress_kip(ki, 2 | 4); // we only need .rodata and .data
    TPRINTFARGS("%kDecompress FS...", colors[3]);

    u8  hash_index = 0, hash_max = 9, hash_order[10],
        key_lengths[10] = {0x10, 0x20, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x20, 0x20};
    u32 start_offset = 0, hks_offset_from_end = ki->kip1->sections[2].size_decomp, alignment = 1;

    // the FS keys appear in different orders
    if (!memcmp(pkg1_id->id, "2016", 4)) {
        // 1.0.0 doesn't have SD keys at all
        hash_max = 6;
        // the first key isn't aligned with the rest
        memcpy(fs_keys[2], ki->kip1->data + ki->kip1->sections[0].size_comp + 0x1ae0e, 0x10);
        hash_index = 1;
        start_offset = 0x1b517;
        hks_offset_from_end = 0x125bc2;
        alignment = 0x10;
        u8 temp[7] = {2, 3, 4, 0, 5, 6, 1};
        memcpy(hash_order, temp, 7);
    } else {
        // 2.0.0 - 7.0.1
        alignment = 0x40;
        switch (pkg1_id->kb) {
        case KB_FIRMWARE_VERSION_100_200:
            start_offset = 0x1d226;
            alignment = 0x10;
            hks_offset_from_end -= 0x26fe;
            break;
        case KB_FIRMWARE_VERSION_300:
            start_offset = 0x1ffa6;
            hks_offset_from_end -= 0x298b;
            break;
        case KB_FIRMWARE_VERSION_301:
            start_offset = 0x20026;
            hks_offset_from_end -= 0x29ab;
            break;
        case KB_FIRMWARE_VERSION_400:
            start_offset = 0x1c64c;
            hks_offset_from_end -= 0x37eb;
            break;
        case KB_FIRMWARE_VERSION_500:
            start_offset = 0x1f3b4;
            hks_offset_from_end -= 0x465b;
            alignment = 0x20;
            break;
        case KB_FIRMWARE_VERSION_600:
        case KB_FIRMWARE_VERSION_620:
            start_offset = 0x27350;
            hks_offset_from_end = 0x17ff5;
            alignment = 8;
            break;
        case KB_FIRMWARE_VERSION_700:
            start_offset = 0x29c50;
            hks_offset_from_end = 0x18bf5;
            alignment = 8;
            break;
        }

        if (pkg1_id->kb <= KB_FIRMWARE_VERSION_500) {
            u8 temp[10] = {2, 3, 4, 0, 5, 7, 9, 8, 6, 1};
            memcpy(hash_order, temp, 10);
        } else {
            u8 temp[10] = {6, 5, 7, 2, 3, 4, 0, 9, 8, 1};
            memcpy(hash_order, temp, 10);
        }
    }

    u8 temp_hash[0x20];
    for (u32 i = ki->kip1->sections[0].size_comp + start_offset; i < ki->size - 0x20; ) {
        se_calc_sha256(temp_hash, ki->kip1->data + i, key_lengths[hash_order[hash_index]]);
        if (!memcmp(temp_hash, fs_hashes_sha256[hash_order[hash_index]], 0x20)) {
            memcpy(fs_keys[hash_order[hash_index]], ki->kip1->data + i, key_lengths[hash_order[hash_index]]);
            /*if (hash_index == hash_max) {
                TPRINTFARGS("%d: %x    end -%x", hash_index, (*(ki->kip1->data + i)), ki->size - i);
            } else {
                TPRINTFARGS("%d: %x rodata +%x", hash_index, (*(ki->kip1->data + i)), i - ki->kip1->sections[0].size_comp);
            }*/
            i += key_lengths[hash_order[hash_index]];
            if (hash_index == hash_max - 1) {
                i = ki->size - hks_offset_from_end;
            } else if (hash_index == hash_max) {
                break;
            }
            hash_index++;
        } else {
            i += alignment;
        }
    }

pkg2_done:
    free(pkg2);
    free(ki);

    TPRINTFARGS("%kFS keys...      ", colors[4]);

    if (_key_exists(fs_keys[0]) && _key_exists(fs_keys[1]) && _key_exists(master_key[0])) {
        _generate_kek(8, fs_keys[0], master_key[0], aes_kek_generation_source, aes_key_generation_source);
        se_aes_crypt_block_ecb(8, 0, header_key + 0x00, fs_keys[1] + 0x00);
        se_aes_crypt_block_ecb(8, 0, header_key + 0x10, fs_keys[1] + 0x10);
    }

    if (_key_exists(fs_keys[5]) && _key_exists(fs_keys[6]) && _key_exists(device_key)) {
        _generate_kek(8, fs_keys[5], device_key, aes_kek_generation_source, NULL);
        se_aes_crypt_block_ecb(8, 0, save_mac_key, fs_keys[6]);
    }

    u32 MAX_KEY = pkg1_id->kb < KB_FIRMWARE_VERSION_620 ? 6 : pkg1_id->kb + 1;

    for (u32 i = 0; i < MAX_KEY; i++) {
        if (!_key_exists(master_key[i]))
            continue;
        if (_key_exists(fs_keys[2]) && _key_exists(fs_keys[3]) && _key_exists(fs_keys[4])) {
            for (u32 j = 0; j < 3; j++) {
                _generate_kek(8, fs_keys[2 + j], master_key[i], aes_kek_generation_source, NULL);
                se_aes_crypt_block_ecb(8, 0, key_area_key[j][i], aes_key_generation_source);
            }
        }
        se_aes_key_set(8, master_key[i], 0x10);
        se_aes_crypt_block_ecb(8, 0, package2_key[i], package2_key_source);
        se_aes_crypt_block_ecb(8, 0, titlekek[i], titlekek_source);
    }


    if (memcmp(pkg1_id->id, "2016", 4))
        gfx_printf(&gfx_con, "%kES & SSL keys... ", colors[5]);
    else
        gfx_printf(&gfx_con, "%kSSL keys...      ", colors[5]);
    if (!_key_exists(header_key) || !_key_exists(bis_key[2]))
        goto key_output;

    se_aes_key_set(4, header_key + 0x00, 0x10);
    se_aes_key_set(5, header_key + 0x10, 0x10);
    se_aes_key_set(8, bis_key[2] + 0x00, 0x10);
    se_aes_key_set(9, bis_key[2] + 0x10, 0x10);

    system_part = nx_emmc_part_find(&gpt, "SYSTEM");
    if (!system_part) {
        EPRINTF("Failed to locate System partition.");
        goto key_output;
    }
    FATFS emmc_fs;
    if (f_mount(&emmc_fs, "emmc:", 1)) {
        EPRINTF("Mount failed.");
        goto key_output;
    }

    DIR dir;
    FILINFO fno;
    FIL fp;
    // sysmodule NCAs only ever have one section (exefs) so 0x600 is sufficient
    u8 *dec_header = (u8*)malloc(0x600);
    char path[100] = "emmc:/Contents/registered";
    u32 titles_found = 0, title_limit = 2, read_bytes = 0;
    if (!memcmp(pkg1_id->id, "2016", 4))
        title_limit = 1;
    u8 *temp_file = NULL;

    u32 x, y, spinner_time = get_tmr_ms(), spinner_idx = 0, color_idx = 0;
    char spinner[4] = {'/', '-', '\\', '|'};
    gfx_con_getpos(&gfx_con, &x, &y);

    if (f_opendir(&dir, path)) {
        EPRINTF("Failed to open System:/Contents/registered.");
        goto dismount;
    }

    // prepopulate /Contents/registered in decrypted sector cache
    while (!f_readdir(&dir, &fno) && fno.fname[0]) {
        if (get_tmr_ms() - spinner_time > 75) {
            spinner_time = get_tmr_ms();
            gfx_con_setpos(&gfx_con, x, y);
            gfx_con_setcol(&gfx_con, colors[color_idx++ % 6], 1, 0xFF1B1B1B);
            gfx_putc(&gfx_con, spinner[spinner_idx++ % 4]);
        }
    }
    f_closedir(&dir);

    if (f_opendir(&dir, path)) {
        EPRINTF("Failed to open System:/Contents/registered.");
        goto dismount;
    }

    path[25] = '/';
    start_offset = 0;

    while (!f_readdir(&dir, &fno) && fno.fname[0] && titles_found < title_limit) {
        if (get_tmr_ms() - spinner_time > 75) {
            spinner_time = get_tmr_ms();
            gfx_con_setpos(&gfx_con, x, y);
            gfx_con_setcol(&gfx_con, colors[color_idx++ % 6], 1, 0xFF1B1B1B);
            gfx_putc(&gfx_con, spinner[spinner_idx++ % 4]);
        }
        memcpy(path + 26, fno.fname, 36);
        path[62] = 0;
        if (fno.fattrib & AM_DIR)
            memcpy(path + 62, "/00", 4);
        if (f_open(&fp, path, FA_READ | FA_OPEN_EXISTING)) continue;
        if (f_lseek(&fp, 0x200) || f_read(&fp, dec_header, 32, &read_bytes) || read_bytes != 32) {
            f_close(&fp);
            continue;
        }
        se_aes_xts_crypt(5, 4, 0, 1, dec_header + 0x200, dec_header, 32, 1);
        // es doesn't contain es key sources on 1.0.0
        if (memcmp(pkg1_id->id, "2016", 4) && *(u32*)(dec_header + 0x210) == 0x33 && dec_header[0x205] == 0) {
            // es (offset 0x210 is lower half of titleid, 0x205 == 0 means it's program nca, not meta)
            switch (pkg1_id->kb) {
            case KB_FIRMWARE_VERSION_100_200:
                start_offset = 0x557b;
                break;
            case KB_FIRMWARE_VERSION_300:
            case KB_FIRMWARE_VERSION_301:
                start_offset = 0x552d;
                break;
            case KB_FIRMWARE_VERSION_400:
                start_offset = 0x5382;
                break;
            case KB_FIRMWARE_VERSION_500:
                start_offset = 0x5a63;
                break;
            case KB_FIRMWARE_VERSION_600:
            case KB_FIRMWARE_VERSION_620:
                start_offset = 0x5674;
                break;
            case KB_FIRMWARE_VERSION_700:
                start_offset = 0x5563;
                break;
            }
            hash_order[2] = 2;
            if (pkg1_id->kb < KB_FIRMWARE_VERSION_500) {
                hash_order[0] = 0;
                hash_order[1] = 1;
            } else {
                hash_order[0] = 1;
                hash_order[1] = 0;
            }
            hash_index = 0;
            // decrypt only what is needed to locate needed keys
            temp_file = (u8*)_nca_process(5, 4, &fp, start_offset, 0x50);
            for (u32 i = 0; i <= 0x40; ) {
                se_calc_sha256(temp_hash, temp_file + i, 0x10);
                if (!memcmp(temp_hash, es_hashes_sha256[hash_order[hash_index]], 0x10)) {
                    memcpy(es_keys[hash_order[hash_index]], temp_file + i, 0x10);
                    hash_index++;
                    if (hash_index == 3)
                        break;
                    i += 0x10;
                } else {
                    i++;
                }
            }
            free(temp_file);
            temp_file = NULL;
            titles_found++;
        } else if (*(u32*)(dec_header + 0x210) == 0x24 && dec_header[0x205] == 0) {
            // ssl
            switch (pkg1_id->kb) {
            case KB_FIRMWARE_VERSION_100_200:
                start_offset = 0x3d41a;
                break;
            case KB_FIRMWARE_VERSION_300:
            case KB_FIRMWARE_VERSION_301:
                start_offset = 0x3cb81;
                break;
            case KB_FIRMWARE_VERSION_400:
                start_offset = 0x3711c;
                break;
            case KB_FIRMWARE_VERSION_500:
                start_offset = 0x37901;
                break;
            case KB_FIRMWARE_VERSION_600:
            case KB_FIRMWARE_VERSION_620:
                start_offset = 0x1d5be;
                break;
            case KB_FIRMWARE_VERSION_700:
                start_offset = 0x1d437;
                break;
            }
            if (!memcmp(pkg1_id->id, "2016", 4))
                start_offset = 0x449dc;
            temp_file = (u8*)_nca_process(5, 4, &fp, start_offset, 0x50);
            for (u32 i = 0; i <= 0x40; i++) {
                se_calc_sha256(temp_hash, temp_file + i, 0x10);
                if (!memcmp(temp_hash, ssl_hashes_sha256[1], 0x10)) {
                    memcpy(ssl_keys[1], temp_file + i, 0x10);
                    // only get ssl_rsa_kek_source_x from SSL on 1.0.0
                    // we get it from ES on every other firmware
                    // and it's located oddly distant from ssl_rsa_kek_source_y on >= 6.0.0
                    if (!memcmp(pkg1_id->id, "2016", 4)) {
                        se_calc_sha256(temp_hash, temp_file + i + 0x10, 0x10);
                        if (!memcmp(temp_hash, ssl_hashes_sha256[0], 0x10))
                            memcpy(es_keys[2], temp_file + i + 0x10, 0x10);
                    }
                    break;
                }
            }
            free(temp_file);
            temp_file = NULL;
            titles_found++;
        }
        f_close(&fp);
    }
    f_closedir(&dir);
    free(dec_header);

    if (f_open(&fp, "sd:/Nintendo/Contents/private", FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Failed to open SD seed verification file from SD.");
        goto dismount;
    }
    // get sd seed verification vector
    if (f_read(&fp, temp_key, 0x10, &read_bytes) || read_bytes != 0x10) {
        EPRINTF("Failed to read SD seed verification vector from SD.");
        f_close(&fp);
        goto dismount;
    }
    f_close(&fp);

    if (f_open(&fp, "emmc:/save/8000000000000043", FA_READ | FA_OPEN_EXISTING) || f_stat("emmc:/save/8000000000000043", &fno)) {
        EPRINTF("Failed to open ns_appman save.");
        goto dismount;
    }

    // locate sd seed
    u8 read_buf[0x20] = {0};
    for (u32 i = 0; i < fno.fsize; i += 0x4000) {
        if (f_lseek(&fp, i) || f_read(&fp, read_buf, 0x20, &read_bytes) || read_bytes != 0x20)
            break;
        if (!memcmp(temp_key, read_buf, 0x10)) {
            memcpy(sd_seed, read_buf + 0x10, 0x10);
            break;
        }
    }
    f_close(&fp);

    // derive eticket_rsa_kek and ssl_rsa_kek
    if (_key_exists(es_keys[0]) && _key_exists(es_keys[1]) && _key_exists(master_key[0])) {
        for (u32 i = 0; i < 0x10; i++)
            temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
        _generate_kek(8, es_keys[1], master_key[0], temp_key, NULL);
        se_aes_crypt_block_ecb(8, 0, eticket_rsa_kek, es_keys[0]);
    }
    if (_key_exists(ssl_keys[1]) && _key_exists(es_keys[2]) && _key_exists(master_key[0])) {
        for (u32 i = 0; i < 0x10; i++)
            temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_01[i];
        _generate_kek(8, es_keys[2], master_key[0], temp_key, NULL);
        se_aes_crypt_block_ecb(8, 0, ssl_rsa_kek, ssl_keys[1]);
    }

dismount:
    f_mount(NULL, "emmc:", 1);
    nx_emmc_gpt_free(&gpt);
    sdmmc_storage_end(&storage);

    gfx_con_setpos(&gfx_con, x - 16, y);
    TPRINTFARGS("%k", colors[5]);

key_output: ;
    char *text_buffer = (char *)calloc(0x4000, 1);
    u32 buf_index = 0;

    SAVE_KEY("aes_kek_generation_source", aes_kek_generation_source, 0x10);
    SAVE_KEY("aes_key_generation_source", aes_key_generation_source, 0x10);
    SAVE_KEY("bis_kek_source", bis_kek_source, 0x10);
    SAVE_KEY_FAMILY("bis_key", bis_key, 4, 0x20);
    SAVE_KEY_FAMILY("bis_key_source", bis_key_source, 3, 0x20);
    SAVE_KEY("device_key", device_key, 0x10);
    SAVE_KEY("eticket_rsa_kek", eticket_rsa_kek, 0x10);
    SAVE_KEY("eticket_rsa_kek_source", es_keys[0], 0x10);
    SAVE_KEY("eticket_rsa_kekek_source", es_keys[1], 0x10);
    SAVE_KEY("header_kek_source", fs_keys[0], 0x10);
    SAVE_KEY("header_key", header_key, 0x20);
    SAVE_KEY("header_key_source", fs_keys[1], 0x20);
    SAVE_KEY_FAMILY("key_area_key_application", key_area_key[0], MAX_KEY, 0x10);
    SAVE_KEY("key_area_key_application_source", fs_keys[2], 0x10);
    SAVE_KEY_FAMILY("key_area_key_ocean", key_area_key[1], MAX_KEY, 0x10);
    SAVE_KEY("key_area_key_ocean_source", fs_keys[3], 0x10);
    SAVE_KEY_FAMILY("key_area_key_system", key_area_key[2], MAX_KEY, 0x10);
    SAVE_KEY("key_area_key_system_source", fs_keys[4], 0x10);
    SAVE_KEY_FAMILY("keyblob", keyblob, 6, 0x90);
    SAVE_KEY_FAMILY("keyblob_key", keyblob_key, 6, 0x10);
    SAVE_KEY_FAMILY("keyblob_key_source", keyblob_key_source, 6, 0x10);
    SAVE_KEY_FAMILY("keyblob_mac_key", keyblob_mac_key, 6, 0x10);
    SAVE_KEY("keyblob_mac_key_source", keyblob_mac_key_source, 0x10);
    SAVE_KEY_FAMILY("master_kek", master_kek, MAX_KEY, 0x10);
    SAVE_KEY("master_kek_source_06", master_kek_sources[0], 0x10);
    SAVE_KEY("master_kek_source_07", master_kek_sources[1], 0x10);
    SAVE_KEY_FAMILY("master_key", master_key, MAX_KEY, 0x10);
    SAVE_KEY("master_key_source", master_key_source, 0x10);
    SAVE_KEY_FAMILY("package1_key", package1_key, 6, 0x10);
    SAVE_KEY_FAMILY("package2_key", package2_key, MAX_KEY, 0x10);
    SAVE_KEY("package2_key_source", package2_key_source, 0x10);
    SAVE_KEY("per_console_key_source", per_console_key_source, 0x10);
    SAVE_KEY("retail_specific_aes_key_source", retail_specific_aes_key_source, 0x10);
    for (u32 i = 0; i < 0x10; i++)
        temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
    SAVE_KEY("rsa_oaep_kek_generation_source", temp_key, 0x10);
    for (u32 i = 0; i < 0x10; i++)
        temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_01[i];
    SAVE_KEY("rsa_private_kek_generation_source", temp_key, 0x10);
    SAVE_KEY("save_mac_kek_source", fs_keys[5], 0x10);
    SAVE_KEY("save_mac_key", save_mac_key, 0x10);
    SAVE_KEY("save_mac_key_source", fs_keys[6], 0x10);
    SAVE_KEY("sd_card_kek_source", fs_keys[7], 0x10);
    SAVE_KEY("sd_card_nca_key_source", fs_keys[8], 0x20);
    SAVE_KEY("sd_card_save_key_source", fs_keys[9], 0x20);
    SAVE_KEY("sd_seed", sd_seed, 0x10);
    SAVE_KEY("secure_boot_key", sbk, 0x10);
    SAVE_KEY("ssl_rsa_kek", ssl_rsa_kek, 0x10);
    SAVE_KEY("ssl_rsa_kek_source_x", es_keys[2], 0x10);
    SAVE_KEY("ssl_rsa_kek_source_y", ssl_keys[1], 0x10);
    SAVE_KEY_FAMILY("titlekek", titlekek, MAX_KEY, 0x10);
    SAVE_KEY("titlekek_source", titlekek_source, 0x10);
    SAVE_KEY("tsec_key", tsec_keys, 0x10);
    if (pkg1_id->kb == KB_FIRMWARE_VERSION_620)
        SAVE_KEY("tsec_root_key", tsec_keys + 0x10, 0x10);

    //gfx_con.fntsz = 8; gfx_puts(&gfx_con, text_buffer); gfx_con.fntsz = 16;

    TPRINTFARGS("\n%kFound %d keys.\n%kLockpick totally", colors[0], _key_count, colors[1]);

    f_mkdir("switch");
    if (!sd_save_to_file(text_buffer, buf_index, "sd:/switch/prod.keys"))
        gfx_printf(&gfx_con, "%kWrote %d bytes to /switch/prod.keys\n", colors[2], buf_index);
    else
        EPRINTF("Failed to save keys to SD.");
    sd_unmount();
    free(text_buffer);

    gfx_printf(&gfx_con, "\n%kVOL + -> Reboot to RCM\n%kVOL - -> Reboot normally\n%kPower -> Power off", colors[3], colors[4], colors[5]);

out_wait: ;
    u32 btn = btn_wait();
    if (btn & BTN_VOL_UP)
        reboot_rcm();
    else if (btn & BTN_VOL_DOWN)
        reboot_normal();
    else
        power_off();
}

static void _save_key(const char *name, const void *data, const u32 len, char *outbuf, u32 *buf_index) {
    if (!_key_exists(data))
        return;
    *buf_index += _sprintf(outbuf + *buf_index, "%s = ", name);
    for (u32 i = 0; i < len; i += 4)
        *buf_index += _sprintf(outbuf + *buf_index, "%08x", byte_swap_32(_REG(data, i)));
    *buf_index += _sprintf(outbuf + *buf_index, "\n");
    _key_count++;
}

static void _save_key_family(const char *name, const void *data, const u32 num_keys, const u32 len, char *outbuf, u32 *buf_index) {
    char temp_name[0x40] = {0};
    for (u32 i = 0; i < num_keys; i++) {
        _sprintf(temp_name, "%s_%02x", name, i);
        _save_key(temp_name, data + i * len, len, outbuf, buf_index);
    }
}

static void _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed, const void *key_seed) {
    if (!_key_exists(key_source) || !_key_exists(master_key) || !_key_exists(kek_seed))
        return;

    se_aes_key_set(ks, master_key, 0x10);
    se_aes_unwrap_key(ks, ks, kek_seed);
    se_aes_unwrap_key(ks, ks, key_source);
    if (key_seed && _key_exists(key_seed))
        se_aes_unwrap_key(ks, ks, key_seed);
}

static inline u32 _read_le_u32(const void *buffer, u32 offset) {
    return (*(u8*)(buffer + offset + 0)        ) |
           (*(u8*)(buffer + offset + 1) << 0x08) |
           (*(u8*)(buffer + offset + 2) << 0x10) |
           (*(u8*)(buffer + offset + 3) << 0x18);
}

static void *_nca_process(u32 hk_ks1, u32 hk_ks2, FIL *fp, u32 key_offset, u32 len) {
    u32 read_bytes = 0, crypt_offset, read_size, num_files, string_table_size, rodata_offset;

    u8 *temp_file = (u8*)malloc(0x400),
        ctr[0x10] = {0};
    if (f_lseek(fp, 0x200) || f_read(fp, temp_file, 0x400, &read_bytes) || read_bytes != 0x400)
        return NULL;
    se_aes_xts_crypt(hk_ks1, hk_ks2, 0, 1, temp_file, temp_file, 0x200, 2);
    // both 1.x and 2.x use master_key_00
    temp_file[0x20] -= temp_file[0x20] ? 1 : 0;
    // decrypt key area and load decrypted key area key
    se_aes_key_set(7, key_area_key[temp_file[7]][temp_file[0x20]], 0x10);
    se_aes_crypt_block_ecb(7, 0, temp_file + 0x120, temp_file + 0x120);
    se_aes_key_set(2, temp_file + 0x120, 0x10);
    for (u32 i = 0; i < 8; i++)
        ctr[i] = temp_file[0x347 - i];
    crypt_offset = _read_le_u32(temp_file, 0x40) * 0x200 + _read_le_u32(temp_file, 0x240);
    read_size = 0x10;
    _nca_fread_ctr(2, fp, temp_file, crypt_offset, read_size, ctr);
    num_files = _read_le_u32(temp_file, 4);
    string_table_size = _read_le_u32(temp_file, 8);
    if (!memcmp(temp_file + 0x10 + num_files * 0x18, "main.npdm", 9))
        crypt_offset += _read_le_u32(temp_file, 0x18);
    crypt_offset += 0x10 + num_files * 0x18 + string_table_size;
    read_size = 0x40;
    _nca_fread_ctr(2, fp, temp_file, crypt_offset, read_size, ctr);
    rodata_offset = _read_le_u32(temp_file, 0x20);

    void *buf = malloc(len);
    _nca_fread_ctr(2, fp, buf, crypt_offset + rodata_offset + key_offset, len, ctr);
    free(temp_file);

    return buf;
}

static u32 _nca_fread_ctr(u32 ks, FIL *fp, void *buffer, u32 offset, u32 len, u8 *ctr) {
    u32 br;
    if (f_lseek(fp, offset) || f_read(fp, buffer, len, &br) || br != len)
        return 0;
    _update_ctr(ctr, offset);

    if (offset % 0x10) {
        u8 *temp = (u8*)malloc(ALIGN(br + offset % 0x10, 0x10));
        memcpy(temp + offset % 0x10, buffer, br);
        se_aes_crypt_ctr(ks, temp, ALIGN(br + offset % 0x10, 0x10), temp, ALIGN(br + offset % 0x10, 0x10), ctr);
        memcpy(buffer, temp + offset % 0x10, br);
        free(temp);
        return br;
    }
    se_aes_crypt_ctr(ks, buffer, br, buffer, br, ctr);
    return br;
}

static void _update_ctr(u8 *ctr, u32 ofs) {
    ofs >>= 4;
    for (u32 i = 0; i < 4; i++, ofs >>= 8)
        ctr[0x10-i-1] = (u8)(ofs & 0xff);
}

static void _putc(char *buffer, const char c) {
    *buffer = c;
}

static u32 _puts(char *buffer, const char *s) {
    u32 count = 0;
    for (; *s; s++, count++)
        _putc(buffer + count, *s);
    return count;
}

static u32 _putn(char *buffer, u32 v, int base, char fill, int fcnt) {
    char buf[0x121];
    static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char *p;
    int c = fcnt;

    if (base > 36)
        return 0;

    p = buf + 0x120;
    *p = 0;
    do {
        c--;
        *--p = digits[v % base];
        v /= base;
    } while (v);

    if (fill != 0) {
        while (c > 0) {
            *--p = fill;
            c--;
        }
    }

    return _puts(buffer, p);
}

static u32 _sprintf(char *buffer, const char *fmt, ...) {
    va_list ap;
    int fill, fcnt;
    u32 count = 0;

    va_start(ap, fmt);
    while(*fmt) {
        if (*fmt == '%') {
            fmt++;
            fill = 0;
            fcnt = 0;
            if ((*fmt >= '0' && *fmt <= '9') || *fmt == ' ') {
                fcnt = *fmt;
                fmt++;
                if (*fmt >= '0' && *fmt <= '9') {
                    fill = fcnt;
                    fcnt = *fmt - '0';
                    fmt++;
                } else {
                    fill = ' ';
                    fcnt -= '0';
                }
            }
            switch (*fmt) {
            case 'c':
                _putc(buffer + count, va_arg(ap, u32));
                count++;
                break;
            case 's':
                count += _puts(buffer + count, va_arg(ap, char *));
                break;
            case 'd':
                count += _putn(buffer + count, va_arg(ap, u32), 10, fill, fcnt);
                break;
            case 'p':
            case 'P':
            case 'x':
            case 'X':
                count += _putn(buffer + count, va_arg(ap, u32), 16, fill, fcnt);
                break;
            case '%':
                _putc(buffer + count, '%');
                count++;
                break;
            case '\0':
                goto out;
            default:
                _putc(buffer + count, '%');
                _putc(buffer + count, *fmt);
                count += 2;
                break;
            }
        } else {
            _putc(buffer + count, *fmt);
            count++;
        }
        fmt++;
    }

    out:
    va_end(ap);
    return count;
}
