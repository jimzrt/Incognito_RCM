/*
 * Copyright (c) 2018 CTCaer
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

#ifndef LV_CONF_H
#define LV_CONF_H

#include <utils/types.h>
#include <memory_map.h>
/*===================
   Dynamic memory
 *===================*/

/* Memory size which will be used by the library
 * to store the graphical objects and other data */
#define LV_MEM_CUSTOM         0              /*1: use custom malloc/free, 0: use the built-in lv_mem_alloc/lv_mem_free*/
#if LV_MEM_CUSTOM == 0
#  define LV_MEM_SIZE         NYX_LV_MEM_SZ  /*Size memory used by `lv_mem_alloc` in bytes (>= 2kB)*/
#  define LV_MEM_ATTR                        /*Complier prefix for big array declaration*/
#  define LV_MEM_ADR          NYX_LV_MEM_ADR /*Set an address for memory pool instead of allocation it as an array. Can be in external SRAM too.*/
#  define LV_MEM_AUTO_DEFRAG  1              /*Automatically defrag on free*/
#else       /*LV_MEM_CUSTOM*/
#  define LV_MEM_CUSTOM_INCLUDE <mem/heap.h> /*Header for the dynamic memory function*/
#  define LV_MEM_CUSTOM_ALLOC   malloc       /*Wrapper to malloc*/
#  define LV_MEM_CUSTOM_FREE    free         /*Wrapper to free*/
#endif     /*LV_MEM_CUSTOM*/

/* Garbage Collector settings
 * Used if lvgl is binded to higher language and the memory is managed by that language */
#define LV_ENABLE_GC 0
#if LV_ENABLE_GC != 0
#  define LV_MEM_CUSTOM_REALLOC   your_realloc           /*Wrapper to realloc*/
#  define LV_MEM_CUSTOM_GET_SIZE  your_mem_get_size      /*Wrapper to lv_mem_get_size*/
#  define LV_GC_INCLUDE "gc.h"                           /*Include Garbage Collector related things*/
#endif /* LV_ENABLE_GC */

/*===================
   Graphical settings
 *===================*/

/* Horizontal and vertical resolution of the library.*/
#define LV_HOR_RES          (1280)
#define LV_VER_RES          (720)

/* Dot Per Inch: used to initialize default sizes. E.g. a button with width = LV_DPI / 2 -> half inch wide
 * (Not so important, you can adjust it to modify default sizes and spaces)*/
#define LV_DPI              100

/* Enable anti-aliasing (lines, and radiuses will be smoothed) */
#define LV_ANTIALIAS        1       /*1: Enable anti-aliasing*/

/*Screen refresh period in milliseconds*/
#define LV_REFR_PERIOD      33

/*-----------------
 *  VDB settings
 *----------------*/

/* VDB (Virtual Display Buffer) is an internal graphics buffer.
 * The GUI will be drawn into this buffer first and then
 * the buffer will be passed to your `disp_drv.disp_flush` function to
 * copy it to your frame buffer.
 * VDB is required for: buffered drawing, opacity, anti-aliasing and shadows
 * Learn more: https://docs.littlevgl.com/#Drawing*/

/* Size of the VDB in pixels. Typical size: ~1/10 screen. Must be >= LV_HOR_RES
 * Setting it to 0 will disable VDB and `disp_drv.disp_fill` and `disp_drv.disp_map` functions
 * will be called to draw to the frame buffer directly*/
#define LV_VDB_SIZE         (LV_VER_RES * LV_HOR_RES)

 /* Bit-per-pixel of VDB. Useful for monochrome or non-standard color format displays.
  * Special formats are handled with `disp_drv.vdb_wr`)*/
#define LV_VDB_PX_BPP       LV_COLOR_SIZE       /*LV_COLOR_SIZE comes from LV_COLOR_DEPTH below to set 8, 16 or 32 bit pixel size automatically */

 /* Place VDB to a specific address (e.g. in external RAM)
  * 0: allocate automatically into RAM
  * LV_VDB_ADR_INV: to replace it later with `lv_vdb_set_adr()`*/
#define LV_VDB_ADR          NYX_LV_VDB_ADR

/* Use two Virtual Display buffers (VDB) to parallelize rendering and flushing
 * The flushing should use DMA to write the frame buffer in the background */
#define LV_VDB_DOUBLE       0

/* Place VDB2 to a specific address (e.g. in external RAM)
 * 0: allocate automatically into RAM
 * LV_VDB_ADR_INV: to replace it later with `lv_vdb_set_adr()`*/
#define LV_VDB2_ADR         0

/* Using true double buffering in `disp_drv.disp_flush` you will always get the image of the whole screen.
 * Your only task is to set the rendered image (`color_p` parameter) as frame buffer address or send it to your display.
 * The best if you do in the blank period of you display to avoid tearing effect.
 * Requires:
 * - LV_VDB_SIZE = LV_HOR_RES * LV_VER_RES
 * - LV_VDB_DOUBLE = 1
 */
#define LV_VDB_TRUE_DOUBLE_BUFFERED 0

/*=================
   Misc. setting
 *=================*/

/*Input device settings*/
#define LV_INDEV_READ_PERIOD            33                     /*Input device read period in milliseconds*/
#define LV_INDEV_POINT_MARKER           0                      /*Mark the pressed points  (required: USE_LV_REAL_DRAW = 1)*/
#define LV_INDEV_DRAG_LIMIT             10                     /*Drag threshold in pixels */
#define LV_INDEV_DRAG_THROW             20                     /*Drag throw slow-down in [%]. Greater value means faster slow-down */
#define LV_INDEV_LONG_PRESS_TIME        400                    /*Long press time in milliseconds*/
#define LV_INDEV_LONG_PRESS_REP_TIME    1000 //Fix keyb        /*Repeated trigger period in long press [ms] */

/*Color settings*/
#define LV_COLOR_DEPTH         32                /*Color depth: 1/8/16/32*/
#define LV_COLOR_16_SWAP       0                 /*Swap the 2 bytes of RGB565 color. Useful if the display has a 8 bit interface (e.g. SPI)*/
#define LV_COLOR_SCREEN_TRANSP 0                 /*1: Enable screen transparency. Useful for OSD or other overlapping GUIs. Requires ARGB8888 colors*/
#define LV_COLOR_TRANSP        LV_COLOR_LIME     /*Images pixels with this color will not be drawn (with chroma keying)*/

/*Text settings*/
#define LV_TXT_UTF8             0                /*Enable UTF-8 coded Unicode character usage */
#define LV_TXT_BREAK_CHARS     " ,.;:-_"         /*Can break texts on these chars*/
#define LV_TXT_LINE_BREAK_LONG_LEN 12            /* If a character is at least this long, will break wherever "prettiest" */
#define LV_TXT_LINE_BREAK_LONG_PRE_MIN_LEN 3     /* Minimum number of characters of a word to put on a line before a break */
#define LV_TXT_LINE_BREAK_LONG_POST_MIN_LEN 1    /* Minimum number of characters of a word to put on a line after a break */

/*Feature usage*/
#define USE_LV_ANIMATION        1               /*1: Enable all animations*/
#define USE_LV_SHADOW           1               /*1: Enable shadows*/
#define USE_LV_GROUP            0               /*1: Enable object groups (for keyboards)*/
#define USE_LV_GPU              0               /*1: Enable GPU interface*/
#define USE_LV_REAL_DRAW        0               /*1: Enable function which draw directly to the frame buffer instead of VDB (required if LV_VDB_SIZE = 0)*/
#define USE_LV_FILESYSTEM       0               /*1: Enable file system (might be required for images*/
#define USE_LV_MULTI_LANG       0               /* Number of languages for labels to store (0: to disable this feature)*/

/*Compiler settings*/
#define LV_ATTRIBUTE_TICK_INC                   /* Define a custom attribute to `lv_tick_inc` function */
#define LV_ATTRIBUTE_TASK_HANDLER               /* Define a custom attribute to `lv_task_handler` function */
#define LV_COMPILER_VLA_SUPPORTED            1  /* 1: Variable length array is supported*/

/*HAL settings*/
#define LV_TICK_CUSTOM               1                       /*1: use a custom tick source (removing the need to manually update the tick with `lv_tick_inc`) */
#if LV_TICK_CUSTOM == 1
#define LV_TICK_CUSTOM_INCLUDE       <utils/util.h>          /*Header for the sys time function*/
#define LV_TICK_CUSTOM_SYS_TIME_EXPR (get_tmr_ms())          /*Expression evaluating to current systime in ms*/
#endif     /*LV_TICK_CUSTOM*/


/*Log settings*/
#define USE_LV_LOG        0   /*Enable/disable the log module*/
#if USE_LV_LOG
/* How important log should be added:
 * LV_LOG_LEVEL_TRACE       A lot of logs to give detailed information
 * LV_LOG_LEVEL_INFO        Log important events
 * LV_LOG_LEVEL_WARN        Log if something unwanted happened but didn't caused problem
 * LV_LOG_LEVEL_ERROR       Only critical issue, when the system may fail
 */
#  define LV_LOG_LEVEL    LV_LOG_LEVEL_WARN
/* 1: Print the log with 'printf'; 0: user need to register a callback*/
#  define LV_LOG_PRINTF   1
#endif  /*USE_LV_LOG*/

/*================
 *  THEME USAGE
 *================*/
#define LV_THEME_LIVE_UPDATE    0       /*1: Allow theme switching at run time. Uses 8..10 kB of RAM*/

#define USE_LV_THEME_HEKATE     1       /*Flat theme with bold colors and light shadows*/

/*==================
 *    FONT USAGE
 *===================*/

/* More info about fonts: https://docs.littlevgl.com/#Fonts
 * To enable a built-in font use 1,2,4 or 8 values
 * which will determine the bit-per-pixel. Higher value means smoother fonts */
#define LV_FONT_QUALITY 8

#define USE_UBUNTU_MONO            LV_FONT_QUALITY

#define USE_INTERUI_20             LV_FONT_QUALITY
#define USE_INTERUI_30             LV_FONT_QUALITY

#define USE_HEKATE_SYMBOL_20       USE_INTERUI_20
#define USE_HEKATE_SYMBOL_30       USE_INTERUI_30
#define USE_HEKATE_SYMBOL_120      LV_FONT_QUALITY

/* Optionally declare your custom fonts here.
 * You can use these fonts as default font too
 * and they will be available globally. E.g.
 * #define LV_FONT_CUSTOM_DECLARE LV_FONT_DECLARE(my_font_1) \
 *                                LV_FONT_DECLARE(my_font_2) \
 */
#define LV_FONT_CUSTOM_DECLARE

#define LV_FONT_DEFAULT        &interui_30     /*Always set a default font from the built-in fonts*/

/*===================
 *  LV_OBJ SETTINGS
 *==================*/
#define LV_OBJ_FREE_NUM_TYPE    uint32_t    /*Type of free number attribute (comment out disable free number)*/
#define LV_OBJ_FREE_PTR         1           /*Enable the free pointer attribute*/
#define LV_OBJ_REALIGN          1  // 0 in OG gui         /*Enable `lv_obj_realaign()` based on `lv_obj_align()` parameters*/

/*==================
 *  LV OBJ X USAGE
 *================*/
/*
 * Documentation of the object types: https://docs.littlevgl.com/#Object-types
 */

/*****************
 * Simple object
 *****************/

/*Label (dependencies: -*/
#define USE_LV_LABEL    1
#if USE_LV_LABEL != 0
#  define LV_LABEL_SCROLL_SPEED       25     /*Hor, or ver. scroll speed [px/sec] in 'LV_LABEL_LONG_SCROLL/ROLL' mode*/
#endif

/*Image (dependencies: lv_label*/
#define USE_LV_IMG      1
#if USE_LV_IMG != 0
#  define LV_IMG_CF_INDEXED   0       /*Enable indexed (palette) images*/
#  define LV_IMG_CF_ALPHA     0       /*Enable alpha indexed images*/
#endif

/*Line (dependencies: -*/
#define USE_LV_LINE     1

/*Arc (dependencies: -)*/
#define USE_LV_ARC      0

/*******************
 * Container objects
 *******************/

/*Container (dependencies: -*/
#define USE_LV_CONT     1

/*Page (dependencies: lv_cont)*/
#define USE_LV_PAGE     1

/*Window (dependencies: lv_cont, lv_btn, lv_label, lv_img, lv_page)*/
#define USE_LV_WIN      1

/*Tab (dependencies: lv_page, lv_btnm)*/
#define USE_LV_TABVIEW      1
#  if USE_LV_TABVIEW != 0
#  define LV_TABVIEW_ANIM_TIME    0     /*Time of slide animation [ms] (0: no animation)*/
#endif

/*Tileview (dependencies: lv_page) */
#define USE_LV_TILEVIEW     0
#if USE_LV_TILEVIEW
#  define LV_TILEVIEW_ANIM_TIME   0     /*Time of slide animation [ms] (0: no animation)*/
#endif

/*************************
 * Data visualizer objects
 *************************/

/*Bar (dependencies: -)*/
#define USE_LV_BAR      1

/*Line meter (dependencies: *;)*/
#define USE_LV_LMETER   0

/*Gauge (dependencies:lv_bar, lv_lmeter)*/
#define USE_LV_GAUGE    0

/*Chart (dependencies: -)*/
#define USE_LV_CHART    0

/*Table (dependencies: lv_label)*/
#define USE_LV_TABLE    1
#if USE_LV_TABLE
#  define LV_TABLE_COL_MAX    12
#endif

/*LED (dependencies: -)*/
#define USE_LV_LED      0

/*Message box (dependencies: lv_rect, lv_btnm, lv_label)*/
#define USE_LV_MBOX     1

/*Text area (dependencies: lv_label, lv_page)*/
#define USE_LV_TA       1
#if USE_LV_TA != 0
#  define LV_TA_CURSOR_BLINK_TIME 400     /*ms*/
#  define LV_TA_PWD_SHOW_TIME     1500    /*ms*/
#endif

/*Spinbox (dependencies: lv_ta)*/
#define USE_LV_SPINBOX  0

/*Calendar (dependencies: -)*/
#define USE_LV_CALENDAR 0

/*Preload (dependencies: lv_arc)*/
#define USE_LV_PRELOAD      0
#if USE_LV_PRELOAD != 0
#  define LV_PRELOAD_DEF_ARC_LENGTH   60      /*[deg]*/
#  define LV_PRELOAD_DEF_SPIN_TIME    1000    /*[ms]*/
#  define LV_PRELOAD_DEF_ANIM         LV_PRELOAD_TYPE_SPINNING_ARC
#endif

/*Canvas (dependencies: lv_img)*/
#define USE_LV_CANVAS       0
/*************************
 * User input objects
 *************************/

/*Button (dependencies: lv_cont*/
#define USE_LV_BTN      1
#if USE_LV_BTN != 0
#  define LV_BTN_INK_EFFECT   0       /*Enable button-state animations - draw a circle on click (dependencies: USE_LV_ANIMATION)*/
#endif

/*Image Button (dependencies: lv_btn*/
#define USE_LV_IMGBTN   1
#if USE_LV_IMGBTN
#  define LV_IMGBTN_TILED 0           /*1: The imgbtn requires left, mid and right parts and the width can be set freely*/
#endif

/*Button matrix (dependencies: -)*/
#define USE_LV_BTNM     1

/*Keyboard (dependencies: lv_btnm)*/
#define USE_LV_KB       0

/*Check box (dependencies: lv_btn, lv_label)*/
#define USE_LV_CB       1

/*List (dependencies: lv_page, lv_btn, lv_label, (lv_img optionally for icons ))*/
#define USE_LV_LIST     1
#if USE_LV_LIST != 0
#  define LV_LIST_FOCUS_TIME  100 /*Default animation time of focusing to a list element [ms] (0: no animation)  */
#endif

/*Drop down list (dependencies: lv_page, lv_label, lv_symbol_def.h)*/
#define USE_LV_DDLIST    1
#if USE_LV_DDLIST != 0
#  define LV_DDLIST_ANIM_TIME     100     /*Open and close default animation time [ms] (0: no animation)*/
#endif

/*Roller (dependencies: lv_ddlist)*/
#define USE_LV_ROLLER    1
#if USE_LV_ROLLER != 0
#  define LV_ROLLER_ANIM_TIME     200     /*Focus animation time [ms] (0: no animation)*/
#endif

/*Slider (dependencies: lv_bar)*/
#define USE_LV_SLIDER    1

/*Switch (dependencies: lv_slider)*/
#define USE_LV_SW        1

#endif /*LV_CONF_H*/

