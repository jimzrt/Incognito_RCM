#ifndef _IO_DEFINED
#define _IO_DEFINED

#include "../../utils/types.h"

bool prodinfo_read (u8 *buff, u32 sector, u32 count);
bool prodinfo_write (u8 *buff, u32 sector, u32 count);

#endif