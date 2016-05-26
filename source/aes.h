// Copyright 2014 Normmatt
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include "common.h"

#define REG_AESCNT      (*(vu32*)0x10009000)
#define REG_AESBLKCNT   (*(vu32*)0x10009004)
#define REG_AESBLKCNTH1 (*(vu16*)0x10009004)
#define REG_AESBLKCNTH2 (*(vu16*)0x10009006)
#define REG_AESWRFIFO   (*(vu32*)0x10009008)
#define REG_AESRDFIFO   (*(vu32*)0x1000900C)
#define REG_AESKEYSEL   (*(vu8*)0x10009010)
#define REG_AESKEYCNT   (*(vu8*)0x10009011)
#define REG_AESCTR      ((vu32*)0x10009020) // 16
#define REG_AESMAC      ((vu32*)0x10009030) // 16
#define REG_AESKEY0     ((vu32*)0x10009040) // 48
#define REG_AESKEY1     ((vu32*)0x10009070) // 48
#define REG_AESKEY2     ((vu32*)0x100090A0) // 48
#define REG_AESKEY3     ((vu32*)0x100090D0) // 48
#define REG_AESKEYFIFO  (*(vu32*)0x10009100)
#define REG_AESKEYXFIFO (*(vu32*)0x10009104)
#define REG_AESKEYYFIFO (*(vu32*)0x10009108)

#define AES_WRITE_FIFO_COUNT    ((REG_AESCNT>>0) & 0x1F)
#define AES_READ_FIFO_COUNT     ((REG_AESCNT>>5) & 0x1F)
#define AES_BUSY                (1u<<31)

#define AES_FLUSH_READ_FIFO     (1u<<10)
#define AES_FLUSH_WRITE_FIFO    (1u<<11)
#define AES_BIT12               (1u<<12)
#define AES_BIT13               (1u<<13)
#define AES_MAC_SIZE(n)         ((n&7u)<<16)
#define AES_MAC_REGISTER_SOURCE (1u<<20)
#define AES_UNKNOWN_21          (1u<<21)
#define AES_OUTPUT_BIG_ENDIAN   (1u<<22)
#define AES_INPUT_BIG_ENDIAN    (1u<<23)
#define AES_OUTPUT_NORMAL_ORDER (1u<<24)
#define AES_INPUT_NORMAL_ORDER  (1u<<25)
#define AES_UNKNOWN_26          (1u<<26)
#define AES_MODE(n)             ((n&7u)<<27)
#define AES_INTERRUPT_ENABLE    (1u<<30)
#define AES_ENABLE              (1u<<31)

#define AES_MODE_CCM_DECRYPT    0u
#define AES_MODE_CCM_ENCRYPT    1u
#define AES_MODE_CTR            2u
#define AES_MODE_UNK3           3u
#define AES_MODE_CBC_DECRYPT    4u
#define AES_MODE_CBC_ENCRYPT    5u
#define AES_MODE_UNK6           6u
#define AES_MODE_UNK7           7u
