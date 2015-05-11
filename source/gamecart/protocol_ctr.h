// Copyright 2014 Normmatt
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include "common.h"

#define REG_CTRCARDCNT     (*(vu32*)0x10004000)
#define REG_CTRCARDBLKCNT  (*(vu32*)0x10004004)
#define REG_CTRCARDSECCNT  (*(vu32*)0x10004008)
#define REG_CTRCARDSECSEED (*(vu32*)0x10004010)
#define REG_CTRCARDCMD     ((vu32*)0x10004020)
#define REG_CTRCARDFIFO    (*(vu32*)0x10004030)

#define CTRCARD_PAGESIZE_0   (0<<16)
#define CTRCARD_PAGESIZE_4   (1<<16)
#define CTRCARD_PAGESIZE_16  (2<<16)
#define CTRCARD_PAGESIZE_64  (3<<16)
#define CTRCARD_PAGESIZE_512 (4<<16)
#define CTRCARD_PAGESIZE_1K  (5<<16)
#define CTRCARD_PAGESIZE_2K  (6<<16)
#define CTRCARD_PAGESIZE_4K  (7<<16)
#define CTRCARD_PAGESIZE_16K (8<<16)
#define CTRCARD_PAGESIZE_64K (9<<16)

#define CTRCARD_CRC_ERROR    (1<<4)
#define CTRCARD_ACTIVATE     (1<<31)           // when writing, get the ball rolling
#define CTRCARD_IE           (1<<30)           // Interrupt enable
#define CTRCARD_WR           (1<<29)           // Card write enable
#define CTRCARD_nRESET       (1<<28)           // value on the /reset pin (1 = high out, not a reset state, 0 = low out = in reset)
#define CTRCARD_BLK_SIZE(n)  (((n)&0xF)<<16)   // Transfer block size

#define CTRCARD_BUSY         (1<<31)           // when reading, still expecting incomming data?
#define CTRCARD_DATA_READY   (1<<27)           // when reading, REG_CTRCARDFIFO has another word of data and is good to go

#define CTRKEY_PARAM 0x1000000

void CTR_SetSecKey(u32 value);
void CTR_SetSecSeed(const u32* seed, bool flag);

void CTR_SendCommand(const u32 command[4], u32 pageSize, u32 blocks, u32 latency, void* buffer);
