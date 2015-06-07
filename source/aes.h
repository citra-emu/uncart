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
#define AES_BUSY                (1<<31)

#define AES_FLUSH_READ_FIFO     (1<<10)
#define AES_FLUSH_WRITE_FIFO    (1<<11)
#define AES_BIT12               (1<<12)
#define AES_BIT13               (1<<13)
#define AES_MAC_SIZE(n)         ((n&7)<<16)
#define AES_MAC_REGISTER_SOURCE (1<<20)
#define AES_UNKNOWN_21          (1<<21)
#define AES_OUTPUT_BIG_ENDIAN   (1<<22)
#define AES_INPUT_BIG_ENDIAN    (1<<23)
#define AES_OUTPUT_NORMAL_ORDER (1<<24)
#define AES_INPUT_NORMAL_ORDER  (1<<25)
#define AES_UNKNOWN_26          (1<<26)
#define AES_MODE(n)             ((n&7)<<27)
#define AES_INTERRUPT_ENABLE    (1<<30)
#define AES_ENABLE              (1<<31)

#define AES_MODE_CCM_DECRYPT    0
#define AES_MODE_CCM_ENCRYPT    1
#define AES_MODE_CTR            2
#define AES_MODE_UNK3           3
#define AES_MODE_CBC_DECRYPT    4
#define AES_MODE_CBC_ENCRYPT    5
#define AES_MODE_UNK6           6
#define AES_MODE_UNK7           7
#define AES_CCM_DECRYPT_MODE    (AES_MODE_CCM_DECRYPT << 27)
#define AES_CCM_ENCRYPT_MODE    (AES_MODE_CCM_ENCRYPT << 27)
#define AES_CTR_MODE            (AES_MODE_CTR << 27)
#define AES_CBC_DECRYPT_MODE    (AES_MODE_CBC_DECRYPT << 27)
#define AES_CBC_ENCRYPT_MODE    (AES_MODE_CBC_ENCRYPT << 27)
#define AES_ECB_DECRYPT_MODE    (AES_MODE_UNK6 << 27)
#define AES_ECB_ENCRYPT_MODE    (AES_MODE_UNK7 << 27)

#define AES_BIG_INPUT      1
#define AES_LITTLE_INPUT   0
#define AES_NORMAL_INPUT   4
#define AES_REVERSED_INPUT 0
#define AES_BLOCK_SIZE 0x10

void add_ctr(void* ctr, u32 carry);

void setup_aeskeyX(u8 keyslot, void* keyx);
void decrypt(void* key, void* iv, void* inbuf, void* outbuf, size_t size);
void setup_aeskey(u32 keyno, int value, void* key);
void use_aeskey(u32 keyno);
void set_ctr(int mode, void* iv);
void aes_decrypt(void* inbuf, void* outbuf, void* iv, size_t size, u32 mode);
void aes_fifos(void* inbuf, void* outbuf, size_t blocks);
void set_aeswrfifo(u32 value);
u32 read_aesrdfifo(void);
u32 aes_getwritecount();
u32 aes_getreadcount();
u32 aescnt_checkwrite();
u32 aescnt_checkread();
