#pragma once

#include "common.h"

#define READ 1
#define WRITE 2
#define CREATE 4

#define REG_CARDCONF (*(vu16*)0x1000000C)
#define REG_CARDCONF2 (*(vu8*)0x10000010)

#define REG_CTRCARDCNT (*(vu32*)0x10004000)
#define REG_CTRCARDBLKCNT (*(vu32*)0x10004004)
#define REG_CTRCARDSECCNT (*(vu32*)0x10004008)
#define REG_CTRCARDSECSEED (*(vu32*)0x10004010)
#define REG_CTRCARDCMD ((vu32*)0x10004020)
#define REG_CTRCARDFIFO (*(vu32*)0x10004030)

#define KEYS (*(vu32*)0x10146000)
#define PXICNT (*(vu32*)0x10163004)
#define IE (*(vu32*)0x10001000)
#define IF (*(vu32*)0x10001004)

#define TM0VAL (*(vu16*)0x10003000)
#define TM0CNT (*(vu16*)0x10003002)
#define TM1VAL (*(vu16*)0x10003004)
#define TM1CNT (*(vu16*)0x10003006)
#define TM2VAL (*(vu16*)0x10003008)
#define TM2CNT (*(vu16*)0x1000300A)
#define TM3VAL (*(vu16*)0x1000300C)
#define TM3CNT (*(vu16*)0x1000300E)

#define NDMAGCNT (*(vu32*)0x10002000)
#define NDMACNT(n) (*(vu32*)(0x1000201C+n*0x1c))

#define REG_AESCNT (*(vu32*)0x10009000)
#define REG_AESBLKCNT (*(vu32*)0x10009004)
#define REG_AESBLKCNTH1 (*(vu16*)0x10009004)
#define REG_AESBLKCNTH2 (*(vu16*)0x10009006)
#define REG_AESWRFIFO (*(vu32*)0x10009008)
#define REG_AESRDFIFO (*(vu32*)0x1000900C)
#define REG_AESKEYSEL (*(vu8*)0x10009010)
#define REG_AESKEYCNT (*(vu8*)0x10009011)
#define REG_AESCTR ((vu32*)0x10009020) //16
#define REG_AESMAC ((vu32*)0x10009030) //16
#define REG_AESKEY0 ((vu32*)0x10009040) //48
#define REG_AESKEY1 ((vu32*)0x10009070) //48
#define REG_AESKEY2 ((vu32*)0x100090A0) //48
#define REG_AESKEY3 ((vu32*)0x100090D0) //48
#define REG_AESKEYFIFO (*(vu32*)0x10009100)
#define REG_AESKEYXFIFO (*(vu32*)0x10009104)
#define REG_AESKEYYFIFO (*(vu32*)0x10009108)

#define AES_WRITE_FIFO_COUNT		((REG_AESCNT>>0) & 0x1F)
#define AES_READ_FIFO_COUNT			((REG_AESCNT>>5) & 0x1F)
#define AES_BUSY					(1<<31)

#define AES_FLUSH_READ_FIFO			(1<<10)
#define AES_FLUSH_WRITE_FIFO		(1<<11)
#define AES_BIT12					(1<<12)
#define AES_BIT13					(1<<13)
#define AES_MAC_SIZE(n)				((n&7)<<16)
#define AES_MAC_REGISTER_SOURCE		(1<<20)
#define AES_UNKNOWN_21				(1<<21)
#define AES_OUTPUT_BIG_ENDIAN		(1<<22)
#define AES_INPUT_BIG_ENDIAN		(1<<23)
#define AES_OUTPUT_NORMAL_ORDER		(1<<24)
#define AES_INPUT_NORMAL_ORDER		(1<<25)
#define AES_UNKNOWN_26				(1<<26)
#define AES_MODE(n)					((n&7)<<27)
#define AES_INTERRUPT_ENABLE		(1<<30)
#define AES_ENABLE					(1<<31)

#define AES_MODE_CCM_DECRYPT		(0)
#define AES_MODE_CCM_ENCRYPT		(1)
#define AES_MODE_CTR				(2)
#define AES_MODE_UNK3				(3)
#define AES_MODE_CBC_DECRYPT		(4)
#define AES_MODE_CBC_ENCRYPT		(5)
#define AES_MODE_UNK6				(6)
#define AES_MODE_UNK7				(7)

#define REG_NTRCARDMCNT (*(vu16*)0x10164000)
#define REG_NTRCARDMDATA (*(vu16*)0x10164002)
#define REG_NTRCARDROMCNT (*(vu32*)0x10164004)
#define REG_NTRCARDCMD ((vu8*)0x10164008)
#define REG_NTRCARDSEEDX_L (*(vu32*)0x10164010)
#define REG_NTRCARDSEEDY_L (*(vu32*)0x10164014)
#define REG_NTRCARDSEEDX_H (*(vu16*)0x10164018)
#define REG_NTRCARDSEEDY_H (*(vu16*)0x1016401A)
#define REG_NTRCARDFIFO (*(vu32*)0x1016401C)

#define NTRCARD_PAGESIZE_0			(0<<24)
#define NTRCARD_PAGESIZE_4			(7<<24)
#define NTRCARD_PAGESIZE_512		(1<<24)
#define NTRCARD_PAGESIZE_1K			(2<<24)
#define NTRCARD_PAGESIZE_2K			(3<<24)
#define NTRCARD_PAGESIZE_4K			(4<<24)
#define NTRCARD_PAGESIZE_8K			(5<<24)
#define NTRCARD_PAGESIZE_16K		(6<<24)

#define CTRCARD_PAGESIZE_0			(0<<16)
#define CTRCARD_PAGESIZE_4			(1<<16)
#define CTRCARD_PAGESIZE_16			(2<<16)
#define CTRCARD_PAGESIZE_64			(3<<16)
#define CTRCARD_PAGESIZE_512		(4<<16)
#define CTRCARD_PAGESIZE_1K			(5<<16)
#define CTRCARD_PAGESIZE_2K			(6<<16)
#define CTRCARD_PAGESIZE_4K			(7<<16)
#define CTRCARD_PAGESIZE_16K		(8<<16)
#define CTRCARD_PAGESIZE_64K		(9<<16)

#define CTRCARD_CRC_ERROR    (1<<4)
#define CTRCARD_ACTIVATE     (1<<31)           // when writing, get the ball rolling
#define CTRCARD_IE           (1<<30)           // Interrupt enable
#define CTRCARD_WR           (1<<29)           // Card write enable
#define CTRCARD_nRESET       (1<<28)           // value on the /reset pin (1 = high out, not a reset state, 0 = low out = in reset)
#define CTRCARD_BLK_SIZE(n)  (((n)&0xF)<<16)   // Transfer block size

#define CTRCARD_BUSY         (1<<31)           // when reading, still expecting incomming data?
#define CTRCARD_DATA_READY   (1<<27)           // when reading, REG_CTRCARDFIFO has another word of data and is good to go

#define NTRCARD_ACTIVATE     (1<<31)           // when writing, get the ball rolling
#define NTRCARD_WR           (1<<30)           // Card write enable
#define NTRCARD_nRESET       (1<<29)           // value on the /reset pin (1 = high out, not a reset state, 0 = low out = in reset)
#define NTRCARD_SEC_LARGE    (1<<28)           // Use "other" secure area mode, which tranfers blocks of 0x1000 bytes at a time
#define NTRCARD_CLK_SLOW     (1<<27)           // Transfer clock rate (0 = 6.7MHz, 1 = 4.2MHz)
#define NTRCARD_BLK_SIZE(n)  (((n)&0x7)<<24)   // Transfer block size, (0 = None, 1..6 = (0x100 << n) bytes, 7 = 4 bytes)
#define NTRCARD_SEC_CMD      (1<<22)           // The command transfer will be hardware encrypted (KEY2)
#define NTRCARD_DELAY2(n)    (((n)&0x3F)<<16)  // Transfer delay length part 2
#define NTRCARD_SEC_SEED     (1<<15)           // Apply encryption (KEY2) seed to hardware registers
#define NTRCARD_SEC_EN       (1<<14)           // Security enable
#define NTRCARD_SEC_DAT      (1<<13)           // The data transfer will be hardware encrypted (KEY2)
#define NTRCARD_DELAY1(n)    ((n)&0x1FFF)      // Transfer delay length part 1

// 3 bits in b10..b8 indicate something
// read bits
#define NTRCARD_BUSY         (1<<31)           // when reading, still expecting incomming data?
#define NTRCARD_DATA_READY   (1<<23)           // when reading, REG_NTRCARDFIFO has another word of data and is good to go

// Card commands
#define NTRCARD_CMD_DUMMY          0x9F
#define NTRCARD_CMD_HEADER_READ    0x00
#define NTRCARD_CMD_HEADER_CHIPID  0x90
#define NTRCARD_CMD_ACTIVATE_BF    0x3C  // Go into blowfish (KEY1) encryption mode
#define NTRCARD_CMD_ACTIVATE_SEC   0x40  // Go into hardware (KEY2) encryption mode
#define NTRCARD_CMD_SECURE_CHIPID  0x10
#define NTRCARD_CMD_SECURE_READ    0x20
#define NTRCARD_CMD_DISABLE_SEC    0x60  // Leave hardware (KEY2) encryption mode
#define NTRCARD_CMD_DATA_MODE      0xA0
#define NTRCARD_CMD_DATA_READ      0xB7
#define NTRCARD_CMD_DATA_CHIPID    0xB8

#define NTRCARD_CR1_ENABLE  0x8000
#define NTRCARD_CR1_IRQ     0x4000

//REG_AUXSPICNT
#define CARD_ENABLE			(1<<15)
#define CARD_SPI_ENABLE		(1<<13)
#define CARD_SPI_BUSY		(1<<7)
#define CARD_SPI_HOLD		(1<<6)
#define KEY_PARAM 0x3F1FFF
#define CTRKEY_PARAM 0x1000000
#define LATENCY 0x822C

#define KEY_A (1<<0)
#define KEY_B 1<<1
#define KEY_SELECT 1<<2
#define KEY_START 1<<3
#define KEY_RIGHT 1<<4
#define KEY_LEFT 1<<5
#define KEY_UP 1<<6
#define KEY_DOWN 1<<7
#define KEY_R 1<<8
#define KEY_L 1<<9
#define KEY_X 1<<10
#define KEY_Y 1<<11