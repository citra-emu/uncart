#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "common.h"
//#include "AES.h"
//#include "DrawCharacter.h"
#include "misc.h"

void ioDelay(u32 us);
extern u8* bottomScreen;

int CartID = -1;
u32 CartType = 0;
int A0_Response = -1;

u32 rand1 = 0;
u32 rand2 = 0;

u32 BSWAP32(u32 val) {
    return (((val >> 24) & 0xFF)) |
           (((val >> 16) & 0xFF) << 8) |
           (((val >> 8) & 0xFF) << 16) |
           ((val & 0xFF) << 24);
}

//Reset the cart slot?
#define REG_CARDCONF (*(vu16*)0x1000000C)
#define REG_CARDCONF2 (*(vu8*)0x10000010)
void GatewayCartInit()
{
    REG_CARDCONF2 = 0x0C;

    REG_CARDCONF &= ~3;

    if(REG_CARDCONF2 == 0xC)
    {
        while(REG_CARDCONF2 != 0);
    }

    if(REG_CARDCONF2 != 0)
    {
        return;
    }

    REG_CARDCONF2 = 0x4;
    while(REG_CARDCONF2 != 0x4);

    REG_CARDCONF2 = 0x8;
    while(REG_CARDCONF2 != 0x8);
}

void SwitchToNTRCARD()
{
    REG_NTRCARDROMCNT = 0x20000000;
    REG_CARDCONF &= ~3;
    REG_CARDCONF &= ~0x100;
    REG_NTRCARDMCNT = NTRCARD_CR1_ENABLE;
}

void SwitchToCTRCARD()
{
    REG_CTRCARDCNT = 0x10000000;
    REG_CARDCONF = (REG_CARDCONF&~3) | 2;
}

void NTR_SendCommand( u32 command[2], u32 pageSize, u32 latency, void * buffer )
{
    REG_NTRCARDMCNT = NTRCARD_CR1_ENABLE;

    for( u32 i=0; i<2; ++i )
    {
        REG_NTRCARDCMD[i*4+0] = command[i]>>24;
        REG_NTRCARDCMD[i*4+1] = command[i]>>16;
        REG_NTRCARDCMD[i*4+2] = command[i]>>8;
        REG_NTRCARDCMD[i*4+3] = command[i]>>0;
    }

    pageSize -= pageSize & 3; // align to 4 byte
    u32 pageParam = NTRCARD_PAGESIZE_4K;
    u32 transferLength = 4096;
    // make zero read and 4 byte read a little special for timing optimization(and 512 too)
    if( 0 == pageSize ) {
        transferLength = 0;
        pageParam = NTRCARD_PAGESIZE_0;
    } else if( 4 == pageSize ) {
        transferLength = 4;
        pageParam = NTRCARD_PAGESIZE_4;
    } else if( 512 == pageSize ) {
        transferLength = 512;
        pageParam = NTRCARD_PAGESIZE_512;
    } else if( 8192 == pageSize ) {
        transferLength = 8192;
        pageParam = NTRCARD_PAGESIZE_8K;
    }

    // go
    REG_NTRCARDROMCNT = 0x10000000;
    REG_NTRCARDROMCNT = KEY_PARAM | NTRCARD_ACTIVATE | NTRCARD_nRESET | pageParam | latency;

    u8 * pbuf = (u8 *)buffer;
    u32 * pbuf32 = (u32 * )buffer;
    bool useBuf = ( NULL != pbuf );
    bool useBuf32 = (useBuf && (0 == (3 & ((u32)buffer))));

    u32 count = 0;
    u32 cardCtrl = REG_NTRCARDROMCNT;

    if(useBuf32)
    {
        while( (cardCtrl & NTRCARD_BUSY) && count < pageSize)
        {
            cardCtrl = REG_NTRCARDROMCNT;
            if( cardCtrl & NTRCARD_DATA_READY  ) {
                u32 data = REG_NTRCARDFIFO;
                *pbuf32++ = data;
                count += 4;
            }
        }
    }
    else if(useBuf)
    {
        while( (cardCtrl & NTRCARD_BUSY) && count < pageSize)
        {
            cardCtrl = REG_NTRCARDROMCNT;
            if( cardCtrl & NTRCARD_DATA_READY  ) {
                u32 data = REG_NTRCARDFIFO;
                pbuf[0] = (unsigned char) (data >>  0);
                pbuf[1] = (unsigned char) (data >>  8);
                pbuf[2] = (unsigned char) (data >> 16);
                pbuf[3] = (unsigned char) (data >> 24);
                pbuf += sizeof (unsigned int);
                count += 4;
            }
        }
    }
    else
    {
        while( (cardCtrl & NTRCARD_BUSY) && count < pageSize)
        {
            cardCtrl = REG_NTRCARDROMCNT;
            if( cardCtrl & NTRCARD_DATA_READY  ) {
                u32 data = REG_NTRCARDFIFO;
                (void)data;
                count += 4;
            }
        }
    }

    // if read is not finished, ds will not pull ROM CS to high, we pull it high manually
    if( count != transferLength ) {
        // MUST wait for next data ready,
        // if ds pull ROM CS to high during 4 byte data transfer, something will mess up
        // so we have to wait next data ready
        do { cardCtrl = REG_NTRCARDROMCNT; } while(!(cardCtrl & NTRCARD_DATA_READY));
        // and this tiny delay is necessary
        //ioAK2Delay(33);
        // pull ROM CS high
        REG_NTRCARDROMCNT = 0x10000000;
        REG_NTRCARDROMCNT = KEY_PARAM | NTRCARD_ACTIVATE | NTRCARD_nRESET/* | 0 | 0x0000*/;
    }
    // wait rom cs high
    do { cardCtrl = REG_NTRCARDROMCNT; } while( cardCtrl & NTRCARD_BUSY );
    //lastCmd[0] = command[0];lastCmd[1] = command[1];
}

void CTR_SendCommand( u32 command[4], u32 pageSize, u32 blocks, u32 latency, void * buffer )
{
    REG_CTRCARDCMD[0] = command[3];
    REG_CTRCARDCMD[1] = command[2];
    REG_CTRCARDCMD[2] = command[1];
    REG_CTRCARDCMD[3] = command[0];

    //Make sure this never happens
    if(blocks == 0) blocks = 1;

    pageSize -= pageSize & 3; // align to 4 byte
    u32 pageParam = CTRCARD_PAGESIZE_4K;
    u32 transferLength = 4096;
    // make zero read and 4 byte read a little special for timing optimization(and 512 too)
    switch(pageSize) {
        case 0:
            transferLength = 0;
            pageParam = CTRCARD_PAGESIZE_0;
            break;
        case 4:
            transferLength = 4;
            pageParam = CTRCARD_PAGESIZE_4;
            break;
        case 64:
            transferLength = 64;
            pageParam = CTRCARD_PAGESIZE_64;
            break;
        case 512:
            transferLength = 512;
            pageParam = CTRCARD_PAGESIZE_512;
            break;
        case 1024:
            transferLength = 1024;
            pageParam = CTRCARD_PAGESIZE_1K;
            break;
        case 2048:
            transferLength = 2048;
            pageParam = CTRCARD_PAGESIZE_2K;
            break;
        case 4096:
            transferLength = 4096;
            pageParam = CTRCARD_PAGESIZE_4K;
            break;
    }

    REG_CTRCARDBLKCNT = blocks - 1;
    transferLength *= blocks;

    // go
    REG_CTRCARDCNT = 0x10000000;
    REG_CTRCARDCNT = /*CTRKEY_PARAM | */CTRCARD_ACTIVATE | CTRCARD_nRESET | pageParam | latency;

    u8 * pbuf = (u8 *)buffer;
    u32 * pbuf32 = (u32 * )buffer;
    bool useBuf = ( NULL != pbuf );
    bool useBuf32 = (useBuf && (0 == (3 & ((u32)buffer))));

    u32 count = 0;
    u32 cardCtrl = REG_CTRCARDCNT;

    if(useBuf32)
    {
        while( (cardCtrl & CTRCARD_BUSY) && count < transferLength)
        {
            cardCtrl = REG_CTRCARDCNT;
            if( cardCtrl & CTRCARD_DATA_READY  ) {
                u32 data = REG_CTRCARDFIFO;
                *pbuf32++ = data;
                count += 4;
            }
        }
    }
    else if(useBuf)
    {
        while( (cardCtrl & CTRCARD_BUSY) && count < transferLength)
        {
            cardCtrl = REG_CTRCARDCNT;
            if( cardCtrl & CTRCARD_DATA_READY  ) {
                u32 data = REG_CTRCARDFIFO;
                pbuf[0] = (unsigned char) (data >>  0);
                pbuf[1] = (unsigned char) (data >>  8);
                pbuf[2] = (unsigned char) (data >> 16);
                pbuf[3] = (unsigned char) (data >> 24);
                pbuf += sizeof (unsigned int);
                count += 4;
            }
        }
    }
    else
    {
        while( (cardCtrl & CTRCARD_BUSY) && count < transferLength)
        {
            cardCtrl = REG_CTRCARDCNT;
            if( cardCtrl & CTRCARD_DATA_READY  ) {
                u32 data = REG_CTRCARDFIFO;
                (void)data;
                count += 4;
            }
        }
    }

    // if read is not finished, ds will not pull ROM CS to high, we pull it high manually
    if( count != transferLength ) {
        // MUST wait for next data ready,
        // if ds pull ROM CS to high during 4 byte data transfer, something will mess up
        // so we have to wait next data ready
        do { cardCtrl = REG_CTRCARDCNT; } while(!(cardCtrl & CTRCARD_DATA_READY));
        // and this tiny delay is necessary
        ioDelay(33);
        // pull ROM CS high
        REG_CTRCARDCNT = 0x10000000;
        REG_CTRCARDCNT = CTRKEY_PARAM | CTRCARD_ACTIVATE | CTRCARD_nRESET;
    }
    // wait rom cs high
    do { cardCtrl = REG_CTRCARDCNT; } while( cardCtrl & CTRCARD_BUSY );
    //lastCmd[0] = command[0];lastCmd[1] = command[1];
}

u32 Cart_GetSecureID()
{
    u32 id = 0;
    u32 getid_cmd[4] = { 0xA2000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand(getid_cmd, 0x4, 1, 0x100802C, &id);
    return id;
}

int Cart_IsInserted()
{
    return (0x9000E2C2 == Cart_GetSecureID() );
}

void Cart_ReadSectorSD(u8* aBuffer,u32 aSector)
{
    u64 adr = ((u64)0xBF << 56) | (aSector * 0x200);
    u32 readheader_cmd[4] = {
        (u32)(adr >> 32),
        (u32)(adr&0xFFFFFFFF),
        0x00000000, 0x00000000
    };
    CTR_SendCommand( readheader_cmd, 0x200, 1, 0x100802C, aBuffer );
}

u32 Cart_GetID()
{
    return CartID;
}

void Cart_Init()
{
    GatewayCartInit(); //Seems to reset the cart slot?

    REG_CTRCARDSECCNT &= 0xFFFFFFFB;

    ioDelay(0xF000);

    SwitchToNTRCARD();

    ioDelay(0xF000);

    REG_NTRCARDROMCNT = 0;
    REG_NTRCARDMCNT = REG_NTRCARDMCNT&0xFF;
    ioDelay(167550);
    REG_NTRCARDMCNT |= (NTRCARD_CR1_ENABLE | NTRCARD_CR1_IRQ);
    REG_NTRCARDROMCNT = NTRCARD_nRESET | NTRCARD_SEC_SEED;
    while (REG_NTRCARDROMCNT & NTRCARD_BUSY);

    // Reset
    u32 reset_cmd[2] = { 0x9F000000, 0x00000000 };
    NTR_SendCommand(reset_cmd, 0x2000, NTRCARD_CLK_SLOW | NTRCARD_DELAY1(0x1FFF) | NTRCARD_DELAY2(0x18), NULL);

    u32 getid_cmd[2] = { 0x90000000, 0x00000000 };
    NTR_SendCommand(getid_cmd, 0x4, NTRCARD_CLK_SLOW | NTRCARD_DELAY1(0x1FFF) | NTRCARD_DELAY2(0x18), &CartID);

    if ((CartID & 0x10000000)) // 3ds
    {
        u32 unknowna0_cmd[2] = { 0xA0000000, 0x00000000 };
        NTR_SendCommand(unknowna0_cmd, 0x4, 0, &A0_Response);

        u32 enter16bytemode_cmd[2] = { 0x3E000000, 0x00000000 };
        NTR_SendCommand(enter16bytemode_cmd, 0x0, 0, NULL);

        SwitchToCTRCARD();

        ioDelay(0xF000);

        REG_CTRCARDBLKCNT = 0;
    }
}

void SendReadCommand( u32 sector, u32 length, u32 blocks, void * buffer )
{
    u32 read_cmd[4] = {
        (0xBF000000 | (u32)(sector>>23)),
        (u32)((sector<<9) & 0xFFFFFFFF),
        0x00000000, 0x00000000
    };
    CTR_SendCommand(read_cmd, length, blocks, 0x100822C, buffer);
}

void GetHeader(void * buffer)
{
    u32 readheader_cmd[4] = { 0x82000000, 0x00000000, 0x00000000, 0x00000000 };
    CTR_SendCommand(readheader_cmd, 0x200, 1, 0x4802C, buffer);
}

//returns 1 if MAC valid otherwise 0
u8 card_aes(u32 *out, u32 *buff, size_t size) { // note size param ignored
    u8 tmp = REG_AESKEYCNT;
    REG_AESCNT |= 0x2800000;
    REG_AESCTR[0] = buff[14];
    REG_AESCTR[1] = buff[13];
    REG_AESCTR[2] = buff[12];
    REG_AESCNT |= 0x2800000;
    REG_AESKEYCNT = (REG_AESKEYCNT & 0xC0) | 0x3B;
    REG_AESKEYYFIFO = buff[0];
    REG_AESKEYYFIFO = buff[1];
    REG_AESKEYYFIFO = buff[2];
    REG_AESKEYYFIFO = buff[3];
    REG_AESKEYCNT = tmp;
    REG_AESKEYSEL = 0x3B;
    REG_AESCNT |= 0x4000000;
    REG_AESCNT |= 0x2970000;
    REG_AESMAC[0] = buff[11];
    REG_AESMAC[1] = buff[10];
    REG_AESMAC[2] = buff[9];
    REG_AESMAC[3] = buff[8];
    REG_AESBLKCNT = 0x10000;
    REG_AESCNT = 0x83D70C00;
    REG_AESWRFIFO = buff[4];
    REG_AESWRFIFO = buff[5];
    REG_AESWRFIFO = buff[6];
    REG_AESWRFIFO = buff[7];
    while (((REG_AESCNT >> 5) & 0x1F) <= 3);
    out[0] = REG_AESRDFIFO;
    out[1] = REG_AESRDFIFO;
    out[2] = REG_AESRDFIFO;
    out[3] = REG_AESRDFIFO;
    return ((REG_AESCNT >> 21) & 1);
}

void ctr_set_sec_key(u32 value) {
    REG_CTRCARDSECCNT |= ((value & 3) << 8) | 4;
    while (!(REG_CTRCARDSECCNT & 0x4000));
}

void ctr_set_sec_seed(u32 *seed, bool flag) {
    REG_CTRCARDSECSEED = BSWAP32(seed[3]);
    REG_CTRCARDSECSEED = BSWAP32(seed[2]);
    REG_CTRCARDSECSEED = BSWAP32(seed[1]);
    REG_CTRCARDSECSEED = BSWAP32(seed[0]);
    REG_CTRCARDSECCNT |= 0x8000;
    while (!(REG_CTRCARDSECCNT & 0x4000));
    if (flag) {
        (*(vu32*)0x1000400C) = 0x00000001; //Enable cart command encryption?
    }
}

void AES_SetKeyControl(u32 a) {
    *((volatile u8*)0x10009011) = a | 0x80;
}

void Cart_Secure_Init(u32 *buf,u32 *out)
{
    AES_SetKeyControl(0x3B);

    u8 mac_valid = card_aes(out, buf, 0x200);

//    if(!mac_valid)
//        ClearScreen(bottomScreen, RGB(255, 0, 0));

    ioDelay(0xF0000);

    ctr_set_sec_key(A0_Response);

    ctr_set_sec_seed(out, true);

    rand1 = 0x42434445;//*((vu32*)0x10011000);
    rand2 = 0x46474849;//*((vu32*)0x10011010);

    u32 seed_cmd[4] = { 0x83000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand( seed_cmd, 0, 1, 0x100822C, NULL );

    out[3] = BSWAP32(rand2);
    out[2] = BSWAP32(rand1);
    ctr_set_sec_seed(out, false);

    //ClearScreen(bottomScreen, RGB(255, 0, 255));

    u32 test = 0;
    u32 A2_cmd[4] = { 0xA2000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand( A2_cmd, 4, 1, 0x100822C, &test );

    //ClearScreen(bottomScreen, RGB(0, 255, 0));

    u32 test2 = 0;
    u32 A3_cmd[4] = { 0xA3000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand( A3_cmd, 4, 1, 0x100822C, &test2 );

    //ClearScreen(bottomScreen, RGB(255, 0, 0));

    u32 C5_cmd[4] = { 0xC5000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand( C5_cmd, 0, 1, 0x100822C, NULL );

    //ClearScreen(bottomScreen, RGB(0, 0, 255));

    CTR_SendCommand( A2_cmd, 4, 1, 0x100822C, &test );
    CTR_SendCommand( A2_cmd, 4, 1, 0x100822C, &test );
    CTR_SendCommand( A2_cmd, 4, 1, 0x100822C, &test );
    CTR_SendCommand( A2_cmd, 4, 1, 0x100822C, &test );
    CTR_SendCommand( A2_cmd, 4, 1, 0x100822C, &test );
}
