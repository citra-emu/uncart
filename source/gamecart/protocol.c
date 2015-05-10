#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "common.h"
//#include "AES.h"
#include "misc.h"
#include "protocol_ctr.h"
#include "protocol_ntr.h"
#include "delay.h"

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

    CTR_SetSecKey(A0_Response);

    CTR_SetSecSeed(out, true);

    rand1 = 0x42434445;//*((vu32*)0x10011000);
    rand2 = 0x46474849;//*((vu32*)0x10011010);

    u32 seed_cmd[4] = { 0x83000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand( seed_cmd, 0, 1, 0x100822C, NULL );

    out[3] = BSWAP32(rand2);
    out[2] = BSWAP32(rand1);
    CTR_SetSecSeed(out, false);

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
