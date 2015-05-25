// Copyright 2014 Normmatt
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "protocol.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "common.h"
#include "aes.h"
#include "protocol_ctr.h"
#include "protocol_ntr.h"
#include "command_ctr.h"
#include "command_ntr.h"
#include "delay.h"

extern u8* bottomScreen;

u32 CartID = -1;
u32 CartType = 0;

static int A0_Response = -1;
static u32 rand1 = 0;
static u32 rand2 = 0;

u32 BSWAP32(u32 val) {
    return (((val >> 24) & 0xFF)) |
           (((val >> 16) & 0xFF) << 8) |
           (((val >> 8) & 0xFF) << 16) |
           ((val & 0xFF) << 24);
}

// TODO: Verify
static void ResetCartSlot(void)
{
    REG_CARDCONF2 = 0x0C;
    REG_CARDCONF &= ~3;

    if (REG_CARDCONF2 == 0xC) {
        while (REG_CARDCONF2 != 0);
    }

    if (REG_CARDCONF2 != 0)
        return;

    REG_CARDCONF2 = 0x4;
    while(REG_CARDCONF2 != 0x4);

    REG_CARDCONF2 = 0x8;
    while(REG_CARDCONF2 != 0x8);
}

static void SwitchToNTRCARD(void)
{
    REG_NTRCARDROMCNT = 0x20000000;
    REG_CARDCONF &= ~3;
    REG_CARDCONF &= ~0x100;
    REG_NTRCARDMCNT = NTRCARD_CR1_ENABLE;
}

static void SwitchToCTRCARD(void)
{
    REG_CTRCARDCNT = 0x10000000;
    REG_CARDCONF = (REG_CARDCONF & ~3) | 2;
}

int Cart_IsInserted(void)
{
    return (0x9000E2C2 == CTR_CmdGetSecureId(rand1, rand2) );
}

u32 Cart_GetID(void)
{
    return CartID;
}

void Cart_Init(void)
{
    ResetCartSlot(); //Seems to reset the cart slot?

    REG_CTRCARDSECCNT &= 0xFFFFFFFB;
    ioDelay(0xF000);

    SwitchToNTRCARD();
    ioDelay(0xF000);

    REG_NTRCARDROMCNT = 0;
    REG_NTRCARDMCNT &= 0xFF;
    ioDelay(167550);

    REG_NTRCARDMCNT |= (NTRCARD_CR1_ENABLE | NTRCARD_CR1_IRQ);
    REG_NTRCARDROMCNT = NTRCARD_nRESET | NTRCARD_SEC_SEED;
    while (REG_NTRCARDROMCNT & NTRCARD_BUSY);

    // Reset
    NTR_CmdReset();
    CartID = NTR_CmdGetCartId();

    // 3ds
    if (CartID & 0x10000000) {
        u32 unknowna0_cmd[2] = { 0xA0000000, 0x00000000 };
        NTR_SendCommand(unknowna0_cmd, 0x4, 0, &A0_Response);

        NTR_CmdEnter16ByteMode();
        SwitchToCTRCARD();
        ioDelay(0xF000);

        REG_CTRCARDBLKCNT = 0;
    }
}

//returns 1 if MAC valid otherwise 0
static u8 card_aes(u32 *out, u32 *buff, size_t size) { // note size param ignored
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

static void AES_SetKeyControl(u32 a) {
    *((volatile u8*)0x10009011) = a | 0x80;
}

void Cart_Secure_Init(u32 *buf, u32 *out)
{
    AES_SetKeyControl(0x3B);

    u8 mac_valid = card_aes(out, buf, 0x200);

//    if (!mac_valid)
//        ClearScreen(bottomScreen, RGB(255, 0, 0));

    ioDelay(0xF0000);

    CTR_SetSecKey(A0_Response);
    CTR_SetSecSeed(out, true);

    rand1 = 0x42434445;//*((vu32*)0x10011000);
    rand2 = 0x46474849;//*((vu32*)0x10011010);

    CTR_CmdSeed(rand1, rand2);

    out[3] = BSWAP32(rand2);
    out[2] = BSWAP32(rand1);
    CTR_SetSecSeed(out, false);

    u32 test = 0;
    const u32 A2_cmd[4] = { 0xA2000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand(A2_cmd, 4, 1, 0x100822C, &test);

    u32 test2 = 0;
    const u32 A3_cmd[4] = { 0xA3000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand(A3_cmd, 4, 1, 0x100822C, &test2);

    const u32 C5_cmd[4] = { 0xC5000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand(C5_cmd, 0, 1, 0x100822C, NULL);

    for (int i = 0; i < 5; ++i) {
        CTR_SendCommand(A2_cmd, 4, 1, 0x100822C, &test);
        ioDelay(0xF0000);
    }
}
