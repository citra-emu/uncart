// Copyright 2014 Normmatt
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "command_ctr.h"

#include "protocol_ctr.h"

void CTR_CmdReadSectorSD(u8* aBuffer, u32 aSector)
{
    u64 adr = ((u64)0xBF << 56) | (aSector * 0x200);
    const u32 readheader_cmd[4] = {
        (u32)(adr >> 32),
        (u32)(adr & 0xFFFFFFFF),
        0x00000000, 0x00000000
    };
    CTR_SendCommand(readheader_cmd, 0x200, 1, 0x100802C, aBuffer);
}

void CTR_CmdReadData(u32 sector, u32 length, u32 blocks, void* buffer)
{
    const u32 read_cmd[4] = {
        (0xBF000000 | (u32)(sector >> 23)),
        (u32)((sector << 9) & 0xFFFFFFFF),
        0x00000000, 0x00000000
    };
    CTR_SendCommand(read_cmd, length, blocks, 0x100822C, buffer);
}

void CTR_CmdReadHeader(void* buffer)
{
    static const u32 readheader_cmd[4] = { 0x82000000, 0x00000000, 0x00000000, 0x00000000 };
    CTR_SendCommand(readheader_cmd, 0x200, 1, 0x4802C, buffer);
}

u32 CTR_CmdGetSecureId(u32 rand1, u32 rand2)
{
    u32 id = 0;
    const u32 getid_cmd[4] = { 0xA2000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand(getid_cmd, 0x4, 1, 0x100802C, &id);
    return id;
}

void CTR_CmdSeed(u32 rand1, u32 rand2)
{
	const u32 seed_cmd[4] = { 0x83000000, 0x00000000, rand1, rand2 };
    CTR_SendCommand(seed_cmd, 0, 1, 0x100822C, NULL);
}
