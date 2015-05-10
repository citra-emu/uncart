#pragma once
#include "common.h"

u32 BSWAP32(u32 val);

void Cart_Init();
int Cart_IsInserted();
void Cart_ReadSectorSD(u8* aBuffer, u32 aSector);
u32 SendReadCommand(u32 adr, u32 length, u32 blocks, void * buffer);
u32 GetHeader(void* buffer);
int Cart_Nin_Init();
u32 Cart_GetID();
void Cart_Secure_Init(u32* buf, u32* out);
