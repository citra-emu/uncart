#pragma once
#include "common.h"

u32 BSWAP32(u32 val);

void Cart_Init();
int Cart_IsInserted();
u32 Cart_GetID();
void Cart_Secure_Init(u32* buf, u32* out);
