#pragma once

#include "common.h"

void CTR_SetSecKey(u32 value);
void CTR_SetSecSeed(const u32* seed, bool flag);

void CTR_SendCommand(const u32 command[4], u32 pageSize, u32 blocks, u32 latency, void* buffer);
