#pragma once
#include "types.h"

void Cart_Init();
int Cart_IsInserted();
void Cart_ReadSectorSD(uint8_t* aBuffer,uint32_t aSector);
u32 SendReadCommand( uint32_t adr, uint32_t length, uint32_t blocks, void * buffer );
u32 GetHeader( void * buffer );
u32 CTR_SendCommand( uint32_t command[4], uint32_t pageSize, uint32_t blocks, uint32_t latency, void * buffer );
int Cart_Nin_Init();
uint32_t Cart_GetID();
// void Cart_Secure_Init(uint32_t *buf,uint32_t *out);
