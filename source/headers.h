#ifndef UNCART_HEADERS_H_
#define UNCART_HEADERS_H_

#include "common.h"

typedef enum
{
	MEDIA_6X_SAVE_CRYPTO = 1,
	MEDIA_CARD_DEVICE = 3,
	MEDIA_PLATFORM_INDEX = 4,
	MEDIA_TYPE_INDEX = 5,
	MEDIA_UNIT_SIZE = 6,
	MEDIA_CARD_DEVICE_OLD = 7
} NcsdFlagIndex;

typedef struct
{
	u32 offset;
	u32 size;
} partition_offsetsize;

typedef struct
{
	u8 sha256[0x100];
	u8 magic[4];
	u32 media_size;
	u8 title_id[8];
	u8 partitions_fs_type[8];
	u8 partitions_crypto_type[8];
	partition_offsetsize offsetsize_table[8];
	u8 exheader_hash[0x20];
	u8 additional_header_size[0x4];
	u8 sector_zero_offset[0x4];
	u8 partition_flags[8];
	u8 partition_id_table[8][8];
	u8 reserved[0x30];
} NCSD_HEADER;

typedef struct
{
	u8 sha256[0x100];
	u8 magic[4];
	u32 content_size;
	u8 title_id[8];
	u8 maker_code[2];
	u8 version[2];
	u8 reserved_0[4];
	u8 program_id[8];
	u8 temp_flag;
	u8 reserved_1[0xF];
	u8 logo_sha_256_hash[0x20];
	u8 product_code[0x10];
	u8 extended_header_sha_256_hash[0x20];
	u8 extended_header_size[4];
	u8 reserved_2[4];
	u8 flags[8];
	u8 plain_region_offset[4];
	u8 plain_region_size[4];
	u8 logo_region_offset[4];
	u8 logo_region_size[4];
	u8 exefs_offset[4];
	u8 exefs_size[4];
	u8 exefs_hash_size[4];
	u8 reserved_4[4];
	u8 romfs_offset[4];
	u8 romfs_size[4];
	u8 romfs_hash_size[4];
	u8 reserved_5[4];
	u8 exefs_sha_256_hash[0x20];
	u8 romfs_sha_256_hash[0x20];
} __attribute__((__packed__))
NCCH_HEADER;

#endif//UNCART_HEADERS_H_

