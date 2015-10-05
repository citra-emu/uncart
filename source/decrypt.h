#include "common.h"
#include "ncch.h"

// Generate list of encrypted data blocks, ordered by file offset
typedef struct EncryptedArea {
    uint32_t addr; // mediaUnits
    uint32_t size; // mediaUnits
    uint32_t uses_7x_crypto;
    uint32_t pad;
    u8 ctr[16] __attribute__((aligned(16)));
    u8 keyY[16] __attribute__((aligned(16)));
} EncryptedArea;

struct Context {
    u32 decrypt;

    u8* buffer;
    size_t buffer_size;

    u32 cart_size;
    u32 media_unit;

    EncryptedArea areas[16];
    int num_areas;

    NCCH_Header ncchs[8]; // one ncch per partition
};

int find_encrypted_ncch_regions(NCCH_Header* ncch, NCSD_Header* ncsd, unsigned partition, struct Context* ctx, u32 initial_sector, u32 dumped);
void decrypt_region(EncryptedArea area, struct Context* ctx, u32 initial_sector, u32 dumped);
