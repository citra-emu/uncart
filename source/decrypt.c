#include "common.h"
#include "crypto.h"
#include "decrypt.h"
#include "draw.h"
#include "ncch.h"

extern s32 CartID;
extern s32 CartID2;

enum NCCH_Type {
    NCCHTYPE_EXHEADER,
    NCCHTYPE_EXEFS,
    NCCHTYPE_ROMFS
};

static void ncch_get_counter(NCCH_Header* header, u8 counter[16], enum NCCH_Type type) {
    u32 version = header->version;
    u32 mediaunitsize = 0x200; // TODO
    u8* partitionid = header->partition_id;
    u32 x = 0;

    memset(counter, 0, 16);

    switch (version) {
    case 0:
    case 2:
        for(u32 i = 0; i < 8; i++)
            counter[i] = partitionid[7 - i];
        counter[8] = type;
        break;
    case 1:
        switch (type) {
        case NCCHTYPE_EXHEADER:
            x = 0x200;
            break;
        case NCCHTYPE_EXEFS:
            x = header->exefs_offset * mediaunitsize;
            break;
        case NCCHTYPE_ROMFS:
            x = header->romfs_offset * mediaunitsize;
            break;
        }

        for(u32 i = 0; i < 8; i++)
            counter[i] = partitionid[i];
        for(u32 i = 0; i < 4; i++)
            counter[12 + i] = x >> ((3 - i) * 8);
        break;
    }
}

int find_encrypted_ncch_regions(NCCH_Header* ncch, NCSD_Header* ncsd, unsigned partition, struct Context* ctx, u32 initial_sector, u32 dumped) {
    u8* source = ctx->buffer;
    u8* dest = (u8*)ncch;
    u32 size = sizeof(NCCH_Header);
    Debug("Detected NCCH: %p, %p, %x, %x", source, dest, size);
    if (ncsd->partition_table[partition].offset > initial_sector) {
        u32 delta = (ncsd->partition_table[partition].offset - initial_sector) * ctx->media_unit;
        source += delta;
    }
    if (ncsd->partition_table[partition].offset < initial_sector) {
        // TODO: I don't think this can ever happen. If it does happen, I don't think it works correctly.
        u32 delta = (initial_sector - ncsd->partition_table[partition].offset) * ctx->media_unit;
        dest += delta;
        size -= delta;
    }
    // TODO: Should make more special cases, I think.
    memcpy(dest, source, size);

    // If the header is complete
    if (initial_sector + dumped >= ncsd->partition_table[partition].offset + sizeof(NCCH_Header)) {
        if (ncch->flags[3] != 0) {
            // This cartridge uses the new crypto method introduced in system version 7.x.
            // TODO: Set the uses_7x_crypto field of the affected encrypted areas appropriately.
            // TODO: System versions older than 7.x require the keyX to be given by the user. If the key is not given, we should abort dumping.
            Debug("ERROR: Cartridge uses 7.x crypto.");
            Debug("uncart does not support this, yet.");
            Debug("Perform a raw dump and decrypt it with");
            Debug("an external tool.");
            Debug("Dumping process aborted.");
            WaitKey();
            return -1;
        }

        // TODO: Consider checking for other flags, in particular the 9.6.0 keyY generator

        if (ncch->extended_header_size) {
            ctx->areas[ctx->num_areas].addr = ncsd->partition_table[partition].offset + sizeof(NCCH_Header) / ctx->media_unit;
            ctx->areas[ctx->num_areas].size = 0x800 / ctx->media_unit; // NOTE: ncchs->extended_header_size doesn't cover the full exheader!
            ctx->areas[ctx->num_areas].uses_7x_crypto = 0;
            memcpy(ctx->areas[ctx->num_areas].keyY, ncch->signature, sizeof(ctx->areas[ctx->num_areas].keyY));
            ncch_get_counter(ncch, ctx->areas[ctx->num_areas].ctr, NCCHTYPE_EXHEADER);
            ctx->num_areas++;
        }

        if (ncch->exefs_offset && ncch->exefs_size) {
            ctx->areas[ctx->num_areas].addr = ncsd->partition_table[partition].offset + ncch->exefs_offset;
            ctx->areas[ctx->num_areas].size = ncch->exefs_size;
            memcpy(ctx->areas[ctx->num_areas].keyY, ncch->signature, sizeof(ctx->areas[ctx->num_areas].keyY));
            ctx->areas[ctx->num_areas].uses_7x_crypto = 0;
            ncch_get_counter(ncch, ctx->areas[ctx->num_areas].ctr, NCCHTYPE_EXEFS);
            ctx->num_areas++;
        }
        if (ncch->romfs_offset && ncch->romfs_size) {
            ctx->areas[ctx->num_areas].addr = ncsd->partition_table[partition].offset + ncch->romfs_offset;
            ctx->areas[ctx->num_areas].uses_7x_crypto = 0;
            ctx->areas[ctx->num_areas].size = ncch->romfs_size;
            memcpy(ctx->areas[ctx->num_areas].keyY, ncch->signature, sizeof(ctx->areas[ctx->num_areas].keyY));
            ncch_get_counter(ncch, ctx->areas[ctx->num_areas].ctr, NCCHTYPE_ROMFS);
            ctx->num_areas++;
        }
    }
    return 0;
}

void decrypt_region(EncryptedArea area, struct Context* ctx, u32 initial_sector, u32 dumped) {
    u32 keyslot = (area.uses_7x_crypto == 0xA) ? 0x18 : (area.uses_7x_crypto != 0) ? 0x25 : 0x2c;
    setup_aeskey(keyslot, AES_BIG_INPUT | AES_NORMAL_INPUT, area.keyY);
    use_aeskey(keyslot);

    static const uint8_t zero_buf[16] __attribute__((aligned(16))) = {0};
    static const uint8_t dec_buf[16] __attribute__((aligned(16))) = {0};
    u32 adr2 = (initial_sector < area.addr) ? area.addr : initial_sector;
    u32 limit = initial_sector + dumped;
    if (initial_sector + dumped > area.addr + area.size)
        limit = area.addr + area.size;
    adr2 *= ctx->media_unit / 16;
    limit *= ctx->media_unit / 16;

    Debug("Decrypting from %08x to %08x", adr2 * 16, limit * 16);

    while (adr2 < limit) {
        set_ctr(AES_BIG_INPUT | AES_NORMAL_INPUT, area.ctr);
        aes_decrypt((void*)zero_buf, (void*)dec_buf, area.ctr, 1, AES_CTR_MODE);
        add_ctr(area.ctr, 1);

        u8* dest = ctx->buffer + adr2 * 16 - (initial_sector * ctx->media_unit);
        for (int k = 0; k < 16; ++k) {
            dest[k] ^= dec_buf[k];
        }
        adr2++;
    }
}
