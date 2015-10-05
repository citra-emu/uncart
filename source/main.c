#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "crypto.h"
#include "draw.h"
#include "hid.h"
#include "ncch.h"
#include "fatfs/ff.h"
#include "gamecart/protocol.h"
#include "gamecart/command_ctr.h"

extern s32 CartID;
extern s32 CartID2;

// File IO utility functions
static FATFS fs;
static FIL file;

static void ClearTop(void) {
    ClearScreen(TOP_SCREEN0, RGB(255, 255, 255));
    ClearScreen(TOP_SCREEN1, RGB(255, 255, 255));
    current_y = 0;
}

static void wait_key(void) {
    Debug("Press key to continue...");
    InputWait();
}

static void ncch_get_counter(NCCH_Header* header, u8 counter[16], u8 type) {
    u32 version = header->version;
    u32 mediaunitsize = 0x200; // TODO
    u8* partitionid = header->partition_id;
    u32 x = 0;

    memset(counter, 0, 16);

    if (version == 2 || version == 0)
    {
        for(u32 i=0; i<8; i++)
            counter[i] = partitionid[7-i];
        counter[8] = type;
    }
    else if (version == 1)
    {
        if (type == 1/*NCCHTYPE_EXHEADER*/)
            x = 0x200;
        else if (type == 2/*NCCHTYPE_EXEFS*/)
            x = header->exefs_offset * mediaunitsize;
        else if (type == 3/*NCCHTYPE_ROMFS*/)
            x = header->romfs_offset * mediaunitsize;

        for(u32 i=0; i<8; i++)
            counter[i] = partitionid[i];
        for(u32 i=0; i<4; i++)
            counter[12+i] = x>>((3-i)*8);
    }
}

// Generate list of encrypted data blocks, ordered by file offset
typedef struct {
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

static void find_encrypted_ncch_regions(NCCH_Header* ncch, NCSD_Header* ncsd, unsigned partition, struct Context* ctx, u32 initial_sector, u32 dumped) {
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
            wait_key();
            // TODO: Come up with a cleaner method of exiting here.
            exit(1);
        }

        // TODO: Consider checking for other flags, in particular the 9.6.0 keyY generator

        if (ncch->extended_header_size) {
            ctx->areas[ctx->num_areas].addr = ncsd->partition_table[partition].offset + sizeof(NCCH_Header) / ctx->media_unit;
            ctx->areas[ctx->num_areas].size = 0x800 / ctx->media_unit; // NOTE: ncchs->extended_header_size doesn't cover the full exheader!
            ctx->areas[ctx->num_areas].uses_7x_crypto = 0;
            memcpy(ctx->areas[ctx->num_areas].keyY, ncch->signature, sizeof(ctx->areas[ctx->num_areas].keyY));
            ncch_get_counter(ncch, ctx->areas[ctx->num_areas].ctr, 1);
            ctx->num_areas++;
        }

        if (ncch->exefs_offset && ncch->exefs_size) {
            ctx->areas[ctx->num_areas].addr = ncsd->partition_table[partition].offset + ncch->exefs_offset;
            ctx->areas[ctx->num_areas].size = ncch->exefs_size;
            memcpy(ctx->areas[ctx->num_areas].keyY, ncch->signature, sizeof(ctx->areas[ctx->num_areas].keyY));
            ctx->areas[ctx->num_areas].uses_7x_crypto = 0;
            ncch_get_counter(ncch, ctx->areas[ctx->num_areas].ctr, 2);
            ctx->num_areas++;
        }
        if (ncch->romfs_offset && ncch->romfs_size) {
            ctx->areas[ctx->num_areas].addr = ncsd->partition_table[partition].offset + ncch->romfs_offset;
            ctx->areas[ctx->num_areas].uses_7x_crypto = 0;
            ctx->areas[ctx->num_areas].size = ncch->romfs_size;
            memcpy(ctx->areas[ctx->num_areas].keyY, ncch->signature, sizeof(ctx->areas[ctx->num_areas].keyY));
            ncch_get_counter(ncch, ctx->areas[ctx->num_areas].ctr, 3);
            ctx->num_areas++;
        }
    }
}

static void decrypt_region(EncryptedArea area, struct Context* ctx, u32 initial_sector, u32 dumped) {
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

int dump_cart_region(u32 start_sector, u32 end_sector, FIL* output_file, struct Context* ctx, NCSD_Header* ncsd) {
    const u32 read_size = 1 * 1024 * 1024 / ctx->media_unit; // 1MB

    u32 current_sector = start_sector;
    while (current_sector < end_sector) {
        ClearTop();
        unsigned int percentage = current_sector * 100 / ctx->cart_size;
        Debug("Dumping %08X / %08X - %3u%%", current_sector, ctx->cart_size, percentage);

        // Read data from cartridge
        u8* read_ptr = ctx->buffer;
        u32 dumped = 0;
        const u32 initial_sector = current_sector;
        while (read_ptr < ctx->buffer + ctx->buffer_size && current_sector < end_sector) {
            Cart_Dummy();
            Cart_Dummy();
            CTR_CmdReadData(current_sector, ctx->media_unit, read_size, read_ptr);
            read_ptr += ctx->media_unit * read_size;
            current_sector += read_size;
            dumped += read_size;
        }

        if (ctx->decrypt) {
            // If we have read (a part of) an NCCH header, update the list of encrypted areas
            for (int partition = 0; partition < 8; ++partition) {
                if (!ncsd->partition_table[partition].offset || !ncsd->partition_table[partition].size)
                    continue;

                if (initial_sector + dumped > ncsd->partition_table[partition].offset &&
                    initial_sector < ncsd->partition_table[partition].offset + (sizeof(NCCH_Header) / ctx->media_unit)) {
                    find_encrypted_ncch_regions(&ctx->ncchs[partition], ncsd, partition, ctx, initial_sector, dumped);
                }
            }

            // Check if the currently dumped area is encrypted, and decrypt it if it is
            for (int area = 0; area < ctx->num_areas; ++area) {
                if (!(initial_sector + dumped >= ctx->areas[area].addr &&
                      initial_sector < ctx->areas[area].addr + ctx->areas[area].size))
                    continue;

                decrypt_region(ctx->areas[area], ctx, initial_sector, dumped);
            }
        }

        // Write dumped data to file
        u8* write_ptr = ctx->buffer;
        while (write_ptr < read_ptr) {
            unsigned int bytes_written = 0;
            f_write(output_file, write_ptr, read_ptr - write_ptr, &bytes_written);
            Debug("Wrote 0x%x bytes, e.g. %08x", bytes_written, *(u32*)write_ptr);

            if (bytes_written == 0) {
                Debug("Writing failed! :( SD full?");
                return -1;
            }

            write_ptr += bytes_written;
        }
    }

    return 0;
}

int main(void) {

restart_program:
    // Setup boring stuff - clear the screen, initialize SD output, etc...
    ClearTop();
    Debug("ROM dump tool v0.2");
    Debug("Insert your game cart now.");
    wait_key();

    // Arbitrary target buffer
    // TODO: This should be done in a nicer way ;)
    u8* target = (u8*)0x22000000;
    u32 target_buf_size = 16u * 1024u * 1024u; // 16MB
    u8* header = (u8*)0x23000000;
    memset(target, 0, target_buf_size); // Clear our buffer

    NCSD_Header ncsd;

    *(vu32*)0x10000020 = 0; // InitFS stuff
    *(vu32*)0x10000020 = 0x340; // InitFS stuff

    // ROM DUMPING CODE STARTS HERE

    Cart_Init();
    Debug("Cart id is %08x", Cart_GetID());
    CTR_CmdReadHeader(header);
    Debug("Done reading header: %08X :)...", *(u32*)&header[0x100]);

    // TODO: Check first header bytes for "NCCH" or other magic words
    u32 sec_keys[4];
    Cart_Secure_Init((u32*)header,sec_keys);

    const u32 mediaUnit = 0x200; // TODO: Read from cart

    // Read out the header 0x0000-0x1000
    Cart_Dummy();
    CTR_CmdReadData(0, mediaUnit, 0x1000 / mediaUnit, target);
    memcpy(&ncsd, target, sizeof(ncsd));

    u32 NCSD_magic = *(u32*)(&target[0x100]);
    u32 cartSize = *(u32*)(&target[0x104]);
    Debug("Cart size: %llu MB", (u64)cartSize * (u64)mediaUnit / 1024ull / 1024ull);
    Debug("%c%c%c%c", ncsd.magic[0], ncsd.magic[1], ncsd.magic[2], ncsd.magic[3]);
    for (int partition = 0; partition < 8; ++partition) {
        Debug("Partition %d: offset %x, size %x", partition,  ncsd.partition_table[partition].offset, ncsd.partition_table[partition].size);
    }
    if (NCSD_magic != 0x4453434E) {
        Debug("NCSD magic not found in header!!!");
        Debug("Press A to continue anyway.");
        if (!(InputWait() & BUTTON_A))
            goto restart_prompt;
    }

    struct Context context = {
        .buffer = target,
        .buffer_size = target_buf_size,
        .cart_size = cartSize,
        .media_unit = mediaUnit,
        .num_areas = 0,
    };

    Debug("Press START to dump a decrypted image.");
    Debug("Press SELECT to dump the raw, encrypted image.");
    for (;;) {
        u32 input = InputWait();
        if (input & BUTTON_START) {
            context.decrypt = 1;
            break;
        } else if (input & BUTTON_SELECT) {
            context.decrypt = 0;
            break;
        } else {
            Debug("Invalid input. Press START or SELECT");
        }
    }

    // Maximum number of blocks in a single file
    u32 file_max_blocks = 2u * 1024u * 1024u * 1024u / mediaUnit; // 2GB
    u32 current_part = 0;

    while (current_part * file_max_blocks < cartSize) {
        // Create output file
        // File extension is "cci"/"3ds" for single-file dumps and "cciN"/"3dN" for split dumps
        char filename_buf[32];
        char* extension = (context.decrypt != 0) ? "cci" : "3d";
        int filename_len = snprintf(filename_buf, sizeof(filename_buf), "/%.16s.%s", &header[0x150], extension);
        if (cartSize <= file_max_blocks) {
            if (context.decrypt == 0) {
                filename_buf[filename_len++] = 's';
                filename_buf[filename_len++] = '\0';
            }
        } else {
            filename_buf[filename_len++] = '0' + current_part;
            filename_buf[filename_len++] = '\0';
        }


        Debug("Writing to file: \"%s\"", filename_buf);
        Debug("Change the SD card now and/or press a key.");
        Debug("(Or SELECT to cancel)");
        if (InputWait() & BUTTON_SELECT)
            break;

        if (f_mount(&fs, "0:", 0) != FR_OK) {
            Debug("Failed to f_mount... Retrying");
            wait_key();
            goto cleanup_none;
        }

        if (f_open(&file, filename_buf, FA_READ | FA_WRITE | FA_CREATE_ALWAYS) != FR_OK) {
            Debug("Failed to create file... Retrying");
            wait_key();
            goto cleanup_mount;
        }

        f_lseek(&file, 0);

        u32 region_start = current_part * file_max_blocks;
        u32 region_end = region_start + file_max_blocks;
        if (region_end > cartSize)
            region_end = cartSize;

        if (dump_cart_region(region_start, region_end, &file, &context, &ncsd) < 0)
            goto cleanup_file;

        if (current_part == 0) {
            // Write header - TODO: Not sure why this is done at the very end..
            f_lseek(&file, 0x1000);
            unsigned int written = 0;
            // Fill the 0x1200-0x4000 unused area with 0xFF instead of random garbage.
            memset(header + 0x200, 0xFF, 0x3000 - 0x200);
            f_write(&file, header, 0x3000, &written);
        }

        Debug("Done!");
        current_part += 1;

cleanup_file:
        // Done, clean up...
        f_sync(&file);
        f_close(&file);
cleanup_mount:
        f_mount(NULL, "0:", 0);
cleanup_none:
        ;
    }

restart_prompt:
    Debug("Press B to exit, any other key to restart.");
    if (!(InputWait() & BUTTON_B))
        goto restart_program;

    return 0;
}
