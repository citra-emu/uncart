#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "draw.h"
#include "hid.h"
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

struct Context {
    u8* buffer;
    size_t buffer_size;

    u32 cart_size;
    u32 media_unit;
};

int dump_cart_region(u32 start_sector, u32 end_sector, FIL* output_file, struct Context* ctx) {
    const u32 read_size = 1 * 1024 * 1024 / ctx->media_unit; // 1MB

    // Dump remaining data
    u32 current_sector = start_sector;
    while (current_sector < end_sector) {
        unsigned int percentage = current_sector * 100 / ctx->cart_size;
        Debug("Dumping %08X / %08X - %3u%%", current_sector, ctx->cart_size, percentage);

        u8* read_ptr = ctx->buffer;
        while (read_ptr < ctx->buffer + ctx->buffer_size && current_sector < end_sector) {
            Cart_Dummy();
            Cart_Dummy();
            CTR_CmdReadData(current_sector, ctx->media_unit, read_size, read_ptr);
            read_ptr += ctx->media_unit * read_size;
            current_sector += read_size;
        }

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

int main() {

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

    u32 NCSD_magic = *(u32*)(&target[0x100]);
    u32 cartSize = *(u32*)(&target[0x104]);
    Debug("Cart size: %llu MB", (u64)cartSize * (u64)mediaUnit / 1024ull / 1024ull);
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
    };

    // Maximum number of blocks in a single file
    u32 file_max_blocks = 2u * 1024u * 1024u * 1024u / mediaUnit; // 2GB
    u32 current_part = 0;

    while (current_part * file_max_blocks < cartSize) {
        // Create output file
        char filename_buf[32];
        char extension_digit = cartSize <= file_max_blocks ? 's' : '0' + current_part;
        snprintf(filename_buf, sizeof(filename_buf), "/%.16s.3d%c", &header[0x150], extension_digit);
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

        if (dump_cart_region(region_start, region_end, &file, &context) < 0)
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
