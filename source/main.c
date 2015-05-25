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

int main() {

restart_program:
    // Setup boring stuff - clear the screen, initialize SD output, etc...
    ClearTop();
    Debug("ROM dump tool v0.2");
    Debug("Insert your game cart and SD card now.");
    wait_key();

    // Arbitrary target buffer
    // TODO: This should be done in a nicer way ;)
    u8* target = (u8*)0x22000000;
    u32 target_buf_size = 16 * 1024 * 1024; // 16MB
    u8* header = (u8*)0x23000000;
    memset(target, 0, target_buf_size); // Clear our buffer

    *(vu32*)0x10000020 = 0; // InitFS stuff
    *(vu32*)0x10000020 = 0x340; // InitFS stuff
    unsigned ret = f_mount(&fs, "0:", 0) == FR_OK;
    if (!ret) {
        Debug("Failed to f_mount...");
        wait_key();
        return 0;
    }

    // ROM DUMPING CODE STARTS HERE

    Cart_Init();
    Debug("Cart id is %08x, press A...", Cart_GetID());
    CTR_CmdReadHeader(header);
    Debug("Done reading header: %08X :)...", *(u32*)&header[0x100]);

    // TODO: Check first header bytes for "NCCH" or other magic words
    u32 sec_keys[4];
    Cart_Secure_Init((u32*)header,sec_keys);

    const u32 mediaUnit = 0x200; // TODO: Read from cart
    u32 blocks = 1 * 1024 * 1024 / mediaUnit; //1MB of blocks

    // Read out the header 0x0000-0x1000
    CTR_CmdReadData(0, mediaUnit, 0x1000 / mediaUnit, target);

    u32 NCSD_magic = *(u32*)(&target[0x100]);
    u32 cartSize = *(u32*)(&target[0x104]);
    Debug("Cart size: %llu MB", (u64)cartSize * (u64)mediaUnit / 1024ull / 1024ull);
    if (NCSD_magic != 0x4453434E) {
        Debug("NCSD magic not found in header!!!");
        Debug("Press A to continue anyway.");
        if (!(InputWait() & 1))
            goto cleanup_mount;
    }

    // Create output file
    char filename_buf[32];
    snprintf(filename_buf, sizeof(filename_buf), "/%.16s.3ds", &header[0x150]);
    Debug("Outputting to file: \"%s\"", filename_buf);

    if (f_open(&file, filename_buf, FA_READ | FA_WRITE | FA_CREATE_ALWAYS) != FR_OK) {
        Debug("Failed to create file...");
        wait_key();
        goto cleanup_mount;
    }


    // Write header to file
    f_lseek(&file, 0);

    Debug("Ready to dump. (SELECT to cancel)");
    if (InputWait() & 4) // Select
        goto cleanup_file;

    // Dump remaining data
    u32 current_sector = 0;
    while (current_sector < cartSize) {
        unsigned int percentage = current_sector * 100 / cartSize;
        Debug("Dumping %08X / %08X - %3u%%", current_sector, cartSize, percentage);

        u8* read_ptr = target;
        while (read_ptr < target + target_buf_size && current_sector < cartSize) {
            CTR_CmdReadData(current_sector, mediaUnit, blocks, read_ptr);
            read_ptr += mediaUnit * blocks;
            current_sector += blocks;
        }

        u8* write_ptr = target;
        while (write_ptr < read_ptr) {
            unsigned int bytes_written = 0;
            f_write(&file, write_ptr, read_ptr - write_ptr, &bytes_written);
            Debug("Wrote 0x%x bytes, e.g. %08x", bytes_written, *(u32*)write_ptr);

            if (bytes_written == 0) {
                Debug("Writing failed! :( SD full?");
                goto cleanup_file;
            }

            write_ptr += bytes_written;
        }
    }
    Debug("Done!");

    // Write header - TODO: Not sure why this is done at the very end..
    f_lseek(&file, 0x1000);
    unsigned int written = 0;
    f_write(&file, header, 0x200, &written);

cleanup_file:
    // Done, clean up...
    f_sync(&file);
    f_close(&file);
cleanup_mount:
    f_mount(NULL, "0:", 0);

    Debug("Press B to exit, any other key to restart.");
    if (!(InputWait() & 2))
        goto restart_program;

    return 0;
}
