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

void ClearTop() {
    ClearScreen(TOP_SCREEN0, RGB(255, 255, 255));
    ClearScreen(TOP_SCREEN1, RGB(255, 255, 255));
    current_y = 0;
}

void wait_key() {
    Debug("");
    Debug("Press key to continue");
    InputWait();
}

int main() {

    // Setup boring stuff - clear the screen, initialize SD output, etc...
    ClearTop();
    Debug("");
    Debug("Hello world from ARM9!");
    Debug("ROM dump tool v0.2", 1, 1, 0xFF);
    wait_key();

    u32 bytes_written = 0;
    u8 String[21];

    // Arbitrary target buffer
    // TODO: This should be done in a nicer way ;)
    volatile u8* target = (vu8*)0x22000000;
    volatile u8* header = (vu8*)0x23000000;

    Debug("ROM dump tool v0.2", 1, 1, 0xFF);
    memset((u8*)target, 0x00, 0x100000); // Clear our 1 MB buffer
    // clear_screens(0x00);

    *(u32*)0x10000020 = 0; // InitFS stuff
    *(u32*)0x10000020 = 0x340; // InitFS stuff
    unsigned ret = f_mount(&fs, "0:", 0) == FR_OK;
    if (!ret) {
        Debug("Failed to f_mount...");
        wait_key();
        return 0;
    }
    Debug("Successfully f_mounted");
    Debug("cleared stuff! Initializing game card...", 1, 1, 0xFF);

    // ROM DUMPING CODE STARTS HERE

    Cart_Init();

    Debug("Done! Cart id is %08x, press A...", (u32)Cart_GetID());

    while((*((vu16*)0x10146000) & 1)); // Wait for button A
    Debug("Done waiting :)...", 1, 1, 0xFF);

    CTR_CmdReadHeader(header);
    Debug("Done reading header: %08x :)...", *(u32*)&header[0x100]);

    // TODO: Check first header bytes for "NCSD" or other magic words which should be there for valid NCCHs
    u32 sec_keys[4];
    Cart_Secure_Init((u32*)header,sec_keys);

    u32 mediaUnit = 0x200;
    u32 ramCache = 0xC000; //24MB/s - 0x1000000

    u32 dumpSize = 0x100000; //1MB
    u32 blocks = dumpSize / mediaUnit; //1MB of blocks

    // Read out the header 0x0000-0x1000
    CTR_CmdReadData(0, mediaUnit, 8, (void*)(target));

    // Create output file - TODO: Put actual information in the file name (game id/name/..?), to have a standardized naming scheme
    memcpy(String, "/dump.3ds\0", 10);

    wait_key();
    Debug("File name: \"%s\"", String);

    unsigned flags = FA_READ | FA_WRITE | FA_CREATE_ALWAYS;
    if (f_open(&file, String, flags) != FR_OK) {
        Debug("Failed to create file...");
        wait_key();
        return 0;
    }

    f_lseek(&file, 0);
    f_sync(&file);
    Debug("Successfully created file");
    wait_key();

    // Write header to file
    u32 written = 0;
    f_write(&file, target, 0x4000, &written);
    f_sync(&file);
    Debug("Wrote header");
    wait_key();


    u32 cartSize = *(u32*)(&target[0x104]);
    Debug("Cart size: %d MB", cartSize * 0x200 / 1024/1024);
    wait_key();

    // Dump remaining data
    for(u32 adr=0x20; adr<cartSize; adr+=ramCache) {
        ClearTop();
        Debug("Wrote 0x%x bytes, e.g. %08x",bytes_written, *(u32*)target);
        u32 dumped = cartSize - adr;
        if(dumped > ramCache) dumped = ramCache;

        for(u32 adr2=0; (adr2 < dumped); adr2+=blocks) {
            u32 currentSector = (adr+adr2);
            u32 percent = ((currentSector*100)/cartSize);
            if ((adr2 % (blocks*3)) == blocks*2)
                Debug("Dumping %08X / %08X - %03d%%",currentSector,cartSize,percent);

            CTR_CmdReadData(currentSector, mediaUnit, blocks, (void*)(target + (adr2 * mediaUnit)));
        }
        f_write(&file, target, dumped * mediaUnit, &bytes_written);
        f_sync(&file);
    }

    // Write header - TODO: Not sure why this is done at the very end..
    f_lseek(&file, 0x1000);
    f_write(&file, header, 0x200, &written);
    f_sync(&file);
    Debug("Wrote 0x%x header bytes", written);
    wait_key();

    // Done, clean up...
    f_close(&file);
    wait_key();
    f_mount(NULL, "0:", 0);

    return 0;
}
