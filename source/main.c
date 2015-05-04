#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "draw.h"
#include "framebuffer.h"
#include "hid.h"
#include "fatfs/ff.h"

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

void AES_SetKeyControl(u32 a) {
    *((volatile u8*)0x10009011) = a | 0x80;
}

void print_status(u8 *Str, u32 x, u32 y, u8 color)
{
    Debug(Str);
}

int main() {

    // Setup boring stuff - clear the screen, initialize SD output, etc...
    ClearTop();
    Debug("");
    Debug("Hello world from ARM9!");
    print_status("ROM dump tool v0.2", 1, 1, 0xFF);
    wait_key();

    u8 file_path[38];
    u32 sdmc_file_handle[8];
    u32 bytes_written = 0;
    u32 i = 0;
    u32 size = 0;
    u8 String[8];
    u8 String2[21];
    static u8 ClearCharacter[2] = {0xDB, 0x00};

    // Arbitrary target buffer
    // TODO: This should be done in a nicer way ;)
    volatile u8* target = (vu8*)0x22000000;
    volatile u8* header = (vu8*)0x23000000;
    u32 *ptr = (u32*)(target + 0x0100);

    print_status("ROM dump tool v0.2", 1, 1, 0xFF);
    memset((u8*)target, 0x00, 0x100000); // Clear our 1 MB buffer
    // clear_screens(0x00);

    unsigned ret;
    *(u32*)0x10000020 = 0; // InitFS stuff
    *(u32*)0x10000020 = 0x340; // InitFS stuff
    ret = f_mount(&fs, "0:", 0) == FR_OK;
    if (!ret) {
        Debug("Failed to f_mount...");
        wait_key();
        return 0;
    }
    Debug("Successfully f_mounted");
    print_status("cleared stuff! Initializing game card...", 1, 1, 0xFF);



    // ROM DUMPING CODE STARTS HERE

    Cart_Init();

    Debug("Done! Cart id is %08x, press A...", (u32)Cart_GetID());

    while((*((vu16*)0x10146000) & 1)); // Wait for button A
    print_status("Done waiting :)...", 1, 1, 0xFF);

    GetHeader(header);
    Debug("Done reading header: %08x :)...", *(u32*)&header[0x100]);

    // TODO: Check first header bytes for "NCSD" or other magic words which should be there for valid NCCHs
    /*  if(*ptr != 0x4453434E) // Check for "NCSD" magic
      {
        Debug("Bad header read! Got %08x, expected %08x", *ptr, 0x4453434E);
        svcSleepThread(150000000LL);
        wait_key();
        return 0;
      }
      print_status("Done checking NCSD magic:)...", 1, 1, 0xFF);
    */



    uint32_t sec_keys[4];
    Cart_Secure_Init((u32*)header,sec_keys);

    uint32_t mediaUnit = 0x200;
    uint32_t ramCache = 0xC000; //24MB/s - 0x1000000

    uint32_t dumpSize = 0x100000; //1MB
    uint32_t blocks = dumpSize / mediaUnit; //1MB of blocks

    // Read out the header 0x0000-0x1000
    SendReadCommand( 0, mediaUnit, 8, (void*)(target) );

    // Create output file - TODO: Put actual information in the file name (game id/name/..?), to have a standardized naming scheme
    memcpy(String2, "/dump.3ds\0", 10);

    wait_key();
    Debug("File name: \"%s\"", String2);
    unsigned flags = FA_READ | FA_WRITE | FA_CREATE_ALWAYS;
    ret = (f_open(&file, String2, flags) == FR_OK);
    if (!ret) {
        Debug("Failed to create file...");
        wait_key();
        return 0;
    }
    f_lseek(&file, 0);
    f_sync(&file);
    Debug("Successfully created file");
    wait_key();

    // Write header to file
    uint32_t written = 0;
    f_write(&file, target, 0x4000, &written);
    f_sync(&file);
    Debug("Wrote header");
    wait_key();


    uint32_t cartSize = (*((uint32_t*)&target[0x104]));
    Debug("Cart size: %d MB", cartSize * 0x200 / 1024/1024);
    wait_key();

    // Dump remaining data
    for(uint32_t adr=0x20; adr<cartSize; adr+=ramCache)
    {
        ClearTop();
        Debug("Wrote 0x%x bytes, e.g. %08x",bytes_written, *(u32*)target);
        uint32_t dumped = cartSize - adr;
        if(dumped > ramCache) dumped = ramCache;

        for(uint32_t adr2=0; (adr2 < dumped); adr2+=blocks)
        {
            uint32_t currentSector = (adr+adr2);
            uint32_t percent = ((currentSector*100)/cartSize);
            if ((adr2 % (blocks*3)) == blocks*2)
                Debug("Dumping %08X / %08X - %03d%%",currentSector,cartSize,percent);

            SendReadCommand( currentSector, mediaUnit, blocks, (void*)(target+(adr2*mediaUnit)) );
        }
        f_write(&file, target, dumped * mediaUnit, &bytes_written);
        f_sync(&file);
    }

    // Write header - TODO: Not sure why this is done at the very end..
    f_lseek(&file, 0x1000);
    f_write(&file, &header, 0x200, &written);
    f_sync(&file);
    Debug("Wrote 0x%x header bytes", written);
    wait_key();

    // Done, clean up...
    f_close(&file);
    wait_key();
    f_mount(NULL, "0:", 0);

    return 0;
}
