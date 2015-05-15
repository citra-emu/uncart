#include "hid.h"

u32 InputWait(void) {
    u32 pad_state_old = ~HID_STATE;
    while (true) {
        u32 pad_state = ~HID_STATE;
        if ((pad_state ^ pad_state_old) & pad_state)
            return pad_state;
        pad_state_old = pad_state;
    }
}
