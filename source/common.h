#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef volatile u8 vu8;
typedef volatile u16 vu16;
typedef volatile u32 vu32;
typedef volatile u64 vu64;

inline char* strupper(const char* str) {
    const size_t string_len = strlen(str);
    char* buffer = (char*)malloc(string_len + 1);

    for (size_t i = 0; i < string_len; ++i)
        buffer[i] = toupper((unsigned)str[i]);

    return buffer;
}

inline char* strlower(const char* str) {
    const size_t string_len = strlen(str);
    char* buffer = (char*)malloc(string_len + 1);

    for (size_t i = 0; i < string_len; ++i)
        buffer[i] = tolower((unsigned)str[i]);

    return buffer;
}
