
#include "utils/headers.h"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif

// Himanshu - Debugging Functions
static char
dlms_nibble_to_char(guint8 nibble)
{
    return (nibble < 10) ? (nibble + '0') : (nibble - 10 + 'A');
}
static void
dlms_print_byte(guint8 byte)
{
    char buf[4];
    for (int i = 0; i < sizeof(guint8) * 2; i++) {
        buf[i] = dlms_nibble_to_char((byte >> (sizeof(guint8) * 8 - 4 * i - 4)) & 0x0f);
    }
    buf[2] = ' ';
    buf[3] = '\0';
    g_print(buf);
}
static void
dlms_print_half_word(guint16 half_word)
{
    char buf[6];
    for (int i = 0; i < sizeof(guint16) * 2; i++) {
        buf[i] = dlms_nibble_to_char((half_word >> (sizeof(guint16) * 8 - 4 * i - 4)) & 0x0f);
    }
    buf[4] = ' ';
    buf[5] = '\0';
    g_print(buf);
}
static void
dlms_print_word(guint32 word)
{
    g_print("%08X ", word);
}
static void
dlms_print_dword(guint64 dword)
{
    g_print("%016lX ", dword);
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
#endif