
#include "headers.h"

/* HDLC frame names for the control field values (with the RRR, P/F, and SSS bits masked off) */
static const value_string dlms_hdlc_frame_names[] = {
    { 0x00, "I (Information)" },
    { 0x01, "RR (Receive Ready)" },
    { 0x03, "UI (Unnumbered Information)" },
    { 0x05, "RNR (Receive Not Ready)" },
    { 0x0f, "DM (Disconnected Mode)" },
    { 0x43, "DISC (Disconnect)" },
    { 0x63, "UA (Unnumbered Acknowledge)" },
    { 0x83, "SNRM (Set Normal Response Mode)" },
    { 0x87, "FRMR (Frame Reject)" },
    { 0, 0 }
};
