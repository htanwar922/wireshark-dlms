
/*
 * The symbols that a Wireshark plugin is required to export.
 */

#include "proto.h"

#define DLMS_PLUGIN_VERSION "0.0.2+"

#if (VERSION_MAJOR > 2) || ((VERSION_MAJOR == 2) && (VERSION_MINOR >= 6))

#define WIRESHARK_VERSION_MAJOR 3
#define WIRESHARK_VERSION_MINOR 2


// WS_DLL_PUBLIC_DEF const gchar plugin_release[] = VERSION_RELEASE;
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = DLMS_PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const gint plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const gint plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC_DEF void
plugin_register(void)
{
    static proto_plugin p;
    p.register_protoinfo = dlms_register_protoinfo;
    p.register_handoff = NULL;
    proto_register_plugin(&p);
}

// WIRESHARK_PLUGIN_REGISTER_EPAN(&module, 0)
// WIRESHARK_PLUGIN_REGISTER_WIRETAP(&module, 0)
// WIRESHARK_PLUGIN_REGISTER_CODEC(&module, 0)

#else /* wireshark < 2.6 */

WS_DLL_PUBLIC_DEF const gchar version[] = DLMS_PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF void
plugin_register(void)
{
    dlms_register_protoinfo();
}

#endif
