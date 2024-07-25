#include <config.h>
#include <epan/packet.h>
#include "dlms.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DLMS_PLUGIN_VERSION "0.9.0"

#if (VERSION_MAJOR >= 4)

void
proto_register_dlms(void)
{
    dlms_register_protoinfo();
}

void
proto_reg_handoff_dlms(void)
{
     dlms_reg_handoff();
}

#elif (VERSION_MAJOR > 2) || ((VERSION_MAJOR == 2) && (VERSION_MINOR >= 6))

/*
 * The symbols that a Wireshark plugin is required to export.
 */
// WS_DLL_PUBLIC_DEF const gchar plugin_release[] = VERSION_RELEASE;
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = DLMS_PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const gint plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const gint plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC_DEF void
plugin_register(void)
{
    static proto_plugin p;
    p.register_protoinfo = dlms_register_protoinfo;
    p.register_handoff = dlms_reg_handoff;
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


#ifdef __cplusplus
}
#endif
