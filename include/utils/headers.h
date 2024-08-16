// This file is used to include all the necessary headers for the DLMS dissector

// #define NEW_PROTO_TREE_API

#include <config.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <ws_symbol_export.h>
#include <wsutil/plugins.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <epan/reassemble.h>

#ifdef __cplusplus
}
#endif

#define UNUSED(x) (void)(x)
