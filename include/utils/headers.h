#define WS_BUILD_DLL
#define NEW_PROTO_TREE_API

#ifdef __cplusplus
extern "C" {
#endif

#include <config.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <ws_symbol_export.h>
#include <wsutil/plugins.h>

#ifdef __cplusplus
}
#endif

#define UNUSED(x) (void)(x)