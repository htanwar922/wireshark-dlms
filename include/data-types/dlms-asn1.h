
#include "utils/headers.h"

// Himanshu
typedef enum {
    ASNT_BOOLEAN           = 1,
    ASNT_INTEGER           = 2,
    ASNT_BIT_STRING        = 3,
    ASNT_OCTET_STRING      = 4,
    ASNT_NULL_TYPE         = 5,
    ASNT_OBJECT_IDENTIFIER = 6,
    ASNT_REAL              = 9,
    ASNT_ENUM              = 10,
    ASNT_NumericString     = 18,
    ASNT_PrintableString   = 19,
    ASNT_TeletexString     = 20,
    ASNT_VisibleString     = 26,
    ASNT_GraphicString     = 25,
} ASNType;

// Himanshu
const char *
dlms_get_object_identifier_name(guint8 v1, guint8 v2, guint16 v3, guint8 v4, guint8 v5, guint8 v6, guint8 v7);

// Himanshu
void
dlms_set_asn_data_value(tvbuff_t *tvb, proto_tree *tree, proto_item *item, guint8 choice, gint *offset);
