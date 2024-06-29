/*
 * The reassembly table is used for reassembling both
 * HDLC I frame segments and DLMS APDU datablocks.
 * The reassembly id is used as hash key to distinguish between the two.
 */

#include "utils/headers.h"

extern reassembly_table dlms_reassembly_table;
extern const fragment_items dlms_fragment_items;

enum {
    /* Do not use 0 as id because that would return a NULL key */
    DLMS_REASSEMBLY_ID_HDLC = 1,
    DLMS_REASSEMBLY_ID_DATABLOCK,
};

guint
dlms_reassembly_hash_func(gconstpointer key);

gint
dlms_reassembly_equal_func(gconstpointer key1, gconstpointer key2);

gpointer
dlms_reassembly_key_func(const packet_info *pinfo, guint32 id, const void *data);
void
dlms_reassembly_free_key_func(gpointer ptr);
