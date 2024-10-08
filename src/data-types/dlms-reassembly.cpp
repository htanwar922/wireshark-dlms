/*
 * The reassembly table is used for reassembling both
 * HDLC I frame segments and DLMS APDU datablocks.
 * The reassembly id is used as hash key to distinguish between the two.
 */

#include "dlms-proto.h"

#include "data-types/dlms-reassembly.h"

reassembly_table dlms_reassembly_table;

const fragment_items dlms_fragment_items = {
    &dlms_ett.fragment,
    &dlms_ett.fragments,
    &dlms_hdr.fragments.hfinfo.id,
    &dlms_hdr.fragment.hfinfo.id,
    &dlms_hdr.fragment_overlap.hfinfo.id,
    &dlms_hdr.fragment_overlap_conflict.hfinfo.id,
    &dlms_hdr.fragment_multiple_tails.hfinfo.id,
    &dlms_hdr.fragment_too_long_fragment.hfinfo.id,
    &dlms_hdr.fragment_error.hfinfo.id,
    &dlms_hdr.fragment_count.hfinfo.id,
    &dlms_hdr.reassembled_in.hfinfo.id,
    &dlms_hdr.reassembled_length.hfinfo.id,
    &dlms_hdr.reassembled_data.hfinfo.id,
    "Fragments"
};

guint
dlms_reassembly_hash_func(gconstpointer key)
{
    return (guint)(gsize)key;
}

gint
dlms_reassembly_equal_func(gconstpointer key1, gconstpointer key2)
{
    return key1 == key2;
}

gpointer
dlms_reassembly_key_func(const packet_info *pinfo, guint32 id, const void *data)
{
    return (gpointer)(gsize)id;
}

void
dlms_reassembly_free_key_func(gpointer ptr)
{
}
