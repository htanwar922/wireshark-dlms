/*
 * The reassembly table is used for reassembling both
 * HDLC I frame segments and DLMS APDU datablocks.
 * The reassembly id is used as hash key to distinguish between the two.
 */
static reassembly_table dlms_reassembly_table;

enum {
    /* Do not use 0 as id because that would return a NULL key */
    DLMS_REASSEMBLY_ID_HDLC = 1,
    DLMS_REASSEMBLY_ID_DATABLOCK,
};

static guint
dlms_reassembly_hash_func(gconstpointer key)
{
    return (gsize)key;
}

static gint
dlms_reassembly_equal_func(gconstpointer key1, gconstpointer key2)
{
    return key1 == key2;
}

static gpointer
dlms_reassembly_key_func(const packet_info *pinfo, guint32 id, const void *data)
{
    return (gpointer)(gsize)id;
}

static void
dlms_reassembly_free_key_func(gpointer ptr)
{
}

static const fragment_items dlms_fragment_items = {
    &dlms_ett.fragment,
    &dlms_ett.fragments,
    &dlms_hfi.fragments.id,
    &dlms_hfi.fragment.id,
    &dlms_hfi.fragment_overlap.id,
    &dlms_hfi.fragment_overlap_conflict.id,
    &dlms_hfi.fragment_multiple_tails.id,
    &dlms_hfi.fragment_too_long_fragment.id,
    &dlms_hfi.fragment_error.id,
    &dlms_hfi.fragment_count.id,
    &dlms_hfi.reassembled_in.id,
    &dlms_hfi.reassembled_length.id,
    &dlms_hfi.reassembled_data.id,
    "Fragments"
};
