
static proto_item *
dlms_dissect_compact_array_content(tvbuff_t *tvb, proto_tree *tree, gint description_offset, gint *content_offset)
{
    proto_item *item, *subitem;
    proto_tree *subtree;
    unsigned choice;

    item = proto_tree_add_item(tree, &dlms_hfi.data, tvb, *content_offset, 0, ENC_NA);
    choice = tvb_get_guint8(tvb, description_offset);
    description_offset += 1;
    if (choice == 1) { /* array */
        guint16 i, elements = tvb_get_ntohs(tvb, description_offset);
        description_offset += 2;
        proto_item_set_text(item, "Array (%u elements)", elements);
        subtree = proto_item_add_subtree(item, dlms_ett.composite_data);
        for (i = 0; i < elements; i++) {
            subitem = dlms_dissect_compact_array_content(tvb, subtree, description_offset, content_offset);
            proto_item_prepend_text(subitem, "[%u] ", i + 1);
        }
    } else if (choice == 2) { /* structure */
        guint32 elements = dlms_get_length(tvb, &description_offset);
        proto_item_set_text(item, "Structure");
        subtree = proto_item_add_subtree(item, dlms_ett.composite_data);
        while (elements--) {
            dlms_dissect_compact_array_content(tvb, subtree, description_offset, content_offset);
            description_offset += dlms_get_type_description_length(tvb, description_offset);
        }
    } else { /* planar type */
        dlms_set_data_value(tvb, item, choice, content_offset);
    }
    proto_item_set_end(item, tvb, *content_offset);

    return item;
}

static proto_item *
dlms_dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    proto_item *item, *subitem;
    proto_tree *subtree;
    unsigned choice, length, i;

    item = proto_tree_add_item(tree, &dlms_hfi.data, tvb, *offset, 1, ENC_NA);
    choice = tvb_get_guint8(tvb, *offset);
    *offset += 1;
    if (choice == 1) { /* array */
        length = dlms_get_length(tvb, offset);
        proto_item_set_text(item, "Array (%u elements)", length);
        subtree = proto_item_add_subtree(item, dlms_ett.composite_data);
        for (i = 0; i < length; i++) {
            subitem = dlms_dissect_data(tvb, pinfo, subtree, offset);
            proto_item_prepend_text(subitem, "[%u] ", i + 1);
        }
    } else if (choice == 2) { /* structure */
        length = dlms_get_length(tvb, offset);
        proto_item_set_text(item, "Structure");
        subtree = proto_item_add_subtree(item, dlms_ett.composite_data);
        for (i = 0; i < length; i++) {
            dlms_dissect_data(tvb, pinfo, subtree, offset);
        }
    } else if (choice == 19) { /* compact-array */
        int description_offset = *offset;
        int description_length = dlms_get_type_description_length(tvb, *offset);
        int content_end;
        unsigned elements;
        subtree = proto_item_add_subtree(item, dlms_ett.composite_data);
        proto_tree_add_item(subtree, &dlms_hfi.type_description, tvb, description_offset, description_length, ENC_NA);
        *offset += description_length;
        length = dlms_dissect_length(tvb, subtree, offset);
        elements = 0;
        content_end = *offset + length;
        while (*offset < content_end) {
            subitem = dlms_dissect_compact_array_content(tvb, subtree, description_offset, offset);
            proto_item_prepend_text(subitem, "[%u] ", ++elements);
        }
        proto_item_set_text(item, "Compact Array (%u elements)", elements);
    } else { /* planar type */
        dlms_set_data_value(tvb, item, choice, offset);
    }
    proto_item_set_end(item, tvb, *offset);

    return item;
}

static void
dlms_dissect_list_of_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, const char *name)
{
    proto_tree *item;
    proto_tree *subtree;
    int sequence_of, i;

    subtree = proto_tree_add_subtree(tree, tvb, *offset, 0, dlms_ett.data, &item, name);
    sequence_of = dlms_get_length(tvb, offset);
    for (i = 0; i < sequence_of; i++) {
        proto_item *subitem = dlms_dissect_data(tvb, pinfo, subtree, offset);
        proto_item_prepend_text(subitem, "[%u] ", i + 1);
    }
    proto_item_set_end(item, tvb, *offset);
}

static void
dlms_dissect_datablock_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *subtree, gint *offset, unsigned block_number, unsigned last_block)
{
    unsigned saved_offset, raw_data_length;
    proto_item *item;
    fragment_head *frags;
    tvbuff_t *rtvb;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (block %u)", block_number);
    if (last_block) {
        col_append_str(pinfo->cinfo, COL_INFO, " (last block)");
    }

    saved_offset = *offset;
    raw_data_length = dlms_get_length(tvb, offset);
    item = proto_tree_add_item(subtree, &dlms_hfi.data, tvb, saved_offset, *offset - saved_offset + raw_data_length, ENC_NA);
    proto_item_append_text(item, " (length %u)", raw_data_length);

    if (block_number == 1) {
        fragment_delete(&dlms_reassembly_table, pinfo, DLMS_REASSEMBLY_ID_DATABLOCK, 0);
    }
    frags = fragment_add_seq_next(&dlms_reassembly_table, tvb, *offset, pinfo, DLMS_REASSEMBLY_ID_DATABLOCK, 0, raw_data_length, last_block == 0);
    rtvb = process_reassembled_data(tvb, *offset, pinfo, "Reassembled", frags, &dlms_fragment_items, 0, tree);
    if (rtvb) {
        gint offset = 0;
        subtree = proto_tree_add_subtree(tree, rtvb, 0, 0, dlms_ett.data, 0, "Reassembled Data");
        dlms_dissect_data(rtvb, pinfo, subtree, &offset);
    }

    *offset += raw_data_length;
}

static void
dlms_dissect_datablock_g(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    proto_tree *subtree;
    unsigned last_block, block_number;
    int result;

    subtree = proto_tree_add_subtree(tree, tvb, 0, 0, dlms_ett.datablock, 0, "Datablock G");

    proto_tree_add_item(subtree, &dlms_hfi.last_block, tvb, *offset, 1, ENC_NA);
    last_block = tvb_get_guint8(tvb, *offset);
    *offset += 1;

    proto_tree_add_item(subtree, &dlms_hfi.block_number, tvb, *offset, 4, ENC_BIG_ENDIAN);
    block_number = tvb_get_ntohl(tvb, *offset);
    *offset += 4;

    result = tvb_get_guint8(tvb, *offset);
    *offset += 1;
    if (result == 0) {
        dlms_dissect_datablock_data(tvb, pinfo, tree, subtree, offset, block_number, last_block);
    } else if (result == 1) {
        dlms_dissect_data_access_result(tvb, pinfo, subtree, offset);
    }
}

static void
dlms_dissect_datablock_sa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    proto_tree *subtree;    
    unsigned last_block, block_number;

    subtree = proto_tree_add_subtree(tree, tvb, 0, 0, dlms_ett.datablock, 0, "Datablock SA");

    proto_tree_add_item(subtree, &dlms_hfi.last_block, tvb, *offset, 1, ENC_NA);
    last_block = tvb_get_guint8(tvb, *offset);
    *offset += 1;

    proto_tree_add_item(subtree, &dlms_hfi.block_number, tvb, *offset, 4, ENC_BIG_ENDIAN);
    block_number = tvb_get_ntohl(tvb, *offset);
    *offset += 4;

    dlms_dissect_datablock_data(tvb, pinfo, tree, subtree, offset, block_number, last_block);
}