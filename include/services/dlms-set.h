
static void
dlms_dissect_set_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    int choice;
    proto_tree *subtree;

    proto_tree_add_item(tree, &dlms_hfi.set_request, tvb, offset, 1, ENC_NA);
    choice = tvb_get_guint8(tvb, offset);
    offset += 1;
    dlms_dissect_invoke_id_and_priority(tree, tvb, &offset);
    if (choice == DLMS_SET_REQUEST_NORMAL) {
        col_add_str(pinfo->cinfo, COL_INFO, "Set-Request-Normal");
        dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, tree, &offset);
        dlms_dissect_selective_access_descriptor(tvb, pinfo, tree, &offset);
        subtree = proto_tree_add_subtree(tree, tvb, 0, 0, dlms_ett.data, 0, "Data");
        dlms_dissect_data(tvb, pinfo, subtree, &offset);
    } else if (choice == DLMS_SET_REQUEST_WITH_FIRST_DATABLOCK) {
        col_add_str(pinfo->cinfo, COL_INFO, "Set-Request-With-First-Datablock");
        dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, tree, &offset);
        dlms_dissect_selective_access_descriptor(tvb, pinfo, tree, &offset);
        dlms_dissect_datablock_sa(tvb, pinfo, tree, &offset);
    } else if (choice == DLMS_SET_REQUEST_WITH_DATABLOCK) {
        col_add_str(pinfo->cinfo, COL_INFO, "Set-Request-With-Datablock");
        dlms_dissect_datablock_sa(tvb, pinfo, tree, &offset);
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Set-Request");
    }
}

static void
dlms_dissect_set_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    unsigned choice, block_number;

    proto_tree_add_item(tree, &dlms_hfi.set_response, tvb, offset, 1, ENC_NA);
    choice = tvb_get_guint8(tvb, offset);
    offset += 1;
    dlms_dissect_invoke_id_and_priority(tree, tvb, &offset);
    if (choice == DLMS_SET_RESPONSE_NORMAL) {
        col_add_str(pinfo->cinfo, COL_INFO, "Set-Response-Normal");
        dlms_dissect_data_access_result(tvb, pinfo, tree, &offset);
    } else if (choice == DLMS_SET_RESPONSE_DATABLOCK) {
        col_add_str(pinfo->cinfo, COL_INFO, "Set-Response-Datablock");
        proto_tree_add_item(tree, &dlms_hfi.block_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        block_number = tvb_get_ntohl(tvb, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (block %u)", block_number);
    } else if (choice == DLMS_SET_RESPONSE_LAST_DATABLOCK) {
        col_add_str(pinfo->cinfo, COL_INFO, "Set-Response-Last-Datablock");
        dlms_dissect_data_access_result(tvb, pinfo, tree, &offset);
        proto_tree_add_item(tree, &dlms_hfi.block_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        block_number = tvb_get_ntohl(tvb, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (block %u)", block_number);
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Set-Response");
    }
}