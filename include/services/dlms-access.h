
static void
dlms_dissect_access_request_specification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    proto_item *item, *subitem;
    proto_tree *subtree, *subsubtree;
    int sequence_of, i;

    subtree = proto_tree_add_subtree(tree, tvb, *offset, 0, dlms_ett.access_request_specification, &item, "Access Request Specification");
    sequence_of = dlms_get_length(tvb, offset);
    for (i = 0; i < sequence_of; i++) {
        int choice = tvb_get_guint8(tvb, *offset);
        subitem = proto_tree_add_item(subtree, &dlms_hfi.access_request, tvb, *offset, 1, ENC_NA);
        proto_item_prepend_text(subitem, "[%u] ", i + 1);
        subsubtree = proto_item_add_subtree(subitem, dlms_ett.access_request);
        *offset += 1;
        switch (choice) {
        case DLMS_ACCESS_REQUEST_GET:
        case DLMS_ACCESS_REQUEST_SET:
            dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, subsubtree, offset);
            break;
        case DLMS_ACCESS_REQUEST_ACTION:
            dlms_dissect_cosem_method_descriptor(tvb, pinfo, subsubtree, offset);
            break;
        case DLMS_ACCESS_REQUEST_GET_WITH_SELECTION:
        case DLMS_ACCESS_REQUEST_SET_WITH_SELECTION:
            dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, subsubtree, offset);
            dlms_dissect_selective_access_descriptor(tvb, pinfo, subsubtree, offset);
            break;
        default:
            DISSECTOR_ASSERT_HINT(choice, "Invalid Access-Request-Specification CHOICE");
        }
    }
    proto_item_set_end(item, tvb, *offset);
}

static void
dlms_dissect_access_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint date_time_offset;
    int date_time_length;
    proto_item *item;

    col_set_str(pinfo->cinfo, COL_INFO, "Access-Request");

    dlms_dissect_long_invoke_id_and_priority(tree, tvb, &offset);

    date_time_offset = offset;
    date_time_length = dlms_get_length(tvb, &offset);
    item = proto_tree_add_item(tree, &dlms_hfi.date_time, tvb, date_time_offset, offset - date_time_offset + date_time_length, ENC_NA);
    dlms_append_date_time_maybe(tvb, item, offset, date_time_length);

    dlms_dissect_access_request_specification(tvb, pinfo, tree, &offset);

    dlms_dissect_list_of_data(tvb, pinfo, tree, &offset, "Access Request List Of Data");
}

static void
dlms_dissect_access_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint date_time_offset;
    int date_time_length;
    proto_item *item;
    proto_tree *subtree, *subsubtree;
    int sequence_of, i;

    col_set_str(pinfo->cinfo, COL_INFO, "Access-Response");

    dlms_dissect_long_invoke_id_and_priority(tree, tvb, &offset);

    date_time_offset = offset;
    date_time_length = dlms_get_length(tvb, &offset);
    item = proto_tree_add_item(tree, &dlms_hfi.date_time, tvb, date_time_offset, offset - date_time_offset + date_time_length, ENC_NA);
    dlms_append_date_time_maybe(tvb, item, offset, date_time_length);

    dlms_dissect_access_request_specification(tvb, pinfo, tree, &offset);

    dlms_dissect_list_of_data(tvb, pinfo, tree, &offset, "Access Response List Of Data");

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, dlms_ett.access_response_specification, 0, "Access Response Specification");
    sequence_of = dlms_get_length(tvb, &offset);
    for (i = 0; i < sequence_of; i++) {
        item = proto_tree_add_item(subtree, &dlms_hfi.access_response, tvb, offset, 1, ENC_NA);
        proto_item_prepend_text(item, "[%u] ", i + 1);
        subsubtree = proto_item_add_subtree(item, dlms_ett.access_request);
        offset += 1;
        dlms_dissect_data_access_result(tvb, pinfo, subsubtree, &offset);
    }
}
