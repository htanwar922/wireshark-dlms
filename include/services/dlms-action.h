
static void
dlms_dissect_action_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    int choice, method_invocation_parameters;
    proto_tree *subtree;

    proto_tree_add_item(tree, &dlms_hfi.action_request, tvb, offset, 1, ENC_NA);
    choice = tvb_get_guint8(tvb, offset);
    offset += 1;
    dlms_dissect_invoke_id_and_priority(tree, tvb, &offset);
    if (choice == DLMS_ACTION_REQUEST_NORMAL) {
        col_add_str(pinfo->cinfo, COL_INFO, "Action-Request-Normal");
        dlms_dissect_cosem_method_descriptor(tvb, pinfo, tree, &offset);
        method_invocation_parameters = tvb_get_guint8(tvb, offset);
        if (method_invocation_parameters) {
            offset += 1;
            subtree = proto_tree_add_subtree(tree, tvb, 0, 0, dlms_ett.data, 0, "Data");
            dlms_dissect_data(tvb, pinfo, subtree, &offset);
        }
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Action-Request");
    }
}

static void
dlms_dissect_action_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    unsigned choice, result;
    const gchar *result_name;
    proto_item *item;

    proto_tree_add_item(tree, &dlms_hfi.action_response, tvb, offset, 1, ENC_NA);
    choice = tvb_get_guint8(tvb, offset);
    offset += 1;
    dlms_dissect_invoke_id_and_priority(tree, tvb, &offset);
    if (choice == DLMS_ACTION_RESPONSE_NORMAL) {
        col_add_str(pinfo->cinfo, COL_INFO, "Action-Response-Normal");
        item = proto_tree_add_item(tree, &dlms_hfi.action_result, tvb, offset, 1, ENC_NA);
        result = tvb_get_guint8(tvb, offset);
        offset += 1;
        if (result) {
            result_name = val_to_str_const(result, dlms_action_result_names, "unknown");
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", result_name);
            expert_add_info(pinfo, item, &dlms_ei.no_success);
        }
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Action-Response");
    }
}
