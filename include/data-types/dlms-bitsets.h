
static void
dlms_dissect_invoke_id_and_priority(proto_tree *tree, tvbuff_t *tvb, gint *offset)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, *offset, 1, dlms_ett.invoke_id_and_priority, 0, "Invoke Id And Priority");
    proto_tree_add_item(subtree, &dlms_hfi.invoke_id, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(subtree, &dlms_hfi.service_class, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(subtree, &dlms_hfi.priority, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

static void
dlms_dissect_long_invoke_id_and_priority(proto_tree *tree, tvbuff_t *tvb, gint *offset)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, *offset, 4, dlms_ett.invoke_id_and_priority, 0, "Long Invoke Id And Priority");
    proto_tree_add_item(subtree, &dlms_hfi.long_invoke_id, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, &dlms_hfi.long_self_descriptive, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, &dlms_hfi.long_processing_option, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, &dlms_hfi.long_service_class, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, &dlms_hfi.long_priority, tvb, *offset, 4, ENC_BIG_ENDIAN);
    *offset += 4;
}
