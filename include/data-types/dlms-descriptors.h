
static void
dlms_dissect_cosem_attribute_or_method_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, int is_attribute)
{
    unsigned class_id, attribute_method_id;
    const dlms_cosem_class *cosem_class;
    const char *attribute_method_name;
    const gchar *instance_name;
    proto_tree *subtree;
    proto_item *item;

    class_id = tvb_get_ntohs(tvb, *offset);
    attribute_method_id = tvb_get_guint8(tvb, *offset + 8);

    cosem_class = dlms_get_class(class_id);
    if (cosem_class) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", cosem_class->name);
        if (is_attribute) {
            attribute_method_name = dlms_get_attribute_name(cosem_class, attribute_method_id);
        } else {
            attribute_method_name = dlms_get_method_name(cosem_class, attribute_method_id);
        }
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %u", class_id);
        attribute_method_name = 0;
    }

    if (attribute_method_name) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ".%s", attribute_method_name);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, ".%u", attribute_method_id);
    }

	instance_name = try_val64_to_str(tvb_get_ntoh48(tvb, *offset + 2), obis_code_names);
	if (instance_name) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", instance_name);
	}
	else {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %u.%u.%u.%u.%u.%u",
			tvb_get_guint8(tvb, *offset + 2),
			tvb_get_guint8(tvb, *offset + 3),
			tvb_get_guint8(tvb, *offset + 4),
			tvb_get_guint8(tvb, *offset + 5),
			tvb_get_guint8(tvb, *offset + 6),
			tvb_get_guint8(tvb, *offset + 7));
	}

    subtree = proto_tree_add_subtree(tree, tvb, *offset, 9, dlms_ett.cosem_attribute_or_method_descriptor, 0,
                                     is_attribute ? "COSEM Attribute Descriptor" : "COSEM Method Descriptor");

    item = proto_tree_add_item(subtree, &dlms_hfi.class_id, tvb, *offset, 2, ENC_BIG_ENDIAN);
    if (cosem_class) {
        proto_item_append_text(item, ": %s (%u)", cosem_class->name, class_id);
    } else {
        proto_item_append_text(item, ": Unknown (%u)", class_id);
        expert_add_info(pinfo, item, &dlms_ei.not_implemented);
    }
    *offset += 2;

    item = proto_tree_add_item(subtree, &dlms_hfi.instance_id, tvb, *offset, 6, ENC_NA);
    proto_item_append_text(item, ": %s (%u.%u.%u.%u.%u.%u)",
                           instance_name ? instance_name : "Unknown",
                           tvb_get_guint8(tvb, *offset),
                           tvb_get_guint8(tvb, *offset + 1),
                           tvb_get_guint8(tvb, *offset + 2),
                           tvb_get_guint8(tvb, *offset + 3),
                           tvb_get_guint8(tvb, *offset + 4),
                           tvb_get_guint8(tvb, *offset + 5));
    *offset += 6;

    item = proto_tree_add_item(subtree,
                               is_attribute ? &dlms_hfi.attribute_id : &dlms_hfi.method_id,
                               tvb, *offset, 1, ENC_BIG_ENDIAN);
    if (attribute_method_name) {
        proto_item_append_text(item, ": %s (%u)", attribute_method_name, attribute_method_id);
    } else {
        proto_item_append_text(item, ": Unknown (%u)", attribute_method_id);
    }
    *offset += 1;
}

static void
dlms_dissect_cosem_attribute_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    dlms_dissect_cosem_attribute_or_method_descriptor(tvb, pinfo, tree, offset, 1);
}

static void
dlms_dissect_cosem_method_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    dlms_dissect_cosem_attribute_or_method_descriptor(tvb, pinfo, tree, offset, 0);
}

static void
dlms_dissect_data_access_result(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    proto_item *item;
    int result;

    item = proto_tree_add_item(tree, &dlms_hfi.data_access_result, tvb, *offset, 1, ENC_NA);
    result = tvb_get_guint8(tvb, *offset);
    *offset += 1;
    if (result != 0) {
        const gchar *str = val_to_str_const(result, dlms_data_access_result_names, "unknown result");
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", str);
        expert_add_info(pinfo, item, &dlms_ei.no_success);
    }
}
