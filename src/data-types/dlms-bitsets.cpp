
#include "dlms-proto.h"

#include "data-types/dlms-bitsets.h"

void
dlms_dissect_invoke_id_and_priority(proto_tree *tree, tvbuff_t *tvb, gint *offset)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, *offset, 1, dlms_ett.invoke_id_and_priority, 0, "Invoke Id And Priority");
    proto_tree_add_item(subtree, *dlms_hdr.invoke_id.p_id, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(subtree, *dlms_hdr.service_class.p_id, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(subtree, *dlms_hdr.priority.p_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

void
dlms_dissect_long_invoke_id_and_priority(proto_tree *tree, tvbuff_t *tvb, gint *offset)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, *offset, 4, dlms_ett.invoke_id_and_priority, 0, "Long Invoke Id And Priority");
    proto_tree_add_item(subtree, *dlms_hdr.long_invoke_id.p_id, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, *dlms_hdr.long_self_descriptive.p_id, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, *dlms_hdr.long_processing_option.p_id, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, *dlms_hdr.long_service_class.p_id, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, *dlms_hdr.long_priority.p_id, tvb, *offset, 4, ENC_BIG_ENDIAN);
    *offset += 4;
}
