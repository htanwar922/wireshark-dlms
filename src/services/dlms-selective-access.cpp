
#include "dlms-proto.h"

#include "data-types/dlms-data.h"

#include "services/dlms-selective-access.h"

void
dlms_dissect_selective_access_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    proto_item *item;
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, *offset, 0, dlms_ett.selective_access_descriptor, &item, "Selective Access Descriptor");
    int selector = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(subtree, *dlms_hdr.access_selector.p_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    if (selector) {
        dlms_dissect_data(tvb, pinfo, subtree, offset);
    }
    proto_item_set_end(item, tvb, *offset);
}