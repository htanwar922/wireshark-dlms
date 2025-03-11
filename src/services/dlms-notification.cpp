
#include "dlms-proto.h"

#include "data-types/dlms-utils.h"
#include "data-types/dlms-bitsets.h"
#include "data-types/dlms-descriptors.h"
#include "data-types/dlms-data.h"

#include "services/dlms-notification.h"

void
dlms_dissect_data_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint date_time_offset;
    gint date_time_length;
    proto_item *item;

    col_set_str(pinfo->cinfo, COL_INFO, "Data-Notification");

    dlms_dissect_long_invoke_id_and_priority(tree, tvb, &offset);

    date_time_offset = offset;
    date_time_length = dlms_get_length(tvb, &offset);
    item = proto_tree_add_item(tree, *dlms_hdr.date_time.p_id, tvb, date_time_offset, offset - date_time_offset + date_time_length, ENC_NA);
    dlms_append_date_time_maybe(tvb, item, offset, date_time_length);

    /* notification-body */
    dlms_dissect_data(tvb, pinfo, tree, &offset);
}

void
dlms_dissect_event_notification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;

    col_add_str(pinfo->cinfo, COL_INFO, "Event-Notification-Request");
    offset += 1; /* time OPTIONAL (assume it is not present) */
    dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, tree, &offset);
    subtree = proto_tree_add_subtree(tree, tvb, 0, 0, dlms_ett.data, 0, "Data");
    dlms_dissect_data(tvb, pinfo, subtree, &offset);
}

// Himanshu
void
dlms_dissect_ded_event_notification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;

    col_add_str(pinfo->cinfo, COL_INFO, "Event-Notification-Request");
    offset += 1; /* time OPTIONAL (assume it is not present) */
    dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, tree, &offset);
    subtree = proto_tree_add_subtree(tree, tvb, 0, 0, dlms_ett.data, 0, "Data");
    dlms_dissect_data(tvb, pinfo, subtree, &offset);
}
