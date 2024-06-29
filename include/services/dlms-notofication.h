
#include "utils/headers.h"

void
dlms_dissect_data_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

void
dlms_dissect_event_notification_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);
