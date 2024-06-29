
#include "utils/headers.h"

void
dlms_dissect_action_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

void
dlms_dissect_action_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_glo_action_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_glo_action_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);
