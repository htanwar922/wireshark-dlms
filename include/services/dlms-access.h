
#include "utils/headers.h"

void
dlms_dissect_access_request_specification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset);

void
dlms_dissect_access_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

void
dlms_dissect_access_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);
