
#include "utils/headers.h"

void
dlms_dissect_get_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

void
dlms_dissect_get_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_glo_get_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_glo_get_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_ded_get_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_ded_get_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);
