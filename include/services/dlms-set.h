
#include "utils/headers.h"

void
dlms_dissect_set_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

void
dlms_dissect_set_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_glo_set_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_glo_set_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_ded_set_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_ded_set_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);
