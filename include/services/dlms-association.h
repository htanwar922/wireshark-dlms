
#include "utils/headers.h"

void
dlms_dissect_conformance(tvbuff_t *tvb, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_context_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_mechanism_name(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_initiate_request(tvbuff_t *tvb, proto_tree *tree, gint offset, gint length);

// Himanshu
void
dlms_dissect_initiate_response(tvbuff_t *tvb, proto_tree *tree, gint offset, gint length);

// Himanshu
void
dlms_dissect_user_information(tvbuff_t *tvb, packet_info * pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_a_associate_aarq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu
void
dlms_dissect_a_associate_aare(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

void
dlms_dissect_aarq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

void
dlms_dissect_aare(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);
