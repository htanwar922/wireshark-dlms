
// #include "utils/headers.h"

proto_item *
dlms_dissect_compact_array_content(tvbuff_t *tvb, proto_tree *tree, gint description_offset, gint *content_offset);

proto_item *
dlms_dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset);

void
dlms_dissect_list_of_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, const char *name);

void
dlms_dissect_datablock_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *subtree, gint *offset, unsigned block_number, unsigned last_block);

void
dlms_dissect_datablock_g(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset);

void
dlms_dissect_datablock_sa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset);

void
dlms_dissect_data_access_result(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset);
