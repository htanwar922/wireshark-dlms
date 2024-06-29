
#include "utils/headers.h"

void
dlms_dissect_cosem_attribute_or_method_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, int is_attribute);

void
dlms_dissect_cosem_attribute_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset);

void
dlms_dissect_cosem_method_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset);
