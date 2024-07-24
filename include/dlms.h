// #include "utils/headers.h"

#ifdef __cplusplus
extern "C" {
#endif

void
dlms_register_protoinfo(void);

void
dlms_reg_handoff(void);

#ifdef __cplusplus
}
#endif

/* Dissect a DLMS Application Packet Data Unit (APDU) */
gboolean
dlms_dissect_apdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint offset);
