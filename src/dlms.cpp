
// #include "utils/headers.h"
#include "utils/dlms-defs.h"
// #include "utils/dlms-hdlc.h"
// #include "utils/dlms-bits.h"
// #include "utils/dlms-choices.h"
// #include "utils/dlms-enums.h"
// #include "utils/cosem-classes.h"
#include "utils/envfile.h"

// #include "obis.h"
// #include "debug.h"

#include "dlms-proto.h"

#include "data-types/dlms-utils.h"
#include "data-types/dlms-asn1.h"
#include "data-types/dlms-reassembly.h"
#include "data-types/dlms-bitsets.h"
#include "data-types/dlms-descriptors.h"
#include "data-types/dlms-data.h"
#include "data-types/dlms-data-ciphered.h"

#include "services/dlms-selective-access.h"
#include "services/dlms-association.h"
#include "services/dlms-get.h"
#include "services/dlms-set.h"
#include "services/dlms-action.h"
#include "services/dlms-access.h"
#include "services/dlms-notification.h"

void
dlms_dissect_exception_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_item *item;

    col_set_str(pinfo->cinfo, COL_INFO, "Exception-Response");
    item = proto_tree_add_item(tree, *dlms_hdr.state_error.p_id, tvb, offset, 1, ENC_NA);
    expert_add_info(pinfo, item, dlms_ei.no_success.ids);
    item = proto_tree_add_item(tree, *dlms_hdr.service_error.p_id, tvb, offset + 1, 1, ENC_NA);
    expert_add_info(pinfo, item, dlms_ei.no_success.ids);
}

/* Dissect a DLMS Application Packet Data Unit (APDU) */
gboolean
dlms_dissect_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    unsigned choice;

    proto_tree_add_item(tree, *dlms_hdr.apdu.p_id, tvb, offset, 1, ENC_NA);
    choice = tvb_get_guint8(tvb, offset);
    offset += 1;
    if (choice == DLMS_DATA_NOTIFICATION) {
        dlms_dissect_data_notification(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_AARQ) {
        dlms_dissect_aarq(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_AARE) {
        dlms_dissect_aare(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_RLRQ) {
        col_set_str(pinfo->cinfo, COL_INFO, "RLRQ");
    } else if (choice == DLMS_RLRE) {
        col_set_str(pinfo->cinfo, COL_INFO, "RLRE");
    } else if (choice == DLMS_GET_REQUEST) {
        dlms_dissect_get_request(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_SET_REQUEST) {
        dlms_dissect_set_request(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_EVENT_NOTIFICATION_REQUEST) {
        dlms_dissect_event_notification_request(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_ACTION_REQUEST) {
        dlms_dissect_action_request(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_GET_RESPONSE) {
        dlms_dissect_get_response(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_SET_RESPONSE) {
        dlms_dissect_set_response(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_ACTION_RESPONSE) {
        dlms_dissect_action_response(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_EXCEPTION_RESPONSE) {
        dlms_dissect_exception_response(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_ACCESS_REQUEST) {
        dlms_dissect_access_request(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_ACCESS_RESPONSE) {
        dlms_dissect_access_response(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_GLO_GET_REQUEST) {
        dlms_dissect_glo_get_request(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_GLO_SET_REQUEST) {
        dlms_dissect_glo_set_request(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_GLO_ACTION_REQUEST) {
        dlms_dissect_glo_action_request(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_GLO_GET_RESPONSE) {
        dlms_dissect_glo_get_response(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_GLO_SET_RESPONSE) {
        dlms_dissect_glo_set_response(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_GLO_ACTION_RESPONSE) {
        dlms_dissect_glo_action_response(tvb, pinfo, tree, offset);
    } else if (choice == DLMS_GENERAL_GLO_CIPHERING) {
        dlms_dissect_general_glo_ciphered_apdu(tvb, pinfo, tree, offset);
    } else if (choice == 0) {
        gint length = dlms_get_length(tvb, &offset);
        proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.glo_null, 0, "Null (Glo-Ciphered)");

        dlms_glo_ciphered_apdu apdu;
        dlms_dissect_glo_ciphered_apdu(tvb, subtree, offset, length, &apdu);

        {{
            tvbuff_t * tvb_plain = dlms_decrypt_glo_ciphered_apdu(&apdu, glo_KEY, client_system_title, glo_AAD, pinfo);
            subtree = proto_tree_add_subtree(tree, tvb_plain, 0, tvb_reported_length(tvb_plain), dlms_ett.null, 0, "Null (Decoded)");
            gboolean ret = dlms_dissect_apdu(tvb_plain, pinfo, subtree, 0);
            //tvb_free(tvb_plain);
            if (ret)
                return true;
        }}{{
            tvbuff_t * tvb_plain = dlms_decrypt_glo_ciphered_apdu(&apdu, glo_KEY, server_system_title, glo_AAD, pinfo);
            subtree = proto_tree_add_subtree(tree, tvb_plain, 0, tvb_reported_length(tvb_plain), dlms_ett.null, 0, "Null (Decoded)");
            gboolean ret = dlms_dissect_apdu(tvb_plain, pinfo, subtree, 0);
            //tvb_free(tvb_plain);
            if (ret)
                return true;
        }}

    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Unknown APDU");
        return false;
    }
    return true;
}

/* Dissect a check sequence field (HCS or FCS) of an HDLC frame */
void
dlms_dissect_hdlc_check_sequence(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length, hf_register_info *hfi)
{
    int i, j;
    unsigned cs;
    proto_item *item;

    cs = 0xffff;
    for (i = 0; i < length; i++) {
        cs = cs ^ tvb_get_guint8(tvb, offset + i);
        for (j = 0; j < 8; j++) {
            if (cs & 1) {
                cs = (cs >> 1) ^ 0x8408;
            } else {
                cs = cs >> 1;
            }
        }
    }
    cs = cs ^ 0xffff;

    item = proto_tree_add_item(tree, *hfi->p_id, tvb, offset + length, 2, ENC_NA);
    if (tvb_get_letohs(tvb, offset + length) != cs) {
        expert_add_info(pinfo, item, dlms_ei.check_sequence.ids);
    }
}

/* Dissect the information field of an HDLC (SNRM or UA) frame */
void
dlms_dissect_hdlc_information(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, 0, 0, dlms_ett.hdlc_information, 0, "Information");
    unsigned format = tvb_get_guint8(tvb, *offset);
    *offset += 1;
    if (format == 0x81) { /* format identifier */
        unsigned group = tvb_get_guint8(tvb, *offset);
        *offset += 1;
        if (group == 0x80) { /* group identifier */
            unsigned i, length = tvb_get_guint8(tvb, *offset);
            *offset += 1;
            for (i = 0; i < length; ) { /* parameters */
                proto_item *item;
                unsigned parameter = tvb_get_guint8(tvb, *offset);
                unsigned j, parameter_length = tvb_get_guint8(tvb, *offset + 1);
                unsigned value = 0;
                for (j = 0; j < parameter_length; j++) {
                    value = (value << 8) + tvb_get_guint8(tvb, *offset + 2 + j);
                }
                item = proto_tree_add_item(subtree, *dlms_hdr.hdlc_parameter.p_id, tvb, *offset, 2 + parameter_length, ENC_NA);
                proto_item_set_text(item, "%s: %u",
                    parameter == 5 ? "Maximum Information Field Length Transmit" :
                    parameter == 6 ? "Maximum Information Field Length Receive" :
                    parameter == 7 ? "Window Size Transmit" :
                    parameter == 8 ? "Window Size Receive" :
                    "Unknown Information Field Parameter",
                    value);
                i += 2 + parameter_length;
                *offset += 2 + parameter_length;
            }
        }
    }
}

/* Dissect a DLMS APDU in an HDLC frame */
void
dlms_dissect_hdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *subtree, *subsubtree;
    proto_item *item;
    fragment_head *frags;
    tvbuff_t *rtvb; /* reassembled tvb */
    unsigned length, segmentation, control;

    subtree = proto_tree_add_subtree(tree, tvb, 0, 0, dlms_ett.hdlc, 0, "HDLC");

    /* Opening flag */
    proto_tree_add_item(subtree, *dlms_hdr.hdlc_flag.p_id, tvb, 0, 1, ENC_NA);

    /* Frame format field */
    subsubtree = proto_tree_add_subtree(subtree, tvb, 1, 2, dlms_ett.hdlc_format, 0, "Frame Format");
    proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_type.p_id, tvb, 1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_segmentation.p_id, tvb, 1, 2, ENC_BIG_ENDIAN);
    segmentation = (tvb_get_ntohs(tvb, 1) >> 11) & 1;
    proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_length.p_id, tvb, 1, 2, ENC_BIG_ENDIAN);
    length = tvb_get_ntohs(tvb, 1) & 0x7ff; /* length of HDLC frame excluding the opening and closing flag fields */

    /* Destination address field */
    subsubtree = proto_tree_add_subtree(subtree, tvb, 3, 1, dlms_ett.hdlc_address, 0, "Destination Address");
    proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_address.p_id, tvb, 3, 1, ENC_NA);

    /* Source address field */
    subsubtree = proto_tree_add_subtree(subtree, tvb, 4, 1, dlms_ett.hdlc_address, 0, "Source Address");
    proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_address.p_id, tvb, 4, 1, ENC_NA);

    /* Control field */
    subsubtree = proto_tree_add_subtree(subtree, tvb, 5, 1, dlms_ett.hdlc_control, 0, "Control");
    control = tvb_get_guint8(tvb, 5);

    /* Header check sequence field */
    if (length > 7) {
        dlms_dissect_hdlc_check_sequence(tvb, pinfo, subtree, 1, 5, &dlms_hdr.hdlc_hcs);
    }

    /* Control sub-fields and information field */
    if ((control & 0x01) == 0x00) {
        col_add_str(pinfo->cinfo, COL_INFO, "HDLC I"); /* Information */
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_frame_i.p_id, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_pf.p_id, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_rsn.p_id, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_ssn.p_id, tvb, 5, 1, ENC_NA);

        subsubtree = proto_tree_add_subtree_format(subtree, tvb, 8, length - 9, dlms_ett.hdlc_information, 0, "Information Field (length %u)", length - 9);
        frags = fragment_add_seq_next(&dlms_reassembly_table, tvb, 8, pinfo, DLMS_REASSEMBLY_ID_HDLC, 0, length - 9, segmentation);
        rtvb = process_reassembled_data(tvb, 8, pinfo, "Reassembled", frags, &dlms_fragment_items, 0, tree);
        if (rtvb) {
            proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_llc.p_id, rtvb, 0, 3, ENC_NA);
            dlms_dissect_apdu(rtvb, pinfo, tree, 3);
        }
    } else if ((control & 0x0f) == 0x01) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC RR"); /* Receive Ready */
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_frame_rr_rnr.p_id, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_pf.p_id, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_rsn.p_id, tvb, 5, 1, ENC_NA);
    } else if ((control & 0x0f) == 0x05) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC RNR"); /* Receive Not Ready */
        item = proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_frame_rr_rnr.p_id, tvb, 5, 1, ENC_NA);
        expert_add_info(pinfo, item, dlms_ei.no_success.ids);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_pf.p_id, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_rsn.p_id, tvb, 5, 1, ENC_NA);
    } else if ((control & 0xef) == 0x83) { /* Set Normal Response Mode */
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC SNRM");
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_frame_other.p_id, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_pf.p_id, tvb, 5, 1, ENC_NA);
        if (length > 7) {
            gint offset = 8;
            dlms_dissect_hdlc_information(tvb, subtree, &offset);
        }
    } else if ((control & 0xef) == 0x43) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC DISC"); /* Disconnect */
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_frame_other.p_id, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_pf.p_id, tvb, 5, 1, ENC_NA);
    } else if ((control & 0xef) == 0x63) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC UA"); /* Unnumbered Acknowledge */
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_frame_other.p_id, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_pf.p_id, tvb, 5, 1, ENC_NA);
        if (length > 7) {
            gint offset = 8;
            dlms_dissect_hdlc_information(tvb, subtree, &offset);
        }
    } else if ((control & 0xef) == 0x0f) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC DM"); /* Disconnected Mode */
        item = proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_frame_other.p_id, tvb, 5, 1, ENC_NA);
        expert_add_info(pinfo, item, dlms_ei.no_success.ids);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_pf.p_id, tvb, 5, 1, ENC_NA);
    } else if ((control & 0xef) == 0x87) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC FRMR"); /* Frame Reject */
        item = proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_frame_other.p_id, tvb, 5, 1, ENC_NA);
        expert_add_info(pinfo, item, dlms_ei.no_success.ids);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_pf.p_id, tvb, 5, 1, ENC_NA);
    } else if ((control & 0xef) == 0x03) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC UI"); /* Unnumbered Information */
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_frame_other.p_id, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, *dlms_hdr.hdlc_pf.p_id, tvb, 5, 1, ENC_NA);
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Unknown HDLC frame");
    }

    /* Frame check sequence field */
    dlms_dissect_hdlc_check_sequence(tvb, pinfo, subtree, 1, length - 2, &dlms_hdr.hdlc_fcs);

    /* Closing flag */
    proto_tree_add_item(subtree, *dlms_hdr.hdlc_flag.p_id, tvb, length + 1, 1, ENC_NA);
}

/* Dissect a DLMS APDU in an IEC 61334-4-32 convergence layer data frame (PLC) */
void
dlms_dissect_432(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree_add_item(tree, *dlms_hdr.iec432llc.p_id, tvb, 0, 3, ENC_NA);
    dlms_dissect_apdu(tvb, pinfo, tree, 3);
}

/* Dissect a DLMS APDU in a Wrapper Protocol Data Unit (TCP/UDP/IP) */
void
dlms_dissect_wrapper(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree_add_item(tree, *dlms_hdr.wrapper_header.p_id, tvb, 0, 8, ENC_NA);
    dlms_dissect_apdu(tvb, pinfo, tree, 8);
}

int
dlms_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    // header_field_info *hfi;
    proto_item *item;
    proto_tree *subtree;
    unsigned first_byte;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DLMS");
    col_clear(pinfo->cinfo, COL_INFO);
    // hfi = proto_registrar_get_nth(dlms_proto);
    item = proto_tree_add_item(tree, dlms_proto, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(item, dlms_ett.dlms);

    first_byte = tvb_get_guint8(tvb, 0);
    if (first_byte == 0x7e) {
        dlms_dissect_hdlc(tvb, pinfo, subtree);
    } else if (first_byte == 0x90) {
        dlms_dissect_432(tvb, pinfo, subtree);
    } else if (first_byte == 0) {
        dlms_dissect_wrapper(tvb, pinfo, subtree);
    } else {
        dlms_dissect_apdu(tvb, pinfo, subtree, 0);
    }

    return tvb_captured_length(tvb);
}

#include "dlms.h"

#ifdef __cplusplus
extern "C" {
#endif

//#include "test.h"
//#include <stdio.h>
#include <direct.h>
//#include <stdlib.h>
void
dlms_register_protoinfo(void)
{
#ifdef __TEST_PLUGIN_H__
    register_foo();
    return;
#endif
    dlms_proto = proto_register_protocol("Device Language Message Specification", "DLMS", "dlms");

    /* Register the dlms_hdr header field info structures */
    proto_register_field_array(dlms_proto, (hf_register_info *)&dlms_hdr, sizeof(DLMSHeaderInfo) / sizeof(hf_register_info));

    /* Initialise and register the dlms_ett protocol subtree indices */
    {
        gint *ett[sizeof(dlms_ett) / sizeof(gint)];
        unsigned i;
        for (i = 0; i < array_length(ett); i++) {
            ett[i] = (gint *)&dlms_ett + i;
            *ett[i] = -1;
        }
        proto_register_subtree_array(ett, array_length(ett));
    }

    /* Register the dlms_ei expert info fields */
    {
        expert_module_t *em = expert_register_protocol(dlms_proto);
        expert_register_field_array(em, (ei_register_info *)&dlms_ei, sizeof (DLMSExpertInfo) / sizeof (ei_register_info));
    }

    /* Register the reassembly table */
    {
        const reassembly_table_functions f = {
            dlms_reassembly_hash_func,
            dlms_reassembly_equal_func,
            dlms_reassembly_key_func,
            dlms_reassembly_key_func,
            dlms_reassembly_free_key_func,
            dlms_reassembly_free_key_func,
        };
        reassembly_table_init(&dlms_reassembly_table, &f);
    }

    std::string envFilePath = getenv("env:WIRESHARK_DLMS_CONFIG_FILE") ? getenv("env:WIRESHARK_DLMS_CONFIG_FILE") : "";
    envFilePath = not envFilePath.empty() ? envFilePath : getenv("WIRESHARK_DLMS_CONFIG_FILE") ? getenv("WIRESHARK_DLMS_CONFIG_FILE") : "";
    envFilePath = not envFilePath.empty() ? envFilePath : std::string(g_path_get_dirname(__FILE__)) + "/../config/config.env";
    if (not envFilePath.empty()) {
        std::map<std::string, std::string> envVariables = readEnvFile(envFilePath);
        if (envVariables.find("DLMS_GLO_KEY") != envVariables.end()) {
            hex_to_uint8(envVariables["DLMS_GLO_KEY"].c_str(), glo_KEY, 16);
        }
        if (envVariables.find("DLMS_AAD_KEY") != envVariables.end()) {
            hex_to_uint8(envVariables["DLMS_AAD_KEY"].c_str(), glo_KEY, 16);
        }
    }
}

void
dlms_reg_handoff(void)
{
#ifdef __TEST_PLUGIN_H__
    handoff_foo();
    return;
#endif
    /* Register the DLMS dissector and the TCP/UDP port assigned by IANA for DLMS */
    dissector_handle_t dh = register_dissector("DLMS", dlms_dissect, dlms_proto);
    //dissector_handle_t dh = create_dissector_handle(dlms_dissect, dlms_proto);
    dissector_add_uint("udp.port", 4059, dh);
    dissector_add_uint("tcp.port", 4059, dh);
    for (int i = 4060; i <= 4069; i++) {
        dissector_add_uint("udp.port", i, dh);
        dissector_add_uint("tcp.port", i, dh);
    }
}

#ifdef __cplusplus
}
#endif
