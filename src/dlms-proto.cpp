
#include "utils/dlms-defs.h"
#include "utils/dlms-hdlc.h"
#include "utils/dlms-bits.h"
#include "utils/dlms-choices.h"
#include "utils/dlms-enums.h"

#include "dlms-proto.h"

/* The DLMS protocol handle */
int dlms_proto;

/* Protocol subtree (ett) indices */
DLMSSubtree dlms_ett;

/* Indexes for the DLMS header_field_info (hfi) structures */
static int dlms_hfidx[sizeof DLMSHeaderInfo / sizeof hf_register_info]{ 0 };

/* The DLMS header_field_info (hfi) structures */
DLMSHeaderInfo dlms_hdr = // DLMSHeaderInfo dlms_hdr HFI_INIT(dlms_proto) =
{
    /* 0: Null */
    { &dlms_hfidx[0], "Null", "dlms.null", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* 1: HDLC */
    { &dlms_hfidx[1], "Flag", "dlms.hdlc.flag", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[2], "Type", "dlms.hdlc.type", FT_UINT16, BASE_DEC, 0, 0xf000, 0, HFILL },
    { &dlms_hfidx[3], "Segmentation", "dlms.hdlc.segmentation", FT_UINT16, BASE_DEC, 0, 0x0800, 0, HFILL },
    { &dlms_hfidx[4], "Length", "dlms.hdlc.length", FT_UINT16, BASE_DEC, 0, 0x07ff, 0, HFILL },
    { &dlms_hfidx[5], "Upper HDLC Address", "dlms.hdlc.address", FT_UINT8, BASE_DEC, 0, 0xfe, 0, HFILL },
    { &dlms_hfidx[6], "Frame", "dlms.hdlc.frame", FT_UINT8, BASE_DEC, dlms_hdlc_frame_names, 0x01, 0, HFILL },
    { &dlms_hfidx[7], "Frame", "dlms.hdlc.frame", FT_UINT8, BASE_DEC, dlms_hdlc_frame_names, 0x0f, 0, HFILL },
    { &dlms_hfidx[8], "Frame", "dlms.hdlc.frame", FT_UINT8, BASE_DEC, dlms_hdlc_frame_names, 0xef, 0, HFILL },
    { &dlms_hfidx[9], "Poll/Final", "dlms.hdlc.pf", FT_UINT8, BASE_DEC, 0, 0x10, 0, HFILL },
    { &dlms_hfidx[10], "Receive Sequence Number", "dlms.hdlc.rsn", FT_UINT8, BASE_DEC, 0, 0xe0, 0, HFILL },
    { &dlms_hfidx[11], "Send Sequence Number", "dlms.hdlc.ssn", FT_UINT8, BASE_DEC, 0, 0x0e, 0, HFILL },
    { &dlms_hfidx[12], "Header Check Sequence", "dlms.hdlc.hcs", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[13], "Frame Check Sequence", "dlms.hdlc.fcs", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[14], "Parameter", "dlms.hdlc.parameter", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[15], "LLC Header", "dlms.hdlc.llc", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* 16: IEC 4-32 LLC */
    { &dlms_hfidx[16], "IEC 4-32 LLC Header", "dlms.iec432llc", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* 17: Wrapper Protocol Data Unit (WPDU) */
    { &dlms_hfidx[17], "Wrapper Header", "dlms.wrapper", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* 18: APDU */
    { &dlms_hfidx[18], "APDU", "dlms.apdu", FT_UINT8, BASE_DEC, dlms_apdu_names, 0, 0, HFILL },
    { &dlms_hfidx[19], "Client Max Receive PDU Size", "dlms.client_max_receive_pdu_size", FT_UINT16, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[20], "Server Max Receive PDU Size", "dlms.server_max_receive_pdu_size", FT_UINT16, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[21], "Get Request", "dlms.get_request", FT_UINT8, BASE_DEC, dlms_get_request_names, 0, 0, HFILL },
    { &dlms_hfidx[22], "Set Request", "dlms.set_request", FT_UINT8, BASE_DEC, dlms_set_request_names, 0, 0, HFILL },
    { &dlms_hfidx[23], "Action Request", "dlms.action_request", FT_UINT8, BASE_DEC, dlms_action_request_names, 0, 0, HFILL },
    { &dlms_hfidx[24], "Get Response", "dlms.get_response", FT_UINT8, BASE_DEC, dlms_get_response_names, 0, 0, HFILL },
    { &dlms_hfidx[25], "Set Response", "dlms.set_response", FT_UINT8, BASE_DEC, dlms_set_response_names, 0, 0, HFILL },
    { &dlms_hfidx[26], "Action Response", "dlms.action_response", FT_UINT8, BASE_DEC, dlms_action_response_names, 0, 0, HFILL },
    { &dlms_hfidx[27], "Access Request", "dlms.action_request", FT_UINT8, BASE_DEC, dlms_access_request_names, 0, 0, HFILL },
    { &dlms_hfidx[28], "Access Response", "dlms.action_response", FT_UINT8, BASE_DEC, dlms_access_response_names, 0, 0, HFILL },
    { &dlms_hfidx[29], "Class Id", "dlms.class_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[30], "Instance Id", "dlms.instance_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[31], "Attribute Id", "dlms.attribute_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[32], "Method Id", "dlms.method_id", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[33], "Access Selector", "dlms.access_selector", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[34], "Data Access Result", "dlms.data_access_result", FT_UINT8, BASE_DEC, dlms_data_access_result_names, 0, 0, HFILL },
    { &dlms_hfidx[35], "Action Result", "dlms.action_result", FT_UINT8, BASE_DEC, dlms_action_result_names, 0, 0, HFILL },
    { &dlms_hfidx[36], "Block Number", "dlms.block_number", FT_UINT32, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[37], "Last Block", "dlms.last_block", FT_BOOLEAN, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[38], "Type Description", "dlms.type_description", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[39], "Data", "dlms.data", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[40], "Date-Time", "dlms.date_time", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[41], "Length", "dlms.length", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[42], "State Error", "dlms.state_error", FT_UINT8, BASE_DEC, dlms_state_error_names, 0, 0, HFILL },
    { &dlms_hfidx[43], "Service Error", "dlms.service_error", FT_UINT8, BASE_DEC, dlms_service_error_names, 0, 0, HFILL },

    /* 44: Invoke-Id-And-Priority */
    { &dlms_hfidx[44], "Invoke Id", "dlms.invoke_id", FT_UINT8, BASE_DEC, 0, 0x0f, 0, HFILL },
    { &dlms_hfidx[45], "Service Class", "dlms.service_class", FT_UINT8, BASE_DEC, dlms_service_class_names, 0x40, 0, HFILL },
    { &dlms_hfidx[46], "Priority", "dlms.priority", FT_UINT8, BASE_DEC, dlms_priority_names, 0x80, 0, HFILL },

    /* 47: Long-Invoke-Id-And-Priority */
    { &dlms_hfidx[47], "Long Invoke Id", "dlms.long_invoke_id", FT_UINT32, BASE_DEC, 0, 0xffffff, 0, HFILL },
    { &dlms_hfidx[48], "Self Descriptive", "dlms.self_descriptive", FT_UINT32, BASE_DEC, dlms_self_descriptive_names, 0x10000000, 0, HFILL },
    { &dlms_hfidx[49], "Processing Option", "dlms.processing_option", FT_UINT32, BASE_DEC, dlms_processing_option_names, 0x20000000, 0, HFILL },
    { &dlms_hfidx[50], "Service Class", "dlms.service_class", FT_UINT32, BASE_DEC, dlms_service_class_names, 0x40000000, 0, HFILL },
    { &dlms_hfidx[51], "Priority", "dlms.priority", FT_UINT32, BASE_DEC, dlms_priority_names, 0x80000000, 0, HFILL },

    /* 52: Conformance bits */
    { &dlms_hfidx[52], "general-protection", "dlms.conformance.general_protection", FT_UINT24, BASE_DEC, 0, 0x400000, 0, HFILL },
    { &dlms_hfidx[53], "general-block-transfer", "dlms.conformance.general_block_transfer", FT_UINT24, BASE_DEC, 0, 0x200000, 0, HFILL },
    { &dlms_hfidx[54], "read", "dlms.conformance.read", FT_UINT24, BASE_DEC, 0, 0x100000, 0, HFILL },
    { &dlms_hfidx[55], "write", "dlms.conformance.write", FT_UINT24, BASE_DEC, 0, 0x080000, 0, HFILL },
    { &dlms_hfidx[56], "unconfirmed-write", "dlms.conformance.unconfirmed_write", FT_UINT24, BASE_DEC, 0, 0x040000, 0, HFILL },
    { &dlms_hfidx[57], "attribute0-supported-with-set", "dlms.conformance.attribute0_supported_with_set", FT_UINT24, BASE_DEC, 0, 0x008000, 0, HFILL },
    { &dlms_hfidx[58], "priority-mgmt-supported", "dlms.conformance.priority_mgmt_supported", FT_UINT24, BASE_DEC, 0, 0x004000, 0, HFILL },
    { &dlms_hfidx[59], "attribute0-supported-with-get", "dlms.conformance.attribute0_supported_with_get", FT_UINT24, BASE_DEC, 0, 0x002000, 0, HFILL },
    { &dlms_hfidx[60], "block-transfer-with-get-or-read", "dlms.conformance.block_transfer_with_get_or_read", FT_UINT24, BASE_DEC, 0, 0x001000, 0, HFILL },
    { &dlms_hfidx[61], "block-transfer-with-set-or-write", "dlms.conformance.block_transfer_with_set_or_write", FT_UINT24, BASE_DEC, 0, 0x000800, 0, HFILL },
    { &dlms_hfidx[62], "block-transfer-with-action", "dlms.conformance.block_transfer_with_action", FT_UINT24, BASE_DEC, 0, 0x000400, 0, HFILL },
    { &dlms_hfidx[63], "multiple-references", "dlms.conformance.multiple_references", FT_UINT24, BASE_DEC, 0, 0x000200, 0, HFILL },
    { &dlms_hfidx[64], "information-report", "dlms.conformance.information_report", FT_UINT24, BASE_DEC, 0, 0x000100, 0, HFILL },
    { &dlms_hfidx[65], "data-notification", "dlms.conformance.data_notification", FT_UINT24, BASE_DEC, 0, 0x000080, 0, HFILL },
    { &dlms_hfidx[66], "access", "dlms.conformance.access", FT_UINT24, BASE_DEC, 0, 0x000040, 0, HFILL },
    { &dlms_hfidx[67], "parameterized-access", "dlms.conformance.parameterized_access", FT_UINT24, BASE_DEC, 0, 0x000020, 0, HFILL },
    { &dlms_hfidx[68], "get", "dlms.conformance.get", FT_UINT24, BASE_DEC, 0, 0x000010, 0, HFILL },
    { &dlms_hfidx[69], "set", "dlms.conformance.set", FT_UINT24, BASE_DEC, 0, 0x000008, 0, HFILL },
    { &dlms_hfidx[70], "selective-access", "dlms.conformance.selective_access", FT_UINT24, BASE_DEC, 0, 0x000004, 0, HFILL },
    { &dlms_hfidx[71], "event-notification", "dlms.conformance.event_notification", FT_UINT24, BASE_DEC, 0, 0x000002, 0, HFILL },
    { &dlms_hfidx[72], "action", "dlms.conformance.action", FT_UINT24, BASE_DEC, 0, 0x000001, 0, HFILL },

    /* 73: fragment_items */
    { &dlms_hfidx[73], "Fragments", "dlms.fragments", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[74], "Fragment", "dlms.fragment", FT_FRAMENUM, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[75], "Fragment Overlap", "dlms.fragment.overlap", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { &dlms_hfidx[76], "Fragment Conflict", "dlms.fragment.conflict", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { &dlms_hfidx[77], "Fragment Multiple", "dlms.fragment.multiple", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { &dlms_hfidx[78], "Fragment Too Long", "dlms.fragment.too_long", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { &dlms_hfidx[79], "Fragment Error", "dlms.fragment.error", FT_FRAMENUM, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[80], "Fragment Count", "dlms.fragment.count", FT_UINT32, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[81], "Reassembled In", "dlms.reassembled_in", FT_FRAMENUM, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[82], "Reassembled Length", "dlms.reassembled_length", FT_UINT32, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[83], "Reassembled Data", "dlms.reassembled_data", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },

    // 84: Himanshu - AARQ/AARE
    { &dlms_hfidx[84], "choice", "dlms.choice", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[85], "context-value", "dlms.context_value", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[86], "context-name", "dlms.context_name", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[87], "protocol-version", "dlms.protocol_version", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[88], "application-context-name", "dlms.application_context_name", FT_OID, BASE_NONE, 0, 0, 0, HFILL },

    // 89: Himanshu - AARQ only
    { &dlms_hfidx[89], "Called AP title", "dlms.called_ap_title", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[90], "Called AE qualifier", "dlms.called_ae_qualifier", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[91], "Called AP invocation-id", "dlms.called_ap_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[92], "Called AE invocation-id", "dlms.called_ae_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[93], "Calling AP title", "dlms.calling_ap_title", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[94], "Calling AE qualifier", "dlms.calling_ae_qualifier", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[95], "Calling AP invocation-id", "dlms.calling_ap_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[96], "Calling AE invocation-id", "dlms.calling_ae_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[97], "Authentication", "dlms.sender_acse_requirements_authentication", FT_UINT8, BASE_DEC, 0, 0x80, 0, HFILL },
    { &dlms_hfidx[98], "Mechanism Name", "dlms.mechanism_name", FT_OID, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[99], "Calling Authentication Value", "dlms.calling_authentication_value", FT_STRING, ENC_ASCII, 0, 0, 0, HFILL },

    // 100: Himanshu - AARE only
    { &dlms_hfidx[100], "Result", "dlms.result", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[101], "Result Source Diagnostic", "dlms.result_source_diagnostic", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[102], "ACSE Service User", "dlms.result_source_diagnostic_acse_service_user", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[103], "ACSE Service Provider", "dlms.result_source_diagnostic_acse_service_provider", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[104], "Responding AP Title", "dlms.responding_AP_title", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[105], "Responding AE Qualifier", "dlms.responding_AE_qualifier", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[106], "Responding AP Invocation_identifier", "dlms.responding_ap_invocation_id", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[107], "Responding AE Invocation_identifier", "dlms.responding_ae_invocation_id", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },

    // 108: Himanshu - AARQ/AARE
    { &dlms_hfidx[108], "Implementation Information", "dlms.implementation_information", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[109], "User Information", "dlms.user_information", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },

    // 110: Himanshu - Initiate Request
    { &dlms_hfidx[110], "Dedicated Key", "dlms.initiate_request_dedicated_key", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[111], "Response Allowed", "dlms.initiate_request_response_allowed", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { &dlms_hfidx[112], "Proposed QoS", "dlms.initiate_request_proposed_qos", FT_INT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[113], "Proposed DLMS version-no", "dlms.initiate_request_proposed_dlms_version_no", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },

    // 114: Himanshu - Initiate Response
    { &dlms_hfidx[114], "Response Negotiated QoS", "dlms.initiate_response_negotiated_qos", FT_INT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[115], "Response Negotiated DLMS version-no", "dlms.initiate_response_negotiated_dlms_version_no", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[116], "Response VAA-Name Component", "dlms.initiate_response_vaa_name_component", FT_UINT16, BASE_HEX, 0, 0, 0, HFILL },

    // Himanshu - Initiate Request (Glo-Ciphered)
        // 117: Security Header //
            // Security Control Byte //
    { &dlms_hfidx[117], "Security Control Compression", "dlms.glo_initiate_request_security_control_compression", FT_UINT8, BASE_DEC, 0, 0x80, 0, HFILL },
    { &dlms_hfidx[118], "Security Control Key Set", "dlms.glo_initiate_request_security_control_key_set", FT_UINT8, BASE_DEC, 0, 0x40, 0, HFILL },
    { &dlms_hfidx[119], "Security Control Encryption", "dlms.glo_initiate_request_security_control_encryption", FT_UINT8, BASE_DEC, 0, 0x20, 0, HFILL },
    { &dlms_hfidx[120], "Security Control Authentication", "dlms.glo_initiate_request_security_control_authentication", FT_UINT8, BASE_DEC, 0, 0x10, 0, HFILL },
    { &dlms_hfidx[121], "Security Control Suite ID", "dlms.glo_initiate_request_security_control_suite_id", FT_UINT8, BASE_DEC, 0, 0x0f, 0, HFILL },
            // Initiator Nonce //
    { &dlms_hfidx[122], "Invocation Counter", "dlms.glo_initiate_request_invocation_counter", FT_UINT32, BASE_HEX_DEC, 0, 0, 0, HFILL },
        // 123: Information // May be Plaintext or Compressed text
    { &dlms_hfidx[123], "Information", "dlms.glo_initiate_request_information", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
        // 124: Ciphertext //
    { &dlms_hfidx[124], "Ciphertext", "dlms.glo_initiate_request_ciphertext", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
        // 125: Authentication Tag //
    { &dlms_hfidx[125], "Authentication Tag", "dlms.glo_initiate_request_authentication_tag", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
};

/* Expert information (ei) fields */
static expert_field ef[sizeof DLMSExpertInfo / sizeof ei_register_info]{ 0 };
DLMSExpertInfo dlms_ei = // DLMSExpertInfo dlms_ei EI_INIT(dlms_proto) =
{
    { &ef[0], {"dlms.no_success", PI_RESPONSE_CODE, PI_NOTE, "No success response", EXPFILL} },
    { &ef[1], {"dlms.not_implemented", PI_UNDECODED, PI_WARN, "Not implemented in the DLMS dissector", EXPFILL} },
    { &ef[2], {"dlms.check_sequence", PI_CHECKSUM, PI_WARN, "Bad HDLC check sequence field value", EXPFILL} },
};
