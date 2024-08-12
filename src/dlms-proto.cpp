
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
static int dlms_hfidx[sizeof (DLMSHeaderInfo) / sizeof (hf_register_info)]{ 0 };
static int i = 0;

/* The DLMS header_field_info (hfi) structures */
DLMSHeaderInfo dlms_hdr = // DLMSHeaderInfo dlms_hdr HFI_INIT(dlms_proto) =
{
    /* Null */
    { &dlms_hfidx[i++], "Null", "dlms.null", FT_NONE, BASE_NONE, 0, 0, 0, -1, 0, HF_REF_TYPE_NONE, -1, NULL },

    /* HDLC */
    { &dlms_hfidx[i++], "Flag", "dlms.hdlc.flag", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Type", "dlms.hdlc.type", FT_UINT16, BASE_DEC, 0, 0xf000, 0, HFILL },
    { &dlms_hfidx[i++], "Segmentation", "dlms.hdlc.segmentation", FT_UINT16, BASE_DEC, 0, 0x0800, 0, HFILL },
    { &dlms_hfidx[i++], "Length", "dlms.hdlc.length", FT_UINT16, BASE_DEC, 0, 0x07ff, 0, HFILL },
    { &dlms_hfidx[i++], "Upper HDLC Address", "dlms.hdlc.address", FT_UINT8, BASE_DEC, 0, 0xfe, 0, HFILL },
    { &dlms_hfidx[i++], "Frame", "dlms.hdlc.frame", FT_UINT8, BASE_DEC, dlms_hdlc_frame_names, 0x01, 0, HFILL },
    { &dlms_hfidx[i++], "Frame", "dlms.hdlc.frame", FT_UINT8, BASE_DEC, dlms_hdlc_frame_names, 0x0f, 0, HFILL },
    { &dlms_hfidx[i++], "Frame", "dlms.hdlc.frame", FT_UINT8, BASE_DEC, dlms_hdlc_frame_names, 0xef, 0, HFILL },
    { &dlms_hfidx[i++], "Poll/Final", "dlms.hdlc.pf", FT_UINT8, BASE_DEC, 0, 0x10, 0, HFILL },
    { &dlms_hfidx[i++], "Receive Sequence Number", "dlms.hdlc.rsn", FT_UINT8, BASE_DEC, 0, 0xe0, 0, HFILL },
    { &dlms_hfidx[i++], "Send Sequence Number", "dlms.hdlc.ssn", FT_UINT8, BASE_DEC, 0, 0x0e, 0, HFILL },
    { &dlms_hfidx[i++], "Header Check Sequence", "dlms.hdlc.hcs", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Frame Check Sequence", "dlms.hdlc.fcs", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Parameter", "dlms.hdlc.parameter", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "LLC Header", "dlms.hdlc.llc", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* IEC 4-32 LLC */
    { &dlms_hfidx[i++], "IEC 4-32 LLC Header", "dlms.iec432llc", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* Wrapper Protocol Data Unit (WPDU) */
    { &dlms_hfidx[i++], "Wrapper Header", "dlms.wrapper", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* APDU */
    { &dlms_hfidx[i++], "APDU", "dlms.apdu", FT_UINT8, BASE_DEC, dlms_apdu_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Client Max Receive PDU Size", "dlms.client_max_receive_pdu_size", FT_UINT16, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Server Max Receive PDU Size", "dlms.server_max_receive_pdu_size", FT_UINT16, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Get Request", "dlms.get_request", FT_UINT8, BASE_DEC, dlms_get_request_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Set Request", "dlms.set_request", FT_UINT8, BASE_DEC, dlms_set_request_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Action Request", "dlms.action_request", FT_UINT8, BASE_DEC, dlms_action_request_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Get Response", "dlms.get_response", FT_UINT8, BASE_DEC, dlms_get_response_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Set Response", "dlms.set_response", FT_UINT8, BASE_DEC, dlms_set_response_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Action Response", "dlms.action_response", FT_UINT8, BASE_DEC, dlms_action_response_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Access Request", "dlms.action_request", FT_UINT8, BASE_DEC, dlms_access_request_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Access Response", "dlms.action_response", FT_UINT8, BASE_DEC, dlms_access_response_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Class Id", "dlms.class_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Instance Id", "dlms.instance_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Attribute Id", "dlms.attribute_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Method Id", "dlms.method_id", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Access Selector", "dlms.access_selector", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Data Access Result", "dlms.data_access_result", FT_UINT8, BASE_DEC, dlms_data_access_result_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Action Result", "dlms.action_result", FT_UINT8, BASE_DEC, dlms_action_result_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Block Number", "dlms.block_number", FT_UINT32, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Last Block", "dlms.last_block", FT_BOOLEAN, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Type Description", "dlms.type_description", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Data", "dlms.data", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Date-Time", "dlms.date_time", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Length", "dlms.length", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "State Error", "dlms.state_error", FT_UINT8, BASE_DEC, dlms_state_error_names, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Service Error", "dlms.service_error", FT_UINT8, BASE_DEC, dlms_service_error_names, 0, 0, HFILL },

    /* Invoke-Id-And-Priority */
    { &dlms_hfidx[i++], "Invoke Id", "dlms.invoke_id", FT_UINT8, BASE_DEC, 0, 0x0f, 0, HFILL },
    { &dlms_hfidx[i++], "Service Class", "dlms.service_class", FT_UINT8, BASE_DEC, dlms_service_class_names, 0x40, 0, HFILL },
    { &dlms_hfidx[i++], "Priority", "dlms.priority", FT_UINT8, BASE_DEC, dlms_priority_names, 0x80, 0, HFILL },

    /* Long-Invoke-Id-And-Priority */
    { &dlms_hfidx[i++], "Long Invoke Id", "dlms.long_invoke_id", FT_UINT32, BASE_DEC, 0, 0xffffff, 0, HFILL },
    { &dlms_hfidx[i++], "Self Descriptive", "dlms.self_descriptive", FT_UINT32, BASE_DEC, dlms_self_descriptive_names, 0x10000000, 0, HFILL },
    { &dlms_hfidx[i++], "Processing Option", "dlms.processing_option", FT_UINT32, BASE_DEC, dlms_processing_option_names, 0x20000000, 0, HFILL },
    { &dlms_hfidx[i++], "Service Class", "dlms.service_class", FT_UINT32, BASE_DEC, dlms_service_class_names, 0x40000000, 0, HFILL },
    { &dlms_hfidx[i++], "Priority", "dlms.priority", FT_UINT32, BASE_DEC, dlms_priority_names, 0x80000000, 0, HFILL },

    /* Conformance bits */
    { &dlms_hfidx[i++], "general-protection", "dlms.conformance.general_protection", FT_UINT24, BASE_DEC, 0, 0x400000, 0, HFILL },
    { &dlms_hfidx[i++], "general-block-transfer", "dlms.conformance.general_block_transfer", FT_UINT24, BASE_DEC, 0, 0x200000, 0, HFILL },
    { &dlms_hfidx[i++], "read", "dlms.conformance.read", FT_UINT24, BASE_DEC, 0, 0x100000, 0, HFILL },
    { &dlms_hfidx[i++], "write", "dlms.conformance.write", FT_UINT24, BASE_DEC, 0, 0x080000, 0, HFILL },
    { &dlms_hfidx[i++], "unconfirmed-write", "dlms.conformance.unconfirmed_write", FT_UINT24, BASE_DEC, 0, 0x040000, 0, HFILL },
    { &dlms_hfidx[i++], "attribute0-supported-with-set", "dlms.conformance.attribute0_supported_with_set", FT_UINT24, BASE_DEC, 0, 0x008000, 0, HFILL },
    { &dlms_hfidx[i++], "priority-mgmt-supported", "dlms.conformance.priority_mgmt_supported", FT_UINT24, BASE_DEC, 0, 0x004000, 0, HFILL },
    { &dlms_hfidx[i++], "attribute0-supported-with-get", "dlms.conformance.attribute0_supported_with_get", FT_UINT24, BASE_DEC, 0, 0x002000, 0, HFILL },
    { &dlms_hfidx[i++], "block-transfer-with-get-or-read", "dlms.conformance.block_transfer_with_get_or_read", FT_UINT24, BASE_DEC, 0, 0x001000, 0, HFILL },
    { &dlms_hfidx[i++], "block-transfer-with-set-or-write", "dlms.conformance.block_transfer_with_set_or_write", FT_UINT24, BASE_DEC, 0, 0x000800, 0, HFILL },
    { &dlms_hfidx[i++], "block-transfer-with-action", "dlms.conformance.block_transfer_with_action", FT_UINT24, BASE_DEC, 0, 0x000400, 0, HFILL },
    { &dlms_hfidx[i++], "multiple-references", "dlms.conformance.multiple_references", FT_UINT24, BASE_DEC, 0, 0x000200, 0, HFILL },
    { &dlms_hfidx[i++], "information-report", "dlms.conformance.information_report", FT_UINT24, BASE_DEC, 0, 0x000100, 0, HFILL },
    { &dlms_hfidx[i++], "data-notification", "dlms.conformance.data_notification", FT_UINT24, BASE_DEC, 0, 0x000080, 0, HFILL },
    { &dlms_hfidx[i++], "access", "dlms.conformance.access", FT_UINT24, BASE_DEC, 0, 0x000040, 0, HFILL },
    { &dlms_hfidx[i++], "parameterized-access", "dlms.conformance.parameterized_access", FT_UINT24, BASE_DEC, 0, 0x000020, 0, HFILL },
    { &dlms_hfidx[i++], "get", "dlms.conformance.get", FT_UINT24, BASE_DEC, 0, 0x000010, 0, HFILL },
    { &dlms_hfidx[i++], "set", "dlms.conformance.set", FT_UINT24, BASE_DEC, 0, 0x000008, 0, HFILL },
    { &dlms_hfidx[i++], "selective-access", "dlms.conformance.selective_access", FT_UINT24, BASE_DEC, 0, 0x000004, 0, HFILL },
    { &dlms_hfidx[i++], "event-notification", "dlms.conformance.event_notification", FT_UINT24, BASE_DEC, 0, 0x000002, 0, HFILL },
    { &dlms_hfidx[i++], "action", "dlms.conformance.action", FT_UINT24, BASE_DEC, 0, 0x000001, 0, HFILL },

    /* fragment_items */
    { &dlms_hfidx[i++], "Fragments", "dlms.fragments", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Fragment", "dlms.fragment", FT_FRAMENUM, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Fragment Overlap", "dlms.fragment.overlap", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Fragment Conflict", "dlms.fragment.conflict", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Fragment Multiple", "dlms.fragment.multiple", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Fragment Too Long", "dlms.fragment.too_long", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Fragment Error", "dlms.fragment.error", FT_FRAMENUM, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Fragment Count", "dlms.fragment.count", FT_UINT32, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Reassembled In", "dlms.reassembled_in", FT_FRAMENUM, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Reassembled Length", "dlms.reassembled_length", FT_UINT32, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Reassembled Data", "dlms.reassembled_data", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },

    // Himanshu - AARQ/AARE
    { &dlms_hfidx[i++], "choice", "dlms.choice", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "context-value", "dlms.context_value", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "context-name", "dlms.context_name", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "protocol-version", "dlms.protocol_version", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "application-context-name", "dlms.application_context_name", FT_OID, BASE_NONE, 0, 0, 0, HFILL },

    // Himanshu - AARQ only
    { &dlms_hfidx[i++], "Called AP title", "dlms.called_ap_title", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Called AE qualifier", "dlms.called_ae_qualifier", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Called AP invocation-id", "dlms.called_ap_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Called AE invocation-id", "dlms.called_ae_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Calling AP title", "dlms.calling_ap_title", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Calling AE qualifier", "dlms.calling_ae_qualifier", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Calling AP invocation-id", "dlms.calling_ap_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Calling AE invocation-id", "dlms.calling_ae_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Authentication", "dlms.sender_acse_requirements_authentication", FT_UINT8, BASE_DEC, 0, 0x80, 0, HFILL },
    { &dlms_hfidx[i++], "CtoS", "dlms.calling_authentication_value", FT_BYTES, ENC_ASCII, 0, 0, 0, HFILL },

    // Himanshu - AARE only
    { &dlms_hfidx[i++], "Result", "dlms.result", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Result Source Diagnostic", "dlms.result_source_diagnostic", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "ACSE Service User", "dlms.result_source_diagnostic_acse_service_user", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "ACSE Service Provider", "dlms.result_source_diagnostic_acse_service_provider", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Responding AP Title", "dlms.responding_AP_title", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Responding AE Qualifier", "dlms.responding_AE_qualifier", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Responding AP Invocation_identifier", "dlms.responding_ap_invocation_id", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Responding AE Invocation_identifier", "dlms.responding_ae_invocation_id", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Authentication", "dlms.responder_acse_requirements_authentication", FT_UINT8, BASE_DEC, 0, 0x80, 0, HFILL },
    { &dlms_hfidx[i++], "StoC", "dlms.responding_authentication_value", FT_BYTES, ENC_ASCII, 0, 0, 0, HFILL },

    // Himanshu - AARQ/AARE
    { &dlms_hfidx[i++], "Mechanism Name", "dlms.mechanism_name", FT_OID, BASE_NONE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Implementation Information", "dlms.implementation_information", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "User Information", "dlms.user_information", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },

    // Himanshu - Initiate Request
    { &dlms_hfidx[i++], "Dedicated Key", "dlms.initiate_request_dedicated_key", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Response Allowed", "dlms.initiate_request_response_allowed", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Proposed QoS", "dlms.initiate_request_proposed_qos", FT_INT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Proposed DLMS version-no", "dlms.initiate_request_proposed_dlms_version_no", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },

    // Himanshu - Initiate Response
    { &dlms_hfidx[i++], "Response Negotiated QoS", "dlms.initiate_response_negotiated_qos", FT_INT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Response Negotiated DLMS version-no", "dlms.initiate_response_negotiated_dlms_version_no", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { &dlms_hfidx[i++], "Response VAA-Name Component", "dlms.initiate_response_vaa_name_component", FT_UINT16, BASE_HEX, 0, 0, 0, HFILL },

    // Himanshu - Initiate Request (Glo-Ciphered)
        // Security Header //
            // Security Control Byte //
    { &dlms_hfidx[i++], "Security Control Compression", "dlms.glo_initiate_request_security_control_compression", FT_UINT8, BASE_DEC, 0, 0x80, 0, HFILL },
    { &dlms_hfidx[i++], "Security Control Key Set", "dlms.glo_initiate_request_security_control_key_set", FT_UINT8, BASE_DEC, 0, 0x40, 0, HFILL },
    { &dlms_hfidx[i++], "Security Control Encryption", "dlms.glo_initiate_request_security_control_encryption", FT_UINT8, BASE_DEC, 0, 0x20, 0, HFILL },
    { &dlms_hfidx[i++], "Security Control Authentication", "dlms.glo_initiate_request_security_control_authentication", FT_UINT8, BASE_DEC, 0, 0x10, 0, HFILL },
    { &dlms_hfidx[i++], "Security Control Suite ID", "dlms.glo_initiate_request_security_control_suite_id", FT_UINT8, BASE_DEC, 0, 0x0f, 0, HFILL },
            // Initiator Nonce //
    { &dlms_hfidx[i++], "Invocation Counter", "dlms.glo_initiate_request_invocation_counter", FT_UINT32, BASE_HEX_DEC, 0, 0, 0, HFILL },
        // Information // May be Plaintext or Compressed text
    { &dlms_hfidx[i++], "Information", "dlms.glo_initiate_request_information", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
        // Ciphertext //
    { &dlms_hfidx[i++], "Ciphertext", "dlms.glo_initiate_request_ciphertext", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
        // Authentication Tag //
    { &dlms_hfidx[i++], "Authentication Tag", "dlms.glo_initiate_request_authentication_tag", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },

    // Himanshu - General APDUs
    { &dlms_hfidx[i++], "System Title", "dlms.general_glo_ciphered_system_title", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
};

/* Expert information (ei) fields */
static expert_field ef[sizeof (DLMSExpertInfo) / sizeof (ei_register_info)]{ 0 };
DLMSExpertInfo dlms_ei = // DLMSExpertInfo dlms_ei EI_INIT(dlms_proto) =
{
    { &ef[0], {"dlms.no_success", PI_RESPONSE_CODE, PI_NOTE, "No success response", EXPFILL} },
    { &ef[1], {"dlms.not_implemented", PI_UNDECODED, PI_WARN, "Not implemented in the DLMS dissector", EXPFILL} },
    { &ef[2], {"dlms.check_sequence", PI_CHECKSUM, PI_WARN, "Bad HDLC check sequence field value", EXPFILL} },
};
