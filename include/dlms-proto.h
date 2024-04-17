
#include "utils/headers.h"

/* The DLMS protocol handle */
static int dlms_proto;

/* Protocol subtree (ett) indices */
static struct {
    gint dlms;
    gint hdlc;
    gint hdlc_format;
    gint hdlc_address;
    gint hdlc_control;
    gint hdlc_information;
    gint invoke_id_and_priority;
    gint access_request_specification;
    gint access_request_type;
    gint access_response_specification;
    gint cosem_attribute_or_method_descriptor;
    gint selective_access_descriptor;
    gint composite_data;
    gint datablock;
    gint data;

    /* fragment_items */
    gint fragment;
    gint fragments;

    // Himanshu - AARQ/AARE
    gint protocol_version;
    gint application_context_name;

    // Himanshu - AARQ only
    gint called_ap_title;
    gint called_ae_qualifier;
    gint called_ap_invocation_id;
    gint called_ae_invocation_id;
    gint calling_ap_title;
    gint calling_ae_qualifier;
    gint calling_ap_invocation_id;
    gint calling_ae_invocation_id;
    gint sender_acse_requirements;
    gint mechanism_name;
    gint calling_authentication_value;

    // Himanshu - AARE only
    gint association_result;
    gint result_source_diagnostic;
    gint result_source_diagnostic_acse_service_user;
    gint result_source_diagnostic_acse_service_provider;
    gint responding_ap_title;
    gint responding_ae_qualifier;
    gint responding_ap_invocation_id;
    gint responding_ae_invocation_id;

    // Himanshu - AARQ/AARE
    gint implementation_information;
    gint user_information;

    // Himanshu - Requests
    gint initiate_request;
    gint get_request;
    gint access_request;

    // Himanshu - Responses
    gint initiate_response;
    gint get_response;
    gint access_response;

    gint conformance; /* InitiateRequest proposed-conformance and InitiateResponse negotiated-confirmance */

    // Himanshu - Requests (Glo-Ciphered)
    gint glo_initiate_request;
    gint glo_get_request;
    gint glo_set_request;
    gint glo_action_request;

    // Himanshu - Responses (Glo-Ciphered)
    gint glo_initiate_response;
    gint glo_get_response;
    gint glo_set_response;
    gint glo_action_response;

    // Himanshu - Glo-Ciphered APDU
    gint glo_security_header;
    gint glo_security_control_byte;

    // Himanshu
    gint null;
    gint glo_null;
} dlms_ett;

/* Expert information (ei) fields */
static struct {
    expert_field no_success;
    expert_field not_implemented;
    expert_field check_sequence; /* bad HDLC check sequence (HCS or FCS) value */
} dlms_ei;

/* The DLMS header_field_info (hfi) structures */
static struct
{
    /* Null */
    header_field_info null;

    /* HDLC */
    header_field_info hdlc_flag; /* opening/closing flag */
    header_field_info hdlc_type; /* frame format type */
    header_field_info hdlc_segmentation; /* frame format segmentation bit */
    header_field_info hdlc_length; /* frame format length sub-field */
    header_field_info hdlc_address; /* destination/source address */
    header_field_info hdlc_frame_i; /* control field & 0x01 (I) */
    header_field_info hdlc_frame_rr_rnr; /* control field & 0x0f (RR or RNR) */
    header_field_info hdlc_frame_other; /* control field & 0xef (all other) */
    header_field_info hdlc_pf; /* poll/final bit */
    header_field_info hdlc_rsn; /* receive sequence number N(R) */
    header_field_info hdlc_ssn; /* send sequence number N(S) */
    header_field_info hdlc_hcs; /* header check sequence */
    header_field_info hdlc_fcs; /* frame check sequence */
    header_field_info hdlc_parameter; /* information field parameter */
    header_field_info hdlc_llc; /* LLC header */

    /* IEC 4-32 LLC */
    header_field_info iec432llc;

    /* Wrapper Protocol Data Unit (WPDU) */
    header_field_info wrapper_header;

    /* APDU */
    header_field_info apdu;
    header_field_info client_max_receive_pdu_size;
    header_field_info server_max_receive_pdu_size;
    header_field_info get_request;
    header_field_info set_request;
    header_field_info action_request;
    header_field_info get_response;
    header_field_info set_response;
    header_field_info action_response;
    header_field_info access_request;
    header_field_info access_response;
    header_field_info class_id;
    header_field_info instance_id;
    header_field_info attribute_id;
    header_field_info method_id;
    header_field_info access_selector;
    header_field_info data_access_result;
    header_field_info action_result;
    header_field_info block_number;
    header_field_info last_block;
    header_field_info type_description;
    header_field_info data;
    header_field_info date_time;
    header_field_info length;
    header_field_info state_error;
    header_field_info service_error;

    /* Invoke-Id-And-Priority */
    header_field_info invoke_id;
    header_field_info service_class;
    header_field_info priority;

    /* Long-Invoke-Id-And-Priority */
    header_field_info long_invoke_id;
    header_field_info long_self_descriptive;
    header_field_info long_processing_option;
    header_field_info long_service_class;
    header_field_info long_priority;

    /* Conformance bits */
    header_field_info conformance_general_protection;
    header_field_info conformance_general_block_transfer;
    header_field_info conformance_read;
    header_field_info conformance_write;
    header_field_info conformance_unconfirmed_write;
    header_field_info conformance_attribute0_supported_with_set;
    header_field_info conformance_priority_mgmt_supported;
    header_field_info conformance_attribute0_supported_with_get;
    header_field_info conformance_block_transfer_with_get_or_read;
    header_field_info conformance_block_transfer_with_set_or_write;
    header_field_info conformance_block_transfer_with_action;
    header_field_info conformance_multiple_references;
    header_field_info conformance_information_report;
    header_field_info conformance_data_notification;
    header_field_info conformance_access;
    header_field_info conformance_parameterized_access;
    header_field_info conformance_get;
    header_field_info conformance_set;
    header_field_info conformance_selective_access;
    header_field_info conformance_event_notification;
    header_field_info conformance_action;

    /* fragment_items */
    header_field_info fragments;
    header_field_info fragment;
    header_field_info fragment_overlap;
    header_field_info fragment_overlap_conflict;
    header_field_info fragment_multiple_tails;
    header_field_info fragment_too_long_fragment;
    header_field_info fragment_error;
    header_field_info fragment_count;
    header_field_info reassembled_in;
    header_field_info reassembled_length;
    header_field_info reassembled_data;

    // Himanshu - AARQ/AARE
    header_field_info choice;
    header_field_info context_value;
    header_field_info context_name;
    header_field_info protocol_version;
    header_field_info application_context_name;

    // Himanshu - AARQ only
    header_field_info called_ap_title;
    header_field_info called_ae_qualifier;
    header_field_info called_ap_invocation_id;
    header_field_info called_ae_invocation_id;
    header_field_info calling_ap_title;
    header_field_info calling_ae_qualifier;
    header_field_info calling_ap_invocation_id;
    header_field_info calling_ae_invocation_id;
    header_field_info sender_acse_requirements_authentication;
    header_field_info mechanism_name;
    header_field_info calling_authentication_value;

    // Himanshu - AARE only
    header_field_info association_result;
    header_field_info result_source_diagnostic;
    header_field_info result_source_diagnostic_acse_service_user;
    header_field_info result_source_diagnostic_acse_service_provider;
    header_field_info responding_ap_title;
    header_field_info responding_ae_qualifier;
    header_field_info responding_ap_invocation_id;
    header_field_info responding_ae_invocation_id;

    // Himanshu - AARQ/AARE
    header_field_info implementation_information;
    header_field_info user_information;

    // Himanshu - Initiate Request
    header_field_info initiate_request_dedicated_key;
    header_field_info initiate_request_response_allowed;
    header_field_info initiate_request_proposed_qos;
    header_field_info initiate_request_proposed_dlms_version_no;

    // Himanshu - Initiate Response
    header_field_info initiate_response_negotiated_qos;
    header_field_info initiate_response_negotiated_dlms_version_no;
    header_field_info initiate_response_vaa_name_component;

    // Himanshu - Glo-Ciphered APDU
        // Security Header //
            // Security Control Byte //
    header_field_info glo_security_control_compression;
    header_field_info glo_security_control_key_set;
    header_field_info glo_security_control_encryption;
    header_field_info glo_security_control_authentication;
    header_field_info glo_security_control_suite_id;
            // Initiator Nonce //
    header_field_info glo_invocation_counter;
        // Information // May be Plaintext or Compressed text
    header_field_info glo_information;
        // Ciphertext //
    header_field_info glo_ciphertext;
        // Authentication Tag //
    header_field_info glo_authentication_tag;
}
dlms_hfi HFI_INIT(dlms_proto) =
{
    /* Null */
    { "Null", "dlms.null", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* HDLC */
    { "Flag", "dlms.hdlc.flag", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Type", "dlms.hdlc.type", FT_UINT16, BASE_DEC, 0, 0xf000, 0, HFILL },
    { "Segmentation", "dlms.hdlc.segmentation", FT_UINT16, BASE_DEC, 0, 0x0800, 0, HFILL },
    { "Length", "dlms.hdlc.length", FT_UINT16, BASE_DEC, 0, 0x07ff, 0, HFILL },
    { "Upper HDLC Address", "dlms.hdlc.address", FT_UINT8, BASE_DEC, 0, 0xfe, 0, HFILL },
    { "Frame", "dlms.hdlc.frame", FT_UINT8, BASE_DEC, dlms_hdlc_frame_names, 0x01, 0, HFILL },
    { "Frame", "dlms.hdlc.frame", FT_UINT8, BASE_DEC, dlms_hdlc_frame_names, 0x0f, 0, HFILL },
    { "Frame", "dlms.hdlc.frame", FT_UINT8, BASE_DEC, dlms_hdlc_frame_names, 0xef, 0, HFILL },
    { "Poll/Final", "dlms.hdlc.pf", FT_UINT8, BASE_DEC, 0, 0x10, 0, HFILL },
    { "Receive Sequence Number", "dlms.hdlc.rsn", FT_UINT8, BASE_DEC, 0, 0xe0, 0, HFILL },
    { "Send Sequence Number", "dlms.hdlc.ssn", FT_UINT8, BASE_DEC, 0, 0x0e, 0, HFILL },
    { "Header Check Sequence", "dlms.hdlc.hcs", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Frame Check Sequence", "dlms.hdlc.fcs", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Parameter", "dlms.hdlc.parameter", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "LLC Header", "dlms.hdlc.llc", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* IEC 4-32 LLC */
    { "IEC 4-32 LLC Header", "dlms.iec432llc", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* Wrapper Protocol Data Unit (WPDU) */
    { "Wrapper Header", "dlms.wrapper", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },

    /* APDU */
    { "APDU", "dlms.apdu", FT_UINT8, BASE_DEC, dlms_apdu_names, 0, 0, HFILL },
    { "Client Max Receive PDU Size", "dlms.client_max_receive_pdu_size", FT_UINT16, BASE_DEC, 0, 0, 0, HFILL },
    { "Server Max Receive PDU Size", "dlms.server_max_receive_pdu_size", FT_UINT16, BASE_DEC, 0, 0, 0, HFILL },
    { "Get Request", "dlms.get_request", FT_UINT8, BASE_DEC, dlms_get_request_names, 0, 0, HFILL },
    { "Set Request", "dlms.set_request", FT_UINT8, BASE_DEC, dlms_set_request_names, 0, 0, HFILL },
    { "Action Request", "dlms.action_request", FT_UINT8, BASE_DEC, dlms_action_request_names, 0, 0, HFILL },
    { "Get Response", "dlms.get_response", FT_UINT8, BASE_DEC, dlms_get_response_names, 0, 0, HFILL },
    { "Set Response", "dlms.set_response", FT_UINT8, BASE_DEC, dlms_set_response_names, 0, 0, HFILL },
    { "Action Response", "dlms.action_response", FT_UINT8, BASE_DEC, dlms_action_response_names, 0, 0, HFILL },
    { "Access Request", "dlms.action_request", FT_UINT8, BASE_DEC, dlms_access_request_names, 0, 0, HFILL },
    { "Access Response", "dlms.action_response", FT_UINT8, BASE_DEC, dlms_access_response_names, 0, 0, HFILL },
    { "Class Id", "dlms.class_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Instance Id", "dlms.instance_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Attribute Id", "dlms.attribute_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Method Id", "dlms.method_id", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { "Access Selector", "dlms.access_selector", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { "Data Access Result", "dlms.data_access_result", FT_UINT8, BASE_DEC, dlms_data_access_result_names, 0, 0, HFILL },
    { "Action Result", "dlms.action_result", FT_UINT8, BASE_DEC, dlms_action_result_names, 0, 0, HFILL },
    { "Block Number", "dlms.block_number", FT_UINT32, BASE_DEC, 0, 0, 0, HFILL },
    { "Last Block", "dlms.last_block", FT_BOOLEAN, BASE_DEC, 0, 0, 0, HFILL },
    { "Type Description", "dlms.type_description", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Data", "dlms.data", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Date-Time", "dlms.date_time", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Length", "dlms.length", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "State Error", "dlms.state_error", FT_UINT8, BASE_DEC, dlms_state_error_names, 0, 0, HFILL },
    { "Service Error", "dlms.service_error", FT_UINT8, BASE_DEC, dlms_service_error_names, 0, 0, HFILL },

    /* Invoke-Id-And-Priority */
    { "Invoke Id", "dlms.invoke_id", FT_UINT8, BASE_DEC, 0, 0x0f, 0, HFILL },
    { "Service Class", "dlms.service_class", FT_UINT8, BASE_DEC, dlms_service_class_names, 0x40, 0, HFILL },
    { "Priority", "dlms.priority", FT_UINT8, BASE_DEC, dlms_priority_names, 0x80, 0, HFILL },

    /* Long-Invoke-Id-And-Priority */
    { "Long Invoke Id", "dlms.long_invoke_id", FT_UINT32, BASE_DEC, 0, 0xffffff, 0, HFILL },
    { "Self Descriptive", "dlms.self_descriptive", FT_UINT32, BASE_DEC, dlms_self_descriptive_names, 0x10000000, 0, HFILL },
    { "Processing Option", "dlms.processing_option", FT_UINT32, BASE_DEC, dlms_processing_option_names, 0x20000000, 0, HFILL },
    { "Service Class", "dlms.service_class", FT_UINT32, BASE_DEC, dlms_service_class_names, 0x40000000, 0, HFILL },
    { "Priority", "dlms.priority", FT_UINT32, BASE_DEC, dlms_priority_names, 0x80000000, 0, HFILL },

    /* proposed-conformance and negotiated-conformance bits */
    { "general-protection", "dlms.conformance.general_protection", FT_UINT24, BASE_DEC, 0, 0x400000, 0, HFILL },
    { "general-block-transfer", "dlms.conformance.general_block_transfer", FT_UINT24, BASE_DEC, 0, 0x200000, 0, HFILL },
    { "read", "dlms.conformance.read", FT_UINT24, BASE_DEC, 0, 0x100000, 0, HFILL },
    { "write", "dlms.conformance.write", FT_UINT24, BASE_DEC, 0, 0x080000, 0, HFILL },
    { "unconfirmed-write", "dlms.conformance.unconfirmed_write", FT_UINT24, BASE_DEC, 0, 0x040000, 0, HFILL },
    { "attribute0-supported-with-set", "dlms.conformance.attribute0_supported_with_set", FT_UINT24, BASE_DEC, 0, 0x008000, 0, HFILL },
    { "priority-mgmt-supported", "dlms.conformance.priority_mgmt_supported", FT_UINT24, BASE_DEC, 0, 0x004000, 0, HFILL },
    { "attribute0-supported-with-get", "dlms.conformance.attribute0_supported_with_get", FT_UINT24, BASE_DEC, 0, 0x002000, 0, HFILL },
    { "block-transfer-with-get-or-read", "dlms.conformance.block_transfer_with_get_or_read", FT_UINT24, BASE_DEC, 0, 0x001000, 0, HFILL },
    { "block-transfer-with-set-or-write", "dlms.conformance.block_transfer_with_set_or_write", FT_UINT24, BASE_DEC, 0, 0x000800, 0, HFILL },
    { "block-transfer-with-action", "dlms.conformance.block_transfer_with_action", FT_UINT24, BASE_DEC, 0, 0x000400, 0, HFILL },
    { "multiple-references", "dlms.conformance.multiple_references", FT_UINT24, BASE_DEC, 0, 0x000200, 0, HFILL },
    { "information-report", "dlms.conformance.information_report", FT_UINT24, BASE_DEC, 0, 0x000100, 0, HFILL },
    { "data-notification", "dlms.conformance.data_notification", FT_UINT24, BASE_DEC, 0, 0x000080, 0, HFILL },
    { "access", "dlms.conformance.access", FT_UINT24, BASE_DEC, 0, 0x000040, 0, HFILL },
    { "parameterized-access", "dlms.conformance.parameterized_access", FT_UINT24, BASE_DEC, 0, 0x000020, 0, HFILL },
    { "get", "dlms.conformance.get", FT_UINT24, BASE_DEC, 0, 0x000010, 0, HFILL },
    { "set", "dlms.conformance.set", FT_UINT24, BASE_DEC, 0, 0x000008, 0, HFILL },
    { "selective-access", "dlms.conformance.selective_access", FT_UINT24, BASE_DEC, 0, 0x000004, 0, HFILL },
    { "event-notification", "dlms.conformance.event_notification", FT_UINT24, BASE_DEC, 0, 0x000002, 0, HFILL },
    { "action", "dlms.conformance.action", FT_UINT24, BASE_DEC, 0, 0x000001, 0, HFILL },

    /* fragment_items */
    { "Fragments", "dlms.fragments", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Fragment", "dlms.fragment", FT_FRAMENUM, BASE_NONE, 0, 0, 0, HFILL },
    { "Fragment Overlap", "dlms.fragment.overlap", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { "Fragment Conflict", "dlms.fragment.conflict", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { "Fragment Multiple", "dlms.fragment.multiple", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { "Fragment Too Long", "dlms.fragment.too_long", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { "Fragment Error", "dlms.fragment.error", FT_FRAMENUM, BASE_NONE, 0, 0, 0, HFILL },
    { "Fragment Count", "dlms.fragment.count", FT_UINT32, BASE_DEC, 0, 0, 0, HFILL },
    { "Reassembled In", "dlms.reassembled_in", FT_FRAMENUM, BASE_NONE, 0, 0, 0, HFILL },
    { "Reassembled Length", "dlms.reassembled_length", FT_UINT32, BASE_DEC, 0, 0, 0, HFILL },
    { "Reassembled Data", "dlms.reassembled_data", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },

    // Himanshu - AARQ/AARE
    { "choice", "dlms.choice", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { "context-value", "dlms.context_value", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "context-name", "dlms.context_name", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "protocol-version", "dlms.protocol_version", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { "application-context-name", "dlms.application_context_name", FT_OID, BASE_NONE, 0, 0, 0, HFILL },

    // Himanshu - AARQ only
    { "Called AP title", "dlms.called_ap_title", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { "Called AE qualifier", "dlms.called_ae_qualifier", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { "Called AP invocation-id", "dlms.called_ap_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Called AE invocation-id", "dlms.called_ae_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Calling AP title", "dlms.calling_ap_title", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { "Calling AE qualifier", "dlms.calling_ae_qualifier", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { "Calling AP invocation-id", "dlms.calling_ap_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Calling AE invocation-id", "dlms.calling_ae_invocation_id", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Authentication", "dlms.sender_acse_requirements_authentication", FT_UINT8, BASE_DEC, 0, 0x80, 0, HFILL },
    { "Mechanism Name", "dlms.mechanism_name", FT_OID, BASE_NONE, 0, 0, 0, HFILL },
    { "Calling Authentication Value", "dlms.calling_authentication_value", FT_STRING, STR_ASCII, 0, 0, 0, HFILL },

    // Himanshu - AARE only
    { "Result", "dlms.result", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Result Source Diagnostic", "dlms.result_source_diagnostic", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { "ACSE Service User", "dlms.result_source_diagnostic_acse_service_user", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "ACSE Service Provider", "dlms.result_source_diagnostic_acse_service_provider", FT_NONE, BASE_NONE, 0, 0, 0, HFILL },
    { "Responding AP Title", "dlms.responding_AP_title", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { "Responding AE Qualifier", "dlms.responding_AE_qualifier", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { "Responding AP Invocation_identifier", "dlms.responding_ap_invocation_id", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { "Responding AE Invocation_identifier", "dlms.responding_ae_invocation_id", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },

    // Himanshu - AARQ/AARE
    { "Implementation Information", "dlms.implementation_information", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
    { "User Information", "dlms.user_information", FT_UINT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },

    // Himanshu - Initiate Request
	{ "Dedicated Key", "dlms.initiate_request_dedicated_key", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
	{ "Response Allowed", "dlms.initiate_request_response_allowed", FT_BOOLEAN, 0, 0, 0, 0, HFILL },
    { "Proposed QoS", "dlms.initiate_request_proposed_qos", FT_INT8, BASE_DEC, 0, 0, 0, HFILL },
    { "Proposed DLMS version-no", "dlms.initiate_request_proposed_dlms_version_no", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },

    // Himanshu - Initiate Response
    { "Response Negotiated QoS", "dlms.initiate_response_negotiated_qos", FT_INT8, BASE_DEC, 0, 0, 0, HFILL },
    { "Response Negotiated DLMS version-no", "dlms.initiate_response_negotiated_dlms_version_no", FT_UINT8, BASE_DEC, 0, 0, 0, HFILL },
    { "Response VAA-Name Component", "dlms.initiate_response_vaa_name_component", FT_UINT16, BASE_HEX, 0, 0, 0, HFILL },

    // Himanshu - Initiate Request (Glo-Ciphered)
        // Security Header //
            // Security Control Byte //
    { "Security Control Compression", "dlms.glo_initiate_request_security_control_compression", FT_UINT8, BASE_DEC, 0, 0x80, 0, HFILL },
    { "Security Control Key Set", "dlms.glo_initiate_request_security_control_key_set", FT_UINT8, BASE_DEC, 0, 0x40, 0, HFILL },
    { "Security Control Encryption", "dlms.glo_initiate_request_security_control_encryption", FT_UINT8, BASE_DEC, 0, 0x20, 0, HFILL },
    { "Security Control Authentication", "dlms.glo_initiate_request_security_control_authentication", FT_UINT8, BASE_DEC, 0, 0x10, 0, HFILL },
    { "Security Control Suite ID", "dlms.glo_initiate_request_security_control_suite_id", FT_UINT8, BASE_DEC, 0, 0x0f, 0, HFILL },
            // Initiator Nonce //
    { "Invocation Counter", "dlms.glo_initiate_request_invocation_counter", FT_UINT32, BASE_HEX_DEC, 0, 0, 0, HFILL },
        // Information //
    { "Information", "dlms.glo_initiate_request_information", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
        // Ciphertext //
    { "Ciphertext", "dlms.glo_initiate_request_ciphertext", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
        // Authentication Tag //
    { "Authentication Tag", "dlms.glo_initiate_request_authentication_tag", FT_BYTES, SEP_SPACE, 0, 0, 0, HFILL },
};
