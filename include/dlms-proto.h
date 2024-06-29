
#include "utils/headers.h"

extern int dlms_proto;

/* Protocol subtree (ett) indices */
struct DLMSSubtree {
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
};

/* The DLMS hf_register_info (hfi) structures */
struct DLMSHeaderInfo
{
    /* 0: Null */
    hf_register_info null;

    /* 1: HDLC */
    hf_register_info hdlc_flag; /* opening/closing flag */
    hf_register_info hdlc_type; /* frame format type */
    hf_register_info hdlc_segmentation; /* frame format segmentation bit */
    hf_register_info hdlc_length; /* frame format length sub-field */
    hf_register_info hdlc_address; /* destination/source address */
    hf_register_info hdlc_frame_i; /* control field & 0x01 (I) */
    hf_register_info hdlc_frame_rr_rnr; /* control field & 0x0f (RR or RNR) */
    hf_register_info hdlc_frame_other; /* control field & 0xef (all other) */
    hf_register_info hdlc_pf; /* poll/final bit */
    hf_register_info hdlc_rsn; /* receive sequence number N(R) */
    hf_register_info hdlc_ssn; /* send sequence number N(S) */
    hf_register_info hdlc_hcs; /* header check sequence */
    hf_register_info hdlc_fcs; /* frame check sequence */
    hf_register_info hdlc_parameter; /* information field parameter */
    hf_register_info hdlc_llc; /* LLC header */

    /* 16: IEC 4-32 LLC */
    hf_register_info iec432llc;

    /* 17: Wrapper Protocol Data Unit (WPDU) */
    hf_register_info wrapper_header;

    /* 18: APDU */
    hf_register_info apdu;
    hf_register_info client_max_receive_pdu_size;
    hf_register_info server_max_receive_pdu_size;
    hf_register_info get_request;
    hf_register_info set_request;
    hf_register_info action_request;
    hf_register_info get_response;
    hf_register_info set_response;
    hf_register_info action_response;
    hf_register_info access_request;
    hf_register_info access_response;
    hf_register_info class_id;
    hf_register_info instance_id;
    hf_register_info attribute_id;
    hf_register_info method_id;
    hf_register_info access_selector;
    hf_register_info data_access_result;
    hf_register_info action_result;
    hf_register_info block_number;
    hf_register_info last_block;
    hf_register_info type_description;
    hf_register_info data;
    hf_register_info date_time;
    hf_register_info length;
    hf_register_info state_error;
    hf_register_info service_error;

    /* 44: Invoke-Id-And-Priority */
    hf_register_info invoke_id;
    hf_register_info service_class;
    hf_register_info priority;

    /* 47: Long-Invoke-Id-And-Priority */
    hf_register_info long_invoke_id;
    hf_register_info long_self_descriptive;
    hf_register_info long_processing_option;
    hf_register_info long_service_class;
    hf_register_info long_priority;

    /* 52: Conformance bits */
    hf_register_info conformance_general_protection;
    hf_register_info conformance_general_block_transfer;
    hf_register_info conformance_read;
    hf_register_info conformance_write;
    hf_register_info conformance_unconfirmed_write;
    hf_register_info conformance_attribute0_supported_with_set;
    hf_register_info conformance_priority_mgmt_supported;
    hf_register_info conformance_attribute0_supported_with_get;
    hf_register_info conformance_block_transfer_with_get_or_read;
    hf_register_info conformance_block_transfer_with_set_or_write;
    hf_register_info conformance_block_transfer_with_action;
    hf_register_info conformance_multiple_references;
    hf_register_info conformance_information_report;
    hf_register_info conformance_data_notification;
    hf_register_info conformance_access;
    hf_register_info conformance_parameterized_access;
    hf_register_info conformance_get;
    hf_register_info conformance_set;
    hf_register_info conformance_selective_access;
    hf_register_info conformance_event_notification;
    hf_register_info conformance_action;

    /* 73: fragment_items */
    hf_register_info fragments;
    hf_register_info fragment;
    hf_register_info fragment_overlap;
    hf_register_info fragment_overlap_conflict;
    hf_register_info fragment_multiple_tails;
    hf_register_info fragment_too_long_fragment;
    hf_register_info fragment_error;
    hf_register_info fragment_count;
    hf_register_info reassembled_in;
    hf_register_info reassembled_length;
    hf_register_info reassembled_data;

    // 84: Himanshu - AARQ/AARE
    hf_register_info choice;
    hf_register_info context_value;
    hf_register_info context_name;
    hf_register_info protocol_version;
    hf_register_info application_context_name;

    // 89: Himanshu - AARQ only
    hf_register_info called_ap_title;
    hf_register_info called_ae_qualifier;
    hf_register_info called_ap_invocation_id;
    hf_register_info called_ae_invocation_id;
    hf_register_info calling_ap_title;
    hf_register_info calling_ae_qualifier;
    hf_register_info calling_ap_invocation_id;
    hf_register_info calling_ae_invocation_id;
    hf_register_info sender_acse_requirements_authentication;
    hf_register_info mechanism_name;
    hf_register_info calling_authentication_value;

    // 100: Himanshu - AARE only
    hf_register_info association_result;
    hf_register_info result_source_diagnostic;
    hf_register_info result_source_diagnostic_acse_service_user;
    hf_register_info result_source_diagnostic_acse_service_provider;
    hf_register_info responding_ap_title;
    hf_register_info responding_ae_qualifier;
    hf_register_info responding_ap_invocation_id;
    hf_register_info responding_ae_invocation_id;

    // 108: Himanshu - AARQ/AARE
    hf_register_info implementation_information;
    hf_register_info user_information;

    // 110: Himanshu - Initiate Request
    hf_register_info initiate_request_dedicated_key;
    hf_register_info initiate_request_response_allowed;
    hf_register_info initiate_request_proposed_qos;
    hf_register_info initiate_request_proposed_dlms_version_no;

    // 114: Himanshu - Initiate Response
    hf_register_info initiate_response_negotiated_qos;
    hf_register_info initiate_response_negotiated_dlms_version_no;
    hf_register_info initiate_response_vaa_name_component;

    // Himanshu - Glo-Ciphered APDU
        // 117: Security Header //
            // Security Control Byte //
    hf_register_info glo_security_control_compression;
    hf_register_info glo_security_control_key_set;
    hf_register_info glo_security_control_encryption;
    hf_register_info glo_security_control_authentication;
    hf_register_info glo_security_control_suite_id;
            // Initiator Nonce //
    hf_register_info glo_invocation_counter;
        // 123: Information // May be Plaintext or Compressed text
    hf_register_info glo_information;
        // 124: Ciphertext //
    hf_register_info glo_ciphertext;
        // 125: Authentication Tag //
    hf_register_info glo_authentication_tag;
}; // __PACKED__;

/* Expert information (ei) fields */
struct DLMSExpertInfo {
    ei_register_info no_success;
    ei_register_info not_implemented;
    ei_register_info check_sequence; /* bad HDLC check sequence (HCS or FCS) value */
};

extern DLMSSubtree dlms_ett;
extern DLMSHeaderInfo dlms_hdr;
extern DLMSExpertInfo dlms_ei;
