
static void
dlms_dissect_conformance(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    header_field_info *hfi;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 7, dlms_ett.conformance, 0, "Conformance");
    for (hfi = &dlms_hfi.conformance_general_protection; hfi <= &dlms_hfi.conformance_action; hfi++) {
        proto_tree_add_item(subtree, hfi, tvb, offset + 4, 3, ENC_BIG_ENDIAN);
    }
}

// Himanshu - Page 117 - Green Book
typedef enum {
    DLMS_SECURITY_CONTROL_COMPRESSION = 0x80,
    DLMS_SECURITY_CONTROL_KEY_SET = 0x40,          // {unicast, broadcast}
    DLMS_SECURITY_CONTROL_ENCRYPTION = 0x20,
    DLMS_SECURITY_CONTROL_AUTHENTICATION = 0x10,
    DLMS_SECURITY_CONTROL_SUITE_ID = 0x0f
} DLMS_SECURITY_CONTROL;

// Himanshu - Page 117,308 - Green Book
static guint8
dlms_dissect_security_header(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    header_field_info *hfi;
    guint8 ret = tvb_get_guint8(tvb, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, 1, dlms_ett.glo_security_control_byte, 0, "Security Control Byte");
    proto_item_append_text(subtree, ": 0x%02x", tvb_get_guint8(tvb, offset));
    for (hfi = &dlms_hfi.glo_security_control_compression; hfi <= &dlms_hfi.glo_security_control_suite_id; hfi++) {
        proto_tree_add_item(subtree, hfi, tvb, offset, 1, ENC_NA);
    }
    offset += 1;
    proto_tree_add_item(tree, &dlms_hfi.glo_invocation_counter, tvb, offset, 4, ENC_NA);
    offset += 4;

    return ret;
}

// Himanshu - Page 116 - Green Book
static guint8
dlms_dissect_glo_ciphered_apdu(tvbuff_t *tvb, proto_tree *tree, gint offset, gint length)
{
    guint8 security_control = dlms_dissect_security_header(tvb, tree, offset);
    offset += 5;

    guint len = length - 5;
    if (security_control & DLMS_SECURITY_CONTROL_AUTHENTICATION) {
        len -= 12;
    }
    if (security_control & DLMS_SECURITY_CONTROL_ENCRYPTION) {
        proto_tree_add_item(tree, &dlms_hfi.glo_ciphertext, tvb, offset, len, ENC_ASCII|ENC_NA);
    } else {
        proto_tree_add_item(tree, &dlms_hfi.glo_information, tvb, offset, len, ENC_ASCII|ENC_NA);
    }
    offset += len;

    if (security_control & DLMS_SECURITY_CONTROL_AUTHENTICATION) {
        proto_tree_add_item(tree, &dlms_hfi.glo_authentication_tag, tvb, offset, 12, ENC_ASCII|ENC_NA);
    }
    return security_control;
}

// Himanshu
static void
dlms_dissect_context_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_item *item;
    guint8 length;

    guint8 choice = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_item(tree, &dlms_hfi.choice, tvb, offset, 1, ENC_NA);
    offset += 1;
    length = dlms_get_length(tvb, &offset);

    if(1) {
        dlms_set_asn_data_value(tvb, tree, item, choice, &offset);
    }
    /* ------------------------- OR ------------------------ */
    else {
        proto_tree_add_item(tree, &dlms_hfi.application_context_name, tvb, ++offset, length, ENC_NA);
    }
}

// Himanshu
static void
dlms_dissect_user_information(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    // guint8 choice = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, &dlms_hfi.choice, tvb, offset, 1, ENC_NA);
    offset += 1;
    guint length = tvb_get_guint8(tvb, offset);   // length of OCTET STRING value of tag USER-INFORMATION
    offset += 1;
    guint8 tag = tvb_get_guint8(tvb, offset);

    // Page 245 - Green Book.
    switch (tag) {
        case 0x01: { /* initiate-request */
            proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.initiate_request, 0, "Initiate-Request");
            offset += 1;
            if (tvb_get_guint8(tvb, offset)) {
                length = tvb_get_guint8(tvb, offset + 1);
                proto_tree_add_item(subtree, &dlms_hfi.initiate_request_dedicated_key, tvb, offset, length, ENC_NA);
                offset += length;
            }
            offset += 1;
            if (tvb_get_guint8(tvb, offset)) {
                proto_tree_add_item(subtree, &dlms_hfi.initiate_request_response_allowed, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            offset += 1;
            if (tvb_get_guint8(tvb, offset)) {
                proto_tree_add_item(subtree, &dlms_hfi.initiate_request_proposed_qos, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            offset += 1;
            proto_tree_add_item(subtree, &dlms_hfi.initiate_request_proposed_dlms_version_no, tvb, offset, 1, ENC_NA);
            offset += 1;
            dlms_dissect_conformance(tvb, subtree, offset);
            offset += 7;
            proto_tree_add_item(subtree, &dlms_hfi.client_max_receive_pdu_size, tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
        }

        case 0x08: { /* initiate-response */
            proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.initiate_response, 0, "Initiate-Response");
            offset += 1;
            if (tvb_get_guint8(tvb, offset)) {
                proto_tree_add_item(subtree, &dlms_hfi.initiate_response_negotiated_qos, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            offset += 1;
            proto_tree_add_item(subtree, &dlms_hfi.initiate_response_negotiated_dlms_version_no, tvb, offset, 1, ENC_NA);
            offset += 1;
            dlms_dissect_conformance(tvb, subtree, offset);
            offset += 7;
            proto_tree_add_item(subtree, &dlms_hfi.client_max_receive_pdu_size, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(subtree, &dlms_hfi.initiate_response_vaa_name_component, tvb, offset, length - 12, ENC_ASCII|ENC_NA);
            break;
        }

        case 0x21: { /* glo-initiate-request */ // Page 116,308 - Green Book
            proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.glo_initiate_request, 0, "Initiate-Request (Glo-Ciphered)");
            offset += 1;
            length = dlms_get_length(tvb, &offset);
            dlms_dissect_glo_ciphered_apdu(tvb, subtree, offset, length);
            break;
        }

        case 0x28: { /* glo-initiate-response */
            proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.glo_initiate_response, 0, "Initiate-Response (Glo-Ciphered)");
            break;
            UNUSED(subtree);
        }

        default:
            DISSECTOR_ASSERT_HINT(tag, "Not implemented User-Information CHOICE");
    }
}

// Himanshu
static void
dlms_dissect_a_associate_aarq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    int tag = tvb_get_guint8(tvb, offset);
    int length = tvb_get_guint8(tvb, offset + 1);

    switch (tag) {
        case 0xa0:{ /* protocol version */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.protocol_version, 0, "Protocol Version");
            proto_tree_add_item(subtree, &dlms_hfi.protocol_version, tvb, offset + 2, 1, ENC_NA);
            break;
        }

        case 0xa1:{ /* application context name */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.application_context_name, 0, "Application Context Name");
            dlms_dissect_context_value(tvb, pinfo, subtree, offset + 2);
            break;
        }

        case 0xa2:{ /* called AP title */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.called_ap_title, 0, "Called AP Title");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, &dlms_hfi.called_ap_title, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa3:{ /* called AE qualifier */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.called_ae_qualifier, 0, "Called AE Qualifier");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, &dlms_hfi.called_ae_qualifier, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa4:{ /* called AP invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.called_ap_invocation_id, 0, "Called AP Invocation ID");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, &dlms_hfi.called_ap_invocation_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xa5:{ /* called AE invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.called_ae_invocation_id, 0, "Called AE Invocation ID");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, &dlms_hfi.called_ae_invocation_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xa6:{ /* calling AP title */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.calling_ap_title, 0, "Calling AP Title");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, &dlms_hfi.calling_ap_title, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa7:{ /* calling AE qualifier */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.calling_ae_qualifier, 0, "Calling AE Qualifier");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, &dlms_hfi.calling_ae_qualifier, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa8:{ /* calling AP invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.calling_ap_invocation_id, 0, "Calling AP Invocation ID");
            proto_tree_add_item(subtree, &dlms_hfi.calling_ap_invocation_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xa9:{ /* calling AE invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.calling_ae_invocation_id, 0, "Calling AE Invocation ID");
            proto_tree_add_item(subtree, &dlms_hfi.calling_ae_invocation_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0x8a:{ /* sender ACSE requirements */                        // 0x80 -- BER type CONTEXT-SPECIFIC
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.sender_acse_requirements, 0, "Sender ACSE Requirements");
            offset += 2 + 1;
            proto_tree_add_item(subtree, &dlms_hfi.sender_acse_requirements_authentication, tvb, offset, 1, ENC_NA);
            break;
        }

        case 0x8b:{ /* mechanism name */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.mechanism_name, 0, "Mechanism Name");
            proto_tree_add_item(subtree, &dlms_hfi.mechanism_name, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xac:{ /* calling authentication value */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.calling_authentication_value, 0, "Calling Authentication Value");
            proto_tree_add_item(subtree, &dlms_hfi.calling_authentication_value, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xad:{ /* implementation information */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.implementation_information, 0, "Implementation Information");
            proto_tree_add_item(subtree, &dlms_hfi.implementation_information, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xbe:{ /* user-information */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.user_information, 0, "User-Information");
            offset += 2;
            dlms_dissect_user_information(tvb, subtree, offset);
            break;
        }

        default:
            DISSECTOR_ASSERT_HINT(tag, "Invalid A-ASSOCIATE-ACSE CHOICE");
    }
}

// Himanshu
static void
dlms_dissect_a_associate_aare(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    proto_item *item;
    int tag = tvb_get_guint8(tvb, offset);
    int length = tvb_get_guint8(tvb, offset + 1);

    switch (tag) {
        case 0xa0:{ /* protocol version */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.protocol_version, 0, "Protocol Version");
            proto_tree_add_item(subtree, &dlms_hfi.protocol_version, tvb, offset + 2, 1, ENC_NA);
            break;
        }

        case 0xa1:{ /* application context name */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.application_context_name, 0, "Application Context Name");
            dlms_dissect_context_value(tvb, pinfo, subtree, offset + 2);
            break;
        }

        case 0xa2:{ /* association result */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.association_result, 0, "Association Result");
            guint8 choice = tvb_get_guint8(tvb, offset + 2);
            item = proto_tree_add_item(subtree, &dlms_hfi.association_result, tvb, offset + 3, length - 1, ENC_NA);
            offset += 3;
            dlms_set_asn_data_value(tvb, subtree, item, choice, &offset);
            break;
        }

        case 0xa3:{ /* result source diagnostic */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.result_source_diagnostic, 0, "Result Source Diagnostic");
            guint8 choice = tvb_get_guint8(tvb, offset + 2);
            length = tvb_get_guint8(tvb, offset + 3);
            offset += 4;

            // Page 248 - Green Book.
            if ((choice & 0xf) == 0x1) { /* ACSE Service user */
                choice = tvb_get_guint8(tvb, offset);
                offset += 1;
                item = proto_tree_add_item(subtree, &dlms_hfi.result_source_diagnostic_acse_service_user, tvb, offset, length - 1, ENC_NA);
                dlms_set_asn_data_value(tvb, subtree, item, choice, &offset);
            } else if ((choice & 0xf) == 0x2) { /* ACSE Service provider */
                choice = tvb_get_guint8(tvb, offset);
                offset += 1;
                item = proto_tree_add_item(subtree, &dlms_hfi.result_source_diagnostic_acse_service_provider, tvb, offset, length - 1, ENC_NA);
                dlms_set_asn_data_value(tvb, subtree, item, choice, &offset);
            }
            break;
        }

        case 0xa4:{ /* responding AP title */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.responding_ap_title, 0, "Responding AP Title");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, &dlms_hfi.responding_ap_title, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa5:{ /* responding AE qualifier */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.responding_ae_qualifier, 0, "Responding AE Qualifier");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, &dlms_hfi.responding_ae_qualifier, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa6:{ /* responding AP invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.responding_ap_invocation_id, 0, "Responding AP Invocation ID");
            proto_tree_add_item(subtree, &dlms_hfi.responding_ap_invocation_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xa7:{ /* responding AE invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.responding_ae_invocation_id, 0, "Responding AE Invocation ID");
            proto_tree_add_item(subtree, &dlms_hfi.responding_ae_invocation_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xbe:{ /* user-information */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.user_information, 0, "User-Information");
            offset += 2;
            dlms_dissect_user_information(tvb, subtree, offset);
            break;
        }
    }
}

static void
dlms_dissect_aarq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    int end, length;
    col_set_str(pinfo->cinfo, COL_INFO, "AARQ");
    length = tvb_get_guint8(tvb, offset);
    offset += 1;
    end = offset + length;
    while (offset < end) {
        length = tvb_get_guint8(tvb, offset + 1);
        dlms_dissect_a_associate_aarq(tvb, pinfo, tree, offset);
        offset += 2 + length;
    }
}

static void
dlms_dissect_aare(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    int end, length;
    col_set_str(pinfo->cinfo, COL_INFO, "AARE");
    length = tvb_get_guint8(tvb, offset);
    offset += 1;
    end = offset + length;
    while (offset < end) {
        length = tvb_get_guint8(tvb, offset + 1);
        dlms_dissect_a_associate_aare(tvb, pinfo, tree, offset);
        offset += 2 + length;
    }
}