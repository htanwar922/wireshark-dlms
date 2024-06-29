
#include "dlms-proto.h"

#include "data-types/dlms-utils.h"
#include "data-types/dlms-asn1.h"
#include "data-types/dlms-data-ciphered.h"

#include "services/dlms-association.h"

void
dlms_dissect_conformance(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    hf_register_info *hfi;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 7, dlms_ett.conformance, 0, "Conformance");
    for (hfi = &dlms_hdr.conformance_general_protection; hfi <= &dlms_hdr.conformance_action; hfi++) {
        proto_tree_add_item(subtree, *hfi->p_id, tvb, offset + 4, 3, ENC_BIG_ENDIAN);
    }
}

// Himanshu
void
dlms_dissect_context_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_item *item;

    guint8 choice = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_item(tree, *dlms_hdr.choice.p_id, tvb, offset, 2, ENC_NA);
    offset += 1;

    if(1) {
        dlms_set_asn_data_value(tvb, tree, item, choice, &offset);
    }
    /* ------------------------- OR ------------------------ */
    else {
        guint8 length = dlms_get_length(tvb, &offset);
        proto_tree_add_item(tree, *dlms_hdr.application_context_name.p_id, tvb, ++offset, length, ENC_NA);
    }
}

// Himanshu
void
dlms_dissect_mechanism_name(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_item *item = proto_tree_add_item(tree, *dlms_hdr.null.p_id, tvb, offset, 0, ENC_NA);

    if(1) {
        dlms_set_asn_data_value(tvb, tree, item, ASNT_OBJECT_IDENTIFIER, &offset);
    }
    /* ------------------------- OR ------------------------ */
    else {
        guint8 length = dlms_get_length(tvb, &offset);
        proto_tree_add_item(tree, *dlms_hdr.mechanism_name.p_id, tvb, offset, length, ENC_NA);
    }
}

// Himanshu
void
dlms_dissect_initiate_request(tvbuff_t *tvb, proto_tree *tree, gint offset, gint length)
{
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.initiate_request, 0, "Initiate-Request");
    offset += 1;
    if (tvb_get_guint8(tvb, offset)) {
        length = tvb_get_guint8(tvb, offset + 1);
        proto_tree_add_item(subtree, *dlms_hdr.initiate_request_dedicated_key.p_id, tvb, offset, length, ENC_NA);
        offset += length;
    }
    offset += 1;
    if (tvb_get_guint8(tvb, offset)) {
        proto_tree_add_item(subtree, *dlms_hdr.initiate_request_response_allowed.p_id, tvb, offset, 1, ENC_NA);
        offset += 1;
    }
    offset += 1;
    if (tvb_get_guint8(tvb, offset)) {
        proto_tree_add_item(subtree, *dlms_hdr.initiate_request_proposed_qos.p_id, tvb, offset, 1, ENC_NA);
        offset += 1;
    }
    offset += 1;
    g_print("HERE : %08x\n", tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN));
    g_print("\t%d\n", *dlms_hdr.initiate_request_proposed_dlms_version_no.p_id);
    g_print("\t%d\n", dlms_hdr.initiate_request_proposed_dlms_version_no.hfinfo.id);
    proto_tree_add_item(subtree, *dlms_hdr.initiate_request_proposed_dlms_version_no.p_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    dlms_dissect_conformance(tvb, subtree, offset);
    offset += 7;
    proto_tree_add_item(subtree, *dlms_hdr.client_max_receive_pdu_size.p_id, tvb, offset, 2, ENC_BIG_ENDIAN);
}

// Himanshu
void
dlms_dissect_initiate_response(tvbuff_t *tvb, proto_tree *tree, gint offset, gint length)
{
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.initiate_response, 0, "Initiate-Response");
    offset += 1;
    if (tvb_get_guint8(tvb, offset)) {
        proto_tree_add_item(subtree, *dlms_hdr.initiate_response_negotiated_qos.p_id, tvb, offset, 1, ENC_NA);
        offset += 1;
    }
    offset += 1;
    proto_tree_add_item(subtree, *dlms_hdr.initiate_response_negotiated_dlms_version_no.p_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    dlms_dissect_conformance(tvb, subtree, offset);
    offset += 7;
    proto_tree_add_item(subtree, *dlms_hdr.client_max_receive_pdu_size.p_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, *dlms_hdr.initiate_response_vaa_name_component.p_id, tvb, offset, length - TAG_LEN, ENC_ASCII|ENC_NA);
}

// Himanshu
void
dlms_dissect_user_information(tvbuff_t *tvb, packet_info * pinfo, proto_tree *tree, gint offset)
{
    // guint8 choice = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, *dlms_hdr.choice.p_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    guint length = tvb_get_guint8(tvb, offset);   // length of OCTET STRING value of tag USER-INFORMATION
    offset += 1;
    guint8 tag = tvb_get_guint8(tvb, offset);

    // Page 245 - Green Book.
    switch (tag) {
        case 0x01: { /* initiate-request */
            dlms_dissect_initiate_request(tvb, tree, offset, length);
            break;
        }

        case 0x08: { /* initiate-response */
            dlms_dissect_initiate_response(tvb, tree, offset, length);
            break;
        }

        case 0x21: { /* glo-initiate-request */ // Page 116,308 - Green Book
            proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.glo_initiate_request, 0, "Initiate-Request (Glo-Ciphered)");
            offset += 1;
            length = dlms_get_length(tvb, &offset);
            dlms_glo_ciphered_apdu apdu;
            dlms_dissect_glo_ciphered_apdu(tvb, subtree, offset, length, &apdu);

            tvbuff_t * tvb_plain = dlms_decrypt_glo_ciphered_apdu(&apdu, glo_KEY, client_system_title, glo_AAD, pinfo);
            dlms_dissect_initiate_request(tvb_plain, subtree, 0, tvb_reported_length(tvb_plain));
            tvb_free(tvb_plain);
            break;
        }

        case 0x28: { /* glo-initiate-response */
            proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.glo_initiate_response, 0, "Initiate-Response (Glo-Ciphered)");
            offset += 1;
            length = dlms_get_length(tvb, &offset);
            dlms_glo_ciphered_apdu apdu;
            dlms_dissect_glo_ciphered_apdu(tvb, subtree, offset, length, &apdu);

            tvbuff_t * tvb_plain = dlms_decrypt_glo_ciphered_apdu(&apdu, glo_KEY, server_system_title, glo_AAD, pinfo);
            dlms_dissect_initiate_response(tvb_plain, subtree, 0, tvb_reported_length(tvb_plain));
            tvb_free(tvb_plain);
            break;
        }

        default:
            DISSECTOR_ASSERT_HINT(tag, "Not implemented User-Information CHOICE");
    }
}

// Himanshu
void
dlms_dissect_a_associate_aarq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    int tag = tvb_get_guint8(tvb, offset);
    int length = tvb_get_guint8(tvb, offset + 1);

    switch (tag) {
        case 0xa0:{ /* protocol version */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.protocol_version, 0, "Protocol Version");
            proto_tree_add_item(subtree, *dlms_hdr.protocol_version.p_id, tvb, offset + 2, 1, ENC_NA);
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
            proto_tree_add_item(subtree, *dlms_hdr.called_ap_title.p_id, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa3:{ /* called AE qualifier */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.called_ae_qualifier, 0, "Called AE Qualifier");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, *dlms_hdr.called_ae_qualifier.p_id, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa4:{ /* called AP invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.called_ap_invocation_id, 0, "Called AP Invocation ID");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, *dlms_hdr.called_ap_invocation_id.p_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xa5:{ /* called AE invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.called_ae_invocation_id, 0, "Called AE Invocation ID");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, *dlms_hdr.called_ae_invocation_id.p_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xa6:{ /* calling AP title */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.calling_ap_title, 0, "Calling AP Title");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, *dlms_hdr.calling_ap_title.p_id, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa7:{ /* calling AE qualifier */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.calling_ae_qualifier, 0, "Calling AE Qualifier");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, *dlms_hdr.calling_ae_qualifier.p_id, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa8:{ /* calling AP invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.calling_ap_invocation_id, 0, "Calling AP Invocation ID");
            proto_tree_add_item(subtree, *dlms_hdr.calling_ap_invocation_id.p_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xa9:{ /* calling AE invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.calling_ae_invocation_id, 0, "Calling AE Invocation ID");
            proto_tree_add_item(subtree, *dlms_hdr.calling_ae_invocation_id.p_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0x8a:{ /* sender ACSE requirements */                        // 0x80 -- BER type CONTEXT-SPECIFIC
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.sender_acse_requirements, 0, "Sender ACSE Requirements");
            offset += 2 + 1;
            proto_tree_add_item(subtree, *dlms_hdr.sender_acse_requirements_authentication.p_id, tvb, offset, 1, ENC_NA);
            break;
        }

        case 0x8b:{ /* mechanism name */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.mechanism_name, 0, "Mechanism Name");
            dlms_dissect_mechanism_name(tvb, pinfo, subtree, offset + 1);
            break;
        }

        case 0xac:{ /* calling authentication value */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.calling_authentication_value, 0, "Calling Authentication Value");
            proto_tree_add_item(subtree, *dlms_hdr.calling_authentication_value.p_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xad:{ /* implementation information */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.implementation_information, 0, "Implementation Information");
            proto_tree_add_item(subtree, *dlms_hdr.implementation_information.p_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xbe:{ /* user-information */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.user_information, 0, "User-Information");
            offset += 2;
            dlms_dissect_user_information(tvb, pinfo, subtree, offset);
            break;
        }

        default:
            DISSECTOR_ASSERT_HINT(tag, "Invalid A-ASSOCIATE-ACSE CHOICE");
    }
}

// Himanshu
void
dlms_dissect_a_associate_aare(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    proto_item *item;
    int tag = tvb_get_guint8(tvb, offset);
    int length = tvb_get_guint8(tvb, offset + 1);

    switch (tag) {
        case 0xa0:{ /* protocol version */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.protocol_version, 0, "Protocol Version");
            proto_tree_add_item(subtree, *dlms_hdr.protocol_version.p_id, tvb, offset + 2, 1, ENC_NA);
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
            item = proto_tree_add_item(subtree, *dlms_hdr.association_result.p_id, tvb, offset + 3, length - 1, ENC_NA);
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
                item = proto_tree_add_item(subtree, *dlms_hdr.result_source_diagnostic_acse_service_user.p_id, tvb, offset, length - 1, ENC_NA);
                dlms_set_asn_data_value(tvb, subtree, item, choice, &offset);
            } else if ((choice & 0xf) == 0x2) { /* ACSE Service provider */
                choice = tvb_get_guint8(tvb, offset);
                offset += 1;
                item = proto_tree_add_item(subtree, *dlms_hdr.result_source_diagnostic_acse_service_provider.p_id, tvb, offset, length - 1, ENC_NA);
                dlms_set_asn_data_value(tvb, subtree, item, choice, &offset);
            }
            break;
        }

        case 0xa4:{ /* responding AP title */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.responding_ap_title, 0, "Responding AP Title");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, *dlms_hdr.responding_ap_title.p_id, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa5:{ /* responding AE qualifier */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.responding_ae_qualifier, 0, "Responding AE Qualifier");
            offset += 2;    // skip 2 bytes
            length = tvb_get_guint8(tvb, offset + 1);
            proto_tree_add_item(subtree, *dlms_hdr.responding_ae_qualifier.p_id, tvb, offset + 2, length, ENC_ASCII|ENC_NA);
            break;
        }

        case 0xa6:{ /* responding AP invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.responding_ap_invocation_id, 0, "Responding AP Invocation ID");
            proto_tree_add_item(subtree, *dlms_hdr.responding_ap_invocation_id.p_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xa7:{ /* responding AE invocation ID */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.responding_ae_invocation_id, 0, "Responding AE Invocation ID");
            proto_tree_add_item(subtree, *dlms_hdr.responding_ae_invocation_id.p_id, tvb, offset + 2, length, ENC_NA);
            break;
        }

        case 0xbe:{ /* user-information */
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, dlms_ett.user_information, 0, "User-Information");
            offset += 2;
            dlms_dissect_user_information(tvb, pinfo, subtree, offset);
            break;
        }
    }
}

void
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

void
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
