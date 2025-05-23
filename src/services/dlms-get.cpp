
#include "utils/dlms-defs.h"
#include "utils/dlms-enums.h"

#include "dlms-proto.h"

#include "data-types/dlms-utils.h"
#include "data-types/dlms-bitsets.h"
#include "data-types/dlms-descriptors.h"
#include "data-types/dlms-data.h"
#include "data-types/dlms-data-ciphered.h"

#include "services/dlms-selective-access.h"
#include "services/dlms-get.h"

void
dlms_dissect_get_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    int choice;
    unsigned block_number;

    tree = proto_tree_add_subtree(tree, tvb, offset, 0, dlms_ett.get_request, 0, "Get-Request");
    proto_item_set_len(tree, tvb_reported_length_remaining(tvb, offset));
    proto_tree_add_item(tree, *dlms_hdr.get_request.p_id, tvb, offset, 1, ENC_NA);
    choice = tvb_get_guint8(tvb, offset);
    offset += 1;
    dlms_dissect_invoke_id_and_priority(tree, tvb, &offset);
    if (choice == DLMS_GET_REQUEST_NORMAL) {
        col_add_str(pinfo->cinfo, COL_INFO, "Get-Request-Normal");
        dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, tree, &offset);
        dlms_dissect_selective_access_descriptor(tvb, pinfo, tree, &offset);
    } else if (choice == DLMS_GET_REQUEST_NEXT) {
        proto_tree_add_item(tree, *dlms_hdr.block_number.p_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        block_number = tvb_get_ntohl(tvb, offset);
        offset += 4;
        col_add_fstr(pinfo->cinfo, COL_INFO, "Get-Request-Next (block %u)", block_number);
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Get-Request");
    }
}

void
dlms_dissect_get_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    int choice, result;
    proto_tree *subtree;

    tree = proto_tree_add_subtree(tree, tvb, offset, 0, dlms_ett.get_response, 0, "Get-Response");
    proto_item_set_len(tree, tvb_reported_length_remaining(tvb, offset));
    proto_tree_add_item(tree, *dlms_hdr.get_response.p_id, tvb, offset, 1, ENC_NA);
    choice = tvb_get_guint8(tvb, offset);
    offset += 1;
    dlms_dissect_invoke_id_and_priority(tree, tvb, &offset);
    if (choice == DLMS_GET_RESPONSE_NORMAL) {
        col_add_str(pinfo->cinfo, COL_INFO, "Get-Response-Normal");
        result = tvb_get_guint8(tvb, offset);
        offset += 1;
        if (result == 0) {
            subtree = proto_tree_add_subtree(tree, tvb, offset, 0, dlms_ett.data, 0, "Data");
            proto_item_set_len(subtree, tvb_reported_length_remaining(tvb, offset));
            dlms_dissect_data(tvb, pinfo, subtree, &offset);
        } else if (result == 1) {
            dlms_dissect_data_access_result(tvb, pinfo, tree, &offset);
        }
    } else if (choice == DLMS_GET_RESPONSE_WITH_DATABLOCK) {
        col_add_str(pinfo->cinfo, COL_INFO, "Get-Response-With-Datablock");
        dlms_dissect_datablock_g(tvb, pinfo, tree, &offset);
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Get-Response");
    }
}

// Himanshu
void
dlms_dissect_glo_get_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint length = dlms_get_length(tvb, &offset);
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.glo_get_request, 0, "Get-Request (Glo-Ciphered)");

    dlms_glo_ciphered_apdu apdu;
    dlms_dissect_ciphered_apdu(tvb, subtree, offset, length, &apdu);

    tvbuff_t * tvb_plain = dlms_decrypt_ciphered_apdu(&apdu, glo_KEY, client_system_title, ciph_AAD, pinfo);
    dlms_dissect_get_request(tvb_plain, pinfo, subtree, 1);
    //tvb_free(tvb_plain);
}

// Himanshu
void
dlms_dissect_glo_get_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint length = dlms_get_length(tvb, &offset);
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.glo_get_response, 0, "Get-Response (Glo-Ciphered)");

    dlms_glo_ciphered_apdu apdu;
    dlms_dissect_ciphered_apdu(tvb, subtree, offset, length, &apdu);

    tvbuff_t * tvb_plain = dlms_decrypt_ciphered_apdu(&apdu, glo_KEY, server_system_title, ciph_AAD, pinfo);
    dlms_dissect_get_response(tvb_plain, pinfo, subtree, 1);
    //tvb_free(tvb_plain);
}

// Himanshu
void
dlms_dissect_ded_get_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint length = dlms_get_length(tvb, &offset);
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.ded_get_request, 0, "Get-Request (Ded-Ciphered)");

    dlms_ded_ciphered_apdu apdu;
    dlms_dissect_ciphered_apdu(tvb, subtree, offset, length, &apdu);

    tvbuff_t * tvb_plain = dlms_decrypt_ciphered_apdu(&apdu, ded_KEY, client_system_title, ciph_AAD, pinfo);
    dlms_dissect_get_request(tvb_plain, pinfo, subtree, 1);
    //tvb_free(tvb_plain);
}

// Himanshu
void
dlms_dissect_ded_get_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint length = dlms_get_length(tvb, &offset);
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.ded_get_response, 0, "Get-Response (Ded-Ciphered)");

    dlms_ded_ciphered_apdu apdu;
    dlms_dissect_ciphered_apdu(tvb, subtree, offset, length, &apdu);

    tvbuff_t * tvb_plain = dlms_decrypt_ciphered_apdu(&apdu, ded_KEY, server_system_title, ciph_AAD, pinfo);
    dlms_dissect_get_response(tvb_plain, pinfo, subtree, 1);
    //tvb_free(tvb_plain);
}