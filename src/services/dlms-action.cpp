
#include "utils/dlms-defs.h"
#include "utils/dlms-enums.h"

#include "dlms-proto.h"

#include "data-types/dlms-utils.h"
#include "data-types/dlms-bitsets.h"
#include "data-types/dlms-descriptors.h"
#include "data-types/dlms-data.h"
#include "data-types/dlms-data-ciphered.h"

#include "services/dlms-action.h"

void
dlms_dissect_action_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    int choice, method_invocation_parameters;
    proto_tree *subtree;

    proto_tree_add_item(tree, *dlms_hdr.action_request.p_id, tvb, offset, 1, ENC_NA);
    choice = tvb_get_guint8(tvb, offset);
    offset += 1;
    dlms_dissect_invoke_id_and_priority(tree, tvb, &offset);
    if (choice == DLMS_ACTION_REQUEST_NORMAL) {
        col_add_str(pinfo->cinfo, COL_INFO, "Action-Request-Normal");
        dlms_dissect_cosem_method_descriptor(tvb, pinfo, tree, &offset);
        method_invocation_parameters = tvb_get_guint8(tvb, offset);
        if (method_invocation_parameters) {
            offset += 1;
            subtree = proto_tree_add_subtree(tree, tvb, 0, 0, dlms_ett.data, 0, "Data");
            dlms_dissect_data(tvb, pinfo, subtree, &offset);
        }
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Action-Request");
    }
}

void
dlms_dissect_action_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    unsigned choice, result;
    const gchar *result_name;
    proto_item *item;

    proto_tree_add_item(tree, *dlms_hdr.action_response.p_id, tvb, offset, 1, ENC_NA);
    choice = tvb_get_guint8(tvb, offset);
    offset += 1;
    dlms_dissect_invoke_id_and_priority(tree, tvb, &offset);
    if (choice == DLMS_ACTION_RESPONSE_NORMAL) {
        col_add_str(pinfo->cinfo, COL_INFO, "Action-Response-Normal");
        item = proto_tree_add_item(tree, *dlms_hdr.action_result.p_id, tvb, offset, 1, ENC_NA);
        result = tvb_get_guint8(tvb, offset);
        offset += 1;
        if (result) {
            result_name = val_to_str_const(result, dlms_action_result_names, "unknown");
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", result_name);
            expert_add_info(pinfo, item, dlms_ei.no_success.ids);
        }
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Action-Response");
    }
}

// Himanshu
void
dlms_dissect_glo_action_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint length = dlms_get_length(tvb, &offset);
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.glo_action_request, 0, "Action-Request (Glo-Ciphered)");

    dlms_glo_ciphered_apdu apdu;
    dlms_dissect_glo_ciphered_apdu(tvb, subtree, offset, length, &apdu);

    tvbuff_t * tvb_plain = dlms_decrypt_glo_ciphered_apdu(&apdu, glo_KEY, client_system_title, glo_AAD, pinfo);
    dlms_dissect_action_request(tvb_plain, pinfo, subtree, 1);
    tvb_free(tvb_plain);
}

// Himanshu
void
dlms_dissect_glo_action_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint length = dlms_get_length(tvb, &offset);
    proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.glo_action_response, 0, "Action-Response (Glo-Ciphered)");

    dlms_glo_ciphered_apdu apdu;
    dlms_dissect_glo_ciphered_apdu(tvb, subtree, offset, length, &apdu);

    tvbuff_t * tvb_plain = dlms_decrypt_glo_ciphered_apdu(&apdu, glo_KEY, server_system_title, glo_AAD, pinfo);
    dlms_dissect_action_response(tvb_plain, pinfo, subtree, 1);
    tvb_free(tvb_plain);
}