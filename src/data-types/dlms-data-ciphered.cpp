
#include "dlms-proto.h"

#include "data-types/dlms-utils.h"
#include "data-types/dlms-data-ciphered.h"

#include "dlms-keys.h"

#include "dlms.h"

// ==================================== With Security Suite 0 ==================================== //

// Himanshu
gint
dlms_decompress(uint8_t *data, gint length, uint8_t *& decompressed)
{
    // decompress here
    g_print("Compression is not supported\n");
    decompressed = (uint8_t *)wmem_alloc(wmem_packet_scope(), length);
    memcpy(decompressed, data, length);
    return length;
}

// Himanshu
tvbuff_t *
dlms_decrypt_glo_ciphered_apdu(const dlms_glo_ciphered_apdu * apdu, const uint8_t *key, const uint8_t *system_title, const uint8_t *aad, packet_info * pinfo)
{
    gint len = 0;
    uint8_t * plaintext = NULL;

    ((uint8_t *)aad)[0] = apdu->security_control_byte;
    uint8_t * iv = (uint8_t *)wmem_alloc(wmem_packet_scope(), IV_LEN);
    memcpy(iv, system_title, 8);
    for (int i = 0; i < 4; i++) {
        iv[i + 8] = (apdu->invocation_counter >> (24 - i * 8)) & 0xff;
    }

    if (apdu->encrypted) {
        plaintext = (uint8_t *)wmem_alloc(wmem_packet_scope(), apdu->text_len);
        AES_128_GCM aes(key, iv);
        len = aes.Decrypt(apdu->glo_ciphertext, apdu->text_len, plaintext, apdu->glo_authentication_tag, aad, AAD_LEN);
        if (len < 0) {
            g_print("Failed to decrypt GLO ciphered APDU\n");
            wmem_free(wmem_packet_scope(), plaintext);
            delete[] iv;
            return 0;
        }
    }
    else {
        plaintext = (uint8_t *)wmem_alloc(wmem_packet_scope(), apdu->text_len);
        memcpy(plaintext, apdu->glo_information, apdu->text_len);
    }
    if (apdu->compressed) {
        uint8_t * compressed = plaintext;
        plaintext = NULL;
        len = dlms_decompress(compressed, len, plaintext);
        wmem_free(wmem_packet_scope(), compressed);
    }

    tvbuff_t * tvb_plain = tvb_new_real_data(plaintext, len, len);
    add_new_data_source(pinfo, tvb_plain, "Decrypted Data");
    wmem_free(wmem_packet_scope(), plaintext);
    wmem_free(wmem_packet_scope(), iv);
    return tvb_plain;
}


// Himanshu - Page 117,308 - Green Book
void
dlms_dissect_security_header(tvbuff_t *tvb, proto_tree *tree, gint offset, dlms_glo_ciphered_apdu * apdu)
{
    proto_tree *subtree;
    hf_register_info *hfi;

    apdu->security_control_byte = tvb_get_guint8(tvb, offset);
    apdu->compressed = apdu->security_control_byte & DLMS_SECURITY_CONTROL_COMPRESSION;
    apdu->key_set = apdu->security_control_byte & DLMS_SECURITY_CONTROL_KEY_SET;
    apdu->encrypted = apdu->security_control_byte & DLMS_SECURITY_CONTROL_ENCRYPTION;
    apdu->authenticated = apdu->security_control_byte & DLMS_SECURITY_CONTROL_AUTHENTICATION;
    apdu->suite_id = apdu->security_control_byte & DLMS_SECURITY_CONTROL_SUITE_ID;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 1, dlms_ett.glo_security_control_byte, 0, "Security Control Byte");
    proto_item_append_text(subtree, ": 0x%02x", tvb_get_guint8(tvb, offset));
    for (hfi = &dlms_hdr.glo_security_control_compression; hfi <= &dlms_hdr.glo_security_control_suite_id; hfi++) {
        proto_tree_add_item(subtree, *hfi->p_id, tvb, offset, 1, ENC_NA);
    }
    offset += 1;

    apdu->invocation_counter = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, *dlms_hdr.glo_invocation_counter.p_id, tvb, offset, 4, ENC_NA);
    offset += 4;
}

// Himanshu - Page 116 - Green Book
void
dlms_dissect_glo_ciphered_apdu(tvbuff_t *tvb, proto_tree *tree, gint offset, gint length, dlms_glo_ciphered_apdu * apdu)
{
    dlms_dissect_security_header(tvb, tree, offset, apdu);
    offset += 5;

    guint len = length - 5;
    if (apdu->authenticated) {
        len -= TAG_LEN;
    }

    apdu->text_len = len;
    if (apdu->encrypted) {
        apdu->glo_ciphertext = tvb_get_ptr(tvb, offset, len);
        proto_tree_add_item(tree, *dlms_hdr.glo_ciphertext.p_id, tvb, offset, len, ENC_ASCII|ENC_NA);
    } else {
        apdu->glo_information = tvb_get_ptr(tvb, offset, len);
        proto_tree_add_item(tree, *dlms_hdr.glo_information.p_id, tvb, offset, len, ENC_ASCII|ENC_NA);
    }
    offset += len;

    if (apdu->authenticated) {
        apdu->glo_authentication_tag = tvb_get_ptr(tvb, offset, TAG_LEN);
        proto_tree_add_item(tree, *dlms_hdr.glo_authentication_tag.p_id, tvb, offset, TAG_LEN, ENC_ASCII|ENC_NA);
    }
}

// Himanshu - Page 119 - Green Book
void
dlms_dissect_general_glo_ciphered_apdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint offset)
{
    col_set_str(pinfo->cinfo, COL_INFO, "General-Glo-Ciphered");

    gint length = tvb_reported_length_remaining(tvb, offset);
    proto_tree* subtree = proto_tree_add_subtree(tree, tvb, offset, length, dlms_ett.general_glo_ciphered_apdu, 0, "General-Glo-Ciphered");

    dlms_general_glo_ciphered_apdu general_apdu;

    gint len = dlms_get_length(tvb, &offset);
    if (len == sizeof general_apdu.system_title)
    {
        proto_tree_add_item(subtree, *dlms_hdr.general_glo_ciphered_system_title.p_id, tvb, offset, len, ENC_ASCII | ENC_NA);
        memcpy(general_apdu.system_title, tvb_get_ptr(tvb, offset, len), len);
        offset += len;
    }
    else {
        proto_tree_add_item(subtree, *dlms_hdr.general_glo_ciphered_system_title.p_id, tvb, offset, 0, ENC_ASCII | ENC_NA);
        g_print("Invalid System Title length\n");
        return;
    }

    dlms_glo_ciphered_apdu& apdu = general_apdu.apdu;

    len = dlms_get_length(tvb, &offset);
    dlms_dissect_glo_ciphered_apdu(tvb, subtree, offset, len, &apdu);

    tvbuff_t* tvb_plain = dlms_decrypt_glo_ciphered_apdu(&apdu, glo_KEY, general_apdu.system_title, glo_AAD, pinfo);
    subtree = proto_tree_add_subtree(tree, tvb_plain, 0, apdu.text_len, dlms_ett.general_glo_ciphered_apdu_decoded, 0, "General-Glo-Ciphered (Decoded)");
    dlms_dissect_apdu(tvb_plain, pinfo, subtree, 0);
    //tvb_free(tvb_plain);
}
