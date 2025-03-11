
#include "utils/headers.h"

#include "dlms-keys.h"

// ==================================== With Security Suite 0 ==================================== //

// Himanshu - Page 117 - Green Book
enum DLMS_SECURITY_CONTROL {
    DLMS_SECURITY_CONTROL_COMPRESSION = 0x80,
    DLMS_SECURITY_CONTROL_KEY_SET = 0x40,          // {unicast, broadcast}
    DLMS_SECURITY_CONTROL_ENCRYPTION = 0x20,
    DLMS_SECURITY_CONTROL_AUTHENTICATION = 0x10,
    DLMS_SECURITY_CONTROL_SUITE_ID = 0x0f
};

struct dlms_security_header {
    // Security Control Byte
    guint8 security_control_byte = 0;
    gboolean compressed = false;
    gboolean key_set = false;
    gboolean encrypted = false;
    gboolean authenticated = false;
    guint8 suite_id = 0;
    // Invocation Counter
    guint32 invocation_counter = 0;
};

// Himanshu - Page 117 - Green Book
struct dlms_ciphered_apdu {
    // Security Header
    dlms_security_header sh;
    // Ciphered APDU
    const uint8_t * ciphertext = NULL;
    const uint8_t * information = NULL;
    guint text_len = 0;
    // Authentication Tag
    const uint8_t *authentication_tag = NULL;

    ~dlms_ciphered_apdu() {
        // Nothing to be deleted. Trust me. - Himanshu
    }
};


// Himanshu - Page 117 - Green Book
struct dlms_glo_ciphered_apdu
: dlms_ciphered_apdu {
    ~dlms_glo_ciphered_apdu() {
        //
    }
};

// Himanshu - Page - Green Book
struct dlms_ded_ciphered_apdu
: dlms_ciphered_apdu {
    ~dlms_ded_ciphered_apdu() {
        //
    }
};

struct dlms_general_glo_ciphered_apdu {
    uint8_t system_title[8]{ 0 };
    dlms_glo_ciphered_apdu apdu;
};

// Himanshu
gint
dlms_decompress(uint8_t *data, gint length, uint8_t *& decompressed);

// Himanshu
tvbuff_t *
dlms_decrypt_ciphered_apdu(const dlms_ciphered_apdu * apdu, const uint8_t *key, const uint8_t *system_title, const uint8_t *aad, packet_info * pinfo);

// Himanshu - Page 117,308 - Green Book
void
dlms_dissect_security_header(tvbuff_t *tvb, proto_tree *tree, gint offset, dlms_security_header * sh);

// Himanshu - Page 116 - Green Book
void
dlms_dissect_ciphered_apdu(tvbuff_t *tvb, proto_tree *tree, gint offset, gint length, dlms_ciphered_apdu * apdu);

// Himanshu - Page 119 - Green Book
void
dlms_dissect_general_glo_ciphered_apdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint offset);

// Himanshu - Page - Green Book
void
dlms_dissect_general_ded_ciphered_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu - Page - Green Book
void
dlms_dissect_general_ciphered_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu - Page - Green Book
void
dlms_dissect_general_signed_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);

// Himanshu - Page - Green Book
void
dlms_dissect_general_block_transfer_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);
