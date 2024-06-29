
#include "dlms-proto.h"

#include "data-types/dlms-utils.h"
#include "data-types/dlms-asn1.h"

// Himanshu
const char *
dlms_get_object_identifier_name(guint8 v1, guint8 v2, guint16 v3, guint8 v4, guint8 v5, guint8 v6, guint8 v7)
{
    if (v1 == 2 && v2 == 16 && v3 == 756)
        switch ((((v4) << 8 | v5) << 8 | v6) << 8 | v7)
        {
        case 0x05080101:
            return "Context-LN-NoCipher";
        case 0x05080102:
            return "Context-SN-NoCipher";
        case 0x05080103:
            return "Context-LN-Cipher";
        case 0x05080104:
            return "Context-SN-Cipher";
        case 0x05080200:
            return "MechanismName-No-Authentication";
        case 0x05080201:
            return "MechanismName-LowLevelSecurity-Authentication";
        case 0x05080202:
            return "MechanismName-HighLevelSecurity-Authentication";
        case 0x05080203:
            return "MechanismName-HighLevelSecurity-Authentication-MD5";
        case 0x05080204:
            return "MechanismName-HighLevelSecurity-Authentication-SHA1";
        case 0x05080205:
            return "MechanismName-HighLevelSecurity-Authentication-GMAC";
        case 0x05080206:
            return "MechanismName-HighLevelSecurity-Authentication-SHA256";
        case 0x05080207:
            return "MechanismName-HighLevelSecurity-Authentication-ECDSA";
        default:
            break;
        }
    return "Unknown Context";
}

// Himanshu
void
dlms_set_asn_data_value(tvbuff_t *tvb, proto_tree *tree, proto_item *item, guint8 choice, gint *offset)
{
    switch ((ASNType)choice) {
        case ASNT_BOOLEAN: {
            gboolean value = tvb_get_guint8(tvb, *offset);
            proto_item_append_text(item, ": %s", value ? "true" : "false");
            *offset += 1;
            break;
        }
        case ASNT_INTEGER: {
            guint length = dlms_get_length(tvb, offset);
            gint value = 0;
            for (guint i = 0; i < length; i++) {
                value = (value << 8) | tvb_get_guint8(tvb, *offset + i);
                *offset += 1;
            }
            proto_item_append_text(item, ": %d", value);
            break;
        }
        case ASNT_BIT_STRING: {
            guint bits = dlms_get_length(tvb, offset);
            guint bytes = (bits + 7) / 8;
            proto_item_set_text(item, "Bit-string (bits: %u, bytes: %u):", bits, bytes);
            *offset += bytes;
            break;
        }
        case ASNT_OCTET_STRING: {
            guint length = dlms_get_length(tvb, offset);
            proto_item_set_text(item, "Octet String (length %u)", length);
            dlms_append_date_time_maybe(tvb, item, *offset, length);
            *offset += length;
            break;
        }
        case ASNT_NULL_TYPE: {
            proto_item_append_text(item, ": Null");
            break;
        }
        case ASNT_OBJECT_IDENTIFIER: {
            guint length = dlms_get_length(tvb, offset);
            proto_item_set_text(item, "Object Identifier (length %u)", length);

            guint8 value1 = tvb_get_guint8(tvb, *offset) / 40;   // 0x28
            guint8 value2 = tvb_get_guint8(tvb, *offset) % 40;   // 0x28
            guint16 value3_1 = tvb_get_guint8(tvb, *offset + 1) << 8 & 0x7f00;
            guint16 value3_2 = tvb_get_guint8(tvb, *offset + 2);
            guint16 value3 = value3_1 >> 1 | value3_2;
            guint8 value4 = tvb_get_guint8(tvb, *offset + 3);
            guint8 value5 = tvb_get_guint8(tvb, *offset + 4);
            guint8 value6 = tvb_get_guint8(tvb, *offset + 5);
            guint8 value7 = tvb_get_guint8(tvb, *offset + 6);

            item = proto_tree_add_item(tree, *dlms_hdr.context_value.p_id, tvb, *offset, length, ENC_NA);
            proto_item_append_text(item, ": %u.%u.%u.%u.%u.%u.%u", value1, value2, value3, value4, value5, value6, value7);
            proto_item_append_text(item, " (joint-iso-itu-t.%u.%u.%u.%u.%u.%u)", tvb_get_guint8(tvb, *offset), value3, value4, value5, value6, value7);
            item = proto_tree_add_item(tree, *dlms_hdr.context_name.p_id, tvb, *offset, length, ENC_NA);
            proto_item_append_text(item, ": %s ", dlms_get_object_identifier_name(value1, value2, value3, value4, value5, value6, value7));
            *offset += 7;
            break;
        }
        case ASNT_REAL: {
            gfloat value = tvb_get_ntohieee_float(tvb, *offset);
            proto_item_append_text(item, ": %f", value);
            *offset += 4;
            break;
        }
        case ASNT_ENUM: {
            guint length = dlms_get_length(tvb, offset);
            proto_item_append_text(item, ": Enum (length %u)", length);
            *offset += length;
            break;
        }
        case ASNT_NumericString: {
            guint length = dlms_get_length(tvb, offset);
            proto_item_append_text(item, ": Numeric String (length %u)", length);
            *offset += length;
            break;
        }
        case ASNT_PrintableString: {
            guint length = dlms_get_length(tvb, offset);
            proto_item_append_text(item, ": Printable String (length %u)", length);
            *offset += length;
            break;
        }
        case ASNT_TeletexString: {
            guint length = dlms_get_length(tvb, offset);
            proto_item_append_text(item, "Teletex String (length %u)", length);
            *offset += length;
            break;
        }
        case ASNT_VisibleString: {
            guint length = dlms_get_length(tvb, offset);
            proto_item_append_text(item, ": Visible String (length %u)", length);
            *offset += length;
            break;
        }
        case ASNT_GraphicString: {
            guint length = dlms_get_length(tvb, offset);
            proto_item_append_text(item, ": Graphic String (length %u)", length);
            *offset += length;
            break;
        }
        default:
            DISSECTOR_ASSERT_HINT(choice, "Invalid data type");
            break;
    }

}