
/* Get the value encoded in the specified length octets in definite form */
static unsigned
dlms_get_length(tvbuff_t *tvb, gint *offset)
{
    unsigned length;

    length = tvb_get_guint8(tvb, *offset);
    if ((length & 0x80) == 0) {
        *offset += 1;
    } else {
        unsigned i, n = length & 0x7f;
        length = 0;
        for (i = 0; i < n; i++) {
            length = (length << 8) + tvb_get_guint8(tvb, *offset + 1 + i);
        }
        *offset += 1 + n;
    }

    return length;
}

static unsigned
dlms_dissect_length(tvbuff_t *tvb, proto_tree *tree, gint *offset)
{
    gint start;
    unsigned length;
    proto_item *item;

    start = *offset;
    length = dlms_get_length(tvb, offset);
    item = proto_tree_add_item(tree, &dlms_hfi.length, tvb, start, *offset - start, ENC_NA);
    proto_item_append_text(item, ": %u", length);

    return length;
}

/* Calculate the number of bytes used by a TypeDescription of a compact array */
static int
dlms_get_type_description_length(tvbuff_t *tvb, gint offset)
{
    int choice = tvb_get_guint8(tvb, offset);
    if (choice == 1) { // array
        return 1 + 2 + dlms_get_type_description_length(tvb, offset + 3);
    } else if (choice == 2) { // structure
        gint end_offset = offset + 1;
        int sequence_of = dlms_get_length(tvb, &end_offset);
        while (sequence_of--) {
            end_offset += dlms_get_type_description_length(tvb, end_offset);
        }
        return end_offset - offset;
    } else {
        return 1;
    }
}

/* Attempt to parse a date-time from an octet-string */
static void
dlms_append_date_time_maybe(tvbuff_t *tvb, proto_item *item, gint offset, unsigned length)
{
    unsigned year, month, day_of_month, day_of_week;
    unsigned hour, minute, second, hundredths;
    /* TODO: unsigned deviation, clock; */

    if (length != 12) return;
    year = tvb_get_ntohs(tvb, offset);
    month = tvb_get_guint8(tvb, offset + 2);
    if (month < 1 || (month > 12 && month < 0xfd)) return;
    day_of_month = tvb_get_guint8(tvb, offset + 3);
    if (day_of_month < 1 || (day_of_month > 31 && day_of_month < 0xfd)) return;
    day_of_week = tvb_get_guint8(tvb, offset + 4);
    if (day_of_week < 1 || (day_of_week > 7 && day_of_week < 0xff)) return;
    hour = tvb_get_guint8(tvb, offset + 5);
    if (hour > 23 && hour < 0xff) return;
    minute = tvb_get_guint8(tvb, offset + 6);
    if (minute > 59 && minute < 0xff) return;
    second = tvb_get_guint8(tvb, offset + 7);
    if (second > 59 && second < 0xff) return;
    hundredths = tvb_get_guint8(tvb, offset + 8);
    if (hundredths > 99 && hundredths < 0xff) return;

    proto_item_append_text(item, year < 0xffff ? " (%u" : " (%X", year);
    proto_item_append_text(item, month < 13 ? "/%02u" : "/%02X", month);
    proto_item_append_text(item, day_of_month < 32 ? "/%02u" : "/%02X", day_of_month);
    proto_item_append_text(item, hour < 24 ? " %02u" : " %02X", hour);
    proto_item_append_text(item, minute < 60 ? ":%02u" : ":%02X", minute);
    proto_item_append_text(item, second < 60 ? ":%02u" : ":%02X", second);
    proto_item_append_text(item, hundredths < 100 ? ".%02u)" : ".%02X)", hundredths);
}

/* Set the value of an item with a planar data type (not array nor structure) */
static void
dlms_set_data_value(tvbuff_t *tvb, proto_item *item, gint choice, gint *offset)
{
    if (choice == 0) {
        proto_item_set_text(item, "Null");
    } else if (choice == 3) {
        gboolean value = tvb_get_guint8(tvb, *offset);
        proto_item_set_text(item, "Boolean: %s", value ? "true" : "false");
        *offset += 1;
    } else if (choice == 4) {
        guint bits = dlms_get_length(tvb, offset);
        guint bytes = (bits + 7) / 8;
        proto_item_set_text(item, "Bit-string (bits: %u, bytes: %u):", bits, bytes);
        *offset += bytes;
    } else if (choice == 5) {
        gint32 value = tvb_get_ntohl(tvb, *offset);
        proto_item_set_text(item, "Double Long: %d", value);
        *offset += 4;
    } else if (choice == 6) {
        guint32 value = tvb_get_ntohl(tvb, *offset);
        proto_item_set_text(item, "Double Long Unsigned: %u", value);
        *offset += 4;
    } else if (choice == 9) {
        guint length = dlms_get_length(tvb, offset);
        proto_item_set_text(item, "Octet String (length %u)", length);
        dlms_append_date_time_maybe(tvb, item, *offset, length);
        *offset += length;
    } else if (choice == 10) {
        guint length = dlms_get_length(tvb, offset);
        proto_item_set_text(item, "Visible String (length %u)", length);
        *offset += length;
    } else if (choice == 12) {
        guint length = dlms_get_length(tvb, offset);
        proto_item_set_text(item, "UTF8 String (length %u)", length);
        *offset += length;
    } else if (choice == 13) {
        guint value = tvb_get_guint8(tvb, *offset);
        proto_item_set_text(item, "BCD: 0x%02x", value);
        *offset += 1;
    } else if (choice == 15) {
	gint8 value = tvb_get_guint8(tvb, *offset);
        proto_item_set_text(item, "Integer: %d", value);
        *offset += 1;
    } else if (choice == 16) {
        gint16 value = tvb_get_ntohs(tvb, *offset);
        proto_item_set_text(item, "Long: %d", value);
        *offset += 2;
    } else if (choice == 17) {
        guint8 value = tvb_get_guint8(tvb, *offset);
        proto_item_set_text(item, "Unsigned: %u", value);
        *offset += 1;
    } else if (choice == 18) {
        guint16 value = tvb_get_ntohs(tvb, *offset);
        proto_item_set_text(item, "Long Unsigned: %u", value);
        *offset += 2;
    } else if (choice == 20) {
        gint64 value = tvb_get_ntoh64(tvb, *offset);
        proto_item_set_text(item, "Long64: %ld", value);
        *offset += 8;
    } else if (choice == 21) {
        guint64 value = tvb_get_ntoh64(tvb, *offset);
        proto_item_set_text(item, "Long64 Unsigned: %lu", value);
        *offset += 8;
    } else if (choice == 22) {
        guint8 value = tvb_get_guint8(tvb, *offset);
        proto_item_set_text(item, "Enum: %u", value);
        *offset += 1;
    } else if (choice == 23) {
        gfloat value = tvb_get_ntohieee_float(tvb, *offset);
        proto_item_set_text(item, "Float32: %f", value);
        *offset += 4;
    } else if (choice == 24) {
        gdouble value = tvb_get_ntohieee_double(tvb, *offset);
        proto_item_set_text(item, "Float64: %f", value);
        *offset += 8;
    } else if (choice == 25) {
        proto_item_set_text(item, "Date Time");
        *offset += 12;
    } else if (choice == 26) {
        proto_item_set_text(item, "Date");
        *offset += 5;
    } else if (choice == 27) {
        proto_item_set_text(item, "Time");
        *offset += 4;
    } else if (choice == 255) {
        proto_item_set_text(item, "Don't Care");
    } else {
        DISSECTOR_ASSERT_HINT(choice, "Invalid data type");
    }
}
