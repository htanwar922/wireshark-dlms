
#include "utils/headers.h"

/* Get the value encoded in the specified length octets in definite form */
unsigned
dlms_get_length(tvbuff_t *tvb, gint *offset);

unsigned
dlms_dissect_length(tvbuff_t *tvb, proto_tree *tree, gint *offset);

/* Calculate the number of bytes used by a TypeDescription of a compact array */
int
dlms_get_type_description_length(tvbuff_t *tvb, gint offset);

/* Attempt to parse a date-time from an octet-string */
void
dlms_append_date_time_maybe(tvbuff_t *tvb, proto_item *item, gint offset, unsigned length);

/* Set the value of an item with a planar data type (not array nor structure) */
void
dlms_set_data_value(tvbuff_t *tvb, proto_item *item, gint choice, gint *offset);
