
#include "utils/headers.h"

#define __TEST_PLUGIN_H__

static int proto_foo;
static int hf_foo_pdu_type;
static int ett_foo = -1;
static int hf_foo_flags;
static int hf_foo_sequenceno;
static int hf_foo_initialip;

static int
dissect_foo(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TEST");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    int offset = 0;
    proto_item* ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    proto_tree* foo_tree = proto_item_add_subtree(ti, ett_foo);
    proto_tree_add_item(foo_tree, hf_foo_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_tree, hf_foo_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_tree, hf_foo_sequenceno, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(foo_tree, hf_foo_initialip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return tvb_captured_length(tvb);
}

void
register_foo(void)
{
    proto_foo = proto_register_protocol(
        "Test Protocol", /* name        */
        "Test",          /* short_name  */
        "test"           /* filter_name */
    );

    static hf_register_info hf[] = {
        { &hf_foo_pdu_type,
            { "FOO PDU Type", "foo.type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_foo_flags,
            { "FOO PDU Flags", "foo.flags",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_foo_sequenceno,
            { "FOO PDU Sequence Number", "foo.seqn",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_foo_initialip,
            { "FOO PDU Initial IP", "foo.initialip",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_foo
    };

    proto_foo = proto_register_protocol(
        "FOO Protocol", /* name       */
        "FOO",          /* short_name */
        "foo"           /* filter_name*/
    );

    proto_register_field_array(proto_foo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
handoff_foo(void)
{
    static dissector_handle_t dh;

    dh = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint("udp.port", 4059, dh);
    dissector_add_uint("tcp.port", 4059, dh);
    for (int i = 4060; i <= 4069; i++) {
        dissector_add_uint("udp.port", i, dh);
        dissector_add_uint("tcp.port", i, dh);
    }
}
