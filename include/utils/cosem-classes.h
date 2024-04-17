
#include "headers.h"

/* Structure with the names of a DLMS/COSEM class */
typedef struct dlms_cosem_class {
    const char *name;
    const char *attributes[18]; /* index 0 is attribute 2 (attribute 1 is always "logical_name") */
    const char *methods[11]; /* index 0 is method 1 */
} dlms_cosem_class;

static const char *
dlms_get_attribute_name(const dlms_cosem_class *c, int attribute_id) {
    if (attribute_id > 1 && attribute_id < array_length(c->attributes) + 2) {
        return c->attributes[attribute_id - 2];
    } else if (attribute_id == 1) {
        return "logical_name";
    }
    return 0;
}

static const char *
dlms_get_method_name(const dlms_cosem_class *c, int method_id) {
    if (method_id > 0 && method_id < array_length(c->methods) + 1) {
        return c->methods[method_id - 1];
    }
    return 0;
}

/* Get the DLMS/COSEM class with the specified class_id */
static const dlms_cosem_class *
dlms_get_class(int class_id) {
    const short ids[] = {
        1, /* data */
        3, /* register */
        4, /* extended register */
        5, /* demand register */
        7, /* profile generic */
        8, /* clock */
        9, /* script table */
        10, /* schedule */
        11, /* special days table */
        15, /* association ln */
        17, /* sap assignment */
        18, /* image transfer */
        19, /* IEC local port setup */          // Himanshu - From Gurux
        20, /* activity calendar */
        21, /* register monitor */
        22, /* single action schedule */
        23, /* IEC hdlc setup */
        27, /* modem configuration */           // Himanshu - From Gurux
        28, /* auto answer */                   // Himanshu - From Gurux
        29, /* auto connect */                  // Himanshu - From Gurux
        30, /* data protection */
        40, /* push setup */                    // Himanshu - From Gurux
        41, /* TCP/UDP Setup */                 // Himanshu - From Gurux
        42, /* IPv4 setup */                     // Himanshu - From Gurux
        43, /* MAC address setup */             // Himanshu - From Gurux
        70, /* disconnect control */
        71, /* limiter */
        104, /* zigbee network control */
        111, /* account */
        112, /* credit */
        113, /* charge */
        115, /* token gateway */
        9000, /* extended data */
    };
    static const struct dlms_cosem_class classes[] = {
        {
            "data",
            {
                "value"
            }
        },{
            "register",
            {
                "value",
                "scaler_unit"
            },{
                "reset"
            }
        },{
            "extended_register",
            {
                "value",
                "scaler_unit",
                "status",
                "capture_time"
            },{
                "reset"
            }
        },{
            "demand_register",
            {
                "current_average_value",
                "last_average_value",
                "scaler_unit",
                "status",
                "capture_time",
                "start_time_current",
                "period",
                "number_of_periods"
            },{
                "reset",
                "next_period"
            }
        },{
            "profile_generic",
            {
                "buffer",
                "capture_objects",
                "capture_period",
                "sort_method",
                "sort_object",
                "entries_in_use",
                "profile_entries"
            },{
                "reset",
                "capture",
                "get_buffer_by_range",
                "get_buffer_by_index"
            }
        },{
            "clock",
            {
                "time",
                "time_zone",
                "status",
                "daylight_savings_begin",
                "daylight_savings_end",
                "daylight_savings_deviation",
                "daylight_savings_enabled",
                "clock_base"
            },{
                "adjust_to_quarter",
                "adjust_to_measuring_period",
                "adjust_to_minute",
                "adjust_to_preset_time",
                "preset_adjusting_time",
                "shift_time"
            }
        },{
            "script_table",
            {
                "scripts"
            },{
                "execute"
            }
        },{
            "schedule",
            {
                "entries"
            },{
                "enable_disable",
                "insert",
                "delete"
            }
        },{
            "special_days_table",
            {
                "entries"
            },{
                "insert",
                "delete"
            }
        },{
            "association_ln",
            {
                "object_list",
                "associated_partners_id",
                "application_context_name",
                "xdlms_context_info",
                "authentication_mechanism_name",
                "secret",
                "association_status",
                "security_setup_reference",
                "user_list",
                "current_user"
            },{
                "reply_to_hls_authentication",
                "change_hls_secret",
                "add_object",
                "remove_object",
                "add_user",
                "remove_user"
            }
        },{
            "sap_assignment",
            {
                "sap_assignment_list"
            },{
                "connect_logical_devices"
            }
        },{
            "image_transfer",
            {
                "image_block_size",
                "image_transferred_blocks_status",
                "image_first_not_transferred_block_number",
                "image_transfer_enabled",
                "image_transfer_status",
                "image_to_activate_info"
            },{
                "image_transfer_initiate",
                "image_block_transfer",
                "image_verify",
                "image_activate"
            }
        },{
            "iec_local_port_setup",
            {
                // Himanshu - From Gurux
            },{
                // Himanshu - From Gurux
            }
        },{
            "activity_calendar",
            {
                "calendar_name_active",
                "season_profile_active",
                "week_profile_table_active",
                "day_profile_table_active",
                "calendar_name_passive",
                "season_profile_passive",
                "week_profile_table_passive",
                "day_profile_table_passive",
                "active_passive_calendar_time"
            },{
                "active_passive_calendar"
            }
        },{
            "register_monitor",
            {
                "thresholds",
                "monitored_value",
                "actions"
            }
        },{
            "single_action_schedule",
            {
                "executed_script",
                "type",
                "execution_time"
            }
        },{
            "iec_hdlc_setup",
            {
                "comm_speed",
                "window_size_transmit",
                "window_size_receive",
                "max_info_field_length_transmit",
                "max_info_field_length_receive",
                "inter_octet_time_out",
                "inactivity_time_out",
                "device_address"
            }
        },{
            "modem_configuration",
            {
                // Himanshu - From Gurux
            },{
                // Himanshu - From Gurux
            }
        },{
            "auto_answer",
            {
                // Himanshu - From Gurux
            },{
                // Himanshu - From Gurux
            }
        },{
            "auto_connect",
            {
                // Himanshu - From Gurux
            },{
                // Himanshu - From Gurux
            }
        },{
            "data_protection",
            {
                "protection_buffer",
                "protection_object_list",
                "protection_parameters_get",
                "protection_parameters_set",
                "required_protection"
            },{
                "get_protected_attributes",
                "set_protected_attributes",
                "invoke_protected_method"
            }
        },{
            "push_setup",
            {
                // Himanshu - From Gurux
            },{
                // Himanshu - From Gurux
            }
        },{
            "tcp_udp_setup",
            {
                // Himanshu - From Gurux
            },{
                // Himanshu - From Gurux
            }
        },{
            "ipv4_setup",
            {
                // Himanshu - From Gurux
            },{
                // Himanshu - From Gurux
            }
        },{
            "mac_address_setup",
            {
                // Himanshu - From Gurux
            },{
                // Himanshu - From Gurux
            }
        },{
            "disconnect_control",
            {
                "output_state",
                "control_state",
                "control_mode"
            },{
                "remote_disconnect",
                "remote_reconnect"
            }
        },{
            "limiter",
            {
                "monitored_value",
                "threshold_active",
                "threshold_normal",
                "threshold_emergency",
                "min_over_threshold_duration",
                "min_under_threshold_duration",
                "emergency_profile",
                "emergency_profile_group_id_list",
                "emergency_profile_active",
                "actions"
            }
        },{
            "zigbee_network_control",
            {
                "enable_disable_joining",
                "join_timeout",
                "active_devices"
            },{
                "register_device",
                "unregister_device",
                "unregister_all_devices",
                "backup_pan",
                "restore_pan",
                "identify_device",
                "remove_mirror",
                "update_network_key",
                "update_link_key",
                "create_pan",
                "remove_pan"
            }
        },{
            "account",
            {
                "account_mode_and_status",
                "current_credit_in_use",
                "current_credit_status",
                "available_credit",
                "amount_to_clear",
                "clearance_threshold",
                "aggregated_debt",
                "credit_reference_list",
                "charge_reference_list",
                "credit_charge_configuration",
                "token_gateway_configuration",
                "account_activation_time",
                "account_closure_time",
                "currency",
                "low_credit_threshold",
                "next_credit_available_threshold",
                "max_provision",
                "max_provision_period"
            },{
                "activate_account",
                "close_account",
                "reset_account"
            }
        },{
            "credit",
            {
                "current_credit_amount",
                "credit_type",
                "priority",
                "warning_threshold",
                "limit",
                "credit_configuration",
                "credit_status",
                "preset_credit_amount",
                "credit_available_threshold",
                "period"
            },{
                "update_amount",
                "set_amount_to_value",
                "invoke_credit"
            }
        },{
            "charge",
            {
                "total_amount_paid",
                "charge_type",
                "priority",
                "unit_charge_active",
                "unit_charge_passive",
                "unit_charge_activation_time",
                "period",
                "charge_configuration",
                "last_collection_time",
                "last_collection_amount",
                "total_amount_remaining",
                "proportion"
            },{
                "update_unit_charge",
                "activate_passive_unit_charge",
                "collect",
                "update_total_amount_remaining",
                "set_total_amount_remaining"
            }
        },{
            "token_gateway",
            {
                "token",
                "token_time",
                "token_description",
                "token_delivery_method",
                "token_status"
            },{
                "enter"
            }
        },{
            "extended_data",
            {
                "value_active",
                "scaler_unit_active",
                "value_passive",
                "scaler_unit_passive",
                "activate_passive_value_time"
            },{
                "reset",
                "activate_passive_value"
            }
        }
    };
    unsigned i;

    for (i = 0; i < array_length(ids); i++) {
        if (ids[i] == class_id) {
            return &classes[i];
        }
    }

    return 0;
}
