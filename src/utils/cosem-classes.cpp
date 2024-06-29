
#include <map>

#include "utils/headers.h"
#include "utils/cosem-classes.h"

const char *
dlms_get_attribute_name(const dlms_cosem_class *c, int attribute_id) {
    if (attribute_id > 1 && attribute_id < array_length(c->attributes) + 2) {
        return c->attributes[attribute_id - 2];
    } else if (attribute_id == 1) {
        return "logical_name";
    }
    return 0;
}

const char *
dlms_get_method_name(const dlms_cosem_class *c, int method_id) {
    if (method_id > 0 && method_id < array_length(c->methods) + 1) {
        return c->methods[method_id - 1];
    }
    return 0;
}

static std::map<int, const dlms_cosem_class> classes = {
    {1, {"data", {"value"}}},
    {3, {"register", {"value", "scaler_unit"}, {"reset"}}},
    {4, {"extended_register", {"value", "scaler_unit", "status", "capture_time"}, {"reset"}}},
    {5, {"demand_register", {"current_average_value", "last_average_value", "scaler_unit", "status", "capture_time", "start_time_current", "period", "number_of_periods"}, {"reset", "next_period"}}},
    {7, {"profile_generic", {"buffer", "capture_objects", "capture_period", "sort_method", "sort_object", "entries_in_use", "profile_entries"}, {"reset", "capture", "get_buffer_by_range", "get_buffer_by_index"}}},
    {8, {"clock", {"time", "time_zone", "status", "daylight_savings_begin", "daylight_savings_end", "daylight_savings_deviation", "daylight_savings_enabled", "clock_base"}, {"adjust_to_quarter", "adjust_to_measuring_period", "adjust_to_minute", "adjust_to_preset_time", "preset_adjusting_time", "shift_time"}}},
    {9, {"script_table", {"scripts"}, {"execute"}}},
    {10, {"schedule", {"entries"}, {"enable_disable", "insert", "delete"}}},
    {11, {"special_days_table", {"entries"}, {"insert", "delete"}}},
    {15, {"association_ln", {"object_list", "associated_partners_id", "application_context_name", "xdlms_context_info", "authentication_mechanism_name", "secret", "association_status", "security_setup_reference", "user_list", "current_user"}, {"reply_to_hls_authentication", "change_hls_secret", "add_object", "remove_object", "add_user", "remove_user"}}},
    {17, {"sap_assignment", {"sap_assignment_list"}, {"connect_logical_devices"}}},
    {18, {"image_transfer", {"image_block_size", "image_transferred_blocks_status", "image_first_not_transferred_block_number", "image_transfer_enabled", "image_transfer_status", "image_to_activate_info"}, {"image_transfer_initiate", "image_block_transfer", "image_verify", "image_activate"}}},
    {19, {"iec_local_port_setup", {}}},
    {20, {"activity_calendar", {"calendar_name_active", "season_profile_active", "week_profile_table_active", "day_profile_table_active", "calendar_name_passive", "season_profile_passive", "week_profile_table_passive", "day_profile_table_passive", "active_passive_calendar_time"}, {"active_passive_calendar"}}},
    {21, {"register_monitor", {"thresholds", "monitored_value", "actions"}}},
    {22, {"single_action_schedule", {"executed_script", "type", "execution_time"}}},
    {23, {"iec_hdlc_setup", {"comm_speed", "window_size_transmit", "window_size_receive", "max_info_field_length_transmit", "max_info_field_length_receive", "inter_octet_time_out", "inactivity_time_out", "device_address"}}},
    {24, {"modem_configuration", {}}},
    {25, {"auto_answer", {}}},
    {26, {"auto_connect", {}}},
    {27, {"data_protection", {"protection_buffer", "protection_object_list", "protection_parameters_get", "protection_parameters_set", "required_protection"}, {"get_protected_attributes", "set_protected_attributes", "invoke_protected_method"}}},
    {28, {"push_setup", {}}},
    {29, {"tcp_udp_setup", {}}},
    {30, {"ipv4_setup", {}}},
    {31, {"mac_address_setup", {}}},
    {32, {"disconnect_control", {"output_state", "control_state", "control_mode"}, {"remote_disconnect", "remote_reconnect"}}},
    {33, {"limiter", {"monitored_value", "threshold_active", "threshold_normal", "threshold_emergency", "min_over_threshold_duration", "min_under_threshold_duration", "emergency_profile", "emergency_profile_group_id_list", "emergency_profile_active", "actions"}}},
    {34, {"zigbee_network_control", {"enable_disable_joining", "join_timeout", "active_devices"}, {"register_device", "unregister_device", "unregister_all_devices", "backup_pan", "restore_pan", "identify_device", "remove_mirror", "update_network_key", "update_link_key", "create_pan", "remove_pan"}}},
    {35, {"account", {"account_mode_and_status", "current_credit_in_use", "current_credit_status", "available_credit", "amount_to_clear", "clearance_threshold", "aggregated_debt", "credit_reference_list", "charge_reference_list", "credit_charge_configuration", "token_gateway_configuration", "account_activation_time", "account_closure_time", "currency", "low_credit_threshold", "next_credit_available_threshold", "max_provision", "max_provision_period"}, {"activate_account", "close_account", "reset_account"}}},
    {36, {"credit", {"current_credit_amount", "credit_type", "priority", "warning_threshold", "limit", "credit_configuration", "credit_status", "preset_credit_amount", "credit_available_threshold", "period"}, {"update_amount", "set_amount_to_value", "invoke_credit"}}},
    {37, {"charge", {"total_amount_paid", "charge_type", "priority", "unit_charge_active", "unit_charge_passive", "unit_charge_activation_time", "period", "charge_configuration", "last_collection_time", "last_collection_amount", "total_amount_remaining", "proportion"}, {"update_unit_charge", "activate_passive_unit_charge", "collect", "update_total_amount_remaining", "set_total_amount_remaining"}}},
    {38, {"token_gateway", {"token", "token_time", "token_description", "token_delivery_method", "token_status"}, {"enter"}}},
    {39, {"extended_data", {"value_active", "scaler_unit_active", "value_passive", "scaler_unit_passive", "activate_passive_value_time"}, {"reset", "activate_passive_value"}}}
};

/* Get the DLMS/COSEM class with the specified class_id */
const dlms_cosem_class *
dlms_get_class(int class_id) {
    auto it = classes.find(class_id);
    if (it != classes.end())
        return &it->second;
    return 0;
}
