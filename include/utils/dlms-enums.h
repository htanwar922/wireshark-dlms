
#include "headers.h"

/* Enumerated values for a Data-Access-Result */
static const value_string dlms_data_access_result_names[] = {
    { 0, "success" },
    { 1, "hardware-fault" },
    { 2, "temporary-failure" },
    { 3, "read-write-denied" },
    { 4, "object-undefined" },
    { 9, "object-class-inconsistent" },
    { 11, "object-unvailable" },
    { 12, "type-unmatched" },
    { 13, "scope-of-access-violated" },
    { 14, "data-block-unavailable" },
    { 15, "long-get-aborted" },
    { 16, "no-long-get-in-progress" },
    { 17, "long-set-aborted" },
    { 18, "no-long-set-in-progress" },
    { 19, "data-block-number-invalid" },
    { 250, "other-reason" },
    { 0, 0 }
};

/* Enumerated values for an Action-Result */
static const value_string dlms_action_result_names[] = {
    { 0, "success" },
    { 1, "hardware-fault" },
    { 2, "temporary-failure" },
    { 3, "read-write-denied" },
    { 4, "object-undefined" },
    { 9, "object-class-inconsistent" },
    { 11, "object-unavailable" },
    { 12, "type-unmatched" },
    { 13, "scope-of-access-violated" },
    { 14, "data-block-unavailable" },
    { 15, "long-action-aborted" },
    { 16, "no-long-action-in-progress" },
    { 250, "other-reason" },
    { 0, 0 }
};

/* Enumerated values for a state-error in an Exception-Response */
static const value_string dlms_state_error_names[] = {
    { 1, "service-not-allowed" },
    { 2, "service-unknown" },
    { 0, 0 }
};

/* Enumerated values for a service-error in an Exception-Response */
static const value_string dlms_service_error_names[] = {
    { 1, "operation-not-possible" },
    { 2, "service-not-supported" },
    { 3, "other-reason" },
    { 0, 0 }
};
