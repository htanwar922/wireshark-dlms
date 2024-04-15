
#include "headers.h"

/* Names of the values of the service-class bit in the Invoke-Id-And-Priority */
static const value_string dlms_service_class_names[] = {
    { 0, "unconfirmed" },
    { 1, "confirmed" },
    { 0, 0 }
};

/* Names of the values of the priority bit in the Invoke-Id-And-Priority */
static const value_string dlms_priority_names[] = {
    { 0, "normal" },
    { 1, "high" },
    { 0, 0 }
};

/* Names of the values of the self-descriptive bit in the Long-Invoke-Id-And-Priority */
static const value_string dlms_self_descriptive_names[] = {
    { 0, "not-self-descriptive" },
    { 1, "self-descriptive" },
    { 0, 0 }
};

/* Names of the values of the processing-option bit in the Long-Invoke-Id-And-Priority */
static const value_string dlms_processing_option_names[] = {
    { 0, "continue-on-error" },
    { 1, "break-on-error" },
    { 0, 0 }
};
