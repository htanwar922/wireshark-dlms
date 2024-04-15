
#include "headers.h"

/* Choice values for the currently supported ACSE and xDLMS APDUs */
#define DLMS_DATA_NOTIFICATION 15
#define DLMS_AARQ 96
#define DLMS_AARE 97
#define DLMS_RLRQ 98
#define DLMS_RLRE 99
#define DLMS_GET_REQUEST 192
#define DLMS_SET_REQUEST 193
#define DLMS_EVENT_NOTIFICATION_REQUEST 194
#define DLMS_ACTION_REQUEST 195
#define DLMS_GET_RESPONSE 196
#define DLMS_SET_RESPONSE 197
#define DLMS_ACTION_RESPONSE 199
#define DLMS_EXCEPTION_RESPONSE 216
#define DLMS_ACCESS_REQUEST 217
#define DLMS_ACCESS_RESPONSE 218
static const value_string dlms_apdu_names[] = {
    { DLMS_DATA_NOTIFICATION, "data-notification" },
    { DLMS_AARQ, "aarq" },
    { DLMS_AARE, "aare" },
    { DLMS_RLRQ, "rlrq" },
    { DLMS_RLRE, "rlre" },
    { DLMS_GET_REQUEST, "get-request" },
    { DLMS_SET_REQUEST, "set-request" },
    { DLMS_EVENT_NOTIFICATION_REQUEST, "event-notification-request" },
    { DLMS_ACTION_REQUEST, "action-request" },
    { DLMS_GET_RESPONSE, "get-response" },
    { DLMS_SET_RESPONSE, "set-response" },
    { DLMS_ACTION_RESPONSE, "action-response" },
    { DLMS_EXCEPTION_RESPONSE, "exception-response" },
    { DLMS_ACCESS_REQUEST, "access-request" },
    { DLMS_ACCESS_RESPONSE, "access-response" },
    { 0, 0 }
};

/* Choice values for a Get-Request */
#define DLMS_GET_REQUEST_NORMAL 1
#define DLMS_GET_REQUEST_NEXT 2
#define DLMS_GET_REQUEST_WITH_LIST 3
static const value_string dlms_get_request_names[] = {
    { DLMS_GET_REQUEST_NORMAL, "get-request-normal" },
    { DLMS_GET_REQUEST_NEXT, "get-request-next" },
    { DLMS_GET_REQUEST_WITH_LIST, "get-request-with-list" },
    { 0, 0 }
};

/* Choice values for a Get-Response */
#define DLMS_GET_RESPONSE_NORMAL 1
#define DLMS_GET_RESPONSE_WITH_DATABLOCK 2
#define DLMS_GET_RESPONSE_WITH_LIST 3
static const value_string dlms_get_response_names[] = {
    { DLMS_GET_RESPONSE_NORMAL, "get-response-normal" },
    { DLMS_GET_RESPONSE_WITH_DATABLOCK, "get-response-with-datablock" },
    { DLMS_GET_RESPONSE_WITH_LIST, "get-response-with-list" },
    { 0, 0 }
};

/* Choice values for a Set-Request */
#define DLMS_SET_REQUEST_NORMAL 1
#define DLMS_SET_REQUEST_WITH_FIRST_DATABLOCK 2
#define DLMS_SET_REQUEST_WITH_DATABLOCK 3
#define DLMS_SET_REQUEST_WITH_LIST 4
#define DLMS_SET_REQUEST_WITH_LIST_AND_FIRST_DATABLOCK 5
static const value_string dlms_set_request_names[] = {
    { DLMS_SET_REQUEST_NORMAL, "set-request-normal" },
    { DLMS_SET_REQUEST_WITH_FIRST_DATABLOCK, "set-request-with-first-datablock" },
    { DLMS_SET_REQUEST_WITH_DATABLOCK, "set-request-with-datablock" },
    { DLMS_SET_REQUEST_WITH_LIST, "set-request-with-list" },
    { DLMS_SET_REQUEST_WITH_LIST_AND_FIRST_DATABLOCK, "set-request-with-list-and-first-datablock" },
    { 0, 0 }
};

/* Choice values for a Set-Response */
#define DLMS_SET_RESPONSE_NORMAL 1
#define DLMS_SET_RESPONSE_DATABLOCK 2
#define DLMS_SET_RESPONSE_LAST_DATABLOCK 3
#define DLMS_SET_RESPONSE_LAST_DATABLOCK_WITH_LIST 4
#define DLMS_SET_RESPONSE_WITH_LIST 5
static const value_string dlms_set_response_names[] = {
    { DLMS_SET_RESPONSE_NORMAL, "set-response-normal" },
    { DLMS_SET_RESPONSE_DATABLOCK, "set-response-datablock" },
    { DLMS_SET_RESPONSE_LAST_DATABLOCK, "set-response-last-datablock" },
    { DLMS_SET_RESPONSE_LAST_DATABLOCK_WITH_LIST, "set-response-last-datablock-with-list" },
    { DLMS_SET_RESPONSE_WITH_LIST, "set-response-with-list" },
    { 0, 0 }
};

/* Choice values for an Action-Request */
#define DLMS_ACTION_REQUEST_NORMAL 1
#define DLMS_ACTION_REQUEST_NEXT_PBLOCK 2
#define DLMS_ACTION_REQUEST_WITH_LIST 3
#define DLMS_ACTION_REQUEST_WITH_FIRST_PBLOCK 4
#define DLMS_ACTION_REQUEST_WITH_LIST_AND_FIRST_PBLOCK 5
#define DLMS_ACTION_REQUEST_WITH_PBLOCK 6
static const value_string dlms_action_request_names[] = {
    { DLMS_ACTION_REQUEST_NORMAL, "action-request-normal" },
    { DLMS_ACTION_REQUEST_NEXT_PBLOCK, "action-request-next-pblock" },
    { DLMS_ACTION_REQUEST_WITH_LIST, "action-request-with-list" },
    { DLMS_ACTION_REQUEST_WITH_FIRST_PBLOCK, "action-request-with-first-pblock" },
    { DLMS_ACTION_REQUEST_WITH_LIST_AND_FIRST_PBLOCK, "action-request-with-list-and-first-pblock" },
    { DLMS_ACTION_REQUEST_WITH_PBLOCK, "action-request-with-pblock" },
    { 0, 0 }
};

/* Choice values for an Action-Response */
#define DLMS_ACTION_RESPONSE_NORMAL 1
#define DLMS_ACTION_RESPONSE_WITH_PBLOCK 2
#define DLMS_ACTION_RESPONSE_WITH_LIST 3
#define DLMS_ACTION_RESPONSE_NEXT_PBLOCK 4
static const value_string dlms_action_response_names[] = {
    { DLMS_ACTION_RESPONSE_NORMAL, "action-response-normal" },
    { DLMS_ACTION_RESPONSE_WITH_PBLOCK, "action-response-with-pblock" },
    { DLMS_ACTION_RESPONSE_WITH_LIST, "action-response-with-list" },
    { DLMS_ACTION_RESPONSE_NEXT_PBLOCK, "action-response-next-pblock" },
    { 0, 0 },
};

/* Choice values for an Access-Request-Specification */
#define DLMS_ACCESS_REQUEST_GET 1
#define DLMS_ACCESS_REQUEST_SET 2
#define DLMS_ACCESS_REQUEST_ACTION 3
#define DLMS_ACCESS_REQUEST_GET_WITH_SELECTION 4
#define DLMS_ACCESS_REQUEST_SET_WITH_SELECTION 5
static const value_string dlms_access_request_names[] = {
    { DLMS_ACCESS_REQUEST_GET, "access-request-get" },
    { DLMS_ACCESS_REQUEST_SET, "access-request-set" },
    { DLMS_ACCESS_REQUEST_ACTION, "access-request-action" },
    { DLMS_ACCESS_REQUEST_GET_WITH_SELECTION, "access-request-get-with-selection" },
    { DLMS_ACCESS_REQUEST_SET_WITH_SELECTION, "access-request-set-with-selection" },
    { 0, 0 },
};
