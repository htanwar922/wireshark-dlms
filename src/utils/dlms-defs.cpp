
#include "utils/dlms-defs.h"

const value_string dlms_apdu_names[] = {
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

    // Himanshu
    { DLMS_GLO_GET_REQUEST, "glo-get-request" },
    { DLMS_GLO_SET_REQUEST, "glo-set-request" },
    { DLMS_GLO_ACTION_REQUEST, "glo-action-request" },
    { DLMS_GLO_GET_RESPONSE, "glo-get-response" },
    { DLMS_GLO_SET_RESPONSE, "glo-set-response" },
    { DLMS_GLO_ACTION_RESPONSE, "glo-action-response" },

    { DLMS_EXCEPTION_RESPONSE, "exception-response" },
    { DLMS_ACCESS_REQUEST, "access-request" },
    { DLMS_ACCESS_RESPONSE, "access-response" },
    { 0, 0 }
};

const value_string dlms_get_request_names[] = {
    { DLMS_GET_REQUEST_NORMAL, "get-request-normal" },
    { DLMS_GET_REQUEST_NEXT, "get-request-next" },
    { DLMS_GET_REQUEST_WITH_LIST, "get-request-with-list" },
    { 0, 0 }
};

const value_string dlms_get_response_names[] = {
    { DLMS_GET_RESPONSE_NORMAL, "get-response-normal" },
    { DLMS_GET_RESPONSE_WITH_DATABLOCK, "get-response-with-datablock" },
    { DLMS_GET_RESPONSE_WITH_LIST, "get-response-with-list" },
    { 0, 0 }
};

const value_string dlms_set_request_names[] = {
    { DLMS_SET_REQUEST_NORMAL, "set-request-normal" },
    { DLMS_SET_REQUEST_WITH_FIRST_DATABLOCK, "set-request-with-first-datablock" },
    { DLMS_SET_REQUEST_WITH_DATABLOCK, "set-request-with-datablock" },
    { DLMS_SET_REQUEST_WITH_LIST, "set-request-with-list" },
    { DLMS_SET_REQUEST_WITH_LIST_AND_FIRST_DATABLOCK, "set-request-with-list-and-first-datablock" },
    { 0, 0 }
};

const value_string dlms_set_response_names[] = {
    { DLMS_SET_RESPONSE_NORMAL, "set-response-normal" },
    { DLMS_SET_RESPONSE_DATABLOCK, "set-response-datablock" },
    { DLMS_SET_RESPONSE_LAST_DATABLOCK, "set-response-last-datablock" },
    { DLMS_SET_RESPONSE_LAST_DATABLOCK_WITH_LIST, "set-response-last-datablock-with-list" },
    { DLMS_SET_RESPONSE_WITH_LIST, "set-response-with-list" },
    { 0, 0 }
};

const value_string dlms_action_request_names[] = {
    { DLMS_ACTION_REQUEST_NORMAL, "action-request-normal" },
    { DLMS_ACTION_REQUEST_NEXT_PBLOCK, "action-request-next-pblock" },
    { DLMS_ACTION_REQUEST_WITH_LIST, "action-request-with-list" },
    { DLMS_ACTION_REQUEST_WITH_FIRST_PBLOCK, "action-request-with-first-pblock" },
    { DLMS_ACTION_REQUEST_WITH_LIST_AND_FIRST_PBLOCK, "action-request-with-list-and-first-pblock" },
    { DLMS_ACTION_REQUEST_WITH_PBLOCK, "action-request-with-pblock" },
    { 0, 0 }
};

const value_string dlms_action_response_names[] = {
    { DLMS_ACTION_RESPONSE_NORMAL, "action-response-normal" },
    { DLMS_ACTION_RESPONSE_WITH_PBLOCK, "action-response-with-pblock" },
    { DLMS_ACTION_RESPONSE_WITH_LIST, "action-response-with-list" },
    { DLMS_ACTION_RESPONSE_NEXT_PBLOCK, "action-response-next-pblock" },
    { 0, 0 },
};

const value_string dlms_access_request_names[] = {
    { DLMS_ACCESS_REQUEST_GET, "access-request-get" },
    { DLMS_ACCESS_REQUEST_SET, "access-request-set" },
    { DLMS_ACCESS_REQUEST_ACTION, "access-request-action" },
    { DLMS_ACCESS_REQUEST_GET_WITH_SELECTION, "access-request-get-with-selection" },
    { DLMS_ACCESS_REQUEST_SET_WITH_SELECTION, "access-request-set-with-selection" },
    { 0, 0 },
};
