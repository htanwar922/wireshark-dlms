
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

// Global Ciphering - Himanshu
#define DLMS_GLO_GET_REQUEST 200
#define DLMS_GLO_SET_REQUEST 201
#define DLMS_GLO_ACTION_REQUEST 203
#define DLMS_GLO_GET_RESPONSE 204
#define DLMS_GLO_SET_RESPONSE 205
#define DLMS_GLO_ACTION_RESPONSE 207

#define DLMS_EXCEPTION_RESPONSE 216
#define DLMS_ACCESS_REQUEST 217
#define DLMS_ACCESS_RESPONSE 218

extern const value_string dlms_apdu_names[];

/* Choice values for a Get-Request */
#define DLMS_GET_REQUEST_NORMAL 1
#define DLMS_GET_REQUEST_NEXT 2
#define DLMS_GET_REQUEST_WITH_LIST 3

extern const value_string dlms_get_request_names[];

/* Choice values for a Get-Response */
#define DLMS_GET_RESPONSE_NORMAL 1
#define DLMS_GET_RESPONSE_WITH_DATABLOCK 2
#define DLMS_GET_RESPONSE_WITH_LIST 3

extern const value_string dlms_get_response_names[];

/* Choice values for a Set-Request */
#define DLMS_SET_REQUEST_NORMAL 1
#define DLMS_SET_REQUEST_WITH_FIRST_DATABLOCK 2
#define DLMS_SET_REQUEST_WITH_DATABLOCK 3
#define DLMS_SET_REQUEST_WITH_LIST 4
#define DLMS_SET_REQUEST_WITH_LIST_AND_FIRST_DATABLOCK 5

extern const value_string dlms_set_request_names[];

/* Choice values for a Set-Response */
#define DLMS_SET_RESPONSE_NORMAL 1
#define DLMS_SET_RESPONSE_DATABLOCK 2
#define DLMS_SET_RESPONSE_LAST_DATABLOCK 3
#define DLMS_SET_RESPONSE_LAST_DATABLOCK_WITH_LIST 4
#define DLMS_SET_RESPONSE_WITH_LIST 5

extern const value_string dlms_set_response_names[];

/* Choice values for an Action-Request */
#define DLMS_ACTION_REQUEST_NORMAL 1
#define DLMS_ACTION_REQUEST_NEXT_PBLOCK 2
#define DLMS_ACTION_REQUEST_WITH_LIST 3
#define DLMS_ACTION_REQUEST_WITH_FIRST_PBLOCK 4
#define DLMS_ACTION_REQUEST_WITH_LIST_AND_FIRST_PBLOCK 5
#define DLMS_ACTION_REQUEST_WITH_PBLOCK 6

extern const value_string dlms_action_request_names[];

/* Choice values for an Action-Response */
#define DLMS_ACTION_RESPONSE_NORMAL 1
#define DLMS_ACTION_RESPONSE_WITH_PBLOCK 2
#define DLMS_ACTION_RESPONSE_WITH_LIST 3
#define DLMS_ACTION_RESPONSE_NEXT_PBLOCK 4

extern const value_string dlms_action_response_names[];

/* Choice values for an Access-Request-Specification */
#define DLMS_ACCESS_REQUEST_GET 1
#define DLMS_ACCESS_REQUEST_SET 2
#define DLMS_ACCESS_REQUEST_ACTION 3
#define DLMS_ACCESS_REQUEST_GET_WITH_SELECTION 4
#define DLMS_ACCESS_REQUEST_SET_WITH_SELECTION 5

extern const value_string dlms_access_request_names[];
