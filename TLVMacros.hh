#ifndef TLVMacros_hh_included
#define TLVMacros_hh_included

// clang-format off

/**
 * TLV types.
 */
#define TLV_TYPE_LOWEST                 1
#define TLV_TYPE_URL                    1
#define TLV_TYPE_RESPONSE0              2
#define TLV_TYPE_USERNAME               3
#define TLV_TYPE_PASSWORD               4
#define TLV_TYPE_POSTFIELDS             5
#define TLV_TYPE_HEADER                 6
#define TLV_TYPE_COOKIE                 7
#define TLV_TYPE_UPLOAD1                8
#define TLV_TYPE_RANGE                  9
#define TLV_TYPE_CUSTOMREQUEST          10
#define TLV_TYPE_MAIL_RECIPIENT         11
#define TLV_TYPE_MAIL_FROM              12
#define TLV_TYPE_MIME_PART              13
#define TLV_TYPE_MIME_PART_NAME         14
#define TLV_TYPE_MIME_PART_DATA         15
#define TLV_TYPE_HTTPAUTH               16
#define TLV_TYPE_RESPONSE1              17
#define TLV_TYPE_RESPONSE2              18
#define TLV_TYPE_RESPONSE3              19
#define TLV_TYPE_RESPONSE4              20
#define TLV_TYPE_RESPONSE5              21
#define TLV_TYPE_RESPONSE6              22
#define TLV_TYPE_RESPONSE7              23
#define TLV_TYPE_RESPONSE8              24
#define TLV_TYPE_RESPONSE9              25
#define TLV_TYPE_RESPONSE10             26
#define TLV_TYPE_OPTHEADER              27
#define TLV_TYPE_NOBODY                 28
#define TLV_TYPE_FOLLOWLOCATION         29
#define TLV_TYPE_ACCEPTENCODING         30
#define TLV_TYPE_SECOND_RESPONSE0       31
#define TLV_TYPE_SECOND_RESPONSE1       32
#define TLV_TYPE_WILDCARDMATCH          33
#define TLV_TYPE_RTSP_REQUEST           34
#define TLV_TYPE_RTSP_SESSION_ID        35
#define TLV_TYPE_RTSP_STREAM_URI        36
#define TLV_TYPE_RTSP_TRANSPORT         37
#define TLV_TYPE_RTSP_CLIENT_CSEQ       38
#define TLV_TYPE_MAIL_AUTH              39
#define TLV_TYPE_HTTP_VERSION           40
#define TLV_TYPE_DOH_URL                41
#define TLV_TYPE_PROXY_URL              42
#define TLV_TYPE_PROXYUSERPWD           43
#define TLV_TYPE_PROXYPORT              44
#define TLV_TYPE_FAILONERROR            45
#define TLV_TYPE_TIMEVALUE              46
#define TLV_TYPE_TIMECONDITION          47
#define TLV_TYPE_PROXYAUTH              48
#define TLV_TYPE_HTTPPROXYTUNNEL        49
#define TLV_TYPE_SUPPRESS_CONNECT_HEADERS 50

#if FUZZ_EXTENDED_TLVS
#define TLV_TYPE_SECOND_RESPONSE2       46
#define TLV_TYPE_SECOND_RESPONSE3       47
#define TLV_TYPE_THIRD_RESPONSE0        48
#define TLV_TYPE_THIRD_RESPONSE1        49
#define TLV_TYPE_THIRD_RESPONSE2        50
#define TLV_TYPE_THIRD_RESPONSE3        51
#define TLV_TYPE_FOURTH_RESPONSE0       52
#define TLV_TYPE_FOURTH_RESPONSE1       53
#define TLV_TYPE_FOURTH_RESPONSE2       54
#define TLV_TYPE_FOURTH_RESPONSE3       55
#define TLV_TYPE_HIGHEST                55
#else
#define TLV_TYPE_HIGHEST                50
#endif
/**
 * TLV function return codes.
 */
#define TLV_RC_NO_ERROR                 0
#define TLV_RC_NO_MORE_TLVS             1
#define TLV_RC_SIZE_ERROR               2

/* Temporary write array size */
#define TEMP_WRITE_ARRAY_SIZE           10

/* Cookie-jar path. */
#define FUZZ_COOKIE_JAR_PATH            "/dev/null"

/* Number of supported responses */
#define TLV_MAX_NUM_RESPONSES           11
// paul fixme increase this?

/* Number of allowed CURLOPT_HEADERs */
#define TLV_MAX_NUM_CURLOPT_HEADER      2000

/* Space variable for all CURLOPTs. */
#define FUZZ_CURLOPT_TRACKER_SPACE      300

/* Number of connections allowed to be opened */
#if FUZZ_EXTENDED_TLVS
#define FUZZ_NUM_CONNECTIONS            4
#else
#define FUZZ_NUM_CONNECTIONS            2
#endif

// clang-format on

#endif // TLVMacros_hh_included
