/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017, Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curl_fuzzer.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

/* Macros */
#define FV_PRINTF(FUZZP, ...)                                                  \
  if ((FUZZP)->verbose) {                                                      \
    printf(__VA_ARGS__);                                                       \
  }

static uint32_t
to_u32(const uint8_t b[4])
{
  uint32_t u;
  u = (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3];
  return u;
}

static uint16_t
to_u16(const uint8_t b[2])
{
  uint16_t u;
  u = (b[0] << 8) + b[1];
  return u;
}
/**
 * Byte stream representation of the TLV header. Casting the byte stream
 * to a TLV_RAW allows us to examine the type and length.
 */
struct TLV_RAW
{
  /* Type of the TLV - 16 bits. */
  uint8_t raw_type[2];

  /* Length of the TLV data - 32 bits. */
  uint8_t raw_length[4];
};

/**
 * Converts a TLV data and length into an allocated string.
 */
char*
fuzz_tlv_to_string(TLV* tlv)
{
  char* tlvstr;

  /* Allocate enough space, plus a null terminator */
  tlvstr = (char*)malloc(tlv->length + 1);

  if (tlvstr != NULL) {
    memcpy(tlvstr, tlv->value, tlv->length);
    tlvstr[tlv->length] = 0;
  }

  return tlvstr;
}

/**
 * TLV access function - gets the first TLV from a data stream.
 */
int
FUZZ_DATA::fuzz_get_first_tlv(TLV* tlv)
{
  /* Reset the cursor. */
  state.data_pos = 0;
  return fuzz_get_tlv_comn(tlv);
}

/**
 * TLV access function - gets the next TLV from a data stream.
 */
int
FUZZ_DATA::fuzz_get_next_tlv(TLV* tlv)
{
  /* Advance the cursor by the full length of the previous TLV. */
  state.data_pos += sizeof(TLV_RAW) + tlv->length;

  /* Work out if there's a TLV's worth of data to read */
  if (state.data_pos + sizeof(TLV_RAW) > state.data_len) {
    /* No more TLVs to parse */
    return TLV_RC_NO_MORE_TLVS;
  }

  return fuzz_get_tlv_comn(tlv);
}

/**
 * Common TLV function for accessing TLVs in a data stream.
 */
int
FUZZ_DATA::fuzz_get_tlv_comn(TLV* tlv)
{
  int rc = 0;

  /* Start by casting the data stream to a TLV. */
  auto raw = (TLV_RAW*)&state.data[state.data_pos];
  size_t data_offset = state.data_pos + sizeof(TLV_RAW);

  /* Set the TLV values. */
  tlv->type = to_u16(raw->raw_type);
  tlv->length = to_u32(raw->raw_length);
  tlv->value = &state.data[data_offset];

  FV_PRINTF(this, "TLV: type %x length %u\n", tlv->type, tlv->length);

  /* Use uint64s to verify lengths of TLVs so that overflow problems don't
     matter. */
  uint64_t check_length = data_offset;
  check_length += tlv->length;

  uint64_t remaining_len = state.data_len;
  FV_PRINTF(this, "Check length of data: %lu \n", check_length);
  FV_PRINTF(this, "Remaining length of data: %lu \n", remaining_len);

  /* Sanity check that the TLV length is ok. */
  if (check_length > remaining_len) {
    FV_PRINTF(this, "Returning TLV_RC_SIZE_ERROR\n");
    rc = TLV_RC_SIZE_ERROR;
  }

  return rc;
}

#define FSET_OPTION(FUZZP, OPTNAME, OPTVALUE)                                  \
  FTRY(curl_easy_setopt((FUZZP)->easy, OPTNAME, OPTVALUE));                    \
  (FUZZP)->options[OPTNAME % 1000] = 1

#define FCHECK_OPTION_UNSET(FUZZP, OPTNAME)                                    \
  FCHECK((FUZZP)->options[OPTNAME % 1000] == 0)

#define FSINGLETONTLV(FUZZP, TLVNAME, OPTNAME)                                 \
  case TLVNAME:                                                                \
    FCHECK_OPTION_UNSET(FUZZP, OPTNAME);                                       \
    tmp = fuzz_tlv_to_string(tlv);                                             \
    FSET_OPTION(FUZZP, OPTNAME, tmp);                                          \
    break

#define FU32TLV(FUZZP, TLVNAME, OPTNAME)                                       \
  case TLVNAME:                                                                \
    if (tlv->length != 4) {                                                    \
      rc = 255;                                                                \
      goto EXIT_LABEL;                                                         \
    }                                                                          \
    FCHECK_OPTION_UNSET(FUZZP, OPTNAME);                                       \
    tmp_u32 = to_u32(tlv->value);                                              \
    FSET_OPTION(FUZZP, OPTNAME, tmp_u32);                                      \
    break
#define FRESPONSETLV(SMAN, TLVNAME, INDEX)                                     \
  case TLVNAME:                                                                \
    (SMAN)->responses.emplace_back(tlv->value,tlv->length);                    \
    break

#define FTRY(FUNC)                                                             \
  {                                                                            \
    int _func_rc = (FUNC);                                                     \
    if (_func_rc) {                                                            \
      rc = _func_rc;                                                           \
      goto EXIT_LABEL;                                                         \
    }                                                                          \
  }
#define FCHECK(COND)                                                           \
  {                                                                            \
    if (!(COND)) {                                                             \
      rc = 255;                                                                \
      goto EXIT_LABEL;                                                         \
    }                                                                          \
  }
/**
 * Do different actions on the CURL handle for different received TLVs.
 */
int
FUZZ_DATA::fuzz_parse_tlv(TLV* tlv)
{
  int rc;
  char* tmp = NULL;
  uint32_t tmp_u32;

  switch (tlv->type) {
    /* The pointers in response TLVs will always be valid as long as the fuzz
       data is in scope, which is the entirety of this file. */
  case TLV_TYPE_RESPONSE0:
      sockman.at(0).add_response(tlv->value,tlv->length);
      break;
  case TLV_TYPE_RESPONSE1:
      sockman.at(1).add_response(tlv->value,tlv->length);
      break;
#if FUZZ_NUM_CONNECTIONS > 2
  case TLV_TYPE_RESPONSE2:
      sockman.at(2).add_response(tlv->value,tlv->length);
      break;
#endif
#if FUZZ_NUM_CONNECTIONS > 3
  case TLV_TYPE_RESPONSE3:
      sockman.at(3).add_response(tlv->value,tlv->length);
      break;
#endif

    case TLV_TYPE_UPLOAD1:
      /* The pointers in the TLV will always be valid as long as the fuzz data
         is in scope, which is the entirety of this file. */

      FCHECK_OPTION_UNSET(this, CURLOPT_UPLOAD);

      upload1_data = tlv->value;
      upload1_data_len = tlv->length;

      FSET_OPTION(this, CURLOPT_UPLOAD, 1L);
      FSET_OPTION(this, CURLOPT_INFILESIZE_LARGE, (curl_off_t)upload1_data_len);
      break;

    case TLV_TYPE_HEADER:
      /* Limit the number of headers that can be added to a message to prevent
         timeouts. */
      if (header_list_count >= TLV_MAX_NUM_CURLOPT_HEADER) {
        rc = 255;
        goto EXIT_LABEL;
      }

      tmp = fuzz_tlv_to_string(tlv);
      header_list = curl_slist_append(header_list, tmp);
      header_list_count++;
      break;

    case TLV_TYPE_MAIL_RECIPIENT:
      tmp = fuzz_tlv_to_string(tlv);
      mail_recipients_list = curl_slist_append(mail_recipients_list, tmp);
      break;

    case TLV_TYPE_MIME_PART:
      if (mime == NULL) {
        mime = curl_mime_init(easy);
      }

      part = curl_mime_addpart(mime);

      /* This TLV may have sub TLVs. */
      fuzz_add_mime_part(tlv, part);
      break;

    case TLV_TYPE_POSTFIELDS:
      FCHECK_OPTION_UNSET(this, CURLOPT_POSTFIELDS);
      postfields = fuzz_tlv_to_string(tlv);
      FSET_OPTION(this, CURLOPT_POSTFIELDS, postfields);
      break;

      /* Define a set of u32 options. */
      FU32TLV(this, TLV_TYPE_HTTPAUTH, CURLOPT_HTTPAUTH);
      FU32TLV(this, TLV_TYPE_OPTHEADER, CURLOPT_HEADER);
      FU32TLV(this, TLV_TYPE_NOBODY, CURLOPT_NOBODY);
      FU32TLV(this, TLV_TYPE_FOLLOWLOCATION, CURLOPT_FOLLOWLOCATION);
      FU32TLV(this, TLV_TYPE_WILDCARDMATCH, CURLOPT_WILDCARDMATCH);
      FU32TLV(this, TLV_TYPE_RTSP_REQUEST, CURLOPT_RTSP_REQUEST);
      FU32TLV(this, TLV_TYPE_RTSP_CLIENT_CSEQ, CURLOPT_RTSP_CLIENT_CSEQ);
      FU32TLV(this, TLV_TYPE_HTTP_VERSION, CURLOPT_HTTP_VERSION);
      FU32TLV(this, TLV_TYPE_FAILONERROR, CURLOPT_FAILONERROR);
      FU32TLV(this, TLV_TYPE_PROXYPORT, CURLOPT_PROXYPORT);
      FU32TLV(this, TLV_TYPE_PROXYAUTH, CURLOPT_PROXYAUTH);
      FU32TLV(this, TLV_TYPE_HTTPPROXYTUNNEL, CURLOPT_HTTPPROXYTUNNEL);
      FU32TLV(this,
              TLV_TYPE_SUPPRESS_CONNECT_HEADERS,
              CURLOPT_SUPPRESS_CONNECT_HEADERS);
      FU32TLV(this, TLV_TYPE_TIMEVALUE, CURLOPT_TIMEVALUE);
      FU32TLV(this, TLV_TYPE_TIMECONDITION, CURLOPT_TIMECONDITION);

      /* Define a set of singleton TLVs - they can only have their value set
         once and all follow the same pattern. */
      FSINGLETONTLV(this, TLV_TYPE_URL, CURLOPT_URL);
      FSINGLETONTLV(this, TLV_TYPE_DOH_URL, CURLOPT_DOH_URL);
      FSINGLETONTLV(this, TLV_TYPE_PROXY_URL, CURLOPT_PROXY);
      FSINGLETONTLV(this, TLV_TYPE_PROXYUSERPWD, CURLOPT_PROXYUSERPWD);
      FSINGLETONTLV(this, TLV_TYPE_USERNAME, CURLOPT_USERNAME);
      FSINGLETONTLV(this, TLV_TYPE_PASSWORD, CURLOPT_PASSWORD);
      FSINGLETONTLV(this, TLV_TYPE_COOKIE, CURLOPT_COOKIE);
      FSINGLETONTLV(this, TLV_TYPE_RANGE, CURLOPT_RANGE);
      FSINGLETONTLV(this, TLV_TYPE_CUSTOMREQUEST, CURLOPT_CUSTOMREQUEST);
      FSINGLETONTLV(this, TLV_TYPE_MAIL_FROM, CURLOPT_MAIL_FROM);
      FSINGLETONTLV(this, TLV_TYPE_ACCEPTENCODING, CURLOPT_ACCEPT_ENCODING);
      FSINGLETONTLV(this, TLV_TYPE_RTSP_SESSION_ID, CURLOPT_RTSP_SESSION_ID);
      FSINGLETONTLV(this, TLV_TYPE_RTSP_STREAM_URI, CURLOPT_RTSP_STREAM_URI);
      FSINGLETONTLV(this, TLV_TYPE_RTSP_TRANSPORT, CURLOPT_RTSP_TRANSPORT);
      FSINGLETONTLV(this, TLV_TYPE_MAIL_AUTH, CURLOPT_MAIL_AUTH);

    default:
      /* The fuzzer generates lots of unknown TLVs - we don't want these in the
         corpus so we reject any unknown TLVs. */
      rc = 127;
      goto EXIT_LABEL;
      break;
  }

  rc = 0;

EXIT_LABEL:

  fuzz_free((void**)&tmp);

  return rc;
}

/**
 * Extract the values from the TLV.
 */
int
fuzz_add_mime_part(TLV* src_tlv, curl_mimepart* part)
{
  FUZZ_DATA part_fuzz{};
  TLV tlv;
  int rc = 0;
  int tlv_rc;

  if (src_tlv->length < sizeof(TLV_RAW)) {
    /* Not enough data for a single TLV - don't continue */
    goto EXIT_LABEL;
  }

  /* Set up the state parser */
  part_fuzz.state.data = src_tlv->value;
  part_fuzz.state.data_len = src_tlv->length;

  for (tlv_rc = part_fuzz.fuzz_get_first_tlv(&tlv); tlv_rc == 0;
       tlv_rc = part_fuzz.fuzz_get_next_tlv(&tlv)) {

    /* Have the TLV in hand. Parse the TLV. */
    rc = fuzz_parse_mime_tlv(part, &tlv);

    if (rc != 0) {
      /* Failed to parse the TLV. Can't continue. */
      goto EXIT_LABEL;
    }
  }

  if (tlv_rc != TLV_RC_NO_MORE_TLVS) {
    /* A TLV call failed. Can't continue. */
    goto EXIT_LABEL;
  }

EXIT_LABEL:

  return rc;
}

/**
 * Do different actions on the mime part for different received TLVs.
 */
int
fuzz_parse_mime_tlv(curl_mimepart* part, TLV* tlv)
{
  int rc;
  char* tmp;

  switch (tlv->type) {
    case TLV_TYPE_MIME_PART_NAME:
      tmp = fuzz_tlv_to_string(tlv);
      curl_mime_name(part, tmp);
      fuzz_free((void**)&tmp);
      break;

    case TLV_TYPE_MIME_PART_DATA:
      curl_mime_data(part, (const char*)tlv->value, tlv->length);
      break;

    default:
      /* The fuzzer generates lots of unknown TLVs - we don't want these in the
         corpus so we reject any unknown TLVs. */
      rc = 255;
      goto EXIT_LABEL;
      break;
  }

  rc = 0;

EXIT_LABEL:

  return rc;
}
