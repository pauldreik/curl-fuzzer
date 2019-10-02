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
#include "testinput.h"
#include <array>
#include <vector>
#include <curl/curl.h>
#include <inttypes.h>
#include "TLVMacros.hh"

enum FUZZ_SOCK_STATE
{
  FUZZ_SOCK_CLOSED,
  FUZZ_SOCK_OPEN,
  FUZZ_SOCK_SHUTDOWN
};

struct TLV
{
  /* Type of the TLV */
  uint16_t type = {};

  /* Length of the TLV data */
  uint32_t length = {};

  /* Pointer to data if length > 0. */
  const uint8_t* value = {};
  enum
  {
    TLVHeaderSize = sizeof(type) + sizeof(length)
  };
};

/**
 * Internal state when parsing a TLV data stream.
 */
struct FUZZ_PARSE_STATE
{
  /* Data stream (non owning)*/
  const uint8_t* data = {};
  size_t data_len = {};

  /* Current position of our "cursor" in processing the data stream. */
  size_t data_pos = {};
};

/**
 * Structure to use for responses.
 */
struct FUZZ_RESPONSE
{
    FUZZ_RESPONSE(const uint8_t* buf, size_t len) : data(buf),data_len(len){}
  /* Response data and length (non-owning)*/
  const uint8_t* data = {};
  size_t data_len = {};
};

struct FUZZ_SOCKET_MANAGER
{
    // this is purely for debug printouts
  unsigned char index=-1;

  /* Responses. Response 0 is sent as soon as the socket is connected. Further
     responses are sent when the socket becomes readable. */
  //std::array<FUZZ_RESPONSE, TLV_MAX_NUM_RESPONSES> responses;
  std::vector<FUZZ_RESPONSE> responses;
  void add_response(const uint8_t* data,size_t size) { responses.emplace_back(data,size);}
  // which response to send the next time (points into responses)
  int response_index=0;
  const FUZZ_RESPONSE& getNextResponse() const { return responses.at(response_index);}
  void stepToNextResponse() {++response_index;}
  bool hasResponsesLeft() const { return response_index<responses.size();}
  /* Server file descriptor. */
  FUZZ_SOCK_STATE fd_state = FUZZ_SOCK_CLOSED;
  curl_socket_t fd=-1;

  // closes the socket unless already closed,
  // marks it as closed
  void close();
};

/**
 * Data local to a fuzzing run.
 */
struct FUZZ_DATA
{
  // this object holds resources, and was not written with
  // C++ in mind so here go our rule of five
  //
  // When creating the object, make sure the value initialize it,
  // so it gets zeroed out properly
  FUZZ_DATA() = default;
  FUZZ_DATA(const FUZZ_DATA&) = delete;
  FUZZ_DATA(FUZZ_DATA&&) = delete;
  FUZZ_DATA& operator=(const FUZZ_DATA&) = delete;
  FUZZ_DATA& operator=(FUZZ_DATA&&) = delete;
  ~FUZZ_DATA();

  // initializes with the given data.
  // the data must outlive the object, since
  // it is referenced, not copied.
  int init(const uint8_t* data, size_t data_len);

  /* CURL easy object */
  CURL* easy;

  /* Parser state */
  FUZZ_PARSE_STATE state;

  /* Temporary writefunction state */
  std::array<char, TEMP_WRITE_ARRAY_SIZE> write_array;

  /* Upload data and length; */
  const uint8_t* upload1_data;
  size_t upload1_data_len;
  size_t upload1_data_written;

  /* Singleton option tracker. Options should only be set once. */
  std::array<unsigned char, FUZZ_CURLOPT_TRACKER_SPACE> options;

  /* CURLOPT_POSTFIELDS data. */
  char* postfields;

  /* List of headers */
  int header_list_count;
  struct curl_slist* header_list;

  /* List of mail recipients */
  struct curl_slist* mail_recipients_list;

  /* List of connect_to strings */
  struct curl_slist* connect_to_list;

  /* Mime data */
  curl_mime* mime;
  curl_mimepart* part;

  /* Server socket managers. Primarily socket manager 0 is used, but some
     protocols (FTP) use two sockets. */
  std::array<FUZZ_SOCKET_MANAGER, FUZZ_NUM_CONNECTIONS> sockman;
  FUZZ_SOCKET_MANAGER& at(size_t index) { return sockman.at(index);}

  /* Verbose mode. */
  int verbose;

  int fuzz_get_tlv_comn(TLV* tlv);
  int fuzz_get_first_tlv(TLV* tlv);
  int fuzz_get_next_tlv(TLV* tlv);
  int fuzz_parse_tlv(TLV* tlv);

  // callbacks to override read/write/socket open
  curl_socket_t open_socket_callback();

  size_t read_callback(char* buffer, size_t size, size_t nitems);
  size_t write_callback(void* contents, size_t size, size_t nmemb);
};

int
fuzz_initialize_fuzz_data(FUZZ_DATA* fuzz,
                          const uint8_t* data,
                          size_t data_len);
int
fuzz_set_easy_options(FUZZ_DATA* fuzz);
void
fuzz_free(void** ptr);
curl_socket_t
fuzz_open_socket(void* ptr,
                 curlsocktype purpose,
                 struct curl_sockaddr* address);
int
fuzz_sockopt_callback(void* ptr, curl_socket_t curlfd, curlsocktype purpose);
size_t
fuzz_read_callback(char* buffer, size_t size, size_t nitems, void* ptr);
size_t
fuzz_write_callback(void* contents, size_t size, size_t nmemb, void* ptr);

int
fuzz_add_mime_part(TLV* src_tlv, curl_mimepart* part);
int
fuzz_parse_mime_tlv(curl_mimepart* part, TLV* tlv);
int
fuzz_handle_transfer(FUZZ_DATA* fuzz);
int
fuzz_send_next_response(FUZZ_DATA* fuzz, FUZZ_SOCKET_MANAGER* sockman);
int
fuzz_select(int nfds,
            fd_set* readfds,
            fd_set* writefds,
            fd_set* exceptfds,
            struct timeval* timeout);
int
fuzz_set_allowed_protocols(FUZZ_DATA* fuzz);
