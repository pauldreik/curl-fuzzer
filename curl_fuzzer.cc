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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cassert>

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
/* Macros */
#define FV_PRINTF(FUZZP, ...)                                                  \
  if ((FUZZP)->verbose) {                                                      \
    printf(__VA_ARGS__);                                                       \
  }

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the CURL API into making a request.
 */
extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  int rc = 0;
  int tlv_rc;
  FUZZ_DATA fuzz{};
  TLV tlv;

  /* Ignore SIGPIPE errors. We'll handle the errors ourselves. */
  signal(SIGPIPE, SIG_IGN);

  if (size < TLV::TLVHeaderSize) {
    /* Not enough data for a single TLV - don't continue */
    goto EXIT_LABEL;
  }

  /* Try to initialize the fuzz data */
  FTRY(fuzz.init(data, size));

  for (tlv_rc = fuzz.fuzz_get_first_tlv(&tlv); tlv_rc == 0;
       tlv_rc = fuzz.fuzz_get_next_tlv(&tlv)) {

    /* Have the TLV in hand. Parse the TLV. */
    rc = fuzz.fuzz_parse_tlv(&tlv);

    if (rc != 0) {
      /* Failed to parse the TLV. Can't continue. */
      goto EXIT_LABEL;
    }
  }

  if (tlv_rc != TLV_RC_NO_MORE_TLVS) {
    /* A TLV call failed. Can't continue. */
    goto EXIT_LABEL;
  }

  /* Set up the standard easy options. */
  FTRY(fuzz_set_easy_options(&fuzz));

  /**
   * Add in more curl options that have been accumulated over possibly
   * multiple TLVs.
   */
  if (fuzz.header_list != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_HTTPHEADER, fuzz.header_list);
  }

  if (fuzz.mail_recipients_list != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_MAIL_RCPT, fuzz.mail_recipients_list);
  }

  if (fuzz.mime != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_MIMEPOST, fuzz.mime);
  }

  /* Run the transfer. */
  fuzz_handle_transfer(&fuzz);

EXIT_LABEL:

  /* This function must always return 0. Non-zero codes are reserved. */
  return 0;
}

/**
 * Set standard options on the curl easy.
 */
int
fuzz_set_easy_options(FUZZ_DATA* fuzz)
{
  int rc = 0;
  unsigned long allowed_protocols;

  /* Set some standard options on the CURL easy handle. We need to override the
     socket function so that we create our own sockets to present to CURL. */
  FTRY(
    curl_easy_setopt(fuzz->easy, CURLOPT_OPENSOCKETFUNCTION, fuzz_open_socket));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_OPENSOCKETDATA, fuzz));

  /* In case something tries to set a socket option, intercept this. */
  FTRY(curl_easy_setopt(
    fuzz->easy, CURLOPT_SOCKOPTFUNCTION, fuzz_sockopt_callback));

  /* Set the standard read function callback. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_READFUNCTION, fuzz_read_callback));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_READDATA, fuzz));

  /* Set the standard write function callback. */
  FTRY(
    curl_easy_setopt(fuzz->easy, CURLOPT_WRITEFUNCTION, fuzz_write_callback));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_WRITEDATA, fuzz));

  /* Set the cookie jar so cookies are tested. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_COOKIEJAR, FUZZ_COOKIE_JAR_PATH));

  /* Time out requests quickly. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_TIMEOUT_MS, 200L));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_SERVER_RESPONSE_TIMEOUT, 1L));

  /* Can enable verbose mode by having the environment variable FUZZ_VERBOSE. */
  if (fuzz->verbose) {
    FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_VERBOSE, 1L));
  }

  /* Force resolution of all addresses to a specific IP address. */
  fuzz->connect_to_list = curl_slist_append(NULL, "::127.0.1.127:");
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_CONNECT_TO, fuzz->connect_to_list));

  /* Limit the protocols in use by this fuzzer. */
  FTRY(fuzz_set_allowed_protocols(fuzz));

EXIT_LABEL:

  return rc;
}

/**
 * If a pointer has been allocated, free that pointer.
 */
void
fuzz_free(void** ptr)
{
  if (*ptr != NULL) {
    free(*ptr);
    *ptr = NULL;
  }
}

/**
 * Function for handling the fuzz transfer, including sending responses to
 * requests.
 */
int
fuzz_handle_transfer(FUZZ_DATA* fuzz)
{
  int rc = 0;

  // how many timeouts in a row
  int double_timeout = 0;

  std::array<FUZZ_SOCKET_MANAGER*, FUZZ_NUM_CONNECTIONS> sman{};

  for (int ii = 0; ii < FUZZ_NUM_CONNECTIONS; ii++) {
    sman[ii] = &fuzz->sockman[ii];
  }

  /* init a multi stack */
  CURLM* multi_handle = curl_multi_init();

  /* add the individual transfers */
  curl_multi_add_handle(multi_handle, fuzz->easy);

  /* Do an initial process. This might end the transfer immediately. */
  int still_running{};
  curl_multi_perform(multi_handle, &still_running);
  FV_PRINTF(fuzz, "FUZZ: Initial perform; still running? %d \n", still_running);

  while (still_running) {
    /* Reset the sets of file descriptors. */
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* Set a timeout of 10ms. This is lower than recommended by the multi guide
       but we're not going to any remote servers, so everything should complete
       very quickly. */
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;

    /* get file descriptors from the transfers */
    int maxfd = -1;
    const CURLMcode mc =
      curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);
    if (mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_fdset() failed, code %d.\n", mc);
      rc = -1;
      break;
    }

    for (int ii = 0; ii < FUZZ_NUM_CONNECTIONS; ii++) {
      /* Add the socket FD into the readable set if connected. */
      if (sman[ii]->fd_state == FUZZ_SOCK_OPEN) {
        FD_SET(sman[ii]->fd, &fdread);

        /* Work out the maximum FD between the cURL file descriptors and the
           server FD. */
        maxfd = std::max(sman[ii]->fd, maxfd);
      }
    }

    /* Work out what file descriptors need work. */
    rc = fuzz_select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    if (rc == -1) {
      /* Had an issue while selecting a file descriptor. Let's just exit. */
      FV_PRINTF(fuzz, "FUZZ: select failed, exiting \n");
      break;
    } else if (rc == 0) {
      FV_PRINTF(fuzz, "FUZZ: Timed out; double timeout? %d \n", double_timeout);

      /* Timed out. */
      if (double_timeout == 1) {
        /* We don't expect multiple timeouts in a row. If there are double
           timeouts then exit. */
        break;
      } else {
        /* Set the timeout flag for the next time we select(). */
        double_timeout = 1;
      }
    } else {
      /* There's an active file descriptor. Reset the timeout flag. */
      double_timeout = 0;
    }

    /* Check to see if a server file descriptor is readable. If it is,
       then send the next response from the fuzzing data. */
    for (int ii = 0; ii < FUZZ_NUM_CONNECTIONS; ii++) {
      if (sman[ii]->fd_state == FUZZ_SOCK_OPEN &&
          FD_ISSET(sman[ii]->fd, &fdread)) {
        rc = fuzz_send_next_response(fuzz, sman[ii]);
        if (rc != 0) {
          /* Failed to send a response. Break out here. */
          break;
        }
      }
    }

    curl_multi_perform(multi_handle, &still_running);
  }

  /* Remove the easy handle from the multi stack. */
  curl_multi_remove_handle(multi_handle, fuzz->easy);

  /* Clean up the multi handle - the top level function will handle the easy
     handle. */
  curl_multi_cleanup(multi_handle);

  return (rc);
}

/**
 * Sends the next fuzzing response to the server file descriptor.
 */
int
fuzz_send_next_response(FUZZ_DATA* fuzz, FUZZ_SOCKET_MANAGER* sman)
{
  int rc = 0;
  ssize_t ret_in;


  /* Need to read all data sent by the client so the file descriptor becomes
     unreadable. Because the file descriptor is non-blocking we won't just
     hang here. */
  do {
      char buffer[8192];
    ret_in = read(sman->fd, buffer, sizeof(buffer));
    if (fuzz->verbose && ret_in > 0) {
      printf("FUZZ[%d]: Received %zu bytes \n==>\n", sman->index, ret_in);
      fwrite(buffer, ret_in, 1, stdout);
      printf("\n<==\n");
    }
  } while (ret_in > 0);

  /* Now send a response to the request that the client just made. */
  if(sman->hasResponsesLeft()) {
  FV_PRINTF(fuzz,
            "FUZZ[%d]: Sending next response: %d \n",
            sman->index,
            sman->response_index);
  const auto& resp=sman->getNextResponse();
  const uint8_t*  data = resp.data;
  const size_t data_len = resp.data_len;
    sman->stepToNextResponse();
  assert (data != NULL);
    if (write(sman->fd, data, data_len) != (ssize_t)data_len) {
      /* Failed to write the data back to the client. Prevent any further
         testing. */
      rc = -1;
    }
  }

  /* Work out if there are any more responses. If not, then shut down the
     server. */
if(!sman->hasResponsesLeft()) {
    FV_PRINTF(fuzz,
              "FUZZ[%d]: Shutting down server socket: %d \n",
              sman->index,
              sman->fd);
    shutdown(sman->fd, SHUT_WR);
    sman->fd_state = FUZZ_SOCK_SHUTDOWN;
  }

  return rc;
}

/**
 * Wrapper for select() so profiling can track it.
 */
int
fuzz_select(int nfds,
            fd_set* readfds,
            fd_set* writefds,
            fd_set* exceptfds,
            struct timeval* timeout)
{
  return select(nfds, readfds, writefds, exceptfds, timeout);
}

/**
 * Set allowed protocols based on the compile options
 */
int
fuzz_set_allowed_protocols(FUZZ_DATA* fuzz)
{
  int rc = 0;
  unsigned long allowed_protocols = 0;

#ifdef FUZZ_PROTOCOLS_ALL
  /* Do not allow telnet currently as it accepts input from stdin. */
  allowed_protocols |= CURLPROTO_ALL & ~CURLPROTO_TELNET;
#endif
#ifdef FUZZ_PROTOCOLS_DICT
  allowed_protocols |= CURLPROTO_DICT;
#endif
#ifdef FUZZ_PROTOCOLS_FILE
  allowed_protocols |= CURLPROTO_FILE;
#endif
#ifdef FUZZ_PROTOCOLS_FTP
  allowed_protocols |= CURLPROTO_FTP;
  allowed_protocols |= CURLPROTO_FTPS;
#endif
#ifdef FUZZ_PROTOCOLS_GOPHER
  allowed_protocols |= CURLPROTO_GOPHER;
#endif
#ifdef FUZZ_PROTOCOLS_HTTP
  allowed_protocols |= CURLPROTO_HTTP;
#endif
#ifdef FUZZ_PROTOCOLS_HTTPS
  allowed_protocols |= CURLPROTO_HTTPS;
#endif
#ifdef FUZZ_PROTOCOLS_IMAP
  allowed_protocols |= CURLPROTO_IMAP;
  allowed_protocols |= CURLPROTO_IMAPS;
#endif
#ifdef FUZZ_PROTOCOLS_LDAP
  allowed_protocols |= CURLPROTO_LDAP;
  allowed_protocols |= CURLPROTO_LDAPS;
#endif
#ifdef FUZZ_PROTOCOLS_POP3
  allowed_protocols |= CURLPROTO_POP3;
  allowed_protocols |= CURLPROTO_POP3S;
#endif
#ifdef FUZZ_PROTOCOLS_RTMP
  allowed_protocols |= CURLPROTO_RTMP;
  allowed_protocols |= CURLPROTO_RTMPE;
  allowed_protocols |= CURLPROTO_RTMPS;
  allowed_protocols |= CURLPROTO_RTMPT;
  allowed_protocols |= CURLPROTO_RTMPTE;
  allowed_protocols |= CURLPROTO_RTMPTS;
#endif
#ifdef FUZZ_PROTOCOLS_RTSP
  allowed_protocols |= CURLPROTO_RTSP;
#endif
#ifdef FUZZ_PROTOCOLS_SCP
  allowed_protocols |= CURLPROTO_SCP;
#endif
#ifdef FUZZ_PROTOCOLS_SFTP
  allowed_protocols |= CURLPROTO_SFTP;
#endif
#ifdef FUZZ_PROTOCOLS_SMB
  allowed_protocols |= CURLPROTO_SMB;
  allowed_protocols |= CURLPROTO_SMBS;
#endif
#ifdef FUZZ_PROTOCOLS_SMTP
  allowed_protocols |= CURLPROTO_SMTP;
  allowed_protocols |= CURLPROTO_SMTPS;
#endif
#ifdef FUZZ_PROTOCOLS_TFTP
  allowed_protocols |= CURLPROTO_TFTP;
#endif

  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_PROTOCOLS, allowed_protocols));

EXIT_LABEL:

  return rc;
}

FUZZ_DATA::~FUZZ_DATA()
{
  int ii;
  auto fuzz = this;
  fuzz_free((void**)&this->postfields);

  for (auto& e : this->sockman) {
    e.close();
  }

  if (this->connect_to_list != NULL) {
    curl_slist_free_all(this->connect_to_list);
    this->connect_to_list = NULL;
  }

  if (this->header_list != NULL) {
    curl_slist_free_all(this->header_list);
    this->header_list = NULL;
  }

  if (this->mail_recipients_list != NULL) {
    curl_slist_free_all(this->mail_recipients_list);
    this->mail_recipients_list = NULL;
  }

  if (this->mime != NULL) {
    curl_mime_free(this->mime);
    this->mime = NULL;
  }

  if (this->easy != NULL) {
    curl_easy_cleanup(this->easy);
    this->easy = NULL;
  }
}

int
FUZZ_DATA::init(const uint8_t* data, size_t data_len)
{
  // do not init twice
  if (this->easy || this->state.data || this->state.data_len)
    return 1;

  /* Create an easy handle. This will have all of the settings configured on
     it. */
  this->easy = curl_easy_init();
  if (!this->easy)
    return 1;

  /* Set up the state parser */
  this->state.data = data;
  this->state.data_len = data_len;

  /* Set up the state of the server sockets. */
  for (int ii = 0; ii < FUZZ_NUM_CONNECTIONS; ii++) {
    this->sockman[ii].index = ii;
    this->sockman[ii].fd_state = FUZZ_SOCK_CLOSED;
  }

  /* Check for verbose mode. */
  this->verbose = (getenv("FUZZ_VERBOSE") != NULL);

  return 0;
}

#if FUZZER_CUSTOM_MUTATOR
/*
 * For whatever reason, the LLVMFuzzerCustomMutator fcn is not picked up unless
 * it is in this file. no clue why, but this works, redirecting it to another
 * name. Is it link ordering? cmake? no clue.
 */
extern "C" size_t
curl_LLVMFuzzerCustomMutator(uint8_t* Data,
                             size_t Size,
                             size_t MaxSize,
                             unsigned int Seed);
extern "C" size_t
LLVMFuzzerCustomMutator(uint8_t* Data,
                        size_t Size,
                        size_t MaxSize,
                        unsigned int Seed)
{
  return curl_LLVMFuzzerCustomMutator(Data, Size, MaxSize, Seed);
}
extern "C" size_t
curl_LLVMFuzzerCustomCrossOver(const uint8_t* Data1,
                               size_t Size1,
                               const uint8_t* Data2,
                               size_t Size2,
                               uint8_t* Out,
                               size_t MaxOutSize,
                               unsigned int Seed);
extern "C" size_t
LLVMFuzzerCustomCrossOver(const uint8_t* Data1,
                          size_t Size1,
                          const uint8_t* Data2,
                          size_t Size2,
                          uint8_t* Out,
                          size_t MaxOutSize,
                          unsigned int Seed)
{
  return curl_LLVMFuzzerCustomCrossOver(
    Data1, Size1, Data2, Size2, Out, MaxOutSize, Seed);
}
#endif

void
FUZZ_SOCKET_MANAGER::close()
{
  if (fd_state != FUZZ_SOCK_CLOSED) {
    ::close(fd);
    fd_state = FUZZ_SOCK_CLOSED;
  }
}
