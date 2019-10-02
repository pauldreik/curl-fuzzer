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
#include <cassert>
#include <curl/curl.h>
#include <fcntl.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>

/* Macros */
#define FV_PRINTF(FUZZP, ...)                                                  \
  if ((FUZZP)->verbose) {                                                      \
    printf(__VA_ARGS__);                                                       \
  }
/**
 * @brief The sockettwin struct
 * RAII object for closing sockets on exit
 */
struct sockettwin
{
  sockettwin() { fds.fill(-1); }
  sockettwin(const sockettwin&) = delete;
  sockettwin(sockettwin&&) = delete;
  sockettwin& operator=(const sockettwin&) = delete;
  sockettwin& operator=(sockettwin&&) = delete;
  int at(size_t index) const { return fds.at(index); }
  explicit operator int*() { return fds.data(); }
  bool valid() const
  {
    return fds[0] >= 0 && fds[1] >= 0 && fds[0] < FD_SETSIZE &&
           fds[1] < FD_SETSIZE;
  }
  int takeOwnerShip(int index)
  {
    int ret = fds.at(index);
    fds[index] = -1;
    return ret;
  }
  ~sockettwin()
  {
    if (fds[0] >= 0) {
      close(fds[0]);
    }
    if (fds[1] >= 0) {
      close(fds[1]);
    }
    fds.fill(-1);
  }
  std::array<int, 2> fds{};
};

curl_socket_t
FUZZ_DATA::open_socket_callback()
{
  FUZZ_SOCKET_MANAGER* sman{};

  /* pick the first available socket */
  for (size_t ii = 0; ii < sockman.size(); ii++) {
    if (sockman[ii].fd_state == FUZZ_SOCK_CLOSED) {
      sman = &sockman[ii];
      break;
    }
  }
  if (!sman) {
    /* all sockets have already been opened. */
    return CURL_SOCKET_BAD;
  }

  FV_PRINTF(
    this, "FUZZ[%d]: Using socket manager %d \n", sman->index, sman->index);

  sockettwin fds;
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, static_cast<int*>(fds))) {
    /* Failed to create a pair of sockets. */
    return CURL_SOCKET_BAD;
  }

  assert(fds.valid());

  /* Make the server non-blocking. */
  const int flags = fcntl(fds.at(0), F_GETFL, 0);
  const int status = fcntl(fds.at(0), F_SETFL, flags | O_NONBLOCK);

  if (status == -1) {
    /* Setting non-blocking failed. Return a negative response code. */
    return CURL_SOCKET_BAD;
  }

  /* At this point, the file descriptors in hand should be good enough to
     work with. */
  sman->fd = fds.takeOwnerShip(0);
  sman->fd_state = FUZZ_SOCK_OPEN;

  /* If the server should be sending data immediately, send it here. */
  if(sman->hasResponsesLeft()) {
  const FUZZ_RESPONSE& resp=sman->getNextResponse();
  sman->stepToNextResponse();

  assert(resp.data != NULL) ;
    FV_PRINTF(this, "FUZZ[%d]: Sending initial response \n", sman->index);

    if (write(sman->fd, resp.data, resp.data_len) != (ssize_t)resp.data_len) {
      /* Close the file descriptors so they don't leak. */
      close(sman->fd);
      sman->fd = -1;
      /* Failed to write all of the response data. */
      return CURL_SOCKET_BAD;
    }
  }

  /* Check to see if the socket should be shut down immediately. */
  if (!sman->hasResponsesLeft()) {
    FV_PRINTF(this,
              "FUZZ[%d]: Shutting down server socket: %d \n",
              sman->index,
              sman->fd);
    shutdown(sman->fd, SHUT_WR);
    sman->fd_state = FUZZ_SOCK_SHUTDOWN;
  }

  /* Return the other half of the socket pair. */
  return fds.takeOwnerShip(1);
}

/**
 * Function for providing a socket to CURL already primed with data.
 */
curl_socket_t
fuzz_open_socket(void* ptr, curlsocktype purpose, struct curl_sockaddr* address)
{
  assert(ptr);
  FUZZ_DATA* fuzz = (FUZZ_DATA*)ptr;
  return fuzz->open_socket_callback();
}

/**
 * Callback function for setting socket options on the sockets created by
 * fuzz_open_socket. In our testbed the sockets are "already connected".
 */
int
fuzz_sockopt_callback(void* ptr, curl_socket_t curlfd, curlsocktype purpose)
{
  (void)ptr;
  (void)curlfd;
  (void)purpose;

  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

size_t
FUZZ_DATA::read_callback(char* buffer, size_t size, size_t nitems)
{

  /* If no upload data has been specified, then return an error code. */
  if (upload1_data_len == 0) {
    /* No data to upload */
    return CURL_READFUNC_ABORT;
  }

  /* Work out how much data is remaining to upload. */
  assert(upload1_data_len >= upload1_data_written);
  size_t remaining_data = upload1_data_len - upload1_data_written;

  /* Respect the buffer size that libcurl is giving us! */
  const size_t buffer_size = size * nitems;
  if (remaining_data > buffer_size) {
    remaining_data = buffer_size;
  }

  if (remaining_data > 0) {
    FV_PRINTF(this,
              "FUZZ: Uploading %zu bytes from position %zu \n",
              remaining_data,
              upload1_data_written);

    /* Send the upload data. */
    memcpy(buffer, upload1_data + upload1_data_written, remaining_data);

    /* Increase the count of written data */
    upload1_data_written += remaining_data;
  }

  return remaining_data;
}

/**
 * Callback function for doing data uploads.
 * see here for a good explanation: https://curl.haxx.se/libcurl/c/CURLOPT_READFUNCTION.html
 */
size_t
fuzz_read_callback(char* buffer, size_t size, size_t nitems, void* ptr)
{
  assert(ptr);
  FUZZ_DATA* fuzz = (FUZZ_DATA*)ptr;
  return fuzz->read_callback(buffer, size, nitems);
}

size_t
FUZZ_DATA::write_callback(void* contents, size_t size, size_t nmemb)
{
  const size_t total = size * nmemb;

  // write some of the data, so one can see easily see
  // what curl tries to do (using the debugger)

  write_array.fill('\0');
  const size_t copy_len = std::min(total, write_array.size());
  memcpy(write_array.data(), contents, copy_len);

  return total;
}

/**
 * Callback function for handling data output quietly.
 */
size_t
fuzz_write_callback(void* contents, size_t size, size_t nmemb, void* ptr)
{
  assert(ptr);
  FUZZ_DATA* fuzz = (FUZZ_DATA*)ptr;
  return fuzz->write_callback(contents, size, nmemb);
}
