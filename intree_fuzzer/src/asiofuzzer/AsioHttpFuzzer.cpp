/*
 * This is an experiment using boost::asio instead of select() based
 * waiting for curl. It sets curl options from fixed positions in the
 * fuzz input data. All this is just for experimenting.
 * by Paul Dreik 2019
 */
#include <algorithm>
#include <array>
#include <cassert>
#include <curl/curl.h>
#include <fcntl.h>
#include <iostream>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>


#include "Context.h"

struct FakeServerSocket;
struct CurlSocket;

static const bool debugoutput = false;



std::vector<int>
getFdsFromCurl(CURLM* multi_handle)
{
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcep;

  FD_ZERO(&fdread);
  FD_ZERO(&fdwrite);
  FD_ZERO(&fdexcep);
  int maxfd = -1;
  const CURLMcode mc =
    curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);
  assert(mc == CURLM_OK);
  std::vector<int> ret;
  for (int i = 0; i <= maxfd; ++i) {
    for (fd_set* s : { &fdread, &fdwrite, &fdexcep }) {
      if (FD_ISSET(i, s)) {
        ret.push_back(i);
      }
    }
  }
  // keep only unique values
  std::sort(begin(ret), end(ret));
  ret.erase(std::unique(begin(ret), end(ret)), end(ret));
  return ret;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 10)
    return 0;
  signal(SIGPIPE, SIG_IGN);

  IOCONTEXT io;

  Context context{ io };

  const auto bytes_consumed=context.setoptions(data,size);
  if(bytes_consumed>=size) {
      //all data was consumed. refuse to run.
      return 0;
  }
  data+=bytes_consumed;
  size-=bytes_consumed;
  context.splitFuzzDataIntoResponses(data,size);

  /* init a multi stack */
  context.m_multi_handle = curl_multi_init();

  /* add the individual transfers */
  int ret = curl_multi_add_handle(context.m_multi_handle, context.m_easy);
  assert(ret == 0);

  // let curl start doing it's thing
  int still_runnning = context.runCurlOnce();

  if (debugoutput)
    std::cout << "initial curl run gave " << still_runnning << std::endl;

  bool exit_now = false;

  // make sure we can't time out indefinitely
  boost::asio::deadline_timer suicide_timer(io);
  suicide_timer.expires_from_now(boost::posix_time::milliseconds(2000));
  suicide_timer.async_wait([&context, &exit_now](auto ec) {
    if (ec != boost::asio::error::operation_aborted) {
      std::cout << "SUICIDE TIMER ec=" << ec << std::endl;
      context.closeall();
      exit_now = true;
    }
  });

  // start the fast timer
  context.resetFastTimer();

  // if curl thinks it's waiting for something, still_running is 1.
  while (!exit_now) {
    // before we invoke run_one(), which might block for a while.
    // let's check that we do not exceed limits for how far
    // ago curl seemed to be alive
    if (context.curl_seems_dead()) {
        if(debugoutput) {
      std::cout << "curl seems dead, exiting!" << std::endl;
        }
      exit_now = true;
      break;
    }

    const int nof_open_serversockets = context.countOpenServerSockets();
    if (debugoutput)
      std::cout << "number of open sockets is "
                << context.countOpenServerSockets() << " + "
                << context.countOpenCurlSockets() << std::endl;

    if (nof_open_serversockets > 0 && still_runnning &&
        context.time_curl_has_had_to_do_something() > 1) {
      // we might be in a situation where curl wants more data,
      // but we did not send it. to avoid timing out,
      // find the first server that still has more data to send.
      if (context.sendOrCloseOne()) {
          if(debugoutput) {
        std::cout << "curl seems dead, sent more data or closed a socket."
                  << std::endl;
          }
      }
    }

    // this is where we might block
    if (nof_open_serversockets > 0 || still_runnning) {
      if (debugoutput)
        std::cout << "run_one()..." << std::endl;
      io.run_one();
    } else {
      exit_now = true;
    }

    if (debugoutput)
      std::cout << "running curl...";
    still_runnning = context.runCurlOnce();
    if (debugoutput)
      std::cout << "got still_running=" << still_runnning << std::endl;
  }
  if (debugoutput)
    std::cout << "after exiting the loop, the number of open sockets is "
              << context.countOpenServerSockets() << " + "
              << context.countOpenCurlSockets() << std::endl;

  if (debugoutput) {
    std::cout
      << "wasted " << context.nfast_timeouts << " fast timeouts.\n"
      << "##############################################################"
      << std::endl;
  }
  return 0;
}

