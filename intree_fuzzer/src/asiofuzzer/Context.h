#pragma once

#include <boost/version.hpp>
#if BOOST_VERSION < 106600
#include <boost/asio/io_service.hpp>
#define IOCONTEXT boost::asio::io_service
#else
#include <boost/asio/io_context.hpp>
#define IOCONTEXT boost::asio::io_context
#endif
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>

#include <curl/curl.h>


struct FakeServerSocket;

struct Context
{
  explicit Context(IOCONTEXT& m_io);
  // returns the number of bytes consumed from data
  size_t setoptions(const uint8_t* data, size_t size);
  // runs curl once, nonblocking. returns what
  // it says is the number of things it waits for (nrunning)
  int runCurlOnce();
  curl_socket_t onSocketOpenCallback();
  void start_async_wait_for_traffic_from_curl();
  void start_wait_for_events_on_curlsockets();
  int countOpenServerSockets();
  /// this may be expensive
  int countOpenCurlSockets();
  // adds the socket if it is not there already
  void addCurlSocket(int fd);
  void closeall();
  void onFastTimer(boost::system::error_code ec);
  void resetFastTimer()
  {
    m_fast_timer.expires_from_now(boost::posix_time::microseconds(100));
    m_fast_timer.async_wait([this](auto ec) { onFastTimer(ec); });
  }
  void curlGaveSignOfLife() { latest_sign_of_life = nfast_timeouts; }
  // each time we do something curl should notice, like having written
  // or closed, so the main loop knows if curl is waiting for us or
  // has died
  void haveMadeSomethingCurlShouldNotice()
  {
    latest_time_of_input = nfast_timeouts;
  }

  bool curl_seems_dead() const
  {
    return time_curl_has_had_to_do_something() > 5;
  }

  int time_curl_has_had_to_do_something() const
  {
    if (latest_time_of_input > latest_sign_of_life) {
      // we have made a change, but not yet seen
      // any signs that curl noticed.
      return (nfast_timeouts - latest_time_of_input);
    } else {
      // latest sign of life was too long ago, and
      // we have not made anything that curl should
      // have noticed
      return (nfast_timeouts - latest_sign_of_life);
    }
  }
  // loops through the server sockets,
  // finds the first one which has no more data
  // to send and sends it. if it could not find one,
  // finds one with data left to send and sends it.
  bool sendOrCloseOne();
  boost::asio::deadline_timer m_fast_timer;
  int nfast_timeouts = 0;
  int latest_sign_of_life = 0;
  int latest_time_of_input = 0;

  ~Context();
  IOCONTEXT& m_io;
  CURL* m_easy{};
  struct curl_slist* m_connect_to_list{};
  CURLM* m_multi_handle{};

  std::string getNextReply();

  // the sockets we use to emulate that curl talks
  // to a server
  std::vector<FakeServerSocket> m_serversockets;
  std::vector<int> m_curlsockets;

  // responses, made up from data by the fuzzer
  void splitFuzzDataIntoResponses(const uint8_t* data,size_t size);
  std::vector<std::string> m_responses;
};

