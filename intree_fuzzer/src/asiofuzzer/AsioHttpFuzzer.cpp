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

#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

struct FakeServerSocket;
struct CurlSocket;

const bool debugoutput = false;

struct Context
{
  Context(boost::asio::io_context& m_io);
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
  void onFastTimer(boost::system::error_code ec)
  {
    if (!ec) {
      if (debugoutput)
        std::cout << "fast timer event" << std::endl;
      ++nfast_timeouts;
      resetFastTimer();
    }
  }
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
  boost::asio::io_context& m_io;
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

struct FakeServerSocket
{
  explicit FakeServerSocket(boost::asio::io_context& io, Context* parent)
    : m_serversocket(io)
    , m_parent(parent)
  {}

  void start_async_read();
  void on_read(const boost::system::error_code& ec, std::size_t bytes_read);

  // returns true if a write was initiated, or the
  // socket closed because no more data to write.
  bool start_async_write();
  void on_write(const boost::system::error_code& ec, std::size_t bytes_read);

  /// we own this one
  boost::asio::posix::stream_descriptor m_serversocket;
  int m_fd_given_to_curl = -1;
  bool m_is_waiting_for_read = false;
  bool m_is_waiting_for_write = false;
  Context* m_parent{};
  std::string m_readbuf;
  std::string m_writebuf;
};

extern "C" int
fuzz_sockopt_callback(void*, curl_socket_t, curlsocktype)
{
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

extern "C" curl_socket_t
fuzz_open_socket(void* ptr, curlsocktype, struct curl_sockaddr*)
{
  assert(ptr);
  Context* context = reinterpret_cast<Context*>(ptr);
  return context->onSocketOpenCallback();
}
extern "C" size_t
fuzz_read_callback(char* buffer, size_t size, size_t nitems, void* ptr) {
     return CURL_READFUNC_ABORT;
}

extern "C" size_t
fuzz_write_callback(void* contents, size_t size, size_t nmemb, void* ptr)
{
  //assert(!"wow, you solved the fuzzing puzzle!");
  return size * nmemb;
}

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

  boost::asio::io_context io;

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

Context::Context(boost::asio::io_context& io)
  : m_io(io)
  , m_fast_timer(io)
{
  m_easy = curl_easy_init();
}


size_t
Context::setoptions(const uint8_t* data, size_t size)
{
    const auto size_at_start=size;
    auto selector=[&](long defaultchoice,const std::initializer_list<long>& choices) {
        if(data && size>0) {
        const size_t selected=data[0];
        ++data;
        --size;
        for(size_t i=0; i<choices.size(); ++i) {
            if(selected==i) {
                return *(choices.begin()+i);
            }
        }
        }
        return defaultchoice;
    };

    auto setoption=[&](CURLoption curloption, auto value) {
        int ret = curl_easy_setopt(m_easy,
                               curloption,
                               value );
        assert(ret == 0);
    };

    auto setFromRandom=[&](CURLoption curloption,
            long defaultchoice,
            const std::initializer_list<long>& choices) {
         auto v=selector(defaultchoice,choices);
         setoption(curloption,v);
    };

    // give the possible bits in choices,
    // a random subset of those will be ored together
    // and set (if nonzero)
    auto setRandomBitmask=[&](CURLoption curloption,
            const std::initializer_list<unsigned long>& choices) {
        if(!data || size==0)
            return;

        const unsigned selected=data[0];
        ++data;
        --size;
        assert(choices.size()<=8);
        unsigned long mask=0;
        for(size_t i=0; i<choices.size(); ++i) {
            if (selected& (1<<i)) {
                    mask |= *(choices.begin()+i);
            }
        }
        if(mask) {
            setoption(curloption,mask);
        }
    };

    // set the http version
    setFromRandom(CURLOPT_HTTP_VERSION,
                  CURL_HTTP_VERSION_NONE,
    {CURL_HTTP_VERSION_1_0,
     CURL_HTTP_VERSION_1_1,
     CURL_HTTP_VERSION_2,
     /*,
     CURL_HTTP_VERSION_2TLS,
     CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE,
     CURL_HTTP_VERSION_3  */ });

    // should we follow location?
    setFromRandom(CURLOPT_FOLLOWLOCATION,1,{0});


    setRandomBitmask(CURLOPT_HTTPAUTH,{
                         CURLAUTH_BASIC ,
                         CURLAUTH_DIGEST,
                         CURLAUTH_DIGEST_IE ,
                         CURLAUTH_BEARER ,
                         //CURLAUTH_NEGOTIATE , // neeeds  GSS-API library
                          CURLAUTH_NTLM ,
                         /*CURLAUTH_NTLM_WB, */
                         CURLAUTH_ANY ,
                         CURLAUTH_ANYSAFE ,
                         /*CURLAUTH_ONLY,*/
                     });
    if(size>0){
        if(!data[0]) {
         setoption(CURLOPT_USERPWD, "james:bond");
        }
         --size;
         ++data;
    }


    //leave room for more options
    auto takeOne=[&]() {if(size>0){--size;++data;}};
    for(int i=0; i<4; ++i) {
        takeOne();
    }

int ret;

  Context& context = *this;

  ret = curl_easy_setopt(
    context.m_easy, CURLOPT_OPENSOCKETFUNCTION, fuzz_open_socket);
  assert(ret == 0);

  ret = curl_easy_setopt(
    context.m_easy, CURLOPT_SOCKOPTFUNCTION, fuzz_sockopt_callback);
  assert(ret == 0);

  ret = curl_easy_setopt(context.m_easy, CURLOPT_OPENSOCKETDATA, &context);
  assert(ret == 0);

  context.m_connect_to_list = curl_slist_append(NULL, "::127.0.1.127:");
  ret = curl_easy_setopt(
    context.m_easy, CURLOPT_CONNECT_TO, context.m_connect_to_list);
  assert(ret == 0);

  setoption(CURLOPT_PROTOCOLS, CURLPROTO_HTTP);

  // using an ip adress maybe bypasses name resolution?
  setoption(CURLOPT_URL, "http://example.com/");


  ret = curl_easy_setopt(
    context.m_easy, CURLOPT_WRITEFUNCTION, fuzz_write_callback);
  assert(ret == 0);

  ret = curl_easy_setopt(
    context.m_easy, CURLOPT_READFUNCTION, fuzz_read_callback);
  assert(ret == 0);

  setoption(CURLOPT_TIMEOUT_MS, 200L);
  setoption(CURLOPT_SERVER_RESPONSE_TIMEOUT, 1L);

  const bool usedoh=false;
if(usedoh) {
  ret = curl_easy_setopt(context.m_easy,CURLOPT_DOH_URL,"http://127.0.0.1/doh");
  assert(ret == 0);
}

const bool useproxy=false;
if(useproxy) {
  ret = curl_easy_setopt(
    context.m_easy, CURLOPT_PROXY, "http://127.0.0.1/");
  assert(ret == 0);


  ret = curl_easy_setopt(context.m_easy, CURLOPT_HTTPPROXYTUNNEL,1L);
        assert(ret == 0);
}

//how many byte did we use
return size_at_start-size;
}

int
Context::runCurlOnce()
{
  int still_running = -1;
  int cmpret = curl_multi_perform(m_multi_handle, &still_running);
  assert(cmpret == CURLM_OK);
  return still_running;
}

curl_socket_t
Context::onSocketOpenCallback()
{
 // assert(m_serversockets.empty() &&
  //       "wow, you got curl to open another socket!");

    // prohibit reallocations because that would
    // mean I would have to care about lifetime
    if(m_serversockets.empty()) {
        m_serversockets.reserve(4);
    }
    assert(m_serversockets.capacity()==4);

    if(m_serversockets.size()>=4) {
        // don't get carried away, curl...
        return CURL_SOCKET_BAD;
    }

  // make the sockets
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {
    /* Failed to create a pair of sockets. */
    return CURL_SOCKET_BAD;
  }
  FakeServerSocket fss(m_io, this);
  // use the first one for ourselves
  fss.m_serversocket.assign(fds[0]);
  fss.m_fd_given_to_curl = fds[1];

  this->addCurlSocket(fds[1]);

  auto& e = this->m_serversockets.emplace_back(std::move(fss));

  // to avoid hanging
  curlGaveSignOfLife();
  haveMadeSomethingCurlShouldNotice();

  // start reading so we notice when curl wants to say something
  e.start_async_read();

  return fds[1];
}

int
Context::countOpenCurlSockets()
{
  int ret = 0;
  for (int fd : m_curlsockets) {
    int a = fcntl(fd, F_GETFD);
    if (a != -1) {
      ++ret;
    }
  }
  return ret;
}

int
Context::countOpenServerSockets()
{
  int ret = 0;

  for (auto& ss : m_serversockets) {
    if (ss.m_serversocket.is_open()) {
      ++ret;
    }
  }
  return ret;
}

void
Context::addCurlSocket(int newfd)
{
  for (int fd : m_curlsockets) {
    if (newfd == fd) {
      return;
    }
  }
  m_curlsockets.emplace_back(newfd);
}

void
Context::closeall()
{
  boost::system::error_code ec;
  for (auto& e : m_serversockets) {
    if (e.m_serversocket.is_open()) {
      e.m_serversocket.close(ec);
      haveMadeSomethingCurlShouldNotice();
    }
  }
}

bool
Context::sendOrCloseOne()
{
  for (FakeServerSocket& fss : m_serversockets) {
    if (fss.start_async_write()) {
      // it was not busy writing already,
      // and either we sent something or
      // it was closed because there was nothing
      // more in the queue to send.
      return true;
    }
  }
  return false;
}

Context::~Context()
{
  curl_multi_remove_handle(m_multi_handle, m_easy);
  curl_multi_cleanup(m_multi_handle);

  curl_easy_cleanup(m_easy);
  curl_slist_free_all(m_connect_to_list);
}

std::string
Context::getNextReply()
{
  std::string ret;
  if(!m_responses.empty()) {
      ret.swap(m_responses.front());
      m_responses.erase(m_responses.begin());
  }
  return ret;
}

void Context::splitFuzzDataIntoResponses(const uint8_t *data, size_t size)
{
    const size_t nsizes=3;
    if(size<nsizes) {
        return;
    }
    std::vector<size_t> sizes(nsizes);
    size_t total=0;
    for(size_t i=0; i<nsizes ; ++i) {
        sizes.at(i)=1+data[i];
        total += sizes.at(i);
    }
    data+=nsizes;
    size-=nsizes;

    // don't leave data at the table.
    if(total<size) {
        sizes.push_back(size-total);
    }


    for(size_t i=0; i<sizes.size() && size>0; ++i) {
        std::string response;
        auto len=std::min(size,sizes.at(i));
        response.assign(data, data + len);
        data+=len;
        size-=len;
        m_responses.emplace_back(std::move(response));
    }
}

void
FakeServerSocket::start_async_read()
{
  if (m_is_waiting_for_read) {
    // already waiting.
    return;
  }
  if (!m_serversocket.is_open()) {
    return;
  }
  m_readbuf.assign(256, '\0');
  if (debugoutput)
    std::cout << "start async read on " << m_serversocket.native_handle()
              << std::endl;
  m_serversocket.async_read_some(boost::asio::buffer(m_readbuf),
                                 [this](auto a, auto b) { on_read(a, b); });

  m_is_waiting_for_read = true;
}

void
FakeServerSocket::on_read(const boost::system::error_code& ec,
                          std::size_t bytes_read)
{
  if (debugoutput)
    std::cout << "on_read(): got " << bytes_read << " byte from socket pair "
              << m_serversocket.native_handle() << "," << m_fd_given_to_curl
              << ": ec=" << ec.message() << std::endl;
  m_is_waiting_for_read = false;

  // if we got data, it means curl lives. reset the suicide counter!
  m_parent->curlGaveSignOfLife();

  if (ec) {
      m_parent->haveMadeSomethingCurlShouldNotice();
    m_serversocket.close();
    return;
  }

  // send a reply!
  start_async_write();

  // also start listening again
  start_async_read();
}

bool
FakeServerSocket::start_async_write()
{
  if (m_is_waiting_for_write) {
    // already waiting.
    return false;
  }
  if (!m_serversocket.is_open()) {
    return false;
  }
  m_writebuf = m_parent->getNextReply();

  if (m_writebuf.empty()) {
    if (debugoutput)
      std::cout << "no more replies to write, closing socket "
                << m_serversocket.native_handle() << std::endl;
    m_serversocket.close();
    m_parent->haveMadeSomethingCurlShouldNotice();
    return true;
  }
  if (debugoutput)
    std::cout << "starting async_write " << m_serversocket.native_handle()
              << std::endl;
  m_serversocket.async_write_some(boost::asio::buffer(m_writebuf),
                                  [this](auto a, auto b) { on_write(a, b); });

  m_is_waiting_for_write = true;
  return true;
}

void
FakeServerSocket::on_write(const boost::system::error_code& ec,
                           std::size_t bytes_written)
{
  if (debugoutput)
    std::cout << "on_write(): has written " << bytes_written
              << " bytes to socket pair " << m_serversocket.native_handle()
              << "," << m_fd_given_to_curl << ": ec=" << ec.message()
              << std::endl;
  m_is_waiting_for_write = false;

  if (ec)
    return;

  // is there anything left to write of this buffer?
  if (m_writebuf.size() > bytes_written) {
    std::cout << "on_write(): still data left to write" << std::endl;
    m_writebuf.erase(0, m_writebuf.size() - bytes_written);

    m_serversocket.async_write_some(boost::asio::buffer(m_writebuf),
                                    [this](auto a, auto b) { on_write(a, b); });
    m_is_waiting_for_write = true;
  }

  // notify that we actually did something curl should have noticed, so
  // the main loop knows when to stop waiting
  m_parent->haveMadeSomethingCurlShouldNotice();
}
