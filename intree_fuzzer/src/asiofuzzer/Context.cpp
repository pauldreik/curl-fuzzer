#include "Context.h"
#include "FakeServerSocket.h"
#include <iostream>

static const bool debugoutput = false;

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


void Context::onFastTimer(boost::system::error_code ec)
{
    if (!ec) {
        if (debugoutput)
            std::cout << "fast timer event" << std::endl;
        ++nfast_timeouts;
        resetFastTimer();
    }
}


Context::Context(IOCONTEXT& io)
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
