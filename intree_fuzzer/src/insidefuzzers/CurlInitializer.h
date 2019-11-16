#ifndef CURLINITIALIZER_H_INCLUDED
#define CURLINITIALIZER_H_INCLUDED

#include <cassert>
#include <curl/curl.h>
class CurlInitializer
{
public:
  CurlInitializer()
  {
    auto ret = curl_global_init(CURL_GLOBAL_DEFAULT);
    assert(ret == 0);
    m_handle = curl_easy_init();
  }
  CURL *handle() const { return m_handle; }
  ~CurlInitializer()
  {
    curl_easy_cleanup(m_handle);
    curl_global_cleanup();
  }

private:
  CURL *m_handle{};
};
#endif
