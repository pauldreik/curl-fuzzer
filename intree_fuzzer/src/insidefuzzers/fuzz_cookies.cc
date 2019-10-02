#include <stdint.h> // for the c version of uint8_t
extern "C"
{
#include "cookie.h"
}
#include <cassert>
#include <cstring>
#include <fstream>

#include "CurlInitializer.h"
#include "FuzzData.h"

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* rawdata, size_t rawsize)
{
  static CurlInitializer curl_raii{};

  FuzzData data(rawdata, rawsize);

  CURL* handle = curl_raii.handle();

  // fuzzing using files on the file system is slow, so only make
  // that happen very seldom.
  const char* cookie_filename = NULL;
  if (data.getUChar() == 123) {
    // initialize once. use the pid to get uniqueness.
    static const std::string filename = [&]() {
      // put it in ram
      auto name = std::string("/dev/shm/cookiefuzzer.tmp.cookiefile.") +
                  std::to_string(getpid());
      return name;
    }();

    // write some garbage to it
    std::ofstream os(filename);
    assert(os);
    auto garbage = data.getzstring();
    os.write(garbage, std::strlen(garbage));

    cookie_filename = filename.c_str();

    // maybe use it as the cookie jar file
    if (data.getUChar() < 10) {
      curl_easy_setopt(handle, CURLOPT_COOKIEJAR, cookie_filename);
    }

    // maybe use it as the cookiefile
    if (data.getUChar() < 10) {
      curl_easy_setopt(handle, CURLOPT_COOKIEFILE, cookie_filename);
    }
  }

  // Curl_cookie_loadfiles(curl.handle());
  CookieInfo* info = Curl_cookie_init(handle,
                                      cookie_filename,
                                      NULL,
                                      data.getBool() // newsession
  );

  const int nof_add = data.getUChar();
  for (int i = 0; i < nof_add; ++i) {
    bool secure = data.getBool();
    Cookie* cookie = Curl_cookie_add(handle,
                                     // data.getBool()?info:NULL,//info
                                     info,              // info
                                     data.getBool(),    // header,
                                     data.getBool(),    // expiry
                                     data.getzstring(), // lineptr
                                     data.getzstring(), // domain
                                     data.getzstring(), // path,
                                     secure);           // secure
  }

  if (data.getBool()) {
    Curl_cookie_clearall(info);
  }

  const int nof_get = data.getUChar();
  for (int i = 0; i < nof_get; ++i) {
    Cookie* cookie2 = Curl_cookie_getlist(info,
                                          data.getzstring(), // host
                                          data.getzstring(), // path
                                          data.getBool());   // secure
    Curl_cookie_freelist(cookie2);
  }

  if (data.getBool()) {
    curl_easy_setopt(handle, CURLOPT_COOKIEJAR, "/dev/null");
  }

  if (data.getBool()) {
    Curl_flush_cookies(handle, data.getBool());
  }
  Curl_cookie_cleanup(info);

  return 0;
}
