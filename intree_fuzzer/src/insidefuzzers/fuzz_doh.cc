#include "curl/curl.h"
#include <stdint.h> // for the c version of uint8_t
extern "C" {
#include "doh.h"
}
#include <cassert>
#include <cstring>
#include <fstream>
#include <tuple>

#include "CurlInitializer.h"
#include "FuzzData.h"

#include "curl_config.h"
extern "C" {
// clang-format off
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"
// clang-format on
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *rawdata, size_t rawsize)
{
  static CurlInitializer curl_raii{};

  FuzzData data(rawdata, rawsize);

  CURL *handle = curl_raii.handle();

  auto host = data.getzstring();
  DNStype dnstype = [&]() {
    switch(data.getUChar() / 40) {
    case 0:
      return DNS_TYPE_A;
    case 1:
      return DNS_TYPE_NS;
    case 2:
      return DNS_TYPE_CNAME;
    case 3:
      return DNS_TYPE_AAAA;
    default:
      // always return something valid
      return DNS_TYPE_A;
    }
  }();

  // make a buffer of random length and content
  auto buf = data.getstring(1000);
  size_t olen = 0;
  doh_encode((const char *)host,
             dnstype,
             (unsigned char *)buf.first,
             buf.second,
             &olen);

  return 0;
}
