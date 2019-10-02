#include "curl/curl.h"
#include <stdint.h> // for the c version of uint8_t
extern "C"
{
#include "doh.h"
}
#include <cassert>
#include <cstring>
#include <fstream>
#include <tuple>

#include "FuzzData.h"

#include "curl_config.h"
extern "C"
{
// clang-format off
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"
  // clang-format on
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* rawdata, size_t rawsize)
{
  FuzzData data(rawdata, rawsize);

  DNStype dnstype = [&]() {
    switch (data.getUChar() / 40) {
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
  struct dohentry d;
  std::memset((void*)&d, 0, sizeof(d));
  doh_decode((unsigned char*)buf.first, buf.second, dnstype, &d);
  de_cleanup(&d);
  return 0;
}
