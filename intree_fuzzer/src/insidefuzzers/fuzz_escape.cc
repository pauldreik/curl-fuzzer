#include "curl/curl.h"
#include <stdint.h> // for the c version of uint8_t
extern "C"
{
#include "escape.h"
}
#include <cassert>
#include <cstring>
#include <fstream>
#include <tuple>

#include "CurlInitializer.h"
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
  static CurlInitializer curl_raii{};

  FuzzData data(rawdata, rawsize);

  CURL* handle = curl_raii.handle();

  const bool usenullterminator = data.getBool();
  const bool use_strlen = data.getBool();
  const bool reject_crlf = data.getBool();

  char* ostring = NULL;
  size_t olen = 0;
  const char* string;
  size_t stringlength = 0;
  if (usenullterminator) {
    string = data.getzstring();
    if (use_strlen) {
      stringlength = std::strlen(string);
    }
  } else {
    std::tie(string, stringlength) = data.getstring();
    if (!string) {
      // do not pass null as data
      return 0;
    }
  }

  auto ret = Curl_urldecode(handle,
                            string,
                            stringlength, // length. 0 means use strlen.
                            &ostring,
                            &olen,
                            reject_crlf);
  free(ostring);
  return 0;
}
