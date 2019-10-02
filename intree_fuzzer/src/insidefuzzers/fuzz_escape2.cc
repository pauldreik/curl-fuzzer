#include <cassert>
#include <cstring>
#include <fstream>
#include <stdint.h> // for the c version of uint8_t

#include "CurlInitializer.h"
#include "FuzzData.h"

#include "curl/curl.h"
extern "C"
{
#include "escape.h"
}

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

  const char* string;
  size_t stringlength = 0;

  if (usenullterminator) {
    auto string2 = data.getstring();
    if (!string2.first) {
      // don't pass null as data
      return 0;
    }
    string = string2.first;
    stringlength = string2.second;
  } else {
    string = data.getzstring();
    if (use_strlen) {
      stringlength = std::strlen(string);
    }
  }
  auto result =
    curl_easy_escape(handle, string, static_cast<int>(stringlength));
  free(result);
  return 0;
}
