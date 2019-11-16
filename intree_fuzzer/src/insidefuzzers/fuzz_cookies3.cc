#include <cassert>
#include <fstream>
#include <sstream>
#include <stdint.h> // for the c version of uint8_t
#include <string>

#include <curl/curl.h>

/*
 * This fuzzer has the advantage that it works with text input,
 * meaning the test cases will be possible to read and even manually
 * modify.
 * By Paul Dreik 2019
 */

void
executeOne(std::istream &iss)
{
  assert(iss);

  CURL *handle = curl_easy_init();

  std::string line;
  while(std::getline(iss, line)) {
    curl_easy_setopt(handle, CURLOPT_COOKIELIST, line.c_str());
  }

  curl_easy_setopt(handle, CURLOPT_COOKIEJAR, "/dev/null");
  curl_easy_perform(handle);

  curl_easy_cleanup(handle);
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *rawdata, size_t rawsize)
{
  const char *beg = (const char *)rawdata;
  const char *end = beg + rawsize;
  std::istringstream iss(std::string(beg, end));

  executeOne(iss);
  return 0;
}

// this is handy for making a reproducer script
#if IMPLEMENT_OWN_MAIN
int
main(int argc, char *argv[])
{
  for(int i = 1; i < argc; ++i) {
    std::ifstream iss(argv[i]);
    executeOne(iss);
  }
}
#endif
