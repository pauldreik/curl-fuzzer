#include <stdint.h> // for the c version of uint8_t
extern "C" {
#include "cookie.h"
#include "netrc.h"
}
#include <cassert>
#include <cstring>
#include <fstream>
#include <memory>
#include <vector>

extern "C" {
// clang-format off
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"
// clang-format on
}

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

class FuzzData
{
public:
  FuzzData(const uint8_t *data, size_t size) : m_data(data), m_size(size) {}

  bool getBool()
  {
    if(m_index < m_size) {
      return m_data[m_index++] > 0x7f;
    }
    return false;
  }
  unsigned char getUChar()
  {
    if(m_index < m_size) {
      return m_data[m_index++];
    }
    return '\0';
  }

  // pod must be trivially copyable
  template <class Pod>
  Pod getItem()
  {
    Pod ret;
    if(m_index + sizeof(Pod) <= m_size) {
      std::memcpy(&ret, m_data + m_index, sizeof(ret));
      m_index += sizeof(ret);
    }
    else {
      std::memset(&ret, 0, sizeof(ret));
    }
    return ret;
  }

  // returns a non-owning char pointer with random length and content-
  char *getzstring()
  {
    size_t len = getItem<std::uint16_t>();
    m_char_arrays.emplace_back(len + 1);
    auto &vec = m_char_arrays.back();
    char *ret = vec.data();
    // fill it with up to len "random" bytes
    const auto eaten = this->min(len, bytes_left());
    std::memcpy(ret, m_data + m_index, eaten);
    m_index += eaten;
    return ret;
  }
  size_t bytes_left() const { return m_size - m_index; }

private:
  static size_t min(size_t a, size_t b) { return a < b ? a : b; }
  const uint8_t *m_data;
  const size_t m_size;
  size_t m_index = 0;
  // use allocated arrays, not string, to find memory errors
  // easier.
  std::vector<std::vector<char>> m_char_arrays;
};

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *rawdata, size_t rawsize)
{
  static CurlInitializer curl_raii{};

  FuzzData data(rawdata, rawsize);

  CURL *handle = curl_raii.handle();

  // initialize once. use the pid to get uniqueness.
  static const std::string filename = [&]() {
    // put it in ram
    auto name =
      std::string("/dev/shm/netrcfuzzer.tmp.") + std::to_string(getpid());
    return name;
  }();

  {
    std::ofstream os(filename);
    assert(os);
    os.write((const char *)rawdata, rawsize);
  }
  const char *host = "example.com";
  char *login = strdup("");
  char *password = strdup("");
  bool login_changed = false;
  bool password_changed = false;

  const int ret = Curl_parsenetrc(host,
                                  &login,
                                  &password,
                                  &login_changed,
                                  &password_changed,
                                  (char *)filename.c_str());
  if(ret > 0) {
    // host not found
    free(password);
    free(login);
  }
  if(ret == 0) {
    // host found, nonexistent login
    free(password);
    free(login);
  }
  if(ret < 0) {
    // host found, nonexistent login
    free(password);
    free(login);
  }
  return 0;
}
