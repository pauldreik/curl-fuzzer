#ifndef FUZZDATA_H_INCLUDED
#define FUZZDATA_H_INCLUDED

// include these, to be able to match libFuzzer signature
// which uses the C version (size_t, not std::size_t etc)
#include <cassert>
#include <cstddef> // for size_t
#include <cstdint> // std::uint16_t etc
#include <cstring> // memcpy
#include <stdint.h> // for the c version of uint8_t
#include <utility> // std::pair
#include <vector>

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
  unsigned short getCappedShort(unsigned short maxval)
  {
    assert(maxval > 0);
    // be wasteful by taking 4 byte
    auto tmp = getItem<unsigned int>();
    while(tmp > maxval) {
      tmp /= 2U;
    }
    return static_cast<unsigned short>(tmp);
  }
  // returns a non-owning char pointer with random length and content,
  // not null terminated.
  std::pair<char *, size_t> getstring(size_t maxlen = 65535)
  {
    assert(maxlen > 0);
    size_t len = getItem<std::uint16_t>();
    while(len > maxlen) {
      len /= 2U;
    }
    if(len == 0) {
      return { nullptr, 0 };
    }
    m_char_arrays.emplace_back(len);
    auto &vec = m_char_arrays.back();
    char *ret = vec.data();
    // fill it with up to len "random" bytes
    const auto eaten = this->min(len, bytes_left());
    std::memcpy(ret, m_data + m_index, eaten);
    m_index += eaten;
    return { ret, len };
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

#endif
