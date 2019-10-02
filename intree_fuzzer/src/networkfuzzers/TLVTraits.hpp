#ifndef TLVTraits_hpp_included
#define TLVTraits_hpp_included

#include <curl/curl.h>
#include <vector>

struct CurlOption
{
  using CurlOptionType = decltype(CURLOPT_UPLOAD);

  enum class Kind : char
  {
    /// a flag that can be zet zero or once.
    not_so_interesting_flag_once,
    /// a string which can be set zero or more times, not so interesting to fuzz
    /// because
    /// it just sets the url/username/password etc
    not_so_interesting_once_string,
    /// a long string, interesting to fuzz, given zero or one time.
    interesting_once_string,
    /// a long string, interesting to fuzz, given zero or more times
    interesting_composing_string,
    /// a string that may be used zero or more times
    not_so_interesting_composing_string,
    /// not so interesting nested tlv:s
    no_so_interesting_once_nestedtlv,
  };
  bool canBeSetMoreThanOnce() const;
  bool isFlag() const;
  bool isString() const;
  bool isOther() const;
  bool isInteresting() const;

  // is len a valid length for this type
  bool isValidLength(size_t len) const;

  static const CurlOptionType invalid_curloption;

  CurlOption(CurlOptionType opt, int16_t tlvtype, Kind kind)
    : m_curloption(opt)
    , m_tlvtype(tlvtype)
    , m_kind(kind)
  {}
  // we use invalid_curloption if this does not apply
  CurlOptionType m_curloption;
  int16_t m_tlvtype;
  Kind m_kind;
};

class TLVTraits
{
public:
  TLVTraits();

  bool canBeSetMoreThanOnce(int16_t tlvtype) const;
  bool isValidType(int16_t tlvtype) const;
  bool isValidLength(int16_t tlvtype, size_t len) const;
  const CurlOption* findOptionByTlvType(int16_t tlvtype) const;

private:
  void addFlag(CurlOption::CurlOptionType opt, int16_t tlvtype);
  void addString(CurlOption::CurlOptionType opt, int16_t tlvtype);

  std::vector<CurlOption> m_all;
};

#endif
