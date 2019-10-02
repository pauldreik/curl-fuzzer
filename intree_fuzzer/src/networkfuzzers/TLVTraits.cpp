#include "TLVTraits.hpp"

#include "TLVMacros.hh"

const CurlOption::CurlOptionType CurlOption::invalid_curloption =
  static_cast<CurlOption::CurlOptionType>(CURLOPT_LASTENTRY);

TLVTraits::TLVTraits()
{

  // large strings, interesting to mutate
#define x(tlvtype)                                                             \
  m_all.emplace_back(CurlOption::invalid_curloption,                           \
                     tlvtype,                                                  \
                     CurlOption::Kind::interesting_composing_string);

  x(TLV_TYPE_RESPONSE0);
  x(TLV_TYPE_RESPONSE1);
  x(TLV_TYPE_RESPONSE2);
  x(TLV_TYPE_RESPONSE3);
  x(TLV_TYPE_RESPONSE4);
  x(TLV_TYPE_RESPONSE5);
  x(TLV_TYPE_RESPONSE6);
  x(TLV_TYPE_RESPONSE7);
  x(TLV_TYPE_RESPONSE8);
  x(TLV_TYPE_RESPONSE9);
  x(TLV_TYPE_RESPONSE10);
#undef x

  // these are list of strings,
#define x(tlvtype)                                                             \
  m_all.emplace_back(CurlOption::invalid_curloption,                           \
                     tlvtype,                                                  \
                     CurlOption::Kind::not_so_interesting_composing_string);
  x(TLV_TYPE_HEADER);
  x(TLV_TYPE_MAIL_RECIPIENT);
#undef x

  // a nested tlv type, for setting mime
#define x(tlvtype)                                                             \
  m_all.emplace_back(CurlOption::invalid_curloption,                           \
                     tlvtype,                                                  \
                     CurlOption::Kind::no_so_interesting_once_nestedtlv);
  x(TLV_TYPE_MIME_PART);
#undef x

  // string to post
#define x(tlvtype, curlopt)                                                    \
  m_all.emplace_back(                                                          \
    curlopt, tlvtype, CurlOption::Kind::not_so_interesting_once_string);
  x(TLV_TYPE_POSTFIELDS, CURLOPT_POSTFIELDS);
#undef x

  // flags
#define x(tlvtype, curlopt)                                                    \
  m_all.emplace_back(                                                          \
    curlopt, tlvtype, CurlOption::Kind::not_so_interesting_flag_once);

  x(TLV_TYPE_UPLOAD1, CURLOPT_UPLOAD);

  x(TLV_TYPE_HTTPAUTH, CURLOPT_HTTPAUTH);
  x(TLV_TYPE_OPTHEADER, CURLOPT_HEADER);
  x(TLV_TYPE_NOBODY, CURLOPT_NOBODY);
  x(TLV_TYPE_FOLLOWLOCATION, CURLOPT_FOLLOWLOCATION);
  x(TLV_TYPE_WILDCARDMATCH, CURLOPT_WILDCARDMATCH);
  x(TLV_TYPE_RTSP_REQUEST, CURLOPT_RTSP_REQUEST);
  x(TLV_TYPE_RTSP_CLIENT_CSEQ, CURLOPT_RTSP_CLIENT_CSEQ);
  x(TLV_TYPE_HTTP_VERSION, CURLOPT_HTTP_VERSION);
  x(TLV_TYPE_FAILONERROR, CURLOPT_FAILONERROR);
  x(TLV_TYPE_PROXYPORT, CURLOPT_PROXYPORT);
  x(TLV_TYPE_PROXYAUTH, CURLOPT_PROXYAUTH);
  x(TLV_TYPE_HTTPPROXYTUNNEL, CURLOPT_HTTPPROXYTUNNEL);
  x(TLV_TYPE_SUPPRESS_CONNECT_HEADERS, CURLOPT_SUPPRESS_CONNECT_HEADERS);
  x(TLV_TYPE_TIMEVALUE, CURLOPT_TIMEVALUE);
  x(TLV_TYPE_TIMECONDITION, CURLOPT_TIMECONDITION);
#undef x

  // short strings
#define x(tlvtype, curlopt)                                                    \
  m_all.emplace_back(                                                          \
    curlopt, tlvtype, CurlOption::Kind::not_so_interesting_once_string);
  x(TLV_TYPE_URL, CURLOPT_URL);
  x(TLV_TYPE_DOH_URL, CURLOPT_DOH_URL);
  x(TLV_TYPE_PROXY_URL, CURLOPT_PROXY);
  x(TLV_TYPE_PROXYUSERPWD, CURLOPT_PROXYUSERPWD);
  x(TLV_TYPE_USERNAME, CURLOPT_USERNAME);
  x(TLV_TYPE_PASSWORD, CURLOPT_PASSWORD);
  x(TLV_TYPE_COOKIE, CURLOPT_COOKIE);
  x(TLV_TYPE_RANGE, CURLOPT_RANGE);
  x(TLV_TYPE_CUSTOMREQUEST, CURLOPT_CUSTOMREQUEST);
  x(TLV_TYPE_MAIL_FROM, CURLOPT_MAIL_FROM);
  x(TLV_TYPE_ACCEPTENCODING, CURLOPT_ACCEPT_ENCODING);
  x(TLV_TYPE_RTSP_SESSION_ID, CURLOPT_RTSP_SESSION_ID);
  x(TLV_TYPE_RTSP_STREAM_URI, CURLOPT_RTSP_STREAM_URI);
  x(TLV_TYPE_RTSP_TRANSPORT, CURLOPT_RTSP_TRANSPORT);
  x(TLV_TYPE_MAIL_AUTH, CURLOPT_MAIL_AUTH);
#undef x
}

bool
TLVTraits::canBeSetMoreThanOnce(int16_t tlvtype) const
{
  auto p = findOptionByTlvType(tlvtype);
  if (p) {
    return p->canBeSetMoreThanOnce();
  } else {
    return false;
  }
}

bool
TLVTraits::isValidType(int16_t tlvtype) const
{
  return findOptionByTlvType(tlvtype) != nullptr;
}

bool
TLVTraits::isValidLength(int16_t tlvtype, size_t len) const
{
  auto p = findOptionByTlvType(tlvtype);
  if (p) {
    return p->isValidLength(len);
  }
  return false;
}

const CurlOption*
TLVTraits::findOptionByTlvType(int16_t tlvtype) const
{
  for (const auto& e : m_all) {
    if (e.m_tlvtype == tlvtype) {
      return &e;
    }
  }
  return nullptr;
}

bool
CurlOption::canBeSetMoreThanOnce() const
{
  switch (m_kind) {
    case Kind::interesting_composing_string:
    case Kind::not_so_interesting_composing_string:
      return true;
    default:
      return false;
  }
}

bool
CurlOption::isFlag() const
{
  switch (m_kind) {
    case Kind::not_so_interesting_flag_once:
      return true;
    default:
      return false;
  }
}

bool
CurlOption::isString() const
{
  switch (m_kind) {
    case Kind::interesting_composing_string:
    case Kind::interesting_once_string:
    case Kind::not_so_interesting_composing_string:
    case Kind::not_so_interesting_once_string:
      return true;
    default:
      return false;
  }
}

bool
CurlOption::isOther() const
{
  return !(isString() || isFlag());
}

bool
CurlOption::isInteresting() const
{
  switch (m_kind) {
    case Kind::interesting_composing_string:
    case Kind::interesting_once_string:
      return true;
    default:
      return false;
  }
}

bool
CurlOption::isValidLength(size_t len) const
{
  switch (m_kind) {
    case Kind::not_so_interesting_flag_once:
      return len == 4;
    default:
      // for the others, anything goes
      return true;
  }
}
