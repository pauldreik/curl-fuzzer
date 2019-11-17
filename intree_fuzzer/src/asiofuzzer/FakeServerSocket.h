
#pragma once

#include "Context.h"

#include <boost/asio/ssl.hpp>
#include <memory>

//#include <variant>

struct FakeServerSocket
{
  FakeServerSocket(IOCONTEXT &io, Context *parent)
    : m_serversocket(io)
    , m_cryptocontext(boost::asio::ssl::context::tlsv12)
    , m_parent(parent)
  {
  }

  void start_async_read();
  void on_read(const boost::system::error_code &ec, std::size_t bytes_read);

  // returns true if a write was initiated, or the
  // socket closed because no more data to write.
  bool start_async_write();
  void on_write(const boost::system::error_code &ec, std::size_t bytes_read);

  /// we own this one
  boost::asio::posix::stream_descriptor m_serversocket;

  boost::asio::ssl::context m_cryptocontext;
  using EncryptedSocket =
    boost::asio::ssl::stream<boost::asio::posix::stream_descriptor>;
  std::unique_ptr<EncryptedSocket> m_encryptedsocket;
  /*std::variant<std::monostate,
   boost::asio::posix::stream_descriptor,
   boost::asio::ssl::stream<boost::asio::posix::stream_descriptor>>
   m_altsocket;*/

  int m_fd_given_to_curl = -1;
  bool m_is_waiting_for_read = false;
  bool m_is_waiting_for_write = false;
  Context *m_parent{};
  std::string m_readbuf;
  std::string m_writebuf;
};
