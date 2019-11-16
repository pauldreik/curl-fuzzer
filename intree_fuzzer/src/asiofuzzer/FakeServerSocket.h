
#pragma once

#include "Context.h"

struct FakeServerSocket
{
  explicit FakeServerSocket(IOCONTEXT& io, Context* parent)
    : m_serversocket(io)
    , m_parent(parent)
  {}

  void start_async_read();
  void on_read(const boost::system::error_code& ec, std::size_t bytes_read);

  // returns true if a write was initiated, or the
  // socket closed because no more data to write.
  bool start_async_write();
  void on_write(const boost::system::error_code& ec, std::size_t bytes_read);

  /// we own this one
  boost::asio::posix::stream_descriptor m_serversocket;
  int m_fd_given_to_curl = -1;
  bool m_is_waiting_for_read = false;
  bool m_is_waiting_for_write = false;
  Context* m_parent{};
  std::string m_readbuf;
  std::string m_writebuf;
};
