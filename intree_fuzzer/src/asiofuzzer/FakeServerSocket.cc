
#include "FakeServerSocket.h"

#include <iostream>
#include <memory>

static const bool debugoutput = false;

void
FakeServerSocket::start_async_read()
{
  if(m_is_waiting_for_read) {
    // already waiting.
    return;
  }
  if(!m_serversocket.is_open()) {
    return;
  }
  m_readbuf.assign(256, '\0');
  if(debugoutput)
    std::cout << "start async read on " << m_serversocket.native_handle()
              << std::endl;

  m_serversocket.async_read_some(
    boost::asio::buffer(m_readbuf.data(), m_readbuf.size()),
    [this](auto a, auto b) { on_read(a, b); });

  m_is_waiting_for_read = true;
}

void
FakeServerSocket::on_read(const boost::system::error_code &ec,
                          std::size_t bytes_read)
{
  if(debugoutput)
    std::cout << "on_read(): got " << bytes_read << " byte from socket pair "
              << m_serversocket.native_handle() << "," << m_fd_given_to_curl
              << ": ec=" << ec.message() << std::endl;
  m_is_waiting_for_read = false;

  // if we got data, it means curl lives. reset the watchdog!
  m_parent->curlGaveSignOfLife();

  if(ec) {
    m_parent->haveMadeSomethingCurlShouldNotice();
    m_serversocket.close();
    return;
  }

  // does the client want to upgrade to tls?
  // (content type handshake 0x16, message type client hello 0x01)
  if(bytes_read >= 8 && m_readbuf.at(0) == 0x16 && m_readbuf.at(5) == 0x01) {
    std::cout << "the client want to speak TLS" << std::endl;

    m_cryptocontext.set_password_callback(
      [](auto, auto) { return std::string("xxxx"); });
    m_cryptocontext.use_certificate_file("cert.pem",
                                         boost::asio::ssl::context::pem);
    m_cryptocontext.use_private_key_file("privkey.pem",
                                         boost::asio::ssl::context::pem);

    m_encryptedsocket = std::make_unique<EncryptedSocket>(
      std::move(m_serversocket), m_cryptocontext);

    m_encryptedsocket->async_handshake(
      boost::asio::ssl::stream_base::handshake_type::server,
      boost::asio::const_buffer(m_readbuf.data(), m_readbuf.size()),
      [=](const boost::system::error_code &error,
          std::size_t bytes_transferred) {
        std::cout << "handshake done with ec=" << ec
                  << " bytes_transferred=" << bytes_transferred << " out of "
                  << bytes_read << std::endl;
        // FIXME setup a read or write
      });
    m_parent->haveMadeSomethingCurlShouldNotice();
    return;
  }

  // send a reply!
  start_async_write();

  // also start listening again
  start_async_read();
}

bool
FakeServerSocket::start_async_write()
{
  if(m_is_waiting_for_write) {
    // already waiting.
    return false;
  }
  if(!m_serversocket.is_open()) {
    return false;
  }
  m_writebuf = m_parent->getNextReply();

  if(m_writebuf.empty()) {
    if(debugoutput)
      std::cout << "no more replies to write, closing socket "
                << m_serversocket.native_handle() << std::endl;
    m_serversocket.close();
    m_parent->haveMadeSomethingCurlShouldNotice();
    return true;
  }
  if(debugoutput)
    std::cout << "starting async_write " << m_serversocket.native_handle()
              << std::endl;
  m_serversocket.async_write_some(boost::asio::buffer(m_writebuf),
                                  [this](auto a, auto b) { on_write(a, b); });

  m_is_waiting_for_write = true;
  return true;
}

void
FakeServerSocket::on_write(const boost::system::error_code &ec,
                           std::size_t bytes_written)
{
  if(debugoutput)
    std::cout << "on_write(): has written " << bytes_written
              << " bytes to socket pair " << m_serversocket.native_handle()
              << "," << m_fd_given_to_curl << ": ec=" << ec.message()
              << std::endl;
  m_is_waiting_for_write = false;

  if(ec)
    return;

  // is there anything left to write of this buffer?
  if(m_writebuf.size() > bytes_written) {
    std::cout << "on_write(): still data left to write" << std::endl;
    m_writebuf.erase(0, m_writebuf.size() - bytes_written);

    m_serversocket.async_write_some(
      boost::asio::buffer(m_writebuf),
      [this](auto a, auto b) { on_write(a, b); });
    m_is_waiting_for_write = true;
  }

  // notify that we actually did something curl should have noticed, so
  // the main loop knows when to stop waiting
  m_parent->haveMadeSomethingCurlShouldNotice();
}
