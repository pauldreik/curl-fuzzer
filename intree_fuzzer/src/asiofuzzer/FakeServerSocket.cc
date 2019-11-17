
#include "FakeServerSocket.h"

#include <iostream>
#include <memory>

static const bool debugoutput = false;

boost::asio::ssl::context FakeServerSocket::m_cryptocontext = []() {
  boost::asio::ssl::context context(boost::asio::ssl::context::tlsv12);

  // made with (copy pasted from command history, probably wrong):
  // openssl req -new > cert.csr
  // openssl rsa -in privkey.pem -out key.pem
  // openssl x509 -in cert.csr -out cert.pem -req -signkey key.pem -days 10000
  // cat privkey.pem |sed -e 's/$/\\n"/g' -e 's/^/"/g'
  const std::string privkey =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIE7zQtww/hesCAggA\n"
    "MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECA/LpuzBMbNwBIIEyLv7fW9BCkn+\n"
    "0kdyeYXPpXuiaz0OgzgiPvQkNh1NZWXX9HQ3Ov1t2ho03xzjGD3FRdzajwBbgrQA\n"
    "99qIX2gjHh79dSPHnQohAn6XSEUi0S9/3dTl5vMEg6o9AmM8T8MDFW9lQhWb0sSD\n"
    "coYmtsWLnBcIeu7qFNJgJra4yXHqbF2DOp1wzkookN7DJVSBKnhmRg7Tx03AXvR+\n"
    "euyHhR0GNtxuvZOgSxeB9fcxgsbS5SAfFNJa8eGy4/QxNhrhk5kTuLfxuZsV8WqT\n"
    "LukV6tqEvKEsq0fSvArFNhCPJtTuctXPBO+MN5NTg6Rj/ONroxP+3Ecd17pdt4Ht\n"
    "OGpy+c4Em1Lo9fuHmUcww5t1EDU/lBqHIC5VB0/Ap1cs2OKvVljX/xmA7+uzcOop\n"
    "cVG5S9F7QqUsELIhUvFrZcdOGuxlgjxev6isX16za831UqCV9U9Lr6a9L31B8a+q\n"
    "zSJ202CHM6WNoCga8pvvHgdQrF4Ih0huIho15sWVvGPjZqyCSA5SaOr73XekOjou\n"
    "PG/E5SWFAZV2qTcqkXXu3sFUrpnI7vU9ckyFLo5MYY6GnnBZk5AONJCy897mrelw\n"
    "i3Cg+cdXG8gQR3K5jQddYc6CdqD9QrTKbS0iZWT/dRkF1BlOZB6oftjXROWnDorH\n"
    "CDprTjafg6WFlHA13tycSnz4Ht13n/0Ud1JZ3uFEk4k6JRYQx75UNTQOALuxcLSm\n"
    "4RDYAd6tifeStpeVpGB/tbk5/2ivQjeapXnHJsozw2dPKvZ1wnQK4optLQGjBf7g\n"
    "5lVUq5etw24FRcQxhzE5P8MvpuykbnRvmTPc/0lmlQWZeu4bSbeLc4QfaoKQQD8c\n"
    "dY9QLHz2k2+XSP7CvADpChiWhhnH8PfTyPyh6flCka3D0R1JlwbvjAGj3d6Z7q0N\n"
    "ToLWWrbJgtD6Qf6MHibVNuZiEPBCiYMnMSPEczrDL5zRejhBqWurRLkxaJ5ij2PM\n"
    "yEXw2q2yE0fG90FC/NZ7Fa6rSZ6p2OTuGdMCO5cSARIjgatIfFtyWJJdulYssOoH\n"
    "qDgtTxT/bwC2+QIHvaaIYDibIdzvIv6t3miGVOvqZp82QcdtsiZeG/OS8OTAZ6bj\n"
    "hCL0021iFBfnSTtWFF6wfUqnoE5pb/2gRruwVXide1ow0YuFt2G3K1XCdLpNLz2J\n"
    "4+M+TZ8FgWLvgwk13h4qgGi2uRXHqnmmPtVrIO/SalG9NGo42kC9NcDrgz8LW609\n"
    "70l4c+UpHs14Wgt9vWoe+GUHC50nadFSeI6FMXEK2KNcI4r7F8eKCPqTcVGIqJcY\n"
    "I9+p3XbnrekSt8ZAxT5ewY1em39KDiZT5jC3Rh3taf4jY4TFSZmwmfWLks+m0rY1\n"
    "FR47FH18IyxeBq71sgQ/9snRmeFPCrBUV1knUIgzbUy5JdXLe/1cRgMHnf90VgzT\n"
    "NsS18AOoSS9pReYhudRASU6n4SyTkD15FZbn492HFKfkAzXJWE1xP2UdCyAVRfWE\n"
    "n5an/KhknSIjdWO/ErxkfQeoY7vZeYRhWtgt8Ud/vDH14PhkINXYJMZsyOG/7QCT\n"
    "RGv5E8J1kSkZuxjKXEHNPJqGBXNATXeRYsBNMWJCTK7MK2KUl8rosN1/9o5Rbd0k\n"
    "9dquNVMqwaMdR0ea+GfwfQ==\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n";

  const std::string cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDETCCAfkCFC0ls5z9wOYJGOMV2WxHWAnmVLnYMA0GCSqGSIb3DQEBCwUAMEUx\n"
    "CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\n"
    "cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTkxMTE2MjEyNjM2WhcNMjIwODEzMjEy\n"
    "NjM2WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\n"
    "CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
    "AQ8AMIIBCgKCAQEAzzPVTFUx/MVEskwVhW0t42dFA8xki5BMWnvySY0EOLaMKQTr\n"
    "TQcB9o7YubCfv5TCFLjlSQ1AynSYs0Fy3Ds9J67M3ZoOP59xu7rMI7eNd2Jo9CYv\n"
    "Nh5FzFhoUkxRtYkzov27ItStCMUaUR1Vf/mXU9X/oTc4EJ0k8+AAkDgIRa9rD1jj\n"
    "kc9hh66IOsANBcgGlIqsVMimY+88WhVs3Zq5sMKzvTdqlkRkoehu5ud5lu55unzz\n"
    "sN0XZB8paeu5Cw0oUoQMuBkvE9wcFcJxRYc1MReLJ2qMxBrJ5Y2pFPq/kFEn2ga6\n"
    "kRZzZeJ9/1xgmFauocdKNDJWc1Rfv9omWBwlIQIDAQABMA0GCSqGSIb3DQEBCwUA\n"
    "A4IBAQCY1/dbLQ2c/OgRGAO5qstsrr0uIEfXzrzrAKWIKRxz9XK+BT0k3CLC8YGD\n"
    "ynX8RoPgV4qGn9egO3cc9YGWMZZ7lfwioUBKvDNQeLMP4lPIIRghCLasagahnu+5\n"
    "BfiXltfVm6d1tn9Y/gTxI70OeZF8MHsLc6+O+/tZq81z4EnXQ+x+QbHOKhEha/HN\n"
    "hY8A9Gw7HxRJ52Sr9V9WHfXPpIfaEyEx80nBZenlHLBm8v2kyCpZFZvzYYCXrobo\n"
    "+MUIXHT/pq+3R41Gjpvayu0UKS2VD5namUOPJcMSHaEF3BbW3nuXNfF9VfShh1GF\n"
    "liL9pVWk/l4tyvz2TIE7GgMgZ3VI\n"
    "-----END CERTIFICATE-----\n";
  context.set_password_callback(
    [](auto, auto) { return std::string("xxxx"); });
  context.use_certificate(boost::asio::buffer(cert),
                          boost::asio::ssl::context::pem);
  context.use_private_key(boost::asio::buffer(privkey),
                          boost::asio::ssl::context::pem);

  return context;
}();

void
FakeServerSocket::start_async_read()
{
  if(m_is_waiting_for_read) {
    // already waiting.
    return;
  }

  const bool encrypted = is_encrypted();

  auto &socket =
    (encrypted ? m_encryptedsocket->next_layer() : m_serversocket);
  if(!socket.is_open()) {
    return;
  }

  m_readbuf.assign(256, '\0');
  if(debugoutput)
    std::cout << "start async read on " << socket.native_handle() << std::endl;

  auto buf = boost::asio::buffer(m_readbuf.data(), m_readbuf.size());
  auto callback = [this](auto a, auto b) { on_read(a, b); };
  if(encrypted) {
    m_encryptedsocket->async_read_some(buf, callback);
  }
  else {
    m_serversocket.async_read_some(buf, callback);
  }

  m_is_waiting_for_read = true;
}

bool
FakeServerSocket::is_encrypted() const
{
  // if we have an encrypted socket, we are encrypted.
  return !!m_encryptedsocket;
}

void
FakeServerSocket::on_read(const boost::system::error_code &ec,
                          std::size_t bytes_read)
{
  const bool encrypted = is_encrypted();
  auto &socket =
    (encrypted ? m_encryptedsocket->next_layer() : m_serversocket);

  if(encrypted) {
    (void)encrypted;
  }

  if(debugoutput)
    std::cout << "on_read(): got " << bytes_read << " byte from socket pair "
              << socket.native_handle() << "," << m_fd_given_to_curl
              << ": ec=" << ec.message() << std::endl;
  m_is_waiting_for_read = false;

  // if we got data, it means curl lives. reset the watchdog!
  m_parent->curlGaveSignOfLife();

  if(ec) {
    m_parent->haveMadeSomethingCurlShouldNotice();
    socket.close();
    return;
  }

  // does the client want to upgrade to tls?
  // (content type handshake 0x16, message type client hello 0x01)
  if(!is_encrypted() && bytes_read >= 8 && m_readbuf.at(0) == 0x16 &&
     m_readbuf.at(5) == 0x01) {
    if(debugoutput)
      std::cout << "the client wants to speak TLS" << std::endl;

    // detect nested tls
    assert(!m_encryptedsocket);
    m_encryptedsocket = std::make_unique<EncryptedSocket>(
      std::move(m_serversocket), m_cryptocontext);

    m_encryptedsocket->async_handshake(
      boost::asio::ssl::stream_base::handshake_type::server,
      boost::asio::const_buffer(m_readbuf.data(), bytes_read),
      [this, bytes_read](const boost::system::error_code &error,
                         std::size_t bytes_transferred) {
        if(debugoutput) {
          std::cout << "TLS handshake done with error=" << error
                    << " bytes_transferred=" << bytes_transferred << " out of "
                    << bytes_read << std::endl;
        }
        if(!error) {
          // handling leftover handshake data seems difficult.
          assert(bytes_read == bytes_transferred);
          this->start_async_read();
        }
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

  const bool encrypted = is_encrypted();

  auto &socket =
    (encrypted ? m_encryptedsocket->next_layer() : m_serversocket);

  if(!socket.is_open()) {
    return false;
  }
  m_writebuf = m_parent->getNextReply();

  if(m_writebuf.empty()) {
    if(debugoutput)
      std::cout << "no more replies to write, closing socket "
                << socket.native_handle() << std::endl;
    socket.close();
    m_parent->haveMadeSomethingCurlShouldNotice();
    return true;
  }
  if(debugoutput)
    std::cout << "starting async_write " << socket.native_handle()
              << std::endl;
  if(encrypted) {
    m_encryptedsocket->async_write_some(
      boost::asio::buffer(m_writebuf),
      [this](auto a, auto b) { on_write(a, b); });
  }
  else {
    m_serversocket.async_write_some(
      boost::asio::buffer(m_writebuf),
      [this](auto a, auto b) { on_write(a, b); });
  }

  m_is_waiting_for_write = true;
  return true;
}

void
FakeServerSocket::on_write(const boost::system::error_code &ec,
                           std::size_t bytes_written)
{
  const bool encrypted = is_encrypted();

  auto &socket =
    (encrypted ? m_encryptedsocket->next_layer() : m_serversocket);

  if(debugoutput)
    std::cout << "on_write(): has written " << bytes_written
              << " bytes to socket pair " << socket.native_handle() << ","
              << m_fd_given_to_curl << ": ec=" << ec.message() << std::endl;
  m_is_waiting_for_write = false;

  if(ec)
    return;

  // is there anything left to write of this buffer?
  if(m_writebuf.size() > bytes_written) {
    std::cout << "on_write(): still data left to write" << std::endl;
    m_writebuf.erase(0, m_writebuf.size() - bytes_written);

    if(encrypted) {
      m_encryptedsocket->async_write_some(
        boost::asio::buffer(m_writebuf),
        [this](auto a, auto b) { on_write(a, b); });
    }
    else {
      m_serversocket.async_write_some(
        boost::asio::buffer(m_writebuf),
        [this](auto a, auto b) { on_write(a, b); });
    }
    m_is_waiting_for_write = true;
  }

  // notify that we actually did something curl should have noticed, so
  // the main loop knows when to stop waiting
  m_parent->haveMadeSomethingCurlShouldNotice();
}
