// ns3sim/src/saf-framing.h
//
// Length-prefixed message framing over an ns-3 TCP socket: each message is
// [4-byte big-endian length][UTF-8 JSON body]. TCP is a byte stream with
// no message boundaries of its own, so a single ns3::Socket::Recv callback
// can deliver a partial message, multiple messages, or a message split
// across several callbacks -- FramedReader buffers bytes per-connection
// and only calls back once a complete frame has arrived.
#pragma once

#include "ns3/socket.h"
#include "ns3/packet.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace safnet {

inline void SendFramed(ns3::Ptr<ns3::Socket> socket, const std::string &body) {
  uint32_t len = static_cast<uint32_t>(body.size());
  std::vector<uint8_t> buf(4 + body.size());
  buf[0] = static_cast<uint8_t>((len >> 24) & 0xFF);
  buf[1] = static_cast<uint8_t>((len >> 16) & 0xFF);
  buf[2] = static_cast<uint8_t>((len >> 8) & 0xFF);
  buf[3] = static_cast<uint8_t>(len & 0xFF);
  std::copy(body.begin(), body.end(), buf.begin() + 4);
  ns3::Ptr<ns3::Packet> packet = ns3::Create<ns3::Packet>(buf.data(), buf.size());
  socket->Send(packet);
}

class FramedReader {
 public:
  using MessageCallback = std::function<void(const std::string &)>;

  explicit FramedReader(MessageCallback cb) : m_cb(std::move(cb)) {}

  // Feed raw bytes received from the socket; invokes the callback once
  // per complete frame, and re-checks the buffer after each one in case
  // several frames arrived back to back.
  void Feed(ns3::Ptr<ns3::Packet> packet) {
    uint32_t size = packet->GetSize();
    std::vector<uint8_t> chunk(size);
    packet->CopyData(chunk.data(), size);
    m_buf.insert(m_buf.end(), chunk.begin(), chunk.end());

    while (true) {
      if (m_buf.size() < 4) return;
      uint32_t len = (static_cast<uint32_t>(m_buf[0]) << 24) |
                     (static_cast<uint32_t>(m_buf[1]) << 16) |
                     (static_cast<uint32_t>(m_buf[2]) << 8) | static_cast<uint32_t>(m_buf[3]);
      if (m_buf.size() < 4 + len) return;
      std::string body(m_buf.begin() + 4, m_buf.begin() + 4 + len);
      m_buf.erase(m_buf.begin(), m_buf.begin() + 4 + len);
      m_cb(body);
    }
  }

 private:
  std::vector<uint8_t> m_buf;
  MessageCallback m_cb;
};

}  // namespace safnet
