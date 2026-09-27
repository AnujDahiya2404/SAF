// ns3sim/src/saf-client-app.h
//
// SafClientApp plays the "MQTT Client" role from Algorithms 1 & 2,
// mirroring saf/client.py: Phase 1 registration (send/receive/ack), then
// Phase 2 for either intent (SessionInitiate -> Level1InfoRequest ->
// alpha=HMAC_k(x||c) request -> VerificationStatus), sharing the same
// steps for publish and subscribe. ns-3 Applications are callback-driven
// rather than the real client's blocking queue.get() calls, so this is a
// small explicit state machine instead -- the *sequence* of steps and
// messages sent is identical to client.py, just not expressed as
// synchronous blocking calls.
//
// Role covers both legitimate traffic and the same attack scenarios
// tests/attack_replay.py and tests/attack_tamper.py exercise against the
// real implementation, so the ns-3 simulation can be checked to reproduce
// the same accept/deny behaviour, not just carry real crypto bytes.
#pragma once

#include "ns3/application.h"
#include "ns3/socket.h"
#include "ns3/ipv4-address.h"

#include <functional>
#include <memory>
#include <string>

#include "saf-crypto.h"
#include "saf-framing.h"
#include "saf-messages.h"

namespace safsim {

enum class ClientRole {
  kPublisher,
  kSubscriber,
  kTamperAttacker,      // registers normally, then sends a corrupted alpha
  kReplayAttacker,      // registers normally, publishes, then replays the same identifier_msg
  kGhostAttacker,       // skips Phase 1 entirely, publishes with a fabricated identity
};

struct ClientEvent {
  double t;
  std::string client_id;
  std::string kind;    // "registered" | "approved" | "denied" | "app_message_received" | "timeout"
  std::string detail;
};

class SafClientApp : public ns3::Application {
 public:
  static ns3::TypeId GetTypeId();
  SafClientApp();
  ~SafClientApp() override;

  void Setup(ns3::Ipv4Address brokerAddress, uint16_t brokerPort, std::string clientId,
             ClientRole role, std::string topic, uint32_t numMessages, ns3::Time publishInterval);

  using EventCallback = std::function<void(const ClientEvent &)>;
  void SetEventCallback(EventCallback cb) { m_eventCb = std::move(cb); }

 private:
  void StartApplication() override;
  void StopApplication() override;

  void HandleConnect(ns3::Ptr<ns3::Socket> s);
  void HandleConnectFail(ns3::Ptr<ns3::Socket> s);
  void HandleRecv(ns3::Ptr<ns3::Socket> s);
  void OnMessage(const std::string &frame);

  void SendRegister();
  void OnPreSessionResponse(const safmsg::PreSessionResponse &resp);
  void SendAck();
  void ScheduleNextAction();
  void SendSessionInitiate();
  void OnLevel1InfoRequest(const safmsg::Level1InfoRequest &req);
  void SendPhase2Request();
  void OnVerificationStatus(const safmsg::VerificationStatus &status);
  void OnAppData(const safmsg::json &body);

  void SendGhostPublish();  // kGhostAttacker: skip Phase 1 entirely

  void Emit(const std::string &kind, const std::string &detail);

  ns3::Ipv4Address m_brokerAddress;
  uint16_t m_brokerPort = 0;
  std::string m_clientId;
  ClientRole m_role = ClientRole::kPublisher;
  std::string m_topic;
  uint32_t m_numMessages = 1;
  uint32_t m_messagesSent = 0;
  ns3::Time m_publishInterval;

  ns3::Ptr<ns3::Socket> m_socket;
  std::unique_ptr<safnet::FramedReader> m_reader;

  // Phase-1 state (Algorithm 1, Step 7)
  safcrypto::Bytes m_x;
  safcrypto::Bytes m_k;
  uint16_t m_c = 0;
  bool m_registered = false;

  // In-flight Phase-2 request bookkeeping
  std::string m_pendingIdentifier;
  std::string m_lastIdentifier;  // for kReplayAttacker
  bool m_replaySent = false;

  EventCallback m_eventCb;
};

}  // namespace safsim
