// ns3sim/src/saf-broker-app.h
//
// SafBrokerApp plays the role of "MQTT Broker" in Algorithms 1 & 2,
// mirroring saf/gateway.py: same verification steps (freshness check,
// duplicate-identifier check, constant-time HMAC compare via
// safcrypto::ConstantTimeEq, same denial reason strings), same shared
// _verify_and_approve()-equivalent for both publish and subscribe intents.
// Since ns-3 has no MQTT broker to delegate actual pub/sub routing to
// (see README.md's ns-3 section), this app also does the minimal topic
// relay a real Mosquitto broker would: once a client's SubscribeRequest
// is Approved, its socket is remembered against that topic, and future
// Approved PublishRequests on the same topic get relayed to it directly
// (AppData) -- functionally equivalent to saf/gateway.py's
// app/<topic> republish + Mosquitto's own delivery, just without a
// separate broker process in between.
#pragma once

#include "ns3/application.h"
#include "ns3/socket.h"
#include "ns3/nstime.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "saf-crypto.h"
#include "saf-framing.h"
#include "saf-messages.h"
#include "saf-state-store.h"

namespace safsim {

struct DecisionLogEntry {
  double t;
  std::string phase;      // "presession" | "publish" | "subscribe"
  std::string client_id;
  std::string status;     // "ESTABLISHED" | "Approved" | "Denied"
  std::string reason;
};

struct BrokerStats {
  uint32_t presession_established = 0;
  uint32_t presession_denied = 0;
  uint32_t phase2_approved = 0;
  uint32_t phase2_denied = 0;
  uint32_t denied_hmac_mismatch = 0;
  uint32_t denied_duplicate_identifier = 0;
  uint32_t denied_stale_timestamp = 0;
  uint32_t denied_unregistered = 0;
  uint32_t app_messages_relayed = 0;
};

class SafBrokerApp : public ns3::Application {
 public:
  static ns3::TypeId GetTypeId();
  SafBrokerApp();
  ~SafBrokerApp() override;

  // maxClients mirrors saf/state_store.py's SAFStateStore(max_clients=50)
  // default -- Section V-B's registration rate limiter. Exposed so a run
  // simulating more than 50 real clients can raise it explicitly instead
  // of silently hitting the cap.
  void Setup(uint16_t port, size_t maxClients = 50);

  const BrokerStats &Stats() const { return m_stats; }
  const std::vector<DecisionLogEntry> &DecisionLog() const { return m_log; }
  SafStateStore &Store() { return m_store; }

 private:
  void StartApplication() override;
  void StopApplication() override;

  bool HandleAccept(ns3::Ptr<ns3::Socket> s, const ns3::Address &from);
  void HandleNewConnection(ns3::Ptr<ns3::Socket> s, const ns3::Address &from);
  void HandleRecv(ns3::Ptr<ns3::Socket> s);
  void HandlePeerClose(ns3::Ptr<ns3::Socket> s);

  void OnMessage(ns3::Ptr<ns3::Socket> s, const std::string &frame);
  void OnPreSessionRequest(ns3::Ptr<ns3::Socket> s, const safmsg::PreSessionRequest &req);
  void OnPreSessionAck(const safmsg::PreSessionAck &ack);
  void OnSessionInitiate(ns3::Ptr<ns3::Socket> s, const safmsg::SessionInitiate &req);
  void OnPublishRequest(ns3::Ptr<ns3::Socket> s, const safmsg::PublishRequest &req);
  void OnSubscribeRequest(ns3::Ptr<ns3::Socket> s, const safmsg::SubscribeRequest &req);

  // Shared Algorithm 2, Steps 3-6 verification -- returns the ClientRecord
  // on Approval (after already sending the status reply), nullptr on
  // Denial (also after already sending the status reply). Mirrors
  // gateway.py's _verify_and_approve() exactly, including which checks
  // run in which order.
  ClientRecord *VerifyAndApprove(ns3::Ptr<ns3::Socket> s, const std::string &clientId,
                                  const std::string &alphaHex, double tMsg,
                                  const std::string &identifierMsg, const std::string &topic,
                                  const std::string &intent);

  void SendTo(ns3::Ptr<ns3::Socket> s, const std::string &frame);
  void LogDecision(const std::string &phase, const std::string &clientId,
                    const std::string &status, const std::string &reason);

  uint16_t m_port = 0;
  ns3::Ptr<ns3::Socket> m_listenSocket;
  SafStateStore m_store;
  BrokerStats m_stats;
  std::vector<DecisionLogEntry> m_log;

  struct Connection {
    std::unique_ptr<safnet::FramedReader> reader;
    std::string clientId;  // filled in once known (after PreSessionRequest)
  };
  std::map<ns3::Ptr<ns3::Socket>, Connection> m_connections;
  std::map<std::string, ns3::Ptr<ns3::Socket>> m_clientSockets;      // client_id -> its socket
  std::map<std::string, std::set<std::string>> m_topicSubscribers;   // topic -> client_ids
};

}  // namespace safsim
