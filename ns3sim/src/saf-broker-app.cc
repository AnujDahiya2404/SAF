#include "saf-broker-app.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/tcp-socket-factory.h"

NS_LOG_COMPONENT_DEFINE("SafBrokerApp");

namespace safsim {

using namespace ns3;

TypeId SafBrokerApp::GetTypeId() {
  static TypeId tid =
      TypeId("safsim::SafBrokerApp").SetParent<Application>().SetGroupName("SafSim");
  return tid;
}

SafBrokerApp::SafBrokerApp() = default;
SafBrokerApp::~SafBrokerApp() = default;

void SafBrokerApp::Setup(uint16_t port) { m_port = port; }

void SafBrokerApp::StartApplication() {
  m_listenSocket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  m_listenSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
  m_listenSocket->Listen();
  m_listenSocket->SetAcceptCallback(MakeCallback(&SafBrokerApp::HandleAccept, this),
                                     MakeCallback(&SafBrokerApp::HandleNewConnection, this));
}

void SafBrokerApp::StopApplication() {
  if (m_listenSocket) {
    m_listenSocket->Close();
  }
  for (auto &kv : m_connections) {
    kv.first->Close();
  }
  m_connections.clear();
}

bool SafBrokerApp::HandleAccept(Ptr<Socket>, const Address &) { return true; }

void SafBrokerApp::HandleNewConnection(Ptr<Socket> s, const Address &) {
  Connection conn;
  conn.reader = std::make_unique<safnet::FramedReader>(
      [this, s](const std::string &frame) { OnMessage(s, frame); });
  m_connections[s] = std::move(conn);
  s->SetRecvCallback(MakeCallback(&SafBrokerApp::HandleRecv, this));
  s->SetCloseCallbacks(MakeCallback(&SafBrokerApp::HandlePeerClose, this),
                        MakeCallback(&SafBrokerApp::HandlePeerClose, this));
}

void SafBrokerApp::HandleRecv(Ptr<Socket> s) {
  auto it = m_connections.find(s);
  if (it == m_connections.end()) return;
  Ptr<Packet> packet;
  while ((packet = s->Recv())) {
    if (packet->GetSize() == 0) break;
    it->second.reader->Feed(packet);
  }
}

void SafBrokerApp::HandlePeerClose(Ptr<Socket> s) {
  auto it = m_connections.find(s);
  if (it != m_connections.end()) {
    if (!it->second.clientId.empty()) {
      m_clientSockets.erase(it->second.clientId);
    }
    m_connections.erase(it);
  }
}

void SafBrokerApp::SendTo(Ptr<Socket> s, const std::string &frame) {
  safnet::SendFramed(s, frame);
}

void SafBrokerApp::LogDecision(const std::string &phase, const std::string &clientId,
                                const std::string &status, const std::string &reason) {
  m_log.push_back({Simulator::Now().GetSeconds(), phase, clientId, status, reason});
}

void SafBrokerApp::OnMessage(Ptr<Socket> s, const std::string &frame) {
  safmsg::json j;
  try {
    j = safmsg::json::parse(frame);
  } catch (const std::exception &e) {
    NS_LOG_WARN("malformed frame from client: " << e.what());
    return;
  }
  safmsg::Kind kind = safmsg::KindFromName(j.at("kind").get<std::string>());
  const safmsg::json &body = j.at("body");

  switch (kind) {
    case safmsg::Kind::kPreSessionRequest:
      OnPreSessionRequest(s, body.get<safmsg::PreSessionRequest>());
      break;
    case safmsg::Kind::kPreSessionAck:
      OnPreSessionAck(body.get<safmsg::PreSessionAck>());
      break;
    case safmsg::Kind::kSessionInitiate:
      OnSessionInitiate(s, body.get<safmsg::SessionInitiate>());
      break;
    case safmsg::Kind::kPublishRequest:
      OnPublishRequest(s, body.get<safmsg::PublishRequest>());
      break;
    case safmsg::Kind::kSubscribeRequest:
      OnSubscribeRequest(s, body.get<safmsg::SubscribeRequest>());
      break;
    default:
      NS_LOG_WARN("broker received unexpected message kind");
  }
}

// ---------------------- Phase 1: Pre-Session (Algorithm 1) ----------------------

void SafBrokerApp::OnPreSessionRequest(Ptr<Socket> s, const safmsg::PreSessionRequest &req) {
  // Step 2: verify client_id -- well-formed, non-empty, reasonably shaped
  // (mirrors gateway.py's _verify_client_id()).
  if (req.client_id.empty() || req.client_id.size() > 128) {
    LogDecision("presession", req.client_id, "DENIED", "invalid client_id");
    m_stats.presession_denied++;
    return;
  }
  if (!m_store.RegistrationAllowed()) {
    LogDecision("presession", req.client_id, "DENIED",
                "registration blocked (rate limit / max clients)");
    m_stats.presession_denied++;
    return;
  }

  // Step 3: broker creates client_state = (session_time, estimated_duration)
  double now = Simulator::Now().GetSeconds();
  std::string sessionTime = "T+" + std::to_string(now) + "s";
  std::string estimatedDuration = "30 mins";
  safcrypto::Bytes stateBytes = safcrypto::SerializeClientState(sessionTime, estimatedDuration);

  // Step 4: x = h(client_state)
  safcrypto::Bytes x = safcrypto::Sha256(stateBytes);

  // Step 5: generate session key k (32 bytes) and counter c (starts at 0)
  safcrypto::Bytes k = safcrypto::GenerateSessionKey();
  uint16_t c = 0;

  m_store.RegisterClient(req.client_id, x, k, c, sessionTime, estimatedDuration);
  m_store.UpdateLastSessionTime(req.client_id, sessionTime);
  m_connections[s].clientId = req.client_id;
  m_clientSockets[req.client_id] = s;

  // Step 6: broker sends y = x || k || c to client
  safmsg::PreSessionResponse resp;
  resp.client_id = req.client_id;
  resp.x_hex = safcrypto::ToHex(x);
  resp.k_hex = safcrypto::ToHex(k);
  resp.c = c;
  resp.session_time = sessionTime;
  resp.estimated_duration = estimatedDuration;
  SendTo(s, safmsg::Envelope(safmsg::Kind::kPreSessionResponse, resp));

  LogDecision("presession", req.client_id, "ESTABLISHED", "");
  m_stats.presession_established++;
}

void SafBrokerApp::OnPreSessionAck(const safmsg::PreSessionAck &ack) {
  // Algorithm 1, Step 8: purely a confirmation -- registration already
  // completed when the PreSessionResponse was sent. Nothing to verify.
  NS_LOG_INFO("received ack from " << ack.client_id);
}

// ---------------------- Phase 2: In-Session (Algorithm 2) ----------------------

void SafBrokerApp::OnSessionInitiate(Ptr<Socket> s, const safmsg::SessionInitiate &req) {
  // Algorithm 2, Step 3: reply with Level1InfoRequest. Pure handshake --
  // doesn't gate VerifyAndApprove() below, matching saf/gateway.py.
  safmsg::Level1InfoRequest resp;
  resp.client_id = req.client_id;
  SendTo(s, safmsg::Envelope(safmsg::Kind::kLevel1InfoRequest, resp));
}

ClientRecord *SafBrokerApp::VerifyAndApprove(Ptr<Socket> s, const std::string &clientId,
                                              const std::string &alphaHex, double tMsg,
                                              const std::string &identifierMsg,
                                              const std::string &topic,
                                              const std::string &intent) {
  ClientRecord *rec = m_store.GetClient(clientId);
  auto deny = [&](const std::string &reason) {
    safmsg::VerificationStatus status;
    status.client_id = clientId;
    status.identifier_msg = identifierMsg;
    status.status = "Denied";
    status.reason = reason;
    SendTo(s, safmsg::Envelope(safmsg::Kind::kVerificationStatus, status));
    LogDecision(intent, clientId, "Denied", reason);
    m_stats.phase2_denied++;
  };

  if (rec == nullptr) {
    deny("unregistered client_id (no Phase-1 client-state on file)");
    m_stats.denied_unregistered++;
    return nullptr;
  }

  // Step 5a: freshness check on t_msg (anti-replay).
  if (!m_store.IsFreshTimestamp(tMsg, Simulator::Now().GetSeconds())) {
    deny("stale timestamp t_msg (possible replay)");
    m_stats.denied_stale_timestamp++;
    return nullptr;
  }

  // Step 5b: identifier_msg uniqueness check.
  if (m_store.IsDuplicateIdentifier(clientId, identifierMsg)) {
    deny("duplicate identifier_msg (replay or unintended duplication)");
    m_stats.denied_duplicate_identifier++;
    return nullptr;
  }

  // Step 5c: verify alpha = HMAC_k(x||c), constant-time compare.
  uint16_t counterVerified = rec->counter;
  safcrypto::Bytes expectedAlpha = safcrypto::ComputeAlpha(rec->session_key, rec->state_hash,
                                                             counterVerified);
  safcrypto::Bytes givenAlpha;
  try {
    givenAlpha = safcrypto::FromHex(alphaHex);
  } catch (...) {
    deny("malformed alpha (not valid hex)");
    return nullptr;
  }
  if (!safcrypto::ConstantTimeEq(expectedAlpha, givenAlpha)) {
    deny("HMAC verification failed (integrity/authenticity check failed)");
    m_stats.denied_hmac_mismatch++;
    return nullptr;
  }

  // Approved.
  m_store.RecordIdentifier(clientId, identifierMsg);
  m_store.BumpCounter(clientId);
  m_store.UpdateLastSessionTime(clientId, "T+" + std::to_string(Simulator::Now().GetSeconds()));

  safmsg::VerificationStatus status;
  status.client_id = clientId;
  status.identifier_msg = identifierMsg;
  status.status = "Approved";
  SendTo(s, safmsg::Envelope(safmsg::Kind::kVerificationStatus, status));
  LogDecision(intent, clientId, "Approved", "");
  m_stats.phase2_approved++;
  return rec;
}

void SafBrokerApp::OnPublishRequest(Ptr<Socket> s, const safmsg::PublishRequest &req) {
  ClientRecord *rec = VerifyAndApprove(s, req.client_id, req.alpha_hex, req.t_msg,
                                        req.identifier_msg, req.topic, "publish");
  if (rec == nullptr) return;

  // Step 7 (relay): stand-in for gateway.py's app/<topic> republish +
  // Mosquitto's own delivery -- send AppData directly to every socket
  // whose client is Approved-subscribed to this topic.
  auto it = m_topicSubscribers.find(req.topic);
  if (it == m_topicSubscribers.end()) return;
  for (const auto &subClientId : it->second) {
    auto sockIt = m_clientSockets.find(subClientId);
    if (sockIt == m_clientSockets.end()) continue;
    safmsg::json appData;
    appData["kind"] = "AppData";
    appData["body"] = {{"topic", req.topic}, {"payload_b64", req.payload_b64}};
    SendTo(sockIt->second, appData.dump());
    m_stats.app_messages_relayed++;
  }
}

void SafBrokerApp::OnSubscribeRequest(Ptr<Socket> s, const safmsg::SubscribeRequest &req) {
  ClientRecord *rec = VerifyAndApprove(s, req.client_id, req.alpha_hex, req.t_msg,
                                        req.identifier_msg, req.topic, "subscribe");
  if (rec == nullptr) return;
  m_topicSubscribers[req.topic].insert(req.client_id);
}

}  // namespace safsim
