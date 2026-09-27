#include "saf-client-app.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/tcp-socket-factory.h"

NS_LOG_COMPONENT_DEFINE("SafClientApp");

namespace safsim {

using namespace ns3;

TypeId SafClientApp::GetTypeId() {
  static TypeId tid =
      TypeId("safsim::SafClientApp").SetParent<Application>().SetGroupName("SafSim");
  return tid;
}

SafClientApp::SafClientApp() = default;
SafClientApp::~SafClientApp() = default;

void SafClientApp::Setup(Ipv4Address brokerAddress, uint16_t brokerPort, std::string clientId,
                          ClientRole role, std::string topic, uint32_t numMessages,
                          Time publishInterval) {
  m_brokerAddress = brokerAddress;
  m_brokerPort = brokerPort;
  m_clientId = std::move(clientId);
  m_role = role;
  m_topic = std::move(topic);
  m_numMessages = numMessages;
  m_publishInterval = publishInterval;
}

void SafClientApp::StartApplication() {
  m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  m_reader = std::make_unique<safnet::FramedReader>(
      [this](const std::string &frame) { OnMessage(frame); });
  m_socket->SetConnectCallback(MakeCallback(&SafClientApp::HandleConnect, this),
                                MakeCallback(&SafClientApp::HandleConnectFail, this));
  m_socket->SetRecvCallback(MakeCallback(&SafClientApp::HandleRecv, this));
  m_socket->Connect(InetSocketAddress(m_brokerAddress, m_brokerPort));
}

void SafClientApp::StopApplication() {
  if (m_socket) {
    m_socket->Close();
  }
}

void SafClientApp::HandleConnect(Ptr<Socket>) {
  if (m_role == ClientRole::kGhostAttacker) {
    SendGhostPublish();
  } else {
    SendRegister();
  }
}

void SafClientApp::HandleConnectFail(Ptr<Socket>) { Emit("timeout", "TCP connect to broker failed"); }

void SafClientApp::HandleRecv(Ptr<Socket> s) {
  Ptr<Packet> packet;
  while ((packet = s->Recv())) {
    if (packet->GetSize() == 0) break;
    m_reader->Feed(packet);
  }
}

void SafClientApp::OnMessage(const std::string &frame) {
  safmsg::json j;
  try {
    j = safmsg::json::parse(frame);
  } catch (const std::exception &e) {
    NS_LOG_WARN("client " << m_clientId << " got malformed frame: " << e.what());
    return;
  }
  std::string kindName = j.at("kind").get<std::string>();
  const safmsg::json &body = j.at("body");

  if (kindName == "AppData") {
    OnAppData(body);
    return;
  }
  switch (safmsg::KindFromName(kindName)) {
    case safmsg::Kind::kPreSessionResponse:
      OnPreSessionResponse(body.get<safmsg::PreSessionResponse>());
      break;
    case safmsg::Kind::kLevel1InfoRequest:
      OnLevel1InfoRequest(body.get<safmsg::Level1InfoRequest>());
      break;
    case safmsg::Kind::kVerificationStatus:
      OnVerificationStatus(body.get<safmsg::VerificationStatus>());
      break;
    default:
      NS_LOG_WARN("client " << m_clientId << " got unexpected message kind " << kindName);
  }
}

void SafClientApp::Emit(const std::string &kind, const std::string &detail) {
  if (m_eventCb) {
    m_eventCb({Simulator::Now().GetSeconds(), m_clientId, kind, detail});
  }
}

// ---------------------- Phase 1: Pre-Session (Algorithm 1) ----------------------

void SafClientApp::SendRegister() {
  safmsg::PreSessionRequest req;
  req.client_id = m_clientId;
  req.request_time = "T+" + std::to_string(Simulator::Now().GetSeconds()) + "s";
  safnet::SendFramed(m_socket, safmsg::Envelope(safmsg::Kind::kPreSessionRequest, req));
}

void SafClientApp::OnPreSessionResponse(const safmsg::PreSessionResponse &resp) {
  // Step 7: client stores x, k, c.
  m_x = safcrypto::FromHex(resp.x_hex);
  m_k = safcrypto::FromHex(resp.k_hex);
  m_c = static_cast<uint16_t>(resp.c);
  m_registered = true;
  Emit("registered", "c=" + std::to_string(m_c));

  // Step 8: client sends ack.
  SendAck();
  ScheduleNextAction();
}

void SafClientApp::SendAck() {
  safmsg::PreSessionAck ack;
  ack.client_id = m_clientId;
  ack.ack = "Acknowledged";
  safnet::SendFramed(m_socket, safmsg::Envelope(safmsg::Kind::kPreSessionAck, ack));
}

// ---------------------- Phase 2: In-Session (Algorithm 2) ----------------------

void SafClientApp::ScheduleNextAction() {
  if (!m_registered) return;
  if (m_messagesSent >= m_numMessages) return;
  SendSessionInitiate();
}

void SafClientApp::SendSessionInitiate() {
  safmsg::SessionInitiate req;
  req.client_id = m_clientId;
  req.intent = (m_role == ClientRole::kSubscriber) ? "subscribe" : "publish";
  req.topic = m_topic;
  safnet::SendFramed(m_socket, safmsg::Envelope(safmsg::Kind::kSessionInitiate, req));
}

void SafClientApp::OnLevel1InfoRequest(const safmsg::Level1InfoRequest &) { SendPhase2Request(); }

void SafClientApp::SendPhase2Request() {
  double tMsg = Simulator::Now().GetSeconds();

  // kReplayAttacker: message index 1 reuses message index 0's
  // identifier_msg, exactly like tests/attack_replay.py's
  // replay_identifier= hook -- a full second Phase-2 round trip, just
  // with a deliberately non-fresh identifier.
  std::string identifierMsg;
  if (m_role == ClientRole::kReplayAttacker && m_messagesSent == 1 && !m_lastIdentifier.empty()) {
    identifierMsg = m_lastIdentifier;
  } else {
    identifierMsg = safcrypto::NewUuidHex();
  }

  safcrypto::Bytes alpha = safcrypto::ComputeAlpha(m_k, m_x, m_c);
  // kTamperAttacker: corrupt only the first message's alpha, exactly like
  // tests/attack_tamper.py's tamper_alpha= hook, then send normally after
  // that to prove the client still works (same "follow-up legitimate
  // publish" the real test checks).
  if (m_role == ClientRole::kTamperAttacker && m_messagesSent == 0) {
    alpha[0] ^= 0xFF;
  }

  std::string payloadB64 = "c2ltLWRhdGE=";  // "sim-data", base64 -- payload content
                                             // is outside the security model here

  if (m_role == ClientRole::kSubscriber) {
    safmsg::SubscribeRequest req;
    req.client_id = m_clientId;
    req.alpha_hex = safcrypto::ToHex(alpha);
    req.t_msg = tMsg;
    req.identifier_msg = identifierMsg;
    req.level1_info = "T+0s";
    req.topic = m_topic;
    safnet::SendFramed(m_socket, safmsg::Envelope(safmsg::Kind::kSubscribeRequest, req));
  } else {
    safmsg::PublishRequest req;
    req.client_id = m_clientId;
    req.alpha_hex = safcrypto::ToHex(alpha);
    req.t_msg = tMsg;
    req.identifier_msg = identifierMsg;
    req.level1_info = "T+0s";
    req.topic = m_topic;
    req.payload_b64 = payloadB64;
    req.encrypted = false;
    req.tampered = (m_role == ClientRole::kTamperAttacker && m_messagesSent == 0);
    req.replayed = (m_role == ClientRole::kReplayAttacker && m_messagesSent == 1);
    safnet::SendFramed(m_socket, safmsg::Envelope(safmsg::Kind::kPublishRequest, req));
  }

  m_pendingIdentifier = identifierMsg;
  m_lastIdentifier = identifierMsg;
  m_messagesSent++;
}

void SafClientApp::OnVerificationStatus(const safmsg::VerificationStatus &status) {
  if (status.status == "Approved") {
    m_c += 1;  // counter increments with each new session/message, mirroring broker
    Emit("approved", (m_role == ClientRole::kSubscriber ? "subscribed to " : "published to ") +
                          m_topic);
  } else {
    Emit("denied", status.reason);
  }

  if (m_messagesSent < m_numMessages) {
    Simulator::Schedule(m_publishInterval, &SafClientApp::SendSessionInitiate, this);
  }
}

void SafClientApp::OnAppData(const safmsg::json &body) {
  std::string topic = body.value("topic", "");
  Emit("app_message_received", "topic=" + topic);
}

// ---------------------- Ghost attacker: never completes Phase 1 ----------------------

void SafClientApp::SendGhostPublish() {
  safmsg::PublishRequest req;
  req.client_id = m_clientId;
  req.alpha_hex = safcrypto::ToHex(safcrypto::HmacSha256(
      safcrypto::Bytes(32, 0), safcrypto::Bytes{'f', 'a', 'k', 'e'}));
  req.t_msg = Simulator::Now().GetSeconds();
  req.identifier_msg = safcrypto::NewUuidHex();
  req.level1_info = "never-registered";
  req.topic = m_topic;
  req.payload_b64 = "bWFsaWNpb3Vz";  // "malicious"
  req.encrypted = false;
  safnet::SendFramed(m_socket, safmsg::Envelope(safmsg::Kind::kPublishRequest, req));
  m_messagesSent++;
}

}  // namespace safsim
