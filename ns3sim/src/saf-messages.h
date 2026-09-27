// ns3sim/src/saf-messages.h
//
// Message envelopes for SAF Phase 1 (Pre-Session) and Phase 2 (In-Session),
// mirroring saf/protocol.py field-for-field. ns-3 has no native MQTT
// support (see README.md's ns-3 section), so instead of per-topic MQTT
// pub/sub these travel as length-prefixed JSON frames over a plain TCP
// socket per client<->broker pair -- Algorithm 1/2 never depend on MQTT's
// own routing semantics for these control messages (they're always
// point-to-point client<->broker), so this is a faithful a transport
// substitution, not a protocol change. Serialized with nlohmann::json for
// the same reason saf/protocol.py uses Python's json module: readable,
// diffable payloads that make the two implementations easy to compare
// side by side.
#pragma once

#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace safmsg {

using json = nlohmann::json;

// ---------------------------------------------------------------------
// Phase 1: Pre-Session (Algorithm 1)
// ---------------------------------------------------------------------

struct PreSessionRequest {
  std::string client_id;
  std::string request_time;  // ISO8601, "Level 1 information"
};
inline void to_json(json &j, const PreSessionRequest &m) {
  j = json{{"client_id", m.client_id}, {"request_time", m.request_time}};
}
inline void from_json(const json &j, PreSessionRequest &m) {
  j.at("client_id").get_to(m.client_id);
  j.at("request_time").get_to(m.request_time);
}

struct PreSessionResponse {
  std::string client_id;
  std::string x_hex;
  std::string k_hex;
  int c = 0;
  std::string session_time;
  std::string estimated_duration;
  std::string status = "ESTABLISHED";
};
inline void to_json(json &j, const PreSessionResponse &m) {
  j = json{{"client_id", m.client_id}, {"x_hex", m.x_hex},
           {"k_hex", m.k_hex},         {"c", m.c},
           {"session_time", m.session_time},
           {"estimated_duration", m.estimated_duration},
           {"status", m.status}};
}
inline void from_json(const json &j, PreSessionResponse &m) {
  j.at("client_id").get_to(m.client_id);
  j.at("x_hex").get_to(m.x_hex);
  j.at("k_hex").get_to(m.k_hex);
  j.at("c").get_to(m.c);
  j.at("session_time").get_to(m.session_time);
  j.at("estimated_duration").get_to(m.estimated_duration);
  j.at("status").get_to(m.status);
}

struct PreSessionAck {
  std::string client_id;
  std::string ack = "Acknowledged";
};
inline void to_json(json &j, const PreSessionAck &m) {
  j = json{{"client_id", m.client_id}, {"ack", m.ack}};
}
inline void from_json(const json &j, PreSessionAck &m) {
  j.at("client_id").get_to(m.client_id);
  j.at("ack").get_to(m.ack);
}

// ---------------------------------------------------------------------
// Phase 2: In-Session (Algorithm 2)
// ---------------------------------------------------------------------

struct SessionInitiate {
  std::string client_id;
  std::string intent;  // "publish" | "subscribe"
  std::string topic;
};
inline void to_json(json &j, const SessionInitiate &m) {
  j = json{{"client_id", m.client_id}, {"intent", m.intent}, {"topic", m.topic}};
}
inline void from_json(const json &j, SessionInitiate &m) {
  j.at("client_id").get_to(m.client_id);
  j.at("intent").get_to(m.intent);
  j.at("topic").get_to(m.topic);
}

struct Level1InfoRequest {
  std::string client_id;
};
inline void to_json(json &j, const Level1InfoRequest &m) { j = json{{"client_id", m.client_id}}; }
inline void from_json(const json &j, Level1InfoRequest &m) { j.at("client_id").get_to(m.client_id); }

struct PublishRequest {
  std::string client_id;
  std::string alpha_hex;
  double t_msg = 0.0;
  std::string identifier_msg;
  std::string level1_info;
  std::string topic;
  std::string payload_b64;
  bool encrypted = false;
  // Attack-simulation hooks, mirroring tests/attack_*.py / client.py's
  // tamper_alpha / replay_identifier params -- not part of the paper's
  // wire format, only used to mark a deliberately-forged message so the
  // sim's own bookkeeping can tell attacker traffic from real traffic.
  bool tampered = false;
  bool replayed = false;
};
inline void to_json(json &j, const PublishRequest &m) {
  j = json{{"client_id", m.client_id},         {"alpha_hex", m.alpha_hex},
           {"t_msg", m.t_msg},                 {"identifier_msg", m.identifier_msg},
           {"level1_info", m.level1_info},     {"topic", m.topic},
           {"payload_b64", m.payload_b64},     {"encrypted", m.encrypted},
           {"tampered", m.tampered},           {"replayed", m.replayed}};
}
inline void from_json(const json &j, PublishRequest &m) {
  j.at("client_id").get_to(m.client_id);
  j.at("alpha_hex").get_to(m.alpha_hex);
  j.at("t_msg").get_to(m.t_msg);
  j.at("identifier_msg").get_to(m.identifier_msg);
  j.at("level1_info").get_to(m.level1_info);
  j.at("topic").get_to(m.topic);
  j.at("payload_b64").get_to(m.payload_b64);
  j.at("encrypted").get_to(m.encrypted);
  m.tampered = j.value("tampered", false);
  m.replayed = j.value("replayed", false);
}

struct SubscribeRequest {
  std::string client_id;
  std::string alpha_hex;
  double t_msg = 0.0;
  std::string identifier_msg;
  std::string level1_info;
  std::string topic;
};
inline void to_json(json &j, const SubscribeRequest &m) {
  j = json{{"client_id", m.client_id}, {"alpha_hex", m.alpha_hex},
           {"t_msg", m.t_msg},         {"identifier_msg", m.identifier_msg},
           {"level1_info", m.level1_info}, {"topic", m.topic}};
}
inline void from_json(const json &j, SubscribeRequest &m) {
  j.at("client_id").get_to(m.client_id);
  j.at("alpha_hex").get_to(m.alpha_hex);
  j.at("t_msg").get_to(m.t_msg);
  j.at("identifier_msg").get_to(m.identifier_msg);
  j.at("level1_info").get_to(m.level1_info);
  j.at("topic").get_to(m.topic);
}

struct VerificationStatus {
  std::string client_id;
  std::string identifier_msg;
  std::string status;  // "Approved" | "Denied"
  std::string reason;
};
inline void to_json(json &j, const VerificationStatus &m) {
  j = json{{"client_id", m.client_id},
           {"identifier_msg", m.identifier_msg},
           {"status", m.status},
           {"reason", m.reason}};
}
inline void from_json(const json &j, VerificationStatus &m) {
  j.at("client_id").get_to(m.client_id);
  j.at("identifier_msg").get_to(m.identifier_msg);
  j.at("status").get_to(m.status);
  m.reason = j.value("reason", "");
}

// Wire envelope: {"kind": "...", "body": {...}} -- stands in for the MQTT
// topic each message type travels on in saf/protocol.py, since a plain
// TCP byte stream has no topic routing of its own.
enum class Kind {
  kPreSessionRequest,
  kPreSessionResponse,
  kPreSessionAck,
  kSessionInitiate,
  kLevel1InfoRequest,
  kPublishRequest,
  kSubscribeRequest,
  kVerificationStatus,
};

inline std::string KindName(Kind k) {
  switch (k) {
    case Kind::kPreSessionRequest: return "PreSessionRequest";
    case Kind::kPreSessionResponse: return "PreSessionResponse";
    case Kind::kPreSessionAck: return "PreSessionAck";
    case Kind::kSessionInitiate: return "SessionInitiate";
    case Kind::kLevel1InfoRequest: return "Level1InfoRequest";
    case Kind::kPublishRequest: return "PublishRequest";
    case Kind::kSubscribeRequest: return "SubscribeRequest";
    case Kind::kVerificationStatus: return "VerificationStatus";
  }
  return "Unknown";
}

inline Kind KindFromName(const std::string &s) {
  if (s == "PreSessionRequest") return Kind::kPreSessionRequest;
  if (s == "PreSessionResponse") return Kind::kPreSessionResponse;
  if (s == "PreSessionAck") return Kind::kPreSessionAck;
  if (s == "SessionInitiate") return Kind::kSessionInitiate;
  if (s == "Level1InfoRequest") return Kind::kLevel1InfoRequest;
  if (s == "PublishRequest") return Kind::kPublishRequest;
  if (s == "SubscribeRequest") return Kind::kSubscribeRequest;
  if (s == "VerificationStatus") return Kind::kVerificationStatus;
  throw std::runtime_error("unknown message kind: " + s);
}

template <typename T>
inline std::string Envelope(Kind k, const T &body) {
  json j;
  j["kind"] = KindName(k);
  j["body"] = body;
  return j.dump();
}

}  // namespace safmsg
