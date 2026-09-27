// ns3sim/src/saf-state-store.h
//
// Broker-side bookkeeping, mirroring saf/state_store.py: the client-state
// table (Algorithm 1) and the identifier_msg replay/duplicate cache +
// timestamp freshness window (Algorithm 2 Step 5 / Section VI-A). Covers
// exactly the subset saf/gateway.py's _verify_and_approve() actually calls
// (registration_allowed, register_client, get_client,
// update_last_session_time, is_fresh_timestamp, is_duplicate_identifier,
// record_identifier, bump_counter) -- the daily-session-cap and
// single-entity-per-client_id methods exist in state_store.py's surface
// but aren't wired into gateway.py's real verification path either, so
// they're left out here too rather than simulating unused code paths.
// No locking: unlike the real threaded Python broker, an ns-3 Application
// runs entirely on the single simulation thread.
#pragma once

#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "saf-crypto.h"

namespace safsim {

struct ClientRecord {
  std::string client_id;
  safcrypto::Bytes state_hash;  // x = h(client_state)   (Algorithm 1, Step 4)
  safcrypto::Bytes session_key; // k                      (Algorithm 1, Step 5)
  uint16_t counter = 0;         // c                      (Algorithm 1, Step 5)
  std::string session_time;
  std::string estimated_duration;
  std::string last_session_time;
};

class SafStateStore {
 public:
  explicit SafStateStore(size_t maxClients = 50, double replayWindowSeconds = 30.0,
                          size_t identifierCacheSize = 5000)
      : m_maxClients(maxClients),
        m_replayWindowSeconds(replayWindowSeconds),
        m_identifierCacheSize(identifierCacheSize) {}

  bool RegistrationAllowed() const { return m_clients.size() < m_maxClients; }

  ClientRecord *RegisterClient(const std::string &clientId, const safcrypto::Bytes &stateHash,
                                const safcrypto::Bytes &sessionKey, uint16_t counter,
                                const std::string &sessionTime,
                                const std::string &estimatedDuration) {
    ClientRecord rec;
    rec.client_id = clientId;
    rec.state_hash = stateHash;
    rec.session_key = sessionKey;
    rec.counter = counter;
    rec.session_time = sessionTime;
    rec.estimated_duration = estimatedDuration;
    m_clients[clientId] = rec;
    m_seenIdentifiers[clientId] = {};
    m_identifierOrder[clientId] = {};
    return &m_clients[clientId];
  }

  ClientRecord *GetClient(const std::string &clientId) {
    auto it = m_clients.find(clientId);
    return it == m_clients.end() ? nullptr : &it->second;
  }

  void UpdateLastSessionTime(const std::string &clientId, const std::string &sessionTime) {
    if (auto *rec = GetClient(clientId)) {
      rec->last_session_time = sessionTime;
    }
  }

  std::optional<uint16_t> BumpCounter(const std::string &clientId) {
    if (auto *rec = GetClient(clientId)) {
      rec->counter += 1;
      return rec->counter;
    }
    return std::nullopt;
  }

  // Section VI-A: "if a message with the same identifier is received more
  // than once, SAF recognizes it as a duplicate."
  bool IsDuplicateIdentifier(const std::string &clientId, const std::string &identifierMsg) {
    auto &seen = m_seenIdentifiers[clientId];
    return seen.count(identifierMsg) > 0;
  }

  void RecordIdentifier(const std::string &clientId, const std::string &identifierMsg) {
    auto &seen = m_seenIdentifiers[clientId];
    auto &order = m_identifierOrder[clientId];
    seen.insert(identifierMsg);
    order.push_back(identifierMsg);
    while (order.size() > m_identifierCacheSize) {
      seen.erase(order.front());
      order.pop_front();
    }
  }

  // The broker checks t_msg falls within an acceptable time window
  // (Algorithm 2 note, Section VI-A) to prevent replay of a captured
  // message at a later time. `now` is the simulation's own current
  // wall-clock-equivalent (ns3::Simulator::Now(), seconds).
  bool IsFreshTimestamp(double tMsg, double now) const {
    return std::abs(now - tMsg) <= m_replayWindowSeconds;
  }

  size_t ClientCount() const { return m_clients.size(); }

 private:
  size_t m_maxClients;
  double m_replayWindowSeconds;
  size_t m_identifierCacheSize;
  std::map<std::string, ClientRecord> m_clients;
  std::map<std::string, std::set<std::string>> m_seenIdentifiers;
  std::map<std::string, std::deque<std::string>> m_identifierOrder;
};

}  // namespace safsim
