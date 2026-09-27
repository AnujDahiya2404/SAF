// ns3sim/src/saf-crypto.h
//
// Cryptographic primitives for the ns-3 SAF simulation. A line-for-line
// mirror of saf/crypto_utils.py (same primitives, same byte layout, same
// HMAC input order), backed by OpenSSL instead of Python's hashlib/hmac.
// tools/crosscheck_hmac verifies these two implementations produce
// bit-identical output on the same inputs -- this file being a *second*
// implementation of the protocol's crypto (not the literal Scyther-modeled
// Python code) is exactly the tradeoff called out in README.md's ns-3
// section, and that cross-check is how it's kept honest.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace safcrypto {

constexpr size_t kSessionKeyLen = 32;  // Sec V-A: "32 bytes of cryptographically random value"
constexpr size_t kCounterLen = 2;      // Sec V-A: "the counter is 2 bytes long"
constexpr size_t kHashLen = 32;        // SHA-256 / 256-bit hash (Sec VI-A)

using Bytes = std::vector<uint8_t>;

// h(.) -- secure one-way hash, SHA-256 (Table V).
Bytes Sha256(const Bytes &data);

// HMAC(.) using SHA-256 (Table V).
Bytes HmacSha256(const Bytes &key, const Bytes &data);

// Timing-safe comparison, mirrors hmac.compare_digest -- required so the
// broker's HMAC/hash checks (Algorithm 2, Step 5) don't leak information
// via timing side channels.
bool ConstantTimeEq(const Bytes &a, const Bytes &b);

// k <- generate_session_key(), 32 cryptographically random bytes
// (Algorithm 1, Step 5).
Bytes GenerateSessionKey();

// 2-byte big-endian encoding of the counter (Section V-A: "A 16-bit
// counter can represent 2^16, which counts up to 65,536 data points.")
Bytes CounterToBytes(uint16_t counter);

// client_state = (session_time, estimated_duration), canonically encoded
// exactly as saf/crypto_utils.py's serialize_client_state (Algorithm 1,
// Step 3): "{session_time}|{estimated_duration}", UTF-8.
Bytes SerializeClientState(const std::string &sessionTime, const std::string &estimatedDuration);

// Algorithm 2, Step 4: alpha = HMAC_k(x || c), exactly as literally
// specified (see saf/crypto_utils.py's docstring re: the base paper's
// real, permanent Niagree/Nisynch gap -- alpha never covers
// identifier_msg/t_msg here either, for the same reason).
Bytes ComputeAlpha(const Bytes &sessionKey, const Bytes &stateHash, uint16_t counter);

std::string ToHex(const Bytes &data);
Bytes FromHex(const std::string &hex);
std::string NewUuidHex();  // identifier_msg -- unique message identifier (Table V)

}  // namespace safcrypto
