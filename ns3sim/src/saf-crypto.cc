#include "saf-crypto.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstdio>
#include <random>
#include <sstream>

namespace safcrypto {

Bytes Sha256(const Bytes &data) {
  Bytes out(kHashLen);
  SHA256(data.data(), data.size(), out.data());
  return out;
}

Bytes HmacSha256(const Bytes &key, const Bytes &data) {
  Bytes out(kHashLen);
  unsigned int len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
       out.data(), &len);
  out.resize(len);
  return out;
}

bool ConstantTimeEq(const Bytes &a, const Bytes &b) {
  if (a.size() != b.size()) {
    return false;
  }
  unsigned char diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

Bytes GenerateSessionKey() {
  Bytes key(kSessionKeyLen);
  if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
    // OpenSSL's CSPRNG failing is exceptional; fall back would be
    // insecure, so treat it as fatal rather than silently degrade.
    std::abort();
  }
  return key;
}

Bytes CounterToBytes(uint16_t counter) {
  return {static_cast<uint8_t>((counter >> 8) & 0xFF), static_cast<uint8_t>(counter & 0xFF)};
}

Bytes SerializeClientState(const std::string &sessionTime, const std::string &estimatedDuration) {
  std::string s = sessionTime + "|" + estimatedDuration;
  return Bytes(s.begin(), s.end());
}

Bytes ComputeAlpha(const Bytes &sessionKey, const Bytes &stateHash, uint16_t counter) {
  Bytes msg = stateHash;
  Bytes c = CounterToBytes(counter);
  msg.insert(msg.end(), c.begin(), c.end());
  return HmacSha256(sessionKey, msg);
}

std::string ToHex(const Bytes &data) {
  static const char *kDigits = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (uint8_t b : data) {
    out.push_back(kDigits[b >> 4]);
    out.push_back(kDigits[b & 0x0F]);
  }
  return out;
}

Bytes FromHex(const std::string &hex) {
  Bytes out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
  }
  return out;
}

std::string NewUuidHex() {
  // uuid4-shaped (32 hex chars, version/variant bits set), matching
  // saf/crypto_utils.py's uuid.uuid4().hex -- randomness source is
  // OpenSSL's CSPRNG for consistency with the rest of this file.
  uint8_t raw[16];
  if (RAND_bytes(raw, sizeof(raw)) != 1) {
    std::abort();
  }
  raw[6] = (raw[6] & 0x0F) | 0x40;  // version 4
  raw[8] = (raw[8] & 0x3F) | 0x80;  // variant 10xx
  Bytes b(raw, raw + 16);
  return ToHex(b);
}

}  // namespace safcrypto
