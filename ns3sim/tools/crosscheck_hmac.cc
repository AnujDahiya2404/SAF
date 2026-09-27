// ns3sim/tools/crosscheck_hmac.cc
//
// Prints safcrypto::ComputeAlpha() (and the underlying SHA-256/HMAC-SHA256
// primitives) on a fixed set of test vectors, in the same format
// tools/crosscheck_hmac.py computes with saf/crypto_utils.py on the same
// vectors -- run both and diff to prove the ns-3 simulation's C++ crypto
// is bit-identical to the Scyther-verified Python implementation it's
// standing in for, not just "the same algorithm in spirit."
#include <iostream>
#include <string>
#include <vector>

#include "saf-crypto.h"

using safcrypto::Bytes;
using safcrypto::ToHex;

namespace {
Bytes FromAscii(const std::string &s) { return Bytes(s.begin(), s.end()); }
}  // namespace

int main() {
  // Fixed vectors -- must match tools/crosscheck_hmac.py exactly.
  struct Vector {
    std::string sessionKeyHex;
    std::string sessionTime;
    std::string estimatedDuration;
    uint16_t counter;
  };
  std::vector<Vector> vectors = {
      {std::string(64, '0'), "2023-06-14T10:05:00Z", "30 mins", 0},
      {std::string(64, 'f'), "2023-06-14T10:05:00Z", "30 mins", 1},
      {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
       "2026-09-27T00:00:00Z", "45 mins", 65535},
  };

  for (const auto &v : vectors) {
    Bytes key = safcrypto::FromHex(v.sessionKeyHex);
    Bytes stateBytes = safcrypto::SerializeClientState(v.sessionTime, v.estimatedDuration);
    Bytes x = safcrypto::Sha256(stateBytes);
    Bytes alpha = safcrypto::ComputeAlpha(key, x, v.counter);

    std::cout << "key=" << v.sessionKeyHex << " session_time=" << v.sessionTime
              << " estimated_duration=" << v.estimatedDuration << " counter=" << v.counter
              << "\n  x=" << ToHex(x) << "\n  alpha=" << ToHex(alpha) << "\n";
  }
  return 0;
}
