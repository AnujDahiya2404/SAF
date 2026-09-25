"""
saf/crypto_utils.py

Cryptographic primitives for the Stateful Authentication Framework (SAF),
following Table V / Section V-A of:

  Jamil, N. et al., "A Novel Stateful Authentication Framework Approach
  with LLM-based IDS for MQTT Security," IEEE Internet of Things Journal,
  2026 (in press), DOI: 10.1109/JIOT.2025.3646115.

Primitives used by the paper:
  - h(.)     : secure one-way hash -> SHA-256
  - HMAC(.)  : HMAC-based message authentication code
  - k        : 32-byte (256-bit) session key, cryptographically random
  - c        : 2-byte (16-bit) counter
"""

import os
import hmac
import hashlib
import secrets
import time
import uuid

SESSION_KEY_LEN_BYTES = 32   # "32 bytes of cryptographically random value" (Sec V-A, step 5)
COUNTER_LEN_BYTES = 2        # "2 bytes long" -> 16-bit counter, max 65536 (Sec V-A)
HASH_LEN_BYTES = 32          # SHA-256 / 256-bit hash (Sec VI-A: "minimum of a 256-bit hash value")


def sha256(data: bytes) -> bytes:
    """h(.) - secure one-way hash, SHA-256 as specified in Table V."""
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC(.) using SHA-256, as specified in Table V."""
    return hmac.new(key, data, hashlib.sha256).digest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Timing-safe comparison, required so the broker's HMAC/hash checks
    (Algorithm 2, Step 5) do not leak information via timing side channels."""
    return hmac.compare_digest(a, b)


def generate_session_key() -> bytes:
    """k <- generate_session_key(), 32 bytes (Algorithm 1, Step 5)."""
    return secrets.token_bytes(SESSION_KEY_LEN_BYTES)


def initial_counter() -> int:
    """c <- 0, initial counter (Algorithm 1, Step 5)."""
    return 0


def counter_to_bytes(c: int) -> bytes:
    """2-byte big-endian encoding of the counter (16-bit, up to 65536 sessions,
    per Section V-A: 'A 16-bit counter can represent 2^16, which counts up
    to 65,536 data points.')"""
    if not (0 <= c < 2 ** (COUNTER_LEN_BYTES * 8)):
        raise ValueError("counter out of 16-bit range")
    return c.to_bytes(COUNTER_LEN_BYTES, byteorder="big")


def new_message_identifier() -> str:
    """identifier_msg - unique message identifier (Table V)."""
    return uuid.uuid4().hex


def current_timestamp() -> float:
    """t_msg - timestamp (Table V). Using epoch seconds (float) for easy
    freshness-window comparisons."""
    return time.time()


def serialize_client_state(session_time: str, estimated_duration: str) -> bytes:
    """Canonical byte encoding of client_state = (session_time, estimated_duration),
    per Algorithm 1, Step 3."""
    return f"{session_time}|{estimated_duration}".encode("utf-8")
