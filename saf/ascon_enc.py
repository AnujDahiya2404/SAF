"""
saf/ascon_enc.py

Wraps the `ascon` PyPI package to implement Algorithm 2, Step 7:
  "The MQTT client encrypts the data using the session key k and the
   ASCON scheme [64] to authenticate-then-encrypt the data."

Table VI in the paper compares ASCON-128 / ASCON-128a / ASCON-80pq against
AES-CTR/GCM variants and justifies ASCON's use for resource-constrained
IoT devices (lower latency, higher throughput, NIST Lightweight
Cryptography standard).

We use ASCON-128 AEAD (the variant explicitly named first in Table VI)
with the SAF session key k as the encryption key.
"""

import os
import ascon  # https://pypi.org/project/ascon/

ASCON_VARIANT = "Ascon-128"       # AEAD variant named first in Table VI of the paper
NONCE_LEN_BYTES = 16              # Ascon-128 nonce length


def ascon_encrypt(session_key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Authenticate-then-encrypt `plaintext` under the SAF session key k.

    session_key must be 16 bytes for the AEAD128 variant's key size; SAF's
    session key is 32 bytes (Sec V-A). We derive a 16-byte ASCON key via
    SHA-256(k)[:16] rather than truncating k directly, so the full 256 bits
    of session-key entropy still feed into the derived key.

    Returns: nonce || ciphertext_with_tag  (nonce prefixed so the receiver
    can decrypt without needing a side channel for it).
    """
    from .crypto_utils import sha256
    ascon_key = sha256(session_key)[:16]
    nonce = os.urandom(NONCE_LEN_BYTES)
    ct = ascon.encrypt(ascon_key, nonce, associated_data, plaintext, variant=ASCON_VARIANT)
    return nonce + ct


def ascon_decrypt(session_key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    """Inverse of ascon_encrypt. Raises ValueError if authentication fails
    (tampered ciphertext / wrong key) -- this is the authenticity guarantee
    SAF relies on for 'high protection' data (Sec V-A)."""
    from .crypto_utils import sha256
    ascon_key = sha256(session_key)[:16]
    nonce, ct = blob[:NONCE_LEN_BYTES], blob[NONCE_LEN_BYTES:]
    pt = ascon.decrypt(ascon_key, nonce, associated_data, ct, variant=ASCON_VARIANT)
    if pt is None:
        raise ValueError("ASCON authentication failed: ciphertext tampered or wrong key")
    return pt
