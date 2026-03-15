"""
registration.py — SPAKE2+ Offline Registration Phase (RFC 9383, Section 3.2)

Responsibilities:
- Derive w0, w1 from the password using Argon2id (libsodium crypto_pwhash)
- Compute L = w1 * P  (the registration record stored on the server)
- Generate fixed public points M and N (unknown discrete logs)

What each party keeps after registration:
  Prover (Client)  : w0, w1
  Verifier (Server): w0, L, salt
"""

import ctypes
import os
from . import PAKE_basic as pb

# ---------------------------------------------------------------------------
# Argon2id parameters (libsodium defaults for interactive use)
# ---------------------------------------------------------------------------
"""
 2(ARGON2ID_ALG) is libsodium's internal C macro for crypto_pwhash_ALG_ARGON2ID13. We need a Salt (random bytes)
 to protect against "Rainbow Table" attacks (pre-computed hash lists). Libsodium requires 16 bytes for Argon2. 
 The OPSLIMIT and MEMLIMIT (64 MB) are libsodium's recommended default settings for interactive logins 
 (fast enough for a web server, too slow for a hacker).
"""
# Corresponds to crypto_pwhash_ALG_ARGON2ID13
ARGON2ID_ALG = 2
# crypto_pwhash_SALTBYTES = 16
SALT_BYTES = 16
# Minimum opslimit / memlimit for interactive security
OPSLIMIT_INTERACTIVE = 2
MEMLIMIT_INTERACTIVE = 67108864  # 64 MiB

# Output length: we need 80 bytes (40 per scalar) for Ristretto255.
"""
RFC 9383 §3.2 states: "The minimum total output length of the PBKDF then is 2 * (ceil(log2(p)) + k) bits."
p is the size of the Ristretto group (252 bits).
log2(p) is 252. Divided by 8 = 31.5 bytes (ceil'd to 32 bytes).
k is an extra safety margin to prevent math biases. The RFC says k >= 64 bits (which is 8 bytes).
So per half (for w0 and then w1), we need 32 + 8 = 40 bytes.
Total: 40 + 40 = 80 bytes.
(We ask Argon2id for 80 bytes, split it in half, then use 

scalar_reduce
 to turn those 40 bytes into a perfect 32-byte Ristretto scalar).
"""
# Ristretto255 group order p is a 252-bit prime, so we need
# ceil(252/8) + 8 = 39.5 → 40 bytes per half to achieve k≥64 bias control.
PBKDF_OUT_LEN = 80 

# ---------------------------------------------------------------------------
# Fixed public points M and N (deterministic, discrete logs unknown)
# ---------------------------------------------------------------------------
# Derived using hash_to_point so anyone can reproduce them.
# Using labels from the RFC naming convention.
M = pb.hash_to_point(b"SPAKE2+-P Ristretto M")
N = pb.hash_to_point(b"SPAKE2+-P Ristretto N")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _encode_with_length(data: bytes) -> bytes:
    """Prefix data with its 8-byte little-endian length, as required by RFC 9383."""
    return len(data).to_bytes(8, "little") + data


def _argon2id(password: bytes, salt: bytes, out_len: int) -> bytes:
    """
    Password-Based Key Derivation Function (PBKDF).
    Derive `out_len` bytes from `password` using libsodium's Argon2id
    (crypto_pwhash). Returns raw key material.

    libsodium signature:
        int crypto_pwhash(unsigned char *out, unsigned long long outlen,
                          const char *passwd, unsigned long long passwdlen,
                          const unsigned char *salt,
                          unsigned long long opslimit,
                          size_t memlimit, int alg);
    Returns 0 on success, -1 on failure.
    """
    out = (ctypes.c_ubyte * out_len)()
    passwd_buf = (ctypes.c_ubyte * len(password)).from_buffer_copy(password)
    salt_buf   = (ctypes.c_ubyte * SALT_BYTES).from_buffer_copy(salt)

    ret = pb.sodium.crypto_pwhash(
        out,  # The empty buffer where the result (80 bytes) goes
        ctypes.c_ulonglong(out_len),# How many bytes we want out (80)
        passwd_buf, # The password + IDs
        ctypes.c_ulonglong(len(password)), # Length of the password buffer
        salt_buf, # The 16-byte random salt
        ctypes.c_ulonglong(OPSLIMIT_INTERACTIVE), # CPU effort parameter
        ctypes.c_size_t(MEMLIMIT_INTERACTIVE), # Memory effort parameter
        ctypes.c_int(ARGON2ID_ALG), # Specifies we want to use Argon2id
    )
    if ret != 0:
        raise RuntimeError("crypto_pwhash (Argon2id) failed")
    return bytes(out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register(password: str,
             id_prover: bytes,
             id_verifier: bytes,
             salt: bytes | None = None
             ) -> dict:
    """
    Perform SPAKE2+ offline registration.

    Parameters
    ----------
    password    : the user's password (will be UTF-8 encoded)
    id_prover   : identifier of the client (e.g. username bytes)
    id_verifier : identifier of the server (e.g. server name bytes)
    salt        : 16-byte random salt; generated fresh if not provided

    Returns
    -------
    {
        # Prover (client) keeps these — re-derive from password each login
        "w0": bytes,   # 32-byte Ristretto255 scalar
        "w1": bytes,   # 32-byte Ristretto255 scalar

        # Verifier (server) stores these in its database
        "L":    bytes, # 32-byte Ristretto255 point  (L = w1 * P)
        "salt": bytes, # 16-byte salt (must be stored alongside w0, L)

        # Public constants shared by both parties
        "M": bytes,    # 32-byte Ristretto255 point
        "N": bytes,    # 32-byte Ristretto255 point
    }
    """
    if salt is None:
        ##TODO: Look if there is a better way to generate salt with Libsodium
        salt = os.urandom(SALT_BYTES)
    if len(salt) != SALT_BYTES:
        raise ValueError(f"salt must be exactly {SALT_BYTES} bytes")

    pw_bytes = password.encode("utf-8")

    # Build the PBKDF input as specified in RFC 9383 §3.2:
    #   len(pw) || pw || len(idProver) || idProver || len(idVerifier) || idVerifier
    pbkdf_input = (
        _encode_with_length(pw_bytes) +
        _encode_with_length(id_prover) +
        _encode_with_length(id_verifier)
    )

    # Derive 80 bytes via Argon2id
    raw = _argon2id(pbkdf_input, salt, PBKDF_OUT_LEN)

    # Split and reduce each half mod p to get valid Ristretto255 scalars
    w0 = pb.scalar_reduce(raw[:40])   # first 40 bytes  → w0 mod p
    w1 = pb.scalar_reduce(raw[40:])   # last  40 bytes  → w1 mod p

    # Registration record: L = w1 * P  (server stores this, not w1)
    L = pb.base_mult(w1)
    return {
        "w0":   w0,
        "w1":   w1,
        "L":    L,
        "salt": salt,
        "M":    M,
        "N":    N,
    }

#Server implementation for multiple users
class ServerDB:

    def __init__(self):
        self.users = {}

    def register_user(self, uname: bytes, pword: str, id_verifier: bytes):
        """
        Registrationg and stores the info
        """
        rec = register(pword, uname, id_verifier)

        # Server stores only w0, L, and salt
        self.users[uname] = {
            "w0": rec["w0"],
            "L": rec["L"],
            "salt": rec["salt"]
        }

        return rec  # Returns this so client can keep w0, w1

    def get_user(self, uname: bytes):
        """
        Retrieve stored server record.
        """
        if uname not in self.users:
            raise ValueError("Unknown user")

        return self.users[uname]

    def list_users(self):
        return list(self.users.keys())
