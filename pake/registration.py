import ctypes
import os
from . import PAKE_basic as pb

# ---------------------------------------------------------------------------
# Argon2id parameters (libsodium defaults for interactive use)
# ---------------------------------------------------------------------------
# Corresponds to crypto_pwhash_ALG_ARGON2ID13
ARGON2ID_ALG = 2
# crypto_pwhash_SALTBYTES = 16
SALT_BYTES = 16
# Minimum opslimit / memlimit for interactive security
OPSLIMIT_INTERACTIVE = 2
MEMLIMIT_INTERACTIVE = 67108864  # 64 MiB

# Output length: we need 80 bytes (40 per scalar) for Ristretto255.

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
