import ctypes
import os
import hashlib

sodium = ctypes.cdll.LoadLibrary("libsodium.so")

if sodium.sodium_init() < 0:
    raise RuntimeError("libsodium init failed")

SCALAR_BYTES = 32
POINT_BYTES = 32

def random_scalar():
    scalar = (ctypes.c_ubyte * SCALAR_BYTES)()
    rand = os.urandom(64)
    sodium.crypto_core_ristretto255_scalar_reduce(scalar, rand)
    return bytes(scalar)

def base_mult(scalar_bytes):
    point = (ctypes.c_ubyte * POINT_BYTES)()
    scalar = (ctypes.c_ubyte * SCALAR_BYTES).from_buffer_copy(scalar_bytes)
    sodium.crypto_scalarmult_ristretto255_base(point, scalar)
    return bytes(point)

def scalarmult(scalar_bytes, point_bytes):
    result = (ctypes.c_ubyte * POINT_BYTES)()
    scalar = (ctypes.c_ubyte * SCALAR_BYTES).from_buffer_copy(scalar_bytes)
    point = (ctypes.c_ubyte * POINT_BYTES).from_buffer_copy(point_bytes)
    sodium.crypto_scalarmult_ristretto255(result, scalar, point)
    return bytes(result)

def hash_to_scalar(password: bytes):
    h = hashlib.sha256(password).digest()
    scalar = (ctypes.c_ubyte * SCALAR_BYTES)()
    sodium.crypto_core_ristretto255_scalar_reduce(scalar, h)
    return bytes(scalar)

"""
def hash_point(point_bytes):
    return hashlib.sha256(point_bytes).digest()
"""
#---------------------------

def hash_to_point(label: bytes) -> bytes:
    """Map an arbitrary label to a Ristretto255 point with unknown discrete log.
    Uses SHA-512 to produce 64 bytes, then crypto_core_ristretto255_from_hash.
    """
    h = hashlib.sha512(label).digest()  # 64 bytes required by libsodium
    point = (ctypes.c_ubyte * POINT_BYTES)()
    hash_buf = (ctypes.c_ubyte * 64).from_buffer_copy(h)
    ret = sodium.crypto_core_ristretto255_from_hash(point, hash_buf)
    if ret != 0:
        raise RuntimeError("hash_to_point failed")
    return bytes(point)


def scalar_reduce(data: bytes) -> bytes:
    """Reduce arbitrary bytes to a valid Ristretto255 scalar (mod p).
    Input must be at least 64 bytes for uniform reduction; if shorter,
    it is zero-padded to 64 bytes.
    """
    padded = data.ljust(64, b'\x00')[:64]
    scalar = (ctypes.c_ubyte * SCALAR_BYTES)()
    buf = (ctypes.c_ubyte * 64).from_buffer_copy(padded)
    sodium.crypto_core_ristretto255_scalar_reduce(scalar, buf)
    return bytes(scalar)
    """
    In elliptic curve cryptography, a point is a coordinate on the curve, but a scalar is an integer used to 
    multiply that point (e.g., $X = x \cdot P$). For Ristretto255, a valid scalar must be an integer between $0$ 
    and $p-1$ (where $p$ is the order of the group, which is roughly $2^{252}$). When we use Argon2id to derive 
    80 bytes for the password, we get completely random bits. If we just take 32 bytes of random bits, the resulting 
    integer might be larger than $p$. If we try to use an invalid, oversized scalar, the cryptographic math will fail.
    Libsodium provides crypto_core_ristretto255_scalar_reduce to fix this. It takes a larger number (e.g. 40 or 64 bytes) 
    and mathematically calculates (number) modulo p, guaranteeing the result is a perfectly valid 32-byte scalar.
    """
# For Authentication    
def point_add(p1: bytes, p2: bytes) -> bytes:
    # Ristretto255 point addition: p1 + p2.
    result = (ctypes.c_ubyte * POINT_BYTES)()
    a = (ctypes.c_ubyte * POINT_BYTES).from_buffer_copy(p1)
    b = (ctypes.c_ubyte * POINT_BYTES).from_buffer_copy(p2)
    ret = sodium.crypto_core_ristretto255_add(result, a, b)
    if ret != 0:
        raise RuntimeError("point_add failed")
    return bytes(result)

def point_sub(p1: bytes, p2: bytes) -> bytes:
    # Ristretto255 point subtraction: p1 - p2.
    result = (ctypes.c_ubyte * POINT_BYTES)()
    a = (ctypes.c_ubyte * POINT_BYTES).from_buffer_copy(p1)
    b = (ctypes.c_ubyte * POINT_BYTES).from_buffer_copy(p2)
    ret = sodium.crypto_core_ristretto255_sub(result, a, b)
    if ret != 0:
        raise RuntimeError("point_sub failed")
    return bytes(result)