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

def is_valid_point(point_bytes: bytes) -> bool:
    """Checks if the given bytes represent a valid Ristretto255 group element."""
    point = (ctypes.c_ubyte * POINT_BYTES).from_buffer_copy(point_bytes)
    return sodium.crypto_core_ristretto255_is_valid_point(point) == 1

def scalarmult(scalar_bytes, point_bytes):
    result = (ctypes.c_ubyte * POINT_BYTES)()
    scalar = (ctypes.c_ubyte * SCALAR_BYTES).from_buffer_copy(scalar_bytes)
    point = (ctypes.c_ubyte * POINT_BYTES).from_buffer_copy(point_bytes)
    ret = sodium.crypto_scalarmult_ristretto255(result, scalar, point)
    if ret != 0:
        raise ValueError("scalarmult failed: invalid group element")
    return bytes(result)

def hash_to_scalar(password: bytes):
    h = hashlib.sha512(password).digest()
    scalar = (ctypes.c_ubyte * SCALAR_BYTES)()
    sodium.crypto_core_ristretto255_scalar_reduce(scalar, h)
    return bytes(scalar)

#---------------------------

def hash_to_point(label: bytes) -> bytes:
    h = hashlib.sha512(label).digest()  # 64 bytes required by libsodium
    point = (ctypes.c_ubyte * POINT_BYTES)()
    hash_buf = (ctypes.c_ubyte * 64).from_buffer_copy(h)
    ret = sodium.crypto_core_ristretto255_from_hash(point, hash_buf)
    if ret != 0:
        raise RuntimeError("hash_to_point failed")
    return bytes(point)


def scalar_reduce(data: bytes) -> bytes:
    padded = data.ljust(64, b'\x00')[:64]
    scalar = (ctypes.c_ubyte * SCALAR_BYTES)()
    buf = (ctypes.c_ubyte * 64).from_buffer_copy(padded)
    sodium.crypto_core_ristretto255_scalar_reduce(scalar, buf)
    return bytes(scalar)

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