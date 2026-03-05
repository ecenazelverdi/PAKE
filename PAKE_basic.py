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

def hash_point(point_bytes):
    return hashlib.sha256(point_bytes).digest()