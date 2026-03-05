import ctypes
import os

# Load libsodium
sodium = ctypes.cdll.LoadLibrary("libsodium.so")

# Initialize
if sodium.sodium_init() < 0:
    raise RuntimeError("libsodium init failed")

# Constants
SCALAR_BYTES = 32
POINT_BYTES = 32

# Allocate buffers
scalar = (ctypes.c_ubyte * SCALAR_BYTES)()
point = (ctypes.c_ubyte * POINT_BYTES)()

# Generate random scalar
rand = os.urandom(64)
sodium.crypto_core_ristretto255_scalar_reduce(scalar, rand)

# Compute public key
sodium.crypto_scalarmult_ristretto255_base(point, scalar)

print("Ristretto point:", bytes(point).hex())