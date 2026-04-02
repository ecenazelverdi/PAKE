from . import PAKE_basic as pb
from . import registration as reg
import hashlib

# ---------------------------------------------------------------------------
# Key Derivation (HKDF)
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract using HMAC-sha512."""
    import hmac
    if len(salt) == 0:
        salt = b'\x00' * 64  # HMAC-SHA512 output length (64 bytes)
    return hmac.new(salt, ikm, hashlib.sha512).digest()

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand using HMAC-sha512."""
    import hmac
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        okm += t
        i += 1
    return okm[:length]


# ---------------------------------------------------------------------------
# Transcript and Key Schedule
# ---------------------------------------------------------------------------

def compute_transcript(context: bytes,
                       id_prover: bytes,
                       id_verifier: bytes,
                       shareP: bytes,
                       shareV: bytes,
                       Z: bytes,
                       V: bytes,
                       w0: bytes) -> bytes:
    return (
        reg._encode_with_length(context) +
        reg._encode_with_length(id_prover) +
        reg._encode_with_length(id_verifier) +
        reg._encode_with_length(reg.M) +
        reg._encode_with_length(reg.N) +
        reg._encode_with_length(shareP) +
        reg._encode_with_length(shareV) +
        reg._encode_with_length(Z) +
        reg._encode_with_length(V) +
        reg._encode_with_length(w0)
    )

def compute_key_schedule(TT: bytes) -> dict:
    # K_main = Hash(TT)
    k_main = hashlib.sha512(TT).digest()

    # K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")
    # Using HKDF with empty salt. We need 64 bytes total (32 for each HMAC-sha512 key)
    prk = _hkdf_extract(b"", k_main)
    confirm_keys = _hkdf_expand(prk, b"ConfirmationKeys", 64)
    k_confirmP = confirm_keys[:32]
    k_confirmV = confirm_keys[32:]

    # K_shared = KDF(nil, K_main, "SharedKey")
    k_shared = _hkdf_expand(prk, b"SharedKey", 32)

    return {
        "K_confirmP": k_confirmP,
        "K_confirmV": k_confirmV,
        "K_shared": k_shared
    }

def compute_mac(key: bytes, message: bytes) -> bytes:
    """Computes HMAC-sha512 for key confirmation."""
    import hmac
    return hmac.new(key, message, hashlib.sha512).digest()


# ---------------------------------------------------------------------------
# Protocol Roles
# ---------------------------------------------------------------------------

class Prover:
    """The Client in the SPAKE2+ protocol."""
    
    def __init__(self, context: bytes, id_prover: bytes, id_verifier: bytes, w0: bytes, w1: bytes):
        self.context = context
        self.id_prover = id_prover
        self.id_verifier = id_verifier
        self.w0 = w0
        self.w1 = w1
        
        # State variables
        self.x = b""
        self.shareP = b""
        self.keys = None

    def create_message(self) -> bytes:
        self.x = pb.random_scalar()
        
        # X = x*P + w0*M
        xP = pb.base_mult(self.x)
        w0M = pb.scalarmult(self.w0, reg.M)
        self.shareP = pb.point_add(xP, w0M)
        
        return self.shareP

    def process_message(self, shareV: bytes) -> bytes:
        # Note: libsodium's scalarmult fails safely if shareV is not a valid group element
        w0N = pb.scalarmult(self.w0, reg.N)
        Y_minus_w0N = pb.point_sub(shareV, w0N)
        Z = pb.scalarmult(self.x, Y_minus_w0N)

        # V = w1 * (shareV - w0*N)
        V = pb.scalarmult(self.w1, Y_minus_w0N)

        # Compute Transcript and Keys
        tt = compute_transcript(self.context, self.id_prover, self.id_verifier, 
                                self.shareP, shareV, Z, V, self.w0)
        self.keys = compute_key_schedule(tt)

        # Compute Prover's confirmation message
        confirmP = compute_mac(self.keys["K_confirmP"], shareV)
        return confirmP

    def verify_confirmation(self, confirmV: bytes) -> bytes:
        """Verify the Verifier's confirmation MAC. Returns K_shared if valid."""
        expected = compute_mac(self.keys["K_confirmV"], self.shareP)
        import hmac
        if not hmac.compare_digest(expected, confirmV):
            raise ValueError("Verifier confirmation MAC is invalid! Possible MITM attack or wrong password.")
        return self.keys["K_shared"]


class Verifier:
    """The Server in the SPAKE2+ protocol."""

    def __init__(self, context: bytes, id_prover: bytes, id_verifier: bytes, w0: bytes, L: bytes):
        self.context = context
        self.id_prover = id_prover
        self.id_verifier = id_verifier
        self.w0 = w0
        self.L = L
        
        # State variables
        self.shareV = b""
        self.keys = None

    def process_message(self, shareP: bytes) -> tuple[bytes, bytes]:
        if not pb.is_valid_point(shareP):
            raise ValueError("shareP is not a valid Ristretto255 group element!")

        y = pb.random_scalar()

        yP = pb.base_mult(y)
        w0N = pb.scalarmult(self.w0, reg.N)
        self.shareV = pb.point_add(yP, w0N)

        w0M = pb.scalarmult(self.w0, reg.M)
        X_minus_w0M = pb.point_sub(shareP, w0M)
        Z = pb.scalarmult(y, X_minus_w0M)

        V = pb.scalarmult(y, self.L)

        # Compute Transcript and Keys
        tt = compute_transcript(self.context, self.id_prover, self.id_verifier, 
                                shareP, self.shareV, Z, V, self.w0)
        self.keys = compute_key_schedule(tt)

        # Compute Verifier's confirmation message
        confirmV = compute_mac(self.keys["K_confirmV"], shareP)
        return (self.shareV, confirmV)

    def verify_confirmation(self, confirmP: bytes) -> bytes:
        """Verify the Prover's confirmation MAC. Returns K_shared if valid."""
        expected = compute_mac(self.keys["K_confirmP"], self.shareV)
        import hmac
        if not hmac.compare_digest(expected, confirmP):
            raise ValueError("Prover confirmation MAC is invalid! Wrong password entered.")
        return self.keys["K_shared"]
