"""
Test to prove that the server handles multiple clients concurrently.

A "slow" client deliberately sleeps for 3 seconds in the middle of its handshake.
A "fast" client connects AFTER the slow client and completes its handshake immediately.

If the server is truly non-blocking (threaded), the fast client will finish
BEFORE the slow client, proving that one user doesn't block another.
"""
import socket
import threading
import time
from datetime import datetime
import registration as r
import online_auth as auth
from config import HOST, PORT, send_msg, recv_msg

def timestamp():
    return datetime.now().strftime('%H:%M:%S.%f')[:-3]

def slow_client():
    """Alice connects first but sleeps for 3 seconds before sending shareP."""
    uname = b"alice"
    password = "password123"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[SLOW Alice]  [{timestamp()}] Connected to server")

        send_msg(s, b"LOGIN")
        send_msg(s, uname)

        salt = recv_msg(s)
        client_reg = r.register(password, uname, b"server", salt=salt)

        prover = auth.Prover(b"SPAKE2+-Loopback", uname, b"server", client_reg["w0"], client_reg["w1"])
        shareP = prover.create_message()

        # Deliberately sleep for 3 seconds to simulate a slow network or slow user
        print(f"[SLOW Alice]  [{timestamp()}] Sleeping for 3 seconds before sending shareP...")
        time.sleep(3)

        print(f"[SLOW Alice]  [{timestamp()}] Woke up! Sending shareP now.")
        send_msg(s, shareP)

        shareV = recv_msg(s)
        confirmV = recv_msg(s)
        confirmP = prover.process_message(shareV)
        k_shared = prover.verify_confirmation(confirmV)
        send_msg(s, confirmP)

        status = recv_msg(s)
        if status == b"OK":
            print(f"[SLOW Alice]  [{timestamp()}] \033[92mSUCCESS\033[0m  K_shared: {k_shared.hex()[:16]}...")

def fast_client():
    """Bob connects 1 second AFTER Alice, but should finish BEFORE her."""
    uname = b"bob"
    password = "hunter2"

    # Wait 1 second so Alice connects first
    time.sleep(1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[FAST Bob]    [{timestamp()}] Connected to server (1 second after Alice)")

        send_msg(s, b"LOGIN")
        send_msg(s, uname)

        salt = recv_msg(s)
        client_reg = r.register(password, uname, b"server", salt=salt)

        prover = auth.Prover(b"SPAKE2+-Loopback", uname, b"server", client_reg["w0"], client_reg["w1"])
        shareP = prover.create_message()
        send_msg(s, shareP)

        shareV = recv_msg(s)
        confirmV = recv_msg(s)
        confirmP = prover.process_message(shareV)
        k_shared = prover.verify_confirmation(confirmV)
        send_msg(s, confirmP)

        status = recv_msg(s)
        if status == b"OK":
            print(f"[FAST Bob]    [{timestamp()}] \033[92mSUCCESS\033[0m  K_shared: {k_shared.hex()[:16]}...")

if __name__ == "__main__":
    print("=" * 65)
    print("  CONCURRENCY TEST: Proving the server is non-blocking")
    print("=" * 65)
    print(f"[Test]        [{timestamp()}] Starting slow client (Alice)...")
    print(f"[Test]        Bob will connect 1 second later.")
    print(f"[Test]        Alice will sleep 3 seconds mid-handshake.")
    print(f"[Test]        If Bob finishes BEFORE Alice, threading works!\n")

    t1 = threading.Thread(target=slow_client)
    t2 = threading.Thread(target=fast_client)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    print(f"\n[Test]        [{timestamp()}] Both clients finished.")
    print("=" * 65)
    print("  If Bob finished BEFORE Alice, the server is non-blocking! ✓")
    print("=" * 65)
