import registration_mul as r
import online_auth as auth

def test_online_auth():

    print("Running Online Authentication (SPAKE2+) tests...\n")

    context = b"DTU-NetworkSecurity-PAKE-v1.0"
    id_verifier = b"server"

    # Create server database
    db = r.ServerDB()

    # Register two users
    alice = db.register_user(b"alice", "secretpassword", id_verifier)
    bob = db.register_user(b"bob", "hunter2", id_verifier)

    print("Registered users:", db.list_users())

    print("--- Online Authentication Phase (Happy Path) ---")
    # 1. Initialize Prover and Verifier
    print("\n--- Alice Login ---")

    server_rec = db.get_user(b"alice")

    prover = auth.Prover(context, b"alice", id_verifier,
                         alice["w0"], alice["w1"])

    verifier = auth.Verifier(context, b"alice", id_verifier,
                             server_rec["w0"], server_rec["L"])

    # 2. Round 1: Prover -> Verifier (shareP)
    shareP = prover.create_message()
    print("Prover sends shareP to Verifier")

    # 3. Round 1: Verifier -> Prover (shareV, confirmV)
    shareV, confirmV = verifier.process_message(shareP)
    print("Verifier sends shareV and confirmV to Prover")

    # 4. Round 2: Prover -> Verifier (confirmP)
    confirmP = prover.process_message(shareV)
    print("Prover sends confirmP to Verifier")

    # 5. Key Confirmation
    # Prover verifies Verifier's confirmation
    key_client = prover.verify_confirmation(confirmV)
    
    # Verifier verifies Prover's confirmation
    key_server = verifier.verify_confirmation(confirmP)

    print("\nShared Keys matched!")
    print(f"Prover's   K_shared: {key_server.hex()}")
    print(f"Verifier's K_shared: {key_client.hex()}")
    assert key_client == key_server, "Keys did not match!"
    print("\nTest 1 (Happy Path for Alice): PASS\n")
    
    print("\n--- Bob Login ---")

    server_rec = db.get_user(b"bob")

    prover = auth.Prover(context, b"bob", id_verifier,
                         bob["w0"], bob["w1"])

    verifier = auth.Verifier(context, b"bob", id_verifier,
                             server_rec["w0"], server_rec["L"])
    shareP = prover.create_message()
    print("Prover sends shareP to Verifier")
    shareV, confirmV = verifier.process_message(shareP)
    print("Verifier sends shareV and confirmV to Prover")
    confirmP = prover.process_message(shareV)
    print("Prover sends confirmP to Verifier")
    key_client = prover.verify_confirmation(confirmV)
    key_server = verifier.verify_confirmation(confirmP)

    print("\nShared Keys matched!")
    print(f"Prover's   K_shared: {key_server.hex()}")
    print(f"Verifier's K_shared: {key_client.hex()}")
    assert key_client == key_server, "Keys did not match!"
    print("\nTest 1 (Happy Path): PASS\n")
    print("--- Online Authentication Phase (Wrong Password) ---")
    # 1. User enters wrong password
    print("\n--- Wrong Password Test ---")

    try:
        server_rec = db.get_user(b"alice")

        wrong_client = r.register("wrongpassword", b"alice", id_verifier)

        prover = auth.Prover(context, b"alice", id_verifier,
                             wrong_client["w0"],
                             wrong_client["w1"])

        verifier = auth.Verifier(context, b"alice", id_verifier,
                                 server_rec["w0"], server_rec["L"])

        shareP = prover.create_message()
        shareV, confirmV = verifier.process_message(shareP)

        confirmP = prover.process_message(shareV)
        
        prover.verify_confirmation(confirmV)


        print("ERROR: Authentication should have failed!")

    except Exception:
        print("Correctly rejected wrong password.")

if __name__ == "__main__":
    test_online_auth()
