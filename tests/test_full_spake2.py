import os
from pake import registration as r
from pake import online_auth as auth

def test_success_case():
    print("--- 1) Success Case: Classic SPAKE2+ Exchange ---")
    context = b"SPAKE2+-Test"
    id_prover = b"alice"
    id_verifier = b"server"
    password = "correct_horse_battery_staple"

    # Step A: Offline Registration
    # Client types password. System derives w0, w1, L. Server stores (w0, L, salt).
    reg_data = r.register(password, id_prover, id_verifier)
    print("[Registration] Alice registered successfully. Server has stored L and w0.")

    # Step B: Online Authentication
    # Client wants to log in. Server sends them the salt so they can re-derive w0, w1.
    client_reg_data = r.register(password, id_prover, id_verifier, salt=reg_data["salt"])
    
    prover = auth.Prover(context, id_prover, id_verifier, client_reg_data["w0"], client_reg_data["w1"])
    verifier = auth.Verifier(context, id_prover, id_verifier, reg_data["w0"], reg_data["L"])

    # Round 1
    shareP = prover.create_message()
    shareV, confirmV = verifier.process_message(shareP)
    
    # Round 2
    confirmP = prover.process_message(shareV)

    # Key Confirmation
    prover_key = prover.verify_confirmation(confirmV)
    verifier_key = verifier.verify_confirmation(confirmP)

    assert prover_key == verifier_key, "Keys should match in the success case!"
    print("[Authentication] Success! Both parties securely agreed on K_shared:")
    print(f"  -> {prover_key.hex()}\n")


def test_fail_registration():
    print("--- 2) Fail Case: Registration ---")
    id_prover = b"bob"
    id_verifier = b"server"
    password = "bob_password"
    
    # Registration can fail if the cryptographic parameters are malformed.
    # For example, libsodium's Argon2id requires exactly a 16-byte salt. 
    # If the system or an attacker provides a corrupted/invalid salt length, it must fail securely.
    bad_salt = os.urandom(8)  # 8 bytes instead of 16
    
    try:
        r.register(password, id_prover, id_verifier, salt=bad_salt)
        assert False, "Should have thrown a ValueError for bad salt!"
    except ValueError as e:
        print(f"[Registration] Correctly failed with malformed input. Error: {e}\n")


def test_fail_authentication():
    print("--- 3) Fail Case: Authentication (Attacker tries to log in) ---")
    context = b"SPAKE2+-Test"
    id_prover = b"charlie"
    id_verifier = b"server"
    real_password = "charlie_secret"
    
    # Charlie registers legitimately
    reg_data = r.register(real_password, id_prover, id_verifier)
    print("[Registration] Charlie registered successfully.")

    # An attacker (Mallory) tries to log in as Charlie. 
    # Mallory doesn't know the password, so she just guesses "password123".
    attacker_password = "password123"
    print(f"[Attack] Mallory attempts to connect as '{id_prover.decode()}' using guessed password: '{attacker_password}'")
    
    # Attacker runs the derivation with the wrong password
    attacker_reg_data = r.register(attacker_password, id_prover, id_verifier, salt=reg_data["salt"])
    
    attacker_prover = auth.Prover(context, id_prover, id_verifier, attacker_reg_data["w0"], attacker_reg_data["w1"])
    server_verifier = auth.Verifier(context, id_prover, id_verifier, reg_data["w0"], reg_data["L"])

    # Round 1: Attacker sends shareP
    attacker_shareP = attacker_prover.create_message()
    
    # Server processes it (Server doesn't know it's an attacker yet, math just proceeds but derives different Z and V)
    server_shareV, server_confirmV = server_verifier.process_message(attacker_shareP)
    
    # Round 2: Attacker processes Server's shareV
    attacker_confirmP = attacker_prover.process_message(server_shareV)

    # Key Confirmation Phase!
    # 1. Attacker tries to verify the Server's validation MAC. Because the Attacker's
    #    keys are different from the Server's keys, the HMAC will NOT match!
    try:
        attacker_prover.verify_confirmation(server_confirmV)
        assert False, "Attacker should not be able to verify the server's MAC!"
    except ValueError as e:
        print(f"[Authentication] Attacker explicitly failed. Error: {e}")

    # 2. Server tries to verify the Attacker's validation MAC.
    try:
        server_verifier.verify_confirmation(attacker_confirmP)
        assert False, "Server should reject the attacker's MAC!"
    except ValueError as e:
        print(f"[Authentication] Server actively rejected the Attacker. Error: {e}\n")


if __name__ == "__main__":
    print("Starting Comprehensive SPAKE2+ Tests\n" + "="*40)
    test_success_case()
    test_fail_registration()
    test_fail_authentication()
    print("All Full-Exchange Tests Passed Successfully!")
