from pake import registration as r
from pake import online_auth as auth

def test_online_auth():
    print("Running Online Authentication (SPAKE2+) tests...\n")
    
    # Context (e.g. protocol name)
    context = b"DTU-NetworkSecurity-PAKE-v1.0"
    id_prover = b"alice"
    id_verifier = b"server"
    password = "supersecretpassword"

    print(f"--- offline registration Phase for user '{id_prover.decode()}' ---")
    reg_data = r.register(password, id_prover, id_verifier)
    print("Registration successful. Server stores w0 and L.\n")


    print("--- Online Authentication Phase (Happy Path) ---")
    # 1. Initialize Prover and Verifier
    prover = auth.Prover(context, id_prover, id_verifier, reg_data["w0"], reg_data["w1"])
    verifier = auth.Verifier(context, id_prover, id_verifier, reg_data["w0"], reg_data["L"])

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
    prover_key = prover.verify_confirmation(confirmV)
    
    # Verifier verifies Prover's confirmation
    verifier_key = verifier.verify_confirmation(confirmP)

    print("\nShared Keys matched!")
    print(f"Prover's   K_shared: {prover_key.hex()}")
    print(f"Verifier's K_shared: {verifier_key.hex()}")
    assert prover_key == verifier_key, "Keys did not match!"
    print("\nTest 1 (Happy Path): PASS\n")

    
    print("--- Online Authentication Phase (Wrong Password) ---")
    # 1. User enters wrong password
    wrong_reg = r.register("wrong_password123", id_prover, id_verifier, salt=reg_data["salt"])
    
    prover2 = auth.Prover(context, id_prover, id_verifier, wrong_reg["w0"], wrong_reg["w1"])
    verifier2 = auth.Verifier(context, id_prover, id_verifier, reg_data["w0"], reg_data["L"])

    shareP2 = prover2.create_message()
    shareV2, confirmV2 = verifier2.process_message(shareP2)
    confirmP2 = prover2.process_message(shareV2)

    try:
        verifier2.verify_confirmation(confirmP2)
        assert False, "Should have thrown an exception!"
    except ValueError as e:
        print(f"Verifier correctly rejected Prover! Error: {e}")
    
    try:
        prover2.verify_confirmation(confirmV2)
        assert False, "Should have thrown an exception!"
    except ValueError as e:
        print(f"Prover correctly rejected Verifier! Error: {e}")

    print("\nTest 2 (Wrong Password): PASS\n")

if __name__ == "__main__":
    test_online_auth()
