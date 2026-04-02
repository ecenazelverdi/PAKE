import socket
from pake import registration as r
from pake import online_auth as auth
from pake.config import HOST, PORT, send_msg, recv_msg
import sys
import time
from datetime import datetime

def run_client(username: str, password: str):
    uname_bytes = username.encode('utf-8')
    t_start = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[Client] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Connected to {HOST}:{PORT}")
        # 1. Send username to server
        send_msg(s, b"LOGIN")
        send_msg(s, uname_bytes)
    
        # 2. Receive salt from server
        salt = recv_msg(s)
        t_net_1 = time.time()
        if not salt:
            print("[Client] Server rejected username.")
            return

        # 3. Derive w0 and w1 using Argon2id
        print("[Client] Received salt. Running Argon2id...")
        t_argon_start = time.time()
        client_reg = r.register(password, uname_bytes, b"server", salt=salt)
        t_argon_end = time.time()

        #==========Step 3: Round 1 — Send your first message==========
        # 4. Create Prover and compute shareP
        t_r1_start = time.time()
        prover = auth.Prover(b"SPAKE2+-Loopback", uname_bytes, b"server", client_reg["w0"], client_reg["w1"])
        shareP = prover.create_message()
        t_r1_end = time.time()

        t_net_2_start = time.time()
        send_msg(s, shareP)
        print("[Client] Sent shareP to server.")

        #==========Step 4: Round 2 — Receive server's response and verify==========
        # 5. Receive shareV and confirmV from server
        shareV = recv_msg(s)
        confirmV = recv_msg(s)
        t_net_2_end = time.time()
        
        t_r2_start = time.time()
        # 6. Process shareV (computes Z, V, keys, and our confirmP)
        try:
            confirmP = prover.process_message(shareV)
            k_shared = prover.verify_confirmation(confirmV)
        except ValueError as e:
            print(f"\033[91mAuthentication FAILED: {e}\033[0m")
            return None
        t_r2_end = time.time()
        
        #==========Step 5: Send your MAC and get result==========
        t_net_3_start = time.time()
        # 8. Send our confirmP to server
        send_msg(s, confirmP)
        
        # 9. Get final status
        status = recv_msg(s)
        t_net_3_end = time.time()

        if status == b"OK":
            duration = (t_net_3_end - t_start) * 1000
            print(f"\033[92mAuthentication SUCCESS!\033[0m")
            print(f"K_shared: {k_shared.hex()}")
            print(f"Handshake completed in {duration:.2f} ms")
            
            return {
                "01_Network_Init_&_Salt": (t_net_1 - t_start) * 1000,
                "02_Argon2_Math": (t_argon_end - t_argon_start) * 1000,
                "03_Client_R1_Math": (t_r1_end - t_r1_start) * 1000,
                "04_Network_R1_Wait_&_Server": (t_net_2_end - t_net_2_start) * 1000,
                "05_Client_R2_Math": (t_r2_end - t_r2_start) * 1000,
                "06_Network_Final_Wait": (t_net_3_end - t_net_3_start) * 1000,
                "Total_Handshake": duration
            }
        else:
            print(f"\033[91mAuthentication FAILED.\033[0m")
            return None

def register_client(username: str, password: str):
    uname_bytes = username.encode('utf-8')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        # Tell server we want to register
        send_msg(s, b"REGISTER")
        send_msg(s, uname_bytes)
        
        # Compute w0, w1, L locally
        reg_data = r.register(password, uname_bytes, b"server")
        
        # Send w0, L, salt to server
        send_msg(s, reg_data["w0"])
        send_msg(s, reg_data["L"])
        send_msg(s, reg_data["salt"])
        
        # Get confirmation
        status = recv_msg(s)
        if status == b"OK":
            print("Registration SUCCESS!")



if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 client.py <register/login> <username> <password>")
        sys.exit(1)
    if sys.argv[1] == "register":
        register_client(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "login":
        run_client(sys.argv[2], sys.argv[3])

    
