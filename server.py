import socket
from pake import registration as r
from pake import online_auth as auth
from pake.config import HOST, PORT, send_msg, recv_msg
import threading #For async purposes
import time
from datetime import datetime

print("Booting up Server Database...")
db = r.ServerDB()
db.register_user(b"alice", "password123", b"server")
db.register_user(b"bob", "hunter2", b"server")

def start_server():
    #python3 server.py & sleep 1; kill %1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # 1. Bind the socket to the IP and Port
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        
        # 2. Tell the OS we are ready to listen for incoming connections
        s.listen()
        print(f"Server actively listening on {HOST}:{PORT}")
    
        # 3. Enter an infinite loop to keep accepting new users forever!
        while True:
            # .accept() will pause your script right here until a client actually connects
            conn, addr = s.accept()
            print(f"Someone connected from {addr}!")
            
            # Pass 'conn' to our newly uncommented function to handle the SPAKE2+ math
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

def handle_client(conn, addr):
    # Talks to the client and does the SPAKE2+ math.
    t_start = time.time()
    print(f"[{addr}] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] New connection opened!")
    try: 
        command = recv_msg(conn).decode('utf-8')
        username_bytes = recv_msg(conn)
        if command == "REGISTER":
            # Receive w0, L, salt from the client
            w0 = recv_msg(conn)
            L = recv_msg(conn)
            salt = recv_msg(conn)
            # Store in database
            db.users[username_bytes] = {"w0": w0, "L": L, "salt": salt}
            send_msg(conn, b"OK")
            print(f"[{addr}] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Registered new user: '{username_bytes.decode()}'")
            
        elif command == "LOGIN":
            # Wait for Username
            if not username_bytes:
                print(f"[{addr}] No username received. Closing connection.")
                return
            print(f"[{addr}] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Login attempt for user: '{username_bytes.decode('utf-8')}'")
            # Database Lookup
            try:
                user_record = db.get_user(username_bytes)
            except ValueError:
                print(f"[{addr}] Unknown user '{username_bytes.decode('utf-8')}'. Aborting.")
                send_msg(conn, b"") # Send empty salt to indicate error (closes connection logically)
                return
            # Send the Salt
            send_msg(conn, user_record["salt"])

            #========== Round 1 ==========
            # Receive Prover's public point (shareP)
            shareP = recv_msg(conn)
            
            # Initialize Verifier (Server) math object
            verifier = auth.Verifier(b"SPAKE2+-Loopback", username_bytes, b"server", user_record["w0"], user_record["L"])
            
            # Process shareP, generate Server's shareV and the confirmation MAC (confirmV)
            print(f"[{addr}] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Received shareP. Computing server math...")
            shareV, confirmV = verifier.process_message(shareP)

            # Send shareV and confirmV back to Prover
            send_msg(conn, shareV)
            send_msg(conn, confirmV)

            #========== Round 2 ==========
            # Receive Prover's confirmation MAC (confirmP)
            confirmP = recv_msg(conn)
            
            # Verify Prover's confirmation
            k_shared = verifier.verify_confirmation(confirmP)
            """
            ANSI Escape Code. It is a special secret command you can put inside a string that tells your MacOS/Linux terminal screen to change the color of the text.

            \033[ is the signal to the terminal: "Hey, stop printing text for a second, I have a color command for you!"
            92m is the specific code for Bright Green.
            91m is the specific code for Bright Red.
            0m is the code for Reset (go back to normal white/gray text).
            """
            
            t_end = time.time()
            print(f"[{addr}] [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] \033[92mSUCCESS\033[0m: User '{username_bytes.decode('utf-8')}' authenticated!")
            print(f"[{addr}] K_shared established: {k_shared.hex()}")
            print(f"[{addr}] Handshake completed in {(t_end - t_start)*1000:.2f} ms")
            
            # Tell the client we succeeded
            send_msg(conn, b"OK")
        else:
            raise ValueError("Invalid command")
    except ValueError as e:
        # If is_valid_point fails, or MAC verification fails, it throws a ValueError!
        print(f"[{addr}] \033[91mFAILED\033[0m: Cryptographic validation rejected the connection. Error: {e}")
        send_msg(conn, b"ERR")
    except Exception as e:
        print(f"[{addr}] Error: {e}")
    finally:
        conn.close()
        print(f"[{addr}] Connection closed.")


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    except Exception as e:
        print(f"An error occurred: {e}")
