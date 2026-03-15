import socket
import ssl
import time

def run_client(password="mypassword"):
    # 1. Setup SSL Context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Using self-signed certs for testing

    start_time = time.perf_counter() # Use high-resolution timer

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # 2. Wrap the socket and perform handshake
        # do_handshake_on_connect=True is the default
        with context.wrap_socket(sock, server_hostname="localhost") as ssock:
            ssock.connect(('127.0.0.1', 8443))
            
            # 3. Send the password
            ssock.sendall(password.encode())
            response = ssock.recv(1024)
            
            end_time = time.perf_counter()
            
            duration_ms = (end_time - start_time) * 1000
            print(f"TLS Version: {ssock.version()}")
            print(f"Handshake + Send Time: {duration_ms:.2f} ms")

if __name__ == "__main__":
    run_client()
