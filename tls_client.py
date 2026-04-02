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
            connect_start = time.perf_counter()
            ssock.connect(('127.0.0.1', 8443))
            connect_end = time.perf_counter()
            
            # 3. Send the password
            ssock.sendall(password.encode())
            response = ssock.recv(1024)
            data_end = time.perf_counter()
            
            total_duration = (data_end - start_time) * 1000
            handshake_duration = (connect_end - connect_start) * 1000
            data_duration = (data_end - connect_end) * 1000
            
            print(f"TLS Version: {ssock.version()}")
            print(f"Handshake Time: {handshake_duration:.2f} ms")
            print(f"Data Exchange Time: {data_duration:.2f} ms")
            print(f"Total Time: {total_duration:.2f} ms")
            
            return {
                "Connection_Handshake": handshake_duration,
                "Data_Exchange": data_duration,
                "Total_Handshake": total_duration
            }

if __name__ == "__main__":
    run_client()
