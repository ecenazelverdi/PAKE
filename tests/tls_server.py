import socket
import ssl

def run_server():
    # 1. Setup SSL Context (TLS 1.3 preferred)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Generate these files using: 
    # openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 8443))
        sock.listen(5)
        print("Server listening on 8443...")

        while True:
            conn, addr = sock.accept()
            with context.wrap_socket(conn, server_side=True) as ssock:
                data = ssock.recv(1024)
                print(f"Received password: {data.decode()}")
                ssock.sendall(b"Authenticated")

if __name__ == "__main__":
    run_server()