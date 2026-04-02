import socket

HOST = '127.0.0.1'
PORT = 5000

def recv_msg(sock: socket.socket) -> bytes:
    #Helper to receive length-prefixed binary messages.
    raw_len = sock.recv(4) # Receives the first 4 bytes (the length of the message)
    if not raw_len:
        return b""
    msg_len = int.from_bytes(raw_len, 'big') # Converts the 4 bytes into an integer
    data = b""
    while len(data) < msg_len:
        packet = sock.recv(msg_len - len(data)) # Receives the rest of the message
        if not packet:
            return b""
        data += packet
    return data

def send_msg(sock: socket.socket, data: bytes):
    #Helper to send length-prefixed binary messages.
    sock.sendall(len(data).to_bytes(4, 'big') + data) # Sends the length of the message (4 bytes) + the message itself
