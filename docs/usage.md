# Usage Guide

This guide covers how to run the PAKE server and interact with it using the client.

## 1. Start the Server

In your first terminal, start the PAKE server:
```bash
python3 server.py
```

## 2. Use the Client

In a second terminal, you can interact with the server.

### Register a new user
```bash
python3 client.py register <username> <password>
```
Example:
```bash
python3 client.py register charlie new_password
```

### Login
```bash
python3 client.py login <username> <password>
```
Example:
```bash
python3 client.py login charlie new_password
```

## 3. Advanced: TLS Support
The project also includes a TLS-wrapped version of the client and server for added transport-layer security.

### Generate Certificates
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

### Run TLS Server
```bash
python3 tls_server.py
```

### Run TLS Client
```bash
python3 tls_client.py
```

## 4. Network Simulation
To simulate real-world network conditions (delay/latency) on Linux:
```bash
sudo tc qdisc add dev lo root netem delay 100ms
```
To remove the delay:
```bash
sudo tc qdisc del dev lo root
```

## 5. Running Tests
To run all tests at once, simply run:
```bash
python3 tests/
```
