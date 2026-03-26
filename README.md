# PAKE Implementation

[![Documentation](https://img.shields.io/badge/docs-live-brightgreen)](https://ecenazelverdi.github.io/PAKE/)

This project requires `libsodium` to be installed on your system.

```bash
sudo apt-get install libsodium-dev
```

## Project Structure

- `pake/`: Core SPAKE2+ implementation (PAKE_basic, registration, online_auth, config).
- `tests/`: Unit and integration tests.
- `server.py`: PAKE Server entry point.
- `client.py`: PAKE Client entry point.
- `tls_server.py`: TLS Server entry point.
- `tls_client.py`: TLS Client entry point.

## How to Run

### 1. Start the Server
In your first terminal, start the PAKE server:
```bash
python3 server.py
```

### 2. Use the Client
In a second terminal, you can interact with the server.

#### Register a new user:
```bash
python3 client.py register <username> <password>
```
Example:
```bash
python3 client.py register charlie new_password
```

#### Login:
```bash
python3 client.py login <username> <password>
```
Example:
```bash
python3 client.py login charlie new_password
```
### 3. Running the TLS tests
Before running the files, generate the certificate using OpenSSL.

#### Certificate generation:
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```
In one terminal, run the server
```bash
python3 tls_server.py
```

In another, run the client
```bash
python3 tls_client.py
```
To add delay using Linux's Traffic Control(tc) use:
```bash
sudo tc qdisc add dev lo root netem delay <duration>
```
To remove the delay
```bash
sudo tc qdisc del dev lo root
```

### Running Tests
To run all tests at once, simply run:
```bash
python3 tests/
```

You can also run individual tests:
```bash
python3 tests/test_registration.py
python3 tests/test_full_spake2.py
```

## Documentation

To view the project's documentation locally with the **Material** theme:

### Build the documentation:
```bash
conda run -n pake mkdocs build
```

### Serve the documentation locally:
```bash
conda run -n pake mkdocs serve
```
Once running, you can access it at [http://127.0.0.1:8000](http://127.0.0.1:8000).
