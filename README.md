After running `pip install -r requirements.txt`, if you get an error, try to run the given code:
```bash
sudo apt-get install libsodium-dev
```

## Project Structure

- `pake/`: Core SPAKE2+ implementation (PAKE_basic, registration, online_auth, config).
- `tests/`: Unit and integration tests.
- `server.py`: PAKE Server entry point.
- `client.py`: PAKE Client entry point.

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