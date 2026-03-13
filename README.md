After running `pip install -r requirements.txt`, if you get an error, try to run the given code:
```bash
sudo apt-get install libsodium-dev
```

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