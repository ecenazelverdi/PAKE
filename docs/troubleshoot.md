# Troubleshooting
### Failed to load libsodium
Try to run the command specifically with sudo. If it still fails. Close and reopen to project, or possibly your computer to refresh it. When you start the installation with sudo, also make sure to enter the right password.

### Client.py don't work
To make sure client works, you need to run the server as well. In one terminal, run the server. In another terminal, run the client.

### How to register new user?
To register a new user, run the following command:
```bash
python3 client.py register <username> <password>
```

### How to login?
To login, run the following command:
```bash
python3 client.py login <username> <password>
```

### test_concurrent / test_online_auth / test_online_authM don't work
To make sure they work, server needs to run. Try running the server in different terminal, then try to run the test file again.
