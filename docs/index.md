# PAKE (Password Authenticated Key Exchange)

Welcome to the documentation for the **PAKE** project—a clean, high-security implementation of the **SPAKE2+** protocol (RFC 9383) using the **Ristretto255** group and **libsodium**.

## Overview

This project provides a robust framework for authenticating users over insecure channels without ever sending passwords or their hashes over the network. It is designed to be resistant to offline dictionary attacks and session hijacking.

!!! success "Key Features"
    - **SPAKE2+ Protocol**: A state-of-the-art balanced PAKE.
    - **Ristretto255**: Fast, high-security elliptic curve operations.
    - **Minimal Dependencies**: Uses Python's built-in `ctypes` to talk directly to `libsodium`.
    - **Concurrent Server**: Real-time handling of multiple authentication requests.

## Project Structure

- `pake/`: Core protocol implementation.
- `tests/`: Comprehensive test suite.
- `server.py` / `client.py`: Networked entry points.

---

[Get Started with Installation](installation.md){ .md-button .md-button--primary }
