# Installation

To get started with the PAKE project, follow these steps to set up your environment and dependencies.

## System Dependencies

This project requires `libsodium` to be installed on your system.

```bash
sudo apt-get install libsodium-dev
```

## Python Dependencies

The project is designed to be minimal. Once `libsodium` is installed on your system, you don't need any external Python libraries to run the core protocol, as it uses `ctypes`.