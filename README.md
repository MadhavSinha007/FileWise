# FileWise
AES-RSA Hybrid Encryption System

This project implements a hybrid encryption system using AES-256-GCM for symmetric encryption and RSA-4096 for encrypting the AES key. This ensures both efficiency and security when encrypting and decrypting files.

## Features

- AES-256-GCM for fast and secure file encryption

- RSA-4096 for encrypting the AES key

- Secure IV and authentication tag handling

- OpenSSL-based encryption and decryption

- Automated build system using Makefile

## Prerequisites

Ensure you have the following installed:

- OpenSSL (latest version)

  Install it using ```sudo apt install libssl-dev```

- GCC (C++ compiler)

## Installation

1. Clone the Repository
```bash
git clone https://github.com/yourusername/aes-rsa-encryption.git
cd aes-rsa-encryption
```
2. Generate RSA Key Pair
```bash
make keys
```

This will generate public_key.pem and private_key.pem in the project directory.

3. Build the Project
```bash
make
```

## Usage

### Encrypt a File
```bash
make encrypt FILE=input.txt OUTPUT=output.enc
```
This will:

- Generate an AES key

- Encrypt input.txt using AES-GCM

- Encrypt the AES key with RSA

- Save the encrypted data to output.enc

### Decrypt a File
```bash
make decrypt FILE=output.enc OUTPUT=decrypted.txt
```
This will:

- Decrypt the AES key using RSA

- Decrypt the file using AES-GCM

- Save the output to decrypted.txt

### Cleanup

To remove compiled files and encrypted outputs:
```bash
make clean
```

License

This repository is under MIT License. Feel free to modify and use it!
