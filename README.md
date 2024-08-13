# Cryptio

**Cryptio** is a [ZNC](https://znc.in/) module that enhances secure communication by implementing Diffie-Hellman key exchange and AES-256 GCM encryption. It ensures that user messages are encrypted, providing data integrity

## Features

- **Diffie-Hellman Key Exchange**: Securely exchanges keys with other users to establish a shared secret.
- **AES-256 GCM Encryption**: Encrypts messages using AES-256 in Galois/Counter Mode (GCM) for both confidentiality and data integrity.
- **Message Length Limit**: Automatically blocks outgoing messages longer than 300 characters to account for encryption overhead.

## Installation

1. sudo apt-get install python3-pycryptodome (required pycryptodome package)
2. put the module in ~/.znc/modules/
3. /msg *status loadmod modpython
4. /msg *status loadmod cryptio

## Usage
Commands<br>
`dhkey <nick>`: Initiates Diffie-Hellman key exchange with the specified user (Obviously both users must have the module loaded)<br>
`setkey <base64_key>`: Manually sets an AES-256 key encoded in Base64

### Limitations
Message Length: 
Messages longer than 300 characters are blocked to avoid issues with encryption overhead. Future versions may implement a more precise calculation.


