# Cryptio

**Cryptio** is a [ZNC](https://znc.in/) python module that enhances secure communication by implementing Diffie-Hellman key exchange and AES-256 GCM encryption. It ensures that user messages are encrypted, providing data integrity

## Features

- **Diffie-Hellman Key Exchange**: Securely exchanges keys with other users to establish a shared secret.
- **AES-256 GCM Encryption**: Encrypts messages using AES-256 in Galois/Counter Mode (GCM) for both confidentiality and data integrity.
- **IRC Message Length**: Enforces the 512-byte IRC line limit after encryption, including the sender hostmask, target, and CRLF. The maximum message length adapts to the actual UTF-8 byte count; oversized messages are rejected without fragmentation.

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
If ZNC cannot determine its own IRC hostmask, outgoing messages are blocked rather than risking an incorrect length calculation.


