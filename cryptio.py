import znc
from Cryptodome.Random import random
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
import base64

class cryptio(znc.Module):
    """
    A ZNC module for secure messaging using Diffie-Hellman key exchange and AES-256 encryption.
    This module intercepts and encrypts/decrypts messages, ensuring secure communication.
    """
    
    module_types = [znc.CModInfo.NetworkModule]
    identifier = "!$~ENC@#"
    max_message_length = 300  # Limit of 300 characters for outgoing messages
    
    def OnLoad(self, args, message):
        """
        Called when the module is loaded. Initializes Diffie-Hellman parameters and generates keys.
        """
        # Diffie-Hellman parameters as specified in RFC 3526 (Group 14)
        self.p = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
            "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
            "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
            "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
        self.g = 2

        # Generate private and public keys
        self.generate_keys()
        return True

    def generate_keys(self):
        """
        Generates Diffie-Hellman private and public keys.
        Logs the details of the keys generated.
        """
        rnd_len = random.StrongRandom().randint(256, 2046)
        self.private_key = random.StrongRandom().getrandbits(rnd_len)
        self.public_key = pow(self.g, self.private_key, self.p)
        self.shared_key = None
        self.aes_key = None

        # Log the generated key information
        self.PutModule("Made with ❤️ by Tom :) e-mail: tom@tom.mk")
        self.PutModule("Diffie Hellman's Key Info:")
        self.PutModule(f"  Bit length of generated private key: {rnd_len} bits")
        self.PutModule(f"  Bit length of generated public key: {self.public_key.bit_length()} bits")
        self.PutModule(f"  Bit length of prime parameter 'p': {self.p.bit_length()} bits")

    def OnModCommand(self, command):
        parts = command.split(" ")
        cmd = parts[0].lower()

        if cmd == "dhkey" and len(parts) == 2:
            self.invia_chiave(parts[1])
        elif cmd == "setkey" and len(parts) == 2:
            self.set_aes_key(parts[1])
        else:
            self.show_help()

    def show_help(self):
        """
        Displays available commands for the module.
        """
        self.PutModule("Available commands:")
        self.PutModule("  dhkey <nick>: Initiates Diffie-Hellman key exchange with the specified user")
        self.PutModule("  setkey <base64_key>: Manually sets an AES-256 key encoded in Base64")

    def set_aes_key(self, new_key):
        """
        Sets the AES-256 key manually from a Base64 or Hex-encoded string.
        """
        try:
            decoded_key = self.decode_key(new_key)
            if decoded_key and len(decoded_key) == 32:
                self.aes_key = decoded_key
                self.PutModule("New AES-256 key successfully set.")
            else:
                self.PutModule("Error: Key must be in Hex (64 characters) or Base64 (44 characters) format and 32 bytes long.")
        except Exception as e:
            self.PutModule(f"Error setting AES key: {str(e)}")

    def decode_key(self, key_str):
        """
        Decodes a key from a Hex or Base64 string.
        """
        if len(key_str) == 64:  # Hex
            return bytes.fromhex(key_str)
        elif len(key_str) == 44:  # Base64
            return base64.b64decode(key_str)
        return None

    def invia_chiave(self, target_nick):
        """
        Sends the public key to the specified target nick.
        """
        public_key_b85 = self.codifica_chiave_pubblica(self.public_key)
        self.PutIRC(f"PRIVMSG {target_nick} :REQ-DH-KEY:{public_key_b85}")

    def codifica_chiave_pubblica(self, chiave_pubblica):
        """
        Encodes the public key using Base85.
        """
        public_key_bytes = chiave_pubblica.to_bytes((chiave_pubblica.bit_length() + 7) // 8, byteorder='big')
        return base64.b85encode(public_key_bytes).decode('utf-8')

    def calcola_chiave_condivisa_e_aes(self, other_public_key_b85):
        """
        Calculates the shared key and derives the AES-256 key.
        Logs the shared key and derived AES key.
        """
        try:
            other_public_key = self.decode_public_key(other_public_key_b85)
            self.shared_key = pow(other_public_key, self.private_key, self.p)
            self.aes_key = SHA256.new(str(self.shared_key).encode()).digest()

            # Log the shared and AES keys
            self.PutModule("Key exchange completed successfully.")
            self.PutModule(f"  Shared key: {self.shared_key}")
            self.PutModule(f"  Derived AES-256 key: {self.aes_key.hex()}")

        except ValueError as e:
            self.PutModule(f"Error decoding public key: {e}")

    def decode_public_key(self, key_b85):
        """
        Decodes a public key from a Base85 string.
        """
        key_bytes = base64.b85decode(key_b85)
        return int.from_bytes(key_bytes, byteorder='big')

    def encrypt_message(self, message):
        """
        Encrypts a message using AES-256 in GCM mode.
        """
        if self.aes_key is None:
            self.PutModule("Error: AES key has not been set.")
            return message

        cipher = AES.new(self.aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        combined_message = cipher.nonce + tag + ciphertext
        return self.identifier + base64.b85encode(combined_message).decode('utf-8')

    def decrypt_message(self, encoded_message):
        """
        Decrypts a message using AES-256 in GCM mode.
        """
        try:
            combined_message = base64.b85decode(encoded_message)
            nonce = combined_message[:16]
            tag = combined_message[16:32]
            ciphertext = combined_message[32:]
            cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        except Exception as e:
            self.PutModule(f"Error decrypting message: {e}")
            return None

    def OnPrivMsg(self, nick, message):
        msg = message.s.strip()

        if msg.startswith("REQ-DH-KEY:"):
            self.handle_key_request(nick, msg)
        elif msg.startswith("RESP-DH-KEY:"):
            self.handle_key_response(msg)
        elif msg.startswith(self.identifier):
            self.handle_encrypted_message(message, msg[len(self.identifier):])
        else:
            self.PutModule("Received unencrypted message.")

        return znc.CONTINUE

    def handle_key_request(self, nick, msg):
        """
        Handles incoming key exchange requests.
        """
        public_key_b85 = self.codifica_chiave_pubblica(self.public_key)
        self.PutIRC(f"PRIVMSG {nick.GetNick()} :RESP-DH-KEY:{public_key_b85}")
        self.calcola_chiave_condivisa_e_aes(msg.split(":")[1])

    def handle_key_response(self, msg):
        """
        Handles responses during key exchange.
        """
        parts = msg.split(":")
        if len(parts) == 2:
            self.calcola_chiave_condivisa_e_aes(parts[1])
        else:
            self.PutModule(f"Invalid RESP-DH-KEY message format: {msg}")

    def handle_encrypted_message(self, message, encoded_message):
        """
        Handles decryption of received messages.
        """
        decrypted_message = self.decrypt_message(encoded_message)
        if decrypted_message:
            message.s = decrypted_message

    def OnChanMsg(self, nick, channel, message):
        if message.s.startswith(self.identifier):
            self.handle_encrypted_message(message, message.s[len(self.identifier):])
        else:
            self.PutModule("Received unencrypted message.")
        
        return znc.CONTINUE

    def OnUserMsg(self, target, message):
        """
        Blocks outgoing user messages over 300 characters to account for encryption overhead. 
        This limit is a temporary safeguard as precise overhead calculations are not yet implemented.
        """
        if len(message.s) > self.max_message_length:
            self.PutModule(f"Error: Message too long ({len(message.s)} characters). Maximum is {self.max_message_length} characters.")
            return znc.HALT  # Prevents the message from being sent

        encrypted_message = self.encrypt_message(message.s)
        message.s = encrypted_message
        
        return znc.CONTINUE
