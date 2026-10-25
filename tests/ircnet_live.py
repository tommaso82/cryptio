"""One-off public IRCnet incremental encrypted channel exchange."""
import base64
from pathlib import Path
import os
import shutil
import socket
import subprocess
import tempfile
import time
from Cryptodome.Cipher import AES

ROOT = Path(__file__).resolve().parent.parent
SERVER = "open.ircnet.com"
CHANNEL = "#cybernet"
ZNC_PORT = 17672
TIMEOUT = 105


def test_nick(suffix):
    return "CTio" + os.environ["GITHUB_RUN_ID"][-4:] + suffix


class IRC:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), 12)
        self.sock.settimeout(0.5)
        self.buffer = b""
        self.messages = []

    def send(self, command):
        self.sock.sendall((command + "\r\n").encode("utf-8"))

    def read_until(self, condition, seconds=TIMEOUT):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                data = self.sock.recv(8192)
            except socket.timeout:
                continue
            if not data:
                raise RuntimeError("IRC connection closed; last messages: " + repr(self.messages[-4:]))
            self.buffer += data
            while b"\r\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\r\n", 1)
                if line.startswith(b"PING "):
                    self.send("PONG " + line[5:].decode("ascii", "replace"))
                    continue
                self.messages.append(line)
                if condition(line):
                    return line
                if b" ERROR " in line or line.startswith(b"ERROR "):
                    raise RuntimeError("IRC error: " + line.decode(errors="replace")[:300])
        raise AssertionError("Timeout: " + repr(self.messages[-6:]))

    def close(self):
        try:
            self.send("QUIT :Cryptio test finished")
        except OSError:
            pass
        self.sock.close()


def main():
    sender = test_nick("A")
    recipient = test_nick("B")
    with tempfile.TemporaryDirectory(prefix="cryptio-ircnet-") as temp:
        work = Path(temp)
        home = work / "znc"
        (home / "configs").mkdir(parents=True)
        (home / "modules").mkdir()
        shutil.copy2(ROOT / "cryptio.py", home / "modules" / "cryptio.py")
        (home / "configs" / "znc.conf").write_text(f"""Version = 1.9.0
LoadModule = modpython
<Listener test>
    AllowIRC = true
    AllowWeb = false
    IPv4 = true
    IPv6 = false
    SSL = false
    Port = {ZNC_PORT}
</Listener>
<User testuser>
    Admin = true
    Nick = {sender}
    Ident = ctiotest
    RealName = Cryptio Test
    <Pass password>
        Method = sha256
        Hash = 49396054dc8263b573d11c9c01e43f89ee772f6dc89b3c630e6dffa9acea4a3e
        Salt = ovexwSL50cC?jE2eCM?x
    </Pass>
    <Network ircnet>
        Server = {SERVER} 6667
        LoadModule = cryptio
    </Network>
</User>
""")
        fp = (work / "znc.log").open("wb")
        znc = subprocess.Popen(["znc", "-f", "-d", str(home)], stdout=fp, stderr=subprocess.STDOUT)
        clients = []
        try:
            # Wait for ZNC to start listening locally.
            deadline = time.monotonic() + 15
            while True:
                try:
                    probe = socket.create_connection(("127.0.0.1", ZNC_PORT), 1)
                    probe.close()
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("ZNC did not start")
                    time.sleep(.1)
            receiver = IRC(SERVER, 6667)
            clients.append(receiver)
            receiver.send("NICK " + recipient)
            receiver.send("USER ctiotest 0 * :Cryptio Test Receiver")
            receiver.read_until(lambda x: b" 001 " + recipient.encode() + b" " in x)
            print("Receiver registered on public IRCnet:", recipient, flush=True)
            receiver.send("JOIN " + CHANNEL)
            receiver.read_until(lambda x: b" 366 " + recipient.encode() + b" " + CHANNEL.encode() + b" " in x)
            print("Receiver joined", CHANNEL, flush=True)

            client = IRC("127.0.0.1", ZNC_PORT)
            clients.append(client)
            client.send("PASS testuser/ircnet:password")
            client.send("NICK " + sender)
            client.send("USER testuser 0 * :Test")
            client.read_until(lambda x: b" 001 " in x)
            client.send("JOIN " + CHANNEL)
            sender_join = receiver.read_until(lambda x: x.startswith(b":" + sender.encode() + b"!") and (b" JOIN :" + CHANNEL.encode() in x or b" JOIN " + CHANNEL.encode() in x))
            print("ZNC connected to public IRCnet; sender joined", CHANNEL, flush=True)

            key = b"0" * 32
            client.send("PRIVMSG *cryptio :setkey " + base64.b64encode(key).decode())
            client.read_until(lambda x: b"New AES-256 key successfully set." in x)

            join_mask = sender_join.split(b" ", 1)[0][1:].decode()
            print("Sender hostmask observed on IRCnet:", join_mask, flush=True)

            def predicted_length(n):
                b85 = (5 * (32 + n) + 3) // 4
                return len(f":{join_mask} PRIVMSG {CHANNEL} :\r\n".encode()) + 8 + b85

            predicted_max = max(n for n in range(450) if predicted_length(n) <= 512)
            print("Predicted channel limit:", predicted_max, "UTF-8 bytes", flush=True)

            def from_sender(line):
                return (line.startswith(b":" + sender.encode() + b"!")
                        and b" PRIVMSG " + CHANNEL.encode() + b" :!$~ENC@#" in line)

            def decrypt_wire(line):
                data = line.split(b" :", 1)[1].decode("ascii")
                assert data.startswith("!$~ENC@#")
                raw = base64.b85decode(data[8:])
                return AES.new(key, AES.MODE_GCM, nonce=raw[:16]).decrypt_and_verify(
                    raw[32:], raw[16:32]).decode("utf-8")

            def encrypt_wire(text):
                cipher = AES.new(key, AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(text.encode("utf-8"))
                return "!$~ENC@#" + base64.b85encode(cipher.nonce + tag + ciphertext).decode("ascii")

            # A reciprocal encrypted message tests Cryptio's incoming OnChanMsg.
            welcome = f"ACK:IRCnet:{os.environ['GITHUB_RUN_ID'][-5:]}"
            receiver.send(f"PRIVMSG {CHANNEL} :{encrypt_wire(welcome)}")
            incoming = client.read_until(
                lambda line: line.startswith(b":" + recipient.encode() + b"!")
                and b" PRIVMSG " + CHANNEL.encode() + b" :" + welcome.encode() in line, 25)
            assert welcome.encode() in incoming
            print("Peer -> Cryptio: public channel decryption verified", flush=True)

            sizes = sorted(set([max(1, predicted_max - 24),
                                predicted_max - 12, predicted_max - 6,
                                predicted_max - 3, predicted_max,
                                predicted_max + 1]))
            delivered = 0
            blocked = False
            for n in sizes:
                header = f"Cryptio IRCnet incremental test {n:03d}:"
                plaintext = header + "X" * (n - len(header))
                assert len(plaintext.encode("utf-8")) == n
                client.send(f"PRIVMSG {CHANNEL} :{plaintext}")
                if n > predicted_max:
                    error = client.read_until(lambda line: b"Error: Message too long" in line, 15)
                    print(f"Cryptio rejected {n} UTF-8 bytes: predicted {predicted_length(n)} IRC bytes", flush=True)
                    print("Module response:", error.decode(errors="replace")[:200], flush=True)
                    try:
                        receiver.read_until(from_sender, 4)
                    except AssertionError as exc:
                        if not str(exc).startswith("Timeout:"):
                            raise
                    else:
                        raise AssertionError("Rejected oversized channel message reached another client")
                    blocked = True
                    break

                wire_line = receiver.read_until(from_sender, 30)
                decrypted = decrypt_wire(wire_line)
                assert decrypted == plaintext, f"Message failed roundtrip at {n} bytes"
                actual = len(wire_line) + 2
                assert actual == predicted_length(n), f"Wire length mismatch at {n}: {actual}"
                assert actual <= 512
                print(f"Cryptio -> peer: {n} plaintext bytes, {actual} IRC bytes, AES-GCM OK", flush=True)
                delivered += 1

                # Each accepted public message receives a cryptographic reply.
                ack = f"ACK:{n}:{os.environ['GITHUB_RUN_ID'][-5:]}"
                receiver.send(f"PRIVMSG {CHANNEL} :{encrypt_wire(ack)}")
                client.read_until(
                    lambda line: line.startswith(b":" + recipient.encode() + b"!")
                    and b" PRIVMSG " + CHANNEL.encode() + b" :" + ack.encode() in line, 25)
                print(f"Peer -> Cryptio: channel ACK for {n} bytes decrypted", flush=True)
                time.sleep(4)  # avoid triggering IRCnet flood protection

            assert blocked and delivered >= 3, "No message-length error after incremental steps"
            assert predicted_length(sizes[-2]) <= 512 < predicted_length(sizes[-1])
            print("PUBLIC IRCNET INCREMENTAL CHANNEL TEST PASS:", delivered,
                  "received + decrypted, one oversized rejected, reciprocal ACKs confirmed", flush=True)
        finally:
            for client in clients:
                client.close()
            znc.terminate()
            try:
                znc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                znc.kill()
            fp.close()
            if __import__("sys").exc_info()[0]:
                log = work / "znc.log"
                print("ZNC diagnostic:", log.read_text(errors="replace")[-5000:], flush=True)


if __name__ == "__main__":
    main()
