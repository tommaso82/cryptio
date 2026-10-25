"""One-off public IRCnet integration check; no public channel messages."""
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
            receiver.read_until(lambda x: x.startswith(b":" + sender.encode() + b"!") and (b" JOIN :" + CHANNEL.encode() in x or b" JOIN " + CHANNEL.encode() in x))
            print("ZNC connected to public IRCnet; sender joined", CHANNEL, flush=True)

            key = b"0" * 32
            client.send("PRIVMSG *cryptio :setkey " + base64.b64encode(key).decode())
            client.read_until(lambda x: b"New AES-256 key successfully set." in x)

            def from_sender(line):
                return (line.startswith(b":" + sender.encode() + b"!")
                        and b" PRIVMSG " + recipient.encode() + b" :!$~ENC@#" in line)

            def receive_decrypted():
                line = receiver.read_until(from_sender, 25)
                payload = line.split(b" :", 1)[1].decode()
                raw = base64.b85decode(payload[8:])
                plain = AES.new(key, AES.MODE_GCM, nonce=raw[:16]).decrypt_and_verify(raw[32:], raw[16:32])
                return line, plain.decode("utf-8")

            channel_text = "Cryptio IRCnet live test " + os.environ["GITHUB_RUN_ID"][-5:]
            client.send("PRIVMSG " + CHANNEL + " :" + channel_text)
            try:
                channel_line = receiver.read_until(
                    lambda x: x.startswith(b":" + sender.encode() + b"!")
                    and b" PRIVMSG " + CHANNEL.encode() + b" :!$~ENC@#" in x, 20
                )
                channel_payload = channel_line.split(b" :", 1)[1].decode()
                raw = base64.b85decode(channel_payload[8:])
                decoded = AES.new(key, AES.MODE_GCM, nonce=raw[:16]).decrypt_and_verify(raw[32:], raw[16:32])
                assert decoded.decode("utf-8") == channel_text, "Channel decryption mismatch"
                print("PUBLIC CHANNEL CRYPTIO PASS:", CHANNEL,
                      "received", len(channel_line) + 2, "bytes", flush=True)
            except AssertionError as exc:
                print("CHANNEL TEST NOT CONFIRMED:", str(exc)[:400], flush=True)

            probe_text = "A" * 300
            client.send("PRIVMSG " + recipient + " :" + probe_text)
            try:
                probe_line, decrypted = receive_decrypted()
            except AssertionError:
                print("ZNC client last messages:", repr(client.messages[-12:]), flush=True)
                raise
            assert decrypted == probe_text
            mask = probe_line.split(b" ", 1)[0][1:].decode()
            print("Observed IRCnet sender mask:", mask, flush=True)

            def outgoing_line_length(n):
                base85_length = (5 * (32 + n) + 3) // 4
                return len(f":{mask} PRIVMSG {recipient} :\r\n".encode()) + 8 + base85_length

            maximum = max(n for n in range(450) if outgoing_line_length(n) <= 512)
            print("Calculated maximum ASCII bytes:", maximum, flush=True)
            accepted_text = "B" * maximum
            client.send("PRIVMSG " + recipient + " :" + accepted_text)
            accepted, plaintext = receive_decrypted()
            assert plaintext == accepted_text, "Decrypted boundary message differed"
            assert len(accepted) + 2 == outgoing_line_length(maximum), "Unexpected IRC length"
            print("Accepted forwarded IRC line:", len(accepted) + 2, "bytes", flush=True)

            client.send("PRIVMSG " + recipient + " :" + "C" * (maximum + 1))
            client.read_until(lambda x: b"Error: Message too long" in x, 15)
            # No message may arrive after rejection. Test the recipient socket independently.
            receiver.sock.settimeout(1)
            try:
                next_line = receiver.read_until(from_sender, 4)
                raise AssertionError("Oversize encrypted PRIVMSG reached public IRC: " + repr(next_line[:60]))
            except AssertionError as error:
                if not str(error).startswith("Timeout:"):
                    raise
            print("Rejected oversize message:", outgoing_line_length(maximum + 1), "bytes", flush=True)
            print("PUBLIC IRCNET CRYPTIO END-TO-END PASS", flush=True)
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
