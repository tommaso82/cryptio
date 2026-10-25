"""Integration smoke test for the actual ZNC/ModPython IRC message path.

Requires znc, znc-python, ngircd, and system python3-pycryptodome.
Runs only on disposable CI runners.
"""
import base64
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parent.parent
SERVER_PORT, ZNC_PORT = 17671, 17672


def wait_port(port, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 1):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"Port {port} did not open")


class Client:
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), 5)
        self.sock.settimeout(0.2)
        self.buffer = b""
        self.history = []

    def send(self, line):
        self.sock.sendall((line + "\r\n").encode("utf-8"))

    def find(self, predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.buffer += self.sock.recv(8192)
            except socket.timeout:
                continue
            while b"\r\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\r\n", 1)
                self.history.append(line)
                if predicate(line):
                    return line
        return None

    def close(self):
        self.sock.close()


def main():
    with tempfile.TemporaryDirectory(prefix="cryptio-znc-") as directory:
        base = Path(directory)
        ngconf = base / "ngircd.conf"
        ngconf.write_text(f"""[Global]
Name = irc.test.local
Info = Cryptio integration
Listen = 127.0.0.1
Ports = {SERVER_PORT}
[Options]
DNS = no
Ident = no
""")
        zhome = base / "znc"
        (zhome / "configs").mkdir(parents=True)
        (zhome / "modules").mkdir()
        shutil.copy2(REPO / "cryptio.py", zhome / "modules" / "cryptio.py")
        (zhome / "configs" / "znc.conf").write_text(f"""Version = 1.9.0
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
    Nick = Tom
    Ident = user
    RealName = Test
    <Pass password>
        Method = sha256
        Hash = 49396054dc8263b573d11c9c01e43f89ee772f6dc89b3c630e6dffa9acea4a3e
        Salt = ovexwSL50cC?jE2eCM?x
    </Pass>
    <Network local>
        Server = 127.0.0.1 {SERVER_PORT}
        LoadModule = cryptio
    </Network>
</User>
""")
        logs = []
        processes = []
        clients = []
        try:
            for args in (
                ["ngircd", "-n", "-f", str(ngconf)],
                ["znc", "-f", "-d", str(zhome)],
            ):
                logfile = (base / ("ngircd.log" if args[0] == "ngircd" else "znc.log")).open("wb")
                logs.append(logfile)
                processes.append(subprocess.Popen(args, stdout=logfile, stderr=subprocess.STDOUT))
                wait_port(SERVER_PORT if args[0] == "ngircd" else ZNC_PORT)

            eve = Client(SERVER_PORT)
            clients.append(eve)
            eve.send("NICK Eve")
            eve.send("USER eve 0 * :Receiver")
            assert eve.find(lambda line: b" 001 Eve " in line), "Eve did not register"
            eve.send("JOIN #canale")
            assert eve.find(lambda line: b" JOIN " in line and b"#canale" in line), "Eve did not join"

            tom = Client(ZNC_PORT)
            clients.append(tom)
            tom.send("PASS testuser/local:password")
            tom.send("NICK TomClient")
            tom.send("USER testuser 0 * :Sender")
            assert tom.find(lambda line: b" 001 " in line), "ZNC client authentication failed"
            tom.send("JOIN #canale")
            assert eve.find(lambda line: b"Tom!" in line and b" JOIN " in line), "ZNC not connected to IRC"

            key = base64.b64encode(b"0" * 32).decode()
            tom.send(f"PRIVMSG *cryptio :setkey {key}")
            assert tom.find(lambda line: b"AES-256 key successfully set" in line), "Cryptio did not load/set key"

            def wait_msg(timeout=12):
                return eve.find(lambda line: b" PRIVMSG #canale :!$~ENC@#" in line, timeout)

            tom.send("PRIVMSG #canale :" + "A" * 300)
            probe = wait_msg()
            assert probe, "Probe encrypted message was not delivered"
            prefix = probe.split(b" ", 1)[0].decode()
            mask = prefix.lstrip(":")
            print(f"Forwarded hostmask: {mask}")
            assert "!" in mask and "@" in mask

            def message_size(n):
                payload = 8 + (5 * (32 + n) + 3) // 4
                return len(f":{mask} PRIVMSG #canale :\r\n".encode()) + payload

            maximum = max(n for n in range(500) if message_size(n) <= 512)
            assert message_size(maximum) <= 512 < message_size(maximum + 1), "Unexpected formula limit"
            print(f"Computed safe limit: {maximum} ASCII bytes")
            tom.send("PRIVMSG #canale :" + "B" * maximum)
            accepted = wait_msg()
            assert accepted and len(accepted) + 2 == message_size(maximum), "Boundary message not delivered intact"
            tom.send("PRIVMSG #canale :" + "C" * (maximum + 1))
            rejected = wait_msg(timeout=4)
            assert rejected is None, "Oversize message reached IRC server"
            assert tom.find(lambda line: b"Message too long" in line, timeout=4), "Expected ZNC module error"
            print(f"LIVE ZNC INTEGRATION: PASS ({message_size(maximum)} bytes accepted, {message_size(maximum + 1)} blocked)")
        finally:
            for client in clients:
                client.close()
            for proc in reversed(processes):
                proc.terminate()
            for proc in processes:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            for fp in logs:
                fp.close()
            if __import__("sys").exc_info()[0]:
                for name in ("znc.log", "ngircd.log"):
                    logpath = base / name
                    if logpath.exists():
                        print(f"==== {name} ====\n" + logpath.read_text(errors="replace")[-8000:])


if __name__ == "__main__":
    main()
