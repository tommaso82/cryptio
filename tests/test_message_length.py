"""Regression tests for Cryptio's IRC line length checks."""
import sys
import types
import unittest

# Simulate the ZNC API; encryption uses the real PyCryptodome dependency.
znc = types.ModuleType("znc")
znc.Module = type("Module", (), {})
znc.CModInfo = type("CModInfo", (), {"NetworkModule": 1})
znc.CONTINUE = 0
znc.HALT = 1
sys.modules["znc"] = znc

from cryptio import cryptio


class Nick:
    def __init__(self, nick="Tom", ident="user", host="example.org"):
        self.nick = nick
        self.ident = ident
        self.host = host

    def GetNick(self):
        return self.nick

    def GetIdent(self):
        return self.ident

    def GetHost(self):
        return self.host

    def GetNickMask(self):
        return f"{self.nick}!{self.ident}@{self.host}"


class Network:
    def __init__(self, nick):
        self.nick = nick

    def GetIRCNick(self):
        return self.nick


class Message:
    def __init__(self, text):
        self.s = text


class MessageLengthTests(unittest.TestCase):
    def setUp(self):
        self.module = cryptio()
        self.module.aes_key = b"0" * 32
        self.nick = Nick()
        self.module.GetNetwork = lambda: Network(self.nick)
        self.logs = []
        self.module.PutModule = self.logs.append

    def check_message(self, text, expected, target="#canale"):
        message = Message(text)
        result = self.module.OnUserMsg(target, message)
        self.assertEqual(result, expected)
        if expected == znc.CONTINUE:
            self.assertLessEqual(self.module.irc_message_length(target, message.s), 512)
            self.assertEqual(self.module.decrypt_message(message.s[len(self.module.identifier):]), text)
        else:
            self.assertEqual(message.s, text)
        return message

    def test_ascii_exact_boundary(self):
        self.check_message("A" * 337, znc.CONTINUE)
        self.check_message("A" * 338, znc.CONTINUE)
        self.check_message("A" * 339, znc.HALT)

    def test_utf8_byte_length_not_character_length(self):
        self.check_message("é" * 169, znc.CONTINUE)
        self.check_message("é" * 170, znc.HALT)
        self.check_message("🙂" * 84, znc.CONTINUE)
        self.check_message("🙂" * 85, znc.HALT)

    def test_long_target_and_hostmask_reduce_capacity(self):
        self.check_message("A" * 338, znc.HALT, target="#" + "x" * 60)
        self.nick.host = "very-long-hostname.example.net"
        self.check_message("A" * 338, znc.HALT)

    def test_unencrypted_messages_use_same_limit(self):
        self.module.aes_key = None
        self.check_message("A" * 400, znc.CONTINUE)
        self.check_message("A" * 480, znc.HALT)

    def test_unknown_hostmask_blocks_instead_of_guessing(self):
        self.nick.host = ""
        self.check_message("hello", znc.HALT)
        self.assertTrue(any("hostmask unavailable" in msg for msg in self.logs))

    def test_rejected_messages_do_not_overwrite_original(self):
        text = "🙂" * 100
        self.check_message(text, znc.HALT)
        self.assertTrue(any("too long" in msg for msg in self.logs))


if __name__ == "__main__":
    unittest.main()
