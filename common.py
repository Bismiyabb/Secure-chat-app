"""Shared helpers: key handling and encrypted, length-prefixed message framing."""
import json
import os
import struct

from cryptography.fernet import Fernet

KEY_FILE = "secret.key"
HEADER = struct.Struct(">I")  # 4-byte big-endian length prefix
MAX_FRAME = 1_000_000  # reject absurdly large frames


def load_or_create_key(path=KEY_FILE):
    """Server calls this: reuse the key if it exists, otherwise generate one."""
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(Fernet.generate_key())
    with open(path, "rb") as f:
        return f.read().strip()


def load_key(path=KEY_FILE):
    """Client calls this: the key file must be copied from the server first."""
    with open(path, "rb") as f:
        return f.read().strip()


def send_message(sock, fernet, payload):
    """Encrypt a dict as JSON and send it with a length prefix."""
    token = fernet.encrypt(json.dumps(payload).encode("utf-8"))
    sock.sendall(HEADER.pack(len(token)) + token)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_message(sock, fernet):
    """Receive one frame, decrypt it and return the dict.

    Raises ConnectionError on disconnect, cryptography.fernet.InvalidToken
    if the message was not encrypted with our key.
    """
    (length,) = HEADER.unpack(_recv_exact(sock, HEADER.size))
    if length > MAX_FRAME:
        raise ConnectionError("frame too large")
    token = _recv_exact(sock, length)
    return json.loads(fernet.decrypt(token).decode("utf-8"))