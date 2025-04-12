import os
import hashlib
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes  # ✅ Required
import json
import struct
import socket
import time
import _log

AES_KEY_SIZE = 32  # AES-256
RSA_KEY_SIZE = 4096  # RSA-4096 for stronger security
AES_IV_SIZE = 12  # IV size for AES-GCM
TAG_SIZE = 16  # Authentication tag size
RSA_SIGNATURE_SIZE = RSA_KEY_SIZE // 8  # Signature size for RSA-4096


def load_config():
    with open("config.json") as f:
        return json.load(f)
    
def derive_password_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode())

def generate_dh_parameters():
    config = load_config()
    private = int.from_bytes(os.urandom(32), 'big')
    g = int(config["g"])
    p = int(config["p"])
    public = pow(g, private, p)
    return private, public, p, g

def compute_shared_secret(their_pub, my_priv, p):
    return pow(their_pub, my_priv, p)

def aes_encrypt(key: bytes, plaintext: bytes):
    iv = get_random_bytes(AES_IV_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv + tag + ciphertext

def aes_decrypt(key: bytes, data: bytes):
    iv, tag, ciphertext = data[:AES_IV_SIZE], data[AES_IV_SIZE:AES_IV_SIZE+TAG_SIZE], data[AES_IV_SIZE+TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

LOGIN_FRAME_T = 1
LIST_FRAME_T = 2
def send_tlv(sock: socket.socket, msg_type: int, value: bytes):
    """
    Sends a TLV frame: 1-byte type, 4-byte length, followed by value.
    Guarantees all bytes are sent.
    """
    header = struct.pack('>BI', msg_type, len(value))  # B=1 byte, I=4-byte big-endian int
    full_msg = header + value
    sock.sendall(full_msg)

# def prepare_tlv(sock: socket.socket, msg_type: int, value: bytes):
#     """
#     Sends a TLV frame: 1-byte type, 4-byte length, followed by value.
#     Guarantees all bytes are sent.
#     """
#     header = struct.pack('>BI', msg_type, len(value))  # B=1 byte, I=4-byte big-endian int
#     full_msg = header + value
#     return full_msg


# --- TLV Receive API ---

def recv_tlv(sock: socket.socket):
    """
    Receives a TLV frame from socket.
    First reads 5 bytes (type + length), then reads full value.
    Returns: (type, value)
    """
    # Read 5 bytes: 1 for type, 4 for length
    header = _recvall(sock, 5)
    if not header:
        return None, None

    msg_type, length = struct.unpack('>BI', header)

    # Now read value
    value = _recvall(sock, length)
    if value is None:
        #raise ConnectionError("Failed to read value for TLV message.")
        return 0, 0

    return msg_type, value


def _recvall(sock: socket.socket, n: int):
    """Receives exactly n bytes or returns None if connection is closed."""
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None  # Connection closed
        data.extend(chunk)
    return bytes(data)

def is_a_replay(time_):
    return not is_not_a_replay(time_)

def is_not_a_replay(time_):
    if abs(time.time() - time_) > 10:
        print("Error: [REPLAY] Timestamp expired.")
        return False
    else:
        return True
