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


LOGIN_FRAME_T = 1
LIST_FRAME_T = 2
RC_AUTH_FRAME_T = 3
LOGIN_ERR_MSG_FRAME_T = 4
C2C_MSG_FRAME_T = 5
LOGOUT_FRAME_1_T = 6
LOGOUT_FRAME_2_T = 7
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

def load_config():
    with open("config.json") as f:
        return json.load(f)

def is_a_replay(time_):
    return not is_not_a_replay(time_)

def is_not_a_replay(time_):
    if abs(time.time() -time_) > 10:
        print("Error: [REPLAY] Timestamp expired.")
        return False
    else:
        return True
    
u_config_ = load_config()
