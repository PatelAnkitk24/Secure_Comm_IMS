import os
import hashlib
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes  # ✅ Required
import json

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
