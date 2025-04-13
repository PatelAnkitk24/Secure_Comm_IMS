
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
from crypto_utils import *
from utils import *
import traceback
from Crypto.Protocol.KDF import PBKDF2
import getpass
import logging
import pickle

user_db_record = [
    {
        "username": "alice",
        "salt": b"static_salt",
        "W": b'\xea\x87\xc1\xb426\xf2G3\x01\x01\xfd\xb6\x82)\x8a\xf3\x8c\xf6\x91\xd7:z\xd4{4\x89\xecv\xa2\xdf\xd4' #pass = 123, W = derive_password_key(password, b'static_salt') # W with len 32 byte
    },
    {
        "username": "bob",
        "salt": b"static_salt",
        "W": b'\\k\xf4\xb7\x02\xc7\xbd\t\x13]\xb6J\x84\x98\x0f\x9fx\xbe\xa5-M~\x94\x11x\xe5\\\xdbG\xb3\x1a\xeb' #pass = 1234, W = derive_password_key(password, b'static_salt') # W with len 32 byte
    },
    {
        "username": "martin",
        "salt": b"static_salt",
        "W": b'\xbe\xed%\xbfu\xfe\x9fk\x02k\xac\x9a\xb0P;\xa2S\xae\x81\xd9kd\xb4\xb0^\xf6\xcd\xeeY\xed\xa5\xe4' #pass = 4321, W = derive_password_key(password, b'static_salt') # W with len 32 byte
    }
]

PRIVATE_KEY_FILE = "server_private.pem.enc"
PUBLIC_KEY_FILE = "server_public.pem"
ENC_USER_DB_RECORD_FILE = "user_db_record.db"
salt = b'$32v3r$al1'

def get_key(password: str):
    return PBKDF2(password, salt, dkLen=32, count=100_000) 

def encrypt_user_db_record(password: str):
    key = get_key(password)
    enc_user_db_record = aes_encrypt(key, pickle.dumps(user_db_record))
    b64_enc_user_db_record = b64encode(enc_user_db_record).decode()
    return b64_enc_user_db_record

def encrypt_private_key(private_key_pem: bytes, password: str):
    key = get_key(password)
    enc_private_key_pem = aes_encrypt(key, private_key_pem)
    b64_enc_private_key_pem = b64encode(enc_private_key_pem).decode()
    return b64_enc_private_key_pem

def create_user_db_record(password: str):
    logging.info("[KEYGEN] Generating user_db_record file")
    try:
        with open(ENC_USER_DB_RECORD_FILE, "w") as priv_file:
            priv_file.write(encrypt_user_db_record(password))
            return user_db_record[:]
    except Exception as e:
        logging.error("[X] Failed to load or encrypt user_db_record_, Reason: %s", e)
        traceback.print_exc()
        exit(1)
    
    logging.info("[DB] User DB Record Saved ...")

def create_keys():
    global rsa_priv_cipher
    password = getpass.getpass("🔐 Enter password to unlock or generate RSA keys: ")
    logging.info("[KEYGEN] Generating RSA key pair...")
    key = RSA.generate(4096)
    private_key_pem = key.export_key()
    private_key = RSA.import_key(private_key_pem)
    rsa_priv_cipher = PKCS1_OAEP.new(private_key)
    encrypted = encrypt_private_key(private_key_pem, password)

    with open(PRIVATE_KEY_FILE, "w") as priv_file:
        priv_file.write(encrypted)
    with open(PUBLIC_KEY_FILE, "wb") as pub_file:
        pub_file.write(key.publickey().export_key())

    logging.info("[KEYGEN] Keys saved.")
    return key, password

#password: BostonCommon@24    
if __name__ == "__main__":
    key, password = create_keys()
    create_user_db_record(password)