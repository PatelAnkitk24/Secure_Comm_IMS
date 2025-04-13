
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from crypto_utils import *
from pow_utils import generate_challenge, validate_proof
import time
import _log
from utils import *
import traceback
from Crypto.Protocol.KDF import PBKDF2
import getpass
import logging
import pickle
import sys


PRIVATE_KEY_FILE = "server_private.pem.enc"
PUBLIC_KEY_FILE = "server_public.pem"
ENC_USER_DB_RECORD_FILE = "user_db_record.db"
salt = b'$32v3r$al1'

rsa_priv_cipher = None

def decrypt_client_login_aes_key(rsa_enc_aes_key):
    return rsa_priv_cipher.decrypt(rsa_enc_aes_key)

def get_key(password: str):
    return PBKDF2(password, salt, dkLen=32, count=100_000) 

def decrypt_user_db_record(password: str, b64_enc_user_db_record):
    key = get_key(password)
    enc_user_db_record = b64decode(b64_enc_user_db_record)
    user_db_record_ = pickle.loads(aes_decrypt(key, enc_user_db_record))
    return user_db_record_

def decrypt_private_key(b64_enc_private_key_pem: bytes, password: str):
    key = get_key(password)
    enc_private_key_pem = b64decode(b64_enc_private_key_pem)
    private_key_pem = aes_decrypt(key, enc_private_key_pem)
    return private_key_pem

def load_user_db_record(password: str):
    try:
        with open(ENC_USER_DB_RECORD_FILE, "r") as f:
            f_data = f.read()
        logging.info("[✓] User DB Record loaded successfully.")
        return decrypt_user_db_record(password, f_data)
    except Exception as e:
        logging.error("[X] Failed to load or decrypt user_db_record_, Reason: %s", e)
        traceback.print_exc()
        sys.exit(1)
    

#password: BostonCommon@24
def load_keys():
    global rsa_priv_cipher
    password = getpass.getpass("🔐 Enter password to unlock or generate RSA keys: ")

    try:
        with open(PRIVATE_KEY_FILE, "r") as f:
            encrypted_data = f.read()
        private_key_pem = decrypt_private_key(encrypted_data, password)
        private_key = RSA.import_key(private_key_pem)
        rsa_priv_cipher = PKCS1_OAEP.new(private_key)
        logging.info("[✓] Private key loaded successfully.")
        return private_key, password
    except Exception as e:
        logging.error("[X] Failed to load or decrypt private key. Reason: %s", e)
        traceback.print_exc()
        exit(1)
    
if __name__ == "__main__":
    key, password = load_keys()
    load_user_db_record(password)