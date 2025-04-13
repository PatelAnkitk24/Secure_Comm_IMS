import socket
import json
import getpass
import random
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from crypto_utils import *
from pow_utils import solve_proof
from base64 import b64encode
from Crypto.Random import get_random_bytes
import hashlib
import signal
import sys
import time
import _log
import listening_client as lc
from utils import *
import argparse
import psutil
from crypto_utils import *

s_c_session_key_SK = None
server_sock = None
logged_in_user = None
this_client_eph_pub = None
this_client_eph_priv = None
this_client_rsa_priv_cipher = None
this_client_rsa_pub_cipher = None
remote_client_dict = {"list": None}
remote_client_session_dict = {}

def gen_eph_rsa_keys():
    key = RSA.generate(4096)
    c_priv = key.export_key()
    c_pub = key.publickey().export_key()
    return c_priv, c_pub

def create_this_client_rsa_cipher():
    _log.logging.info(f"[✓] Creating This Client Ephemaral RSA resources")
    global this_client_eph_pub, this_client_eph_priv
    global this_client_rsa_priv_cipher, this_client_rsa_pub_cipher
    #Generate ephemeral RSA keys of client
    this_client_eph_priv, this_client_eph_pub = gen_eph_rsa_keys()
    this_client_rsa_priv_cipher = PKCS1_OAEP.new(RSA.import_key(this_client_eph_priv))
    this_client_rsa_pub_cipher = PKCS1_OAEP.new(RSA.import_key(this_client_eph_pub))

def decrypt_client_auth_aes_key(rsa_enc_aes_key):
    return this_client_rsa_priv_cipher.decrypt(rsa_enc_aes_key)

def show_c_list(c_dict:dict):
    for user in c_dict.values():
        print(f"Name: {user['username']:<13} IP: {user['ip']:<15} Port: {user['port']:<5}")
    
def get_user_from_remote_client_dict(name):
    for user in remote_client_dict["list"].values():
        if user['username'] == name:
            return user
    return None

def update_remote_client_dict(dict_):
    remote_client_dict["list"] = dict_

def get_list_from_server(server: socket.socket, session_key_SK):
    # Send List Command
    request = aes_encrypt(session_key_SK, json.dumps({"command": "list", "time": time.time()}).encode())
    send_tlv(server, LIST_FRAME_T, request)
    type_, msg = recv_tlv(server)
    if type_ == LIST_FRAME_T:
        response = json.loads(aes_decrypt(session_key_SK, msg).decode())
        # _log.logging.debug(f"User List From Server : \n{response}")
        return response
    if type_ == None:
        _log.logging.error(f"Error: Unexpected resposne from server with type {type_}")
        return None
    else:
        _log.logging.error(f"Error: Unexpected resposne from server with type {type_}")
        return None

def update_client_session_resources_against(dict_):
    to_remove = []

    # Find usernames in remote_client_session_dict that are not in dict_
    for user in remote_client_session_dict:
        if user not in dict_:
            to_remove.append(user['username'])

    # Remove them after iteration (safe removal)
    for username in to_remove:
        del remote_client_session_dict[username]
        print(f"[INFO] Removed stale client session for '{username}'")

def del_client_from_client_session_resources(u_name):
    del remote_client_session_dict[u_name]