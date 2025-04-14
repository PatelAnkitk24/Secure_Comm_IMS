import socket
import json
import threading
import os
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from crypto_utils import *
from pow_utils import generate_challenge, validate_proof
import time
import hashlib
import signal
import sys
import time
import _log
from utils import *
import client_resources
import traceback

lc_sock:socket.socket = None

def cleanup():
    global lc_sock
    _log.logging.info("[🧹] Cleaning up resources for listening client ...")
    if lc_sock != None :
        _log.logging.info("[🧹] Closing listening client Socket For Graceful Termination")
        lc_sock.close()

def remote_client_auth(conn, addr):
    try:
        '''
        receive remote client auth payload
        '''
        # Receive Remote client auth payload with username, time, challenge, aes_key
        type_, _remote_client_auth_payload  = recv_tlv(conn)
        if type_ != RC_AUTH_FRAME_T:
            _log.logging.error("Error: Not A Remote Client Auth Frame")
            conn.close()
            return None
        remote_client_auth_payload = json.loads(_remote_client_auth_payload.decode())
        if remote_client_auth_payload["type"] != "rc_auth":
            _log.logging.error("Error: expecting rc_auth type frame")
            conn.close()
            return None
        remote_client_auth_aes_key = client_resources.decrypt_client_auth_aes_key(b64decode(remote_client_auth_payload["rsa_enc_client_auth_aes_key"]))
        #_log.logging.debug(f"remote_client_auth_aes_key {remote_client_auth_aes_key}")
        received_remote_client_auth_sub_payload = json.loads(aes_decrypt(remote_client_auth_aes_key, b64decode(remote_client_auth_payload["aes_enc_client_auth_sub_payload"])).decode())
        if is_a_replay(received_remote_client_auth_sub_payload["time"]):
            _log.logging.error("Error: [REPLAY] Timestamp expired.")
            conn.close()
            return None
        remote_client_user_name = received_remote_client_auth_sub_payload["username"]
        
        c2c_session_key_SK = b64decode(received_remote_client_auth_sub_payload["SK"])
        enc_c1 = b64decode(received_remote_client_auth_sub_payload["enc_c1"])
        c1=json.loads(aes_decrypt(c2c_session_key_SK, enc_c1).decode())["c1"]
        _log.logging.info(f"[✓] Successfully reception of remote client auth payload from {remote_client_user_name}")
        
        '''
        Prepare this client auth payload
        '''
        remote_user_dict = client_resources.get_user_from_remote_client_dict(remote_client_user_name)
        if remote_user_dict == None:
            _log.logging.info(f"[✓] Unable to find userinfo for {remote_client_user_name}")
            conn.close()
            return None
        remote_client_rsa_pub_cipher = PKCS1_OAEP.new(RSA.import_key(b64decode(remote_user_dict['ephemeral_pub'])))

        this_client_auth_aes_key = get_random_bytes(32)
        enc_this_client_auth_aes_key = remote_client_rsa_pub_cipher.encrypt(this_client_auth_aes_key)
        # Prepare full RSA-AES-wrapped this client auth sub payload
        # Send encrypted PoW challenge and c1-1 response
        prefix, difficulty = generate_challenge()
        c1 = c1 - 1
        enc_c1_resp = aes_encrypt(c2c_session_key_SK, json.dumps({"c1_resp": c1}).encode())
        this_client_auth_sub_payload = {
            "username": client_resources.logged_in_user,
            "c1_check": b64encode(enc_c1_resp).decode(),
            "time": time.time(),
            "PoW": {
                "challenge": prefix,
                "difficulty": difficulty
            }
        }
        enc_this_client_auth_sub_payload = aes_encrypt(this_client_auth_aes_key, json.dumps(this_client_auth_sub_payload).encode())
        this_client_auth_payload = {
            "type": "rc_auth",
            "rsa_enc_client_auth_aes_key": b64encode(enc_this_client_auth_aes_key).decode(),
            "aes_enc_client_auth_sub_payload" : b64encode(enc_this_client_auth_sub_payload).decode()
        }
        send_tlv(conn, RC_AUTH_FRAME_T, json.dumps(this_client_auth_payload).encode())
        _log.logging.info(f"[✓] Successfully transmission of remote client's auth payload from {client_resources.logged_in_user} to {remote_client_user_name}")

        '''
        Verify remote client auth PoW-resp payload
        '''
        type_, _remote_client_auth_pow_payload  = recv_tlv(conn)
        if type_ != RC_AUTH_FRAME_T:
            _log.logging.error("Error: Not A Remote Client Auth Frame")
            conn.close()
            return None
        remote_client_auth_pow_payload = json.loads(_remote_client_auth_pow_payload.decode())
        if remote_client_auth_pow_payload["type"] != "rc_auth":
            _log.logging.error("Error: expecting rc_auth type frame")
            conn.close()
            return None
        remote_client_auth_aes_key = client_resources.decrypt_client_auth_aes_key(b64decode(remote_client_auth_pow_payload["rsa_enc_client_auth_aes_key"]))
        #_log.logging.debug(f"remote_client_auth_aes_key {remote_client_auth_aes_key}")
        received_remote_client_auth_sub_pow_resp_payload = json.loads(aes_decrypt(remote_client_auth_aes_key, b64decode(remote_client_auth_pow_payload["aes_enc_client_auth_sub_pow_resp_payload"])).decode())
        if is_a_replay(received_remote_client_auth_sub_pow_resp_payload["time"]):
            _log.logging.error("Error: [REPLAY] Timestamp expired.")
            conn.close()
            return None
        if remote_client_user_name != received_remote_client_auth_sub_pow_resp_payload["username"]:
            _log.logging.error("Error: remote_client usernmae mistmatch")
            conn.close()
        enc_PoW_Response = b64decode(received_remote_client_auth_sub_pow_resp_payload["PoW-Response"])
        nonce_data = json.loads(aes_decrypt(c2c_session_key_SK, enc_PoW_Response).decode())
        if not validate_proof(prefix, nonce_data.get("nonce"), difficulty):
            _log.logging.error("Error: Invalid PoW-Response")
            conn.close()
            return None
        _log.logging.info("[✓] Successfully Verification of Proof-Of-Work")
        _log.logging.info(f"[+] Authenticated {remote_client_user_name} and established secure session.")
        return 0, c2c_session_key_SK
    except Exception as e:
        _log.logging.error(f"[ERROR] {e}")
        traceback.print_exc()
        raise

def c2c_session(conn, c2c_session_key_SK):
    try:
        while True:
            type_, enc_payload  = recv_tlv(conn)
            if type_ != C2C_MSG_FRAME_T:
                _log.logging.error("Error: Not A Remote Client Message Frame")
                return None
            try:
                payload = json.loads(aes_decrypt(c2c_session_key_SK, enc_payload).decode())
            except Exception as e:
                _log.logging.error(f"[ERROR] {e}")
                continue
            if is_a_replay(payload["time"]):
                _log.logging.error("Error: [REPLAY] Timestamp expired.")
                continue
            _log.logging.info(f"Message: From {payload['username']}, msg: '{payload['msg']}'")
    except Exception as e:
        _log.logging.error(f"[ERROR] {e}")
        conn.close()

def handle_lc_client(conn: socket.socket, addr):
    try: 
        client_resources.update_remote_client_dict(client_resources.get_list_from_server(client_resources.server_sock, client_resources.s_c_session_key_SK))
        response, c2c_session_key_SK = remote_client_auth(conn, addr)
        if response == 0:
            c2c_session(conn, c2c_session_key_SK)
        else:
            _log.logging.error(f"Error: Login Failed from {addr}")
    except Exception as e:
        _log.logging.error(f"[ERROR] {e}")
        traceback.print_exc()
        conn.close()
        return
    finally:
        conn.close()
        return 

def listening_client(ip):
    try:
        global lc_sock
        lc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lc_sock.bind((ip, u_config_["client_port"]))
        lc_sock.listen()
        _log.logging.info(f"[listening Client] Listening on IP: {ip} and Port {u_config_['client_port']} ...")
        while True:
            conn, addr = lc_sock.accept()
            threading.Thread(target=handle_lc_client, args=(conn, addr), daemon=True).start()
    except Exception as e:
        _log.logging.error(f"[ERROR] {e}")
        _log.logging.error(f"[ERROR] Failed to start client listening server")
        traceback.print_exc()
        cleanup()
        _log.logging.error("🔪 Sending SIGINT (like Ctrl+C)...")
        os.kill(os.getpid(), signal.SIGINT)


def start_listening_client(ip):
    threading.Thread(target=listening_client, args=(ip,), daemon=True).start()