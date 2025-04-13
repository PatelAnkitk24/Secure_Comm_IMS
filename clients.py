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
import client_resources
import traceback

live_client_session = {}


def get_user_pass_as_W():
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    # Derive W from password
    W = derive_password_key(password, b'static_salt') # W with len 32 byte
    _log.logging.debug(f"W {W}")
    # To loose password to avoid password leak 
    password = None
    return username,W

def load_server_server_pub_key():
    # Load server public RSA key
    with open("server_public.pem", "rb") as f:
        server_pub_key = RSA.import_key(f.read())
    server_rsa_pub_cipher = PKCS1_OAEP.new(server_pub_key)
    return server_rsa_pub_cipher

def client_login(ip):
    username,W = get_user_pass_as_W()    
    server_rsa_pub_cipher = load_server_server_pub_key()

    # Generate ephemeral DH keys
    a, g_a, p, g = generate_dh_parameters()
    # Encrypt g^a mod p using W
    encrypted_ga = aes_encrypt(W, str(g_a).encode())
    b64_enc_ga = b64encode(encrypted_ga).decode()

    # 1. Generate AES key for login
    client_login_aes_key = get_random_bytes(32)
    enc_client_login_aes_key = server_rsa_pub_cipher.encrypt(client_login_aes_key)
    # Prepare full RSA-AES-wrapped login payload
    client_login_sub_payload = {
        "username": username,
        "Wga": b64_enc_ga,
        "pKc": b64encode(client_resources.this_client_eph_pub).decode(),
        "c_port": u_config_["client_port"],
        "time": time.time()
    }
    enc_client_login_sub_payload = aes_encrypt(client_login_aes_key, json.dumps(client_login_sub_payload).encode())
    client_login_payload = {
        "type": "login",
        "rsa_enc_client_login_aes_key": b64encode(enc_client_login_aes_key).decode(),
        "aes_enc_client_login_sub_payload" : b64encode(enc_client_login_sub_payload).decode()
    }

    # Connect to server and send RSA-wrapped login
    client_resources.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_resources.server_sock.settimeout(5)  # Optional: set a timeout for connection attempt
    client_resources.server_sock.bind((ip, 0)) # 0 means ephemeral port

    try:
        client_resources.server_sock.connect((u_config_["server_ip"], u_config_["server_port"]))
        _log.logging.info("[✓] Connected to server.")
    except socket.timeout:
        _log.logging.error("⏱ Connection attempt timed out.")
    except ConnectionRefusedError:
        _log.logging.error("[X] Connection refused — is the server running?")
    except OSError as e:
        _log.logging.error(f"[!] OS error occurred: {e}")
        cleanup()

    send_tlv(client_resources.server_sock, LOGIN_FRAME_T, json.dumps(client_login_payload).encode())
    # client_resources.server_sock.send(json.dumps(client_login_payload).encode())
    _log.logging.info("[✓] Successfully transmission of client's login payload")
    #exit()

    '''
    Second Login transaction from server to client
    '''
    # c_rsa_priv_key = RSA.import_key(c_rsa_priv)
    # client_rsa_priv_cipher = PKCS1_OAEP.new(c_rsa_priv_key)

    # Receive encrypted W{g^b mod p} and server pub key
    type_, received_login_payload  = recv_tlv(client_resources.server_sock)
    if type_ == LOGIN_ERR_MSG_FRAME_T:
        _log.logging.error(f"[X] Login Failed With Message From Server : {received_login_payload.decode()}")
        cleanup()
    server_login_payload = json.loads(received_login_payload.decode())
    server_login_sub_payload = {}
    try:
        if server_login_payload["type"] == "login":
            _log.logging.info("[✓] Successfully reception of server's login payload")
            '''
            Perfect Forward Secrecy
            '''
            server_login_aes_key = client_resources.this_client_rsa_priv_cipher.decrypt(b64decode(server_login_payload["rsa_enc_server_login_aes_key"]))
            #_log.logging.debug(f"server_login_aes_key {server_login_aes_key}")
            received_server_login_sub_payload = json.loads(aes_decrypt(server_login_aes_key, b64decode(server_login_payload["aes_enc_server_login_sub_payload"])).decode())

            enc_gb = b64decode(received_server_login_sub_payload["Wgb"])
            server_login_sub_payload["gb"] = int(aes_decrypt(W,enc_gb))
            dh_shared_K = compute_shared_secret(server_login_sub_payload["gb"], a, p)
            dh_shared_K_bytes = dh_shared_K.to_bytes((dh_shared_K.bit_length() + 7) // 8, 'big')
            #_log.logging.debug(f"Shared key bit length: {dh_shared_K.bit_length()}")
            dh_shared_K_bytes = hashlib.sha256(dh_shared_K.to_bytes((dh_shared_K.bit_length() + 7) // 8, 'big')).digest()
            if (dh_shared_K_bytes):
                _log.logging.info("[✓] Shared DH secret K established.")
            #_log.logging.debug(f"dh_shared_k_bytes {dh_shared_K_bytes}")
            a = g_a = 0 # Forget private and public DH keys for PFS
            
            server_login_sub_payload["time"] = received_server_login_sub_payload["time"]
            if is_a_replay(server_login_sub_payload["time"]):
                _log.logging.error("Error: [REPLAY] Timestamp expired.")
                cleanup()

            '''
            Transaction From server to client for Proof Of Work
            '''
            # Receive encrypted challenge from server (using K)
            type_, received_login_payload  = recv_tlv(client_resources.server_sock)
            if type_ == LOGIN_ERR_MSG_FRAME_T:
                _log.logging.error(f"[X] Login Failed With Message From Server : {received_login_payload.decode()}")
                cleanup()
            if type_ != LOGIN_FRAME_T:
                _log.logging.error("Error: Not A Login Frame")
                cleanup()
            challenge_json = json.loads(aes_decrypt(dh_shared_K_bytes, received_login_payload).decode())
            #_log.logging.debug(f"challenge_json {challenge_json}")
            #_log.logging.debug(f"[CHALLENGE] Solve {challenge_json['challenge']} with difficulty {challenge_json['difficulty']}")
           
            '''
            Transaction From client to server with Proof Of Work response
            '''
            # Solve and respond with encrypted proof
            nonce = solve_proof(challenge_json["challenge"], challenge_json["difficulty"])
            enc_nonce = aes_encrypt(dh_shared_K_bytes, json.dumps({"nonce": nonce}).encode())
            send_tlv(client_resources.server_sock, LOGIN_FRAME_T, enc_nonce)
            _log.logging.info("[✓] Successfully Transmission of Proof-Of-Work")

            type_, received_login_payload  = recv_tlv(client_resources.server_sock)
            if type_ == LOGIN_ERR_MSG_FRAME_T:
                _log.logging.error(f"[X] Login Failed With Message From Server : {received_login_payload.decode()}")
                cleanup()
            if type_ != LOGIN_FRAME_T:
                _log.logging.error("Error: Not A Login Frame")
                cleanup()
            _log.logging.info(f"[✓] Message From Server : {aes_decrypt(dh_shared_K_bytes, received_login_payload).decode()}")

            '''
            Transaction form client to server Session Key Exchange
            ''' 
            # Step 1: Generate session key SK and random c3
            session_key_SK = get_random_bytes(32)
            c3 = random.randint(100, 999)
            #_log.logging.debug(f"c3 {c3}")
            encrypted_c3 = aes_encrypt(session_key_SK, json.dumps({"c3": c3}).encode())
            msg1 = {
                "SK": b64encode(session_key_SK).decode(),
                "enc_c3": b64encode(encrypted_c3).decode()
            }
            enc_msg1 = aes_encrypt(dh_shared_K_bytes, json.dumps(msg1).encode())
            #_log.logging.debug(f"enc_msg1 {enc_msg1}")
            send_tlv(client_resources.server_sock, LOGIN_FRAME_T, enc_msg1)

            '''
            Transaction form server to client for Session Key Exchange
            '''
            # Step 2: Receive and decrypt server response
            type_, received_login_payload  = recv_tlv(client_resources.server_sock)
            if type_ == LOGIN_ERR_MSG_FRAME_T:
                _log.logging.error(f"[X] Login Failed With Message From Server : {received_login_payload.decode()}")
                cleanup()
            if type_ != LOGIN_FRAME_T:
                _log.logging.error("Error: Not A Login Frame")
                cleanup()
            msg2 = json.loads(aes_decrypt(dh_shared_K_bytes, received_login_payload).decode())
            enc_response = b64decode(msg2["enc_response"])
            response = json.loads(aes_decrypt(session_key_SK, enc_response).decode())
    
            if response["c3_check"] != c3 - 1:
                _log.logging.error("[X] c3 verification failed.")
                cleanup()
            c4 = response["c4"]

            '''
            Transaction form client to server for Session Key Exchange
            '''
            # Step 3: Send SK_check = c4 - 1 encrypted with SK, then with shared_K
            enc_msg3 = aes_encrypt(session_key_SK, json.dumps({"c4_check": c4 - 1}).encode())
            final_msg = aes_encrypt(dh_shared_K_bytes, json.dumps({"enc_c4_check": b64encode(enc_msg3).decode()}).encode())
            send_tlv(client_resources.server_sock, LOGIN_FRAME_T, final_msg)

            type_, received_login_payload  = recv_tlv(client_resources.server_sock)
            if type_ == LOGIN_ERR_MSG_FRAME_T:
                _log.logging.error(f"[X] Login Failed With Message From Server : {received_login_payload.decode()}")
                cleanup()
            if type_ != LOGIN_FRAME_T:
                _log.logging.error("Error: Not A Login Frame")
                cleanup()
            _log.logging.info(f"[✓] Login Sucess With Message From Server : {aes_decrypt(session_key_SK, received_login_payload).decode()}")
            _log.logging.info(f"[+] Final session key established: {session_key_SK.hex()}")
            client_resources.logged_in_user = username
            return client_resources.server_sock, session_key_SK
        else:
            client_resources.server_sock.send(b"Error: expecting login type frame from server")
            cleanup()
    except Exception as e:
        _log.logging.error(f"[ERROR] {e}")
        traceback.print_exc()
        raise
    

def get_service(server: socket.socket, session_key_SK, command):
    if command == "list":
        return client_resources.get_list_from_server(server, session_key_SK)
    else:
        return None

def cleanup():
    _log.logging.info("[🧹] Cleaning up resources...")
    if client_resources.server_sock != None :
        _log.logging.info("[🧹] Closing Server Socket For Graceful Termination")
        client_resources.server_sock.close()
        time.sleep(1)
    lc.cleanup()
    # Close sockets, save files, etc.
    sys.exit(0)

def signal_signint_handler(sig, frame):
    _log.logging.info("🔴 Caught Ctrl+C (SIGINT)")
    cleanup()

def connect_to_remote_user(user,c_ip):
    #TODO: is this live_client_session required?
    global live_client_session

    pKc = b64decode(user['ephemeral_pub'])
    rc_ip = user['ip']
    rc_port = user['port']
    remote_user_name = user['username']
    
    '''
    Send remote user auth payload
    '''    
    remote_client_rsa_pub_cipher = PKCS1_OAEP.new(RSA.import_key(pKc))

    this_client_auth_aes_key = get_random_bytes(32)
    c2c_session_key_SK = get_random_bytes(32)
    enc_this_client_auth_aes_key = remote_client_rsa_pub_cipher.encrypt(this_client_auth_aes_key)
    # Prepare full RSA-AES-wrapped remote client auth sub payload
    c1 = random.randint(100, 999)
    enc_c1 = aes_encrypt(c2c_session_key_SK, json.dumps({"c1": c1}).encode())
    this_client_auth_sub_payload = {
        "username": client_resources.logged_in_user,
        "SK": b64encode(c2c_session_key_SK).decode(),
        "enc_c1": b64encode(enc_c1).decode(),
        "time": time.time()
    }
    enc_this_client_auth_sub_payload = aes_encrypt(this_client_auth_aes_key, json.dumps(this_client_auth_sub_payload).encode())
    this_client_auth_payload = {
        "type": "rc_auth",
        "rsa_enc_client_auth_aes_key": b64encode(enc_this_client_auth_aes_key).decode(),
        "aes_enc_client_auth_sub_payload" : b64encode(enc_this_client_auth_sub_payload).decode()
    }

    # Connect to server and send RSA-wrapped login
    remote_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_client_sock.settimeout(5)  # Optional: set a timeout for connection attempt
    remote_client_sock.bind((c_ip, 0)) # 0 means ephemeral port

    # TODO: decide whether to close remote_client_sock in below exception
    try:
        remote_client_sock.connect((rc_ip, rc_port))
        _log.logging.info(f"[✓] Connected to remote client with IP {rc_ip}, Port {rc_port}.")
    except socket.timeout:
        _log.logging.error("⏱ Connection attempt timed out.")
    except ConnectionRefusedError:
        _log.logging.error(f"[X] Connection refused by user {remote_user_name} on IP {rc_ip} Port {rc_port} — is the server running?")
    except OSError as e:
        _log.logging.error(f"[!] OS error occurred: {e}")
   # remote_client_cleanup(name)

    send_tlv(remote_client_sock, RC_AUTH_FRAME_T, json.dumps(this_client_auth_payload).encode())

    # client_resources.server_sock.send(json.dumps(remote_client_login_payload).encode())
    _log.logging.info(f"[✓] Successfully transmission of remote client's auth payload from {client_resources.logged_in_user} to {remote_user_name}")

    '''
    Receive remote user auth payload
    '''
    type_, _remote_client_auth_payload  = recv_tlv(remote_client_sock)
    if type_ != RC_AUTH_FRAME_T:
        _log.logging.error("Error: Not Remote Client Auth Frame")
        remote_client_sock.close()
        return None
    remote_client_auth_payload = json.loads(_remote_client_auth_payload.decode())
    
    if remote_client_auth_payload["type"] != "rc_auth":
        _log.logging.error("Error: expecting rc_auth type frame")
        remote_client_sock.close()
        return None
    remote_client_auth_aes_key = client_resources.decrypt_client_auth_aes_key(b64decode(remote_client_auth_payload["rsa_enc_client_auth_aes_key"]))
    #_log.logging.debug(f"remote_client_auth_aes_key {remote_client_auth_aes_key}")
    received_remote_client_auth_sub_payload = json.loads(aes_decrypt(remote_client_auth_aes_key, b64decode(remote_client_auth_payload["aes_enc_client_auth_sub_payload"])).decode())

    if is_a_replay(received_remote_client_auth_sub_payload["time"]):
        _log.logging.error("Error: [REPLAY] Timestamp expired.")
        remote_client_sock.close()
        return None
    remote_client_user_name = received_remote_client_auth_sub_payload["username"]
    if remote_client_user_name != remote_user_name:
            _log.logging.error(f"Error: remote_client usernmae mistmatch received user name {remote_client_user_name}, requested user name {remote_user_name}")
            remote_client_sock.close()
    enc_c1_check = b64decode(received_remote_client_auth_sub_payload["c1_check"])
    c1_resp = json.loads(aes_decrypt(c2c_session_key_SK, enc_c1_check).decode())["c1_resp"]
    if c1_resp != c1 - 1:
        _log.logging.error("[X] c1 verification failed.")
    _log.logging.info(f"[✓] Successfully reception of remote client auth payload from {remote_client_user_name} ")
    
    '''
    Proof Of Work
    '''
    _log.logging.info("[✓] Successfully Reception of Proof-Of-Work")
    prefix = received_remote_client_auth_sub_payload["PoW"]["challenge"]
    difficulty= received_remote_client_auth_sub_payload["PoW"]["difficulty"]
    nonce = solve_proof(prefix, difficulty)
    enc_nonce = aes_encrypt(c2c_session_key_SK, json.dumps({"nonce": nonce}).encode())
    # Prepare full RSA-AES-wrapped remote client PoW response payload
    this_client_auth_sub_pow_resp_payload = {
        "username": client_resources.logged_in_user,
        "PoW-Response": b64encode(enc_nonce).decode(),
        "time": time.time()
    }
    enc_this_client_auth_sub_pow_resp_payload = aes_encrypt(this_client_auth_aes_key, json.dumps(this_client_auth_sub_pow_resp_payload).encode())
    this_client_auth_pow_resp_payload = {
        "type": "rc_auth",
        "rsa_enc_client_auth_aes_key": b64encode(enc_this_client_auth_aes_key).decode(),
        "aes_enc_client_auth_sub_pow_resp_payload" : b64encode(enc_this_client_auth_sub_pow_resp_payload).decode()
    }
    send_tlv(remote_client_sock, RC_AUTH_FRAME_T, json.dumps(this_client_auth_pow_resp_payload).encode())

    # client_resources.server_sock.send(json.dumps(remote_client_login_payload).encode())
    _log.logging.info(f"[✓] Successfully transmission of remote client's auth pow-response payload from {client_resources.logged_in_user} to {remote_user_name}")    
    _log.logging.info(f"[+] Authenticated {remote_client_user_name} and established secure session.")
    
supported_cmd_list = ['list', 'user <username>', 'help']
def main(c_ip):
    server, session_key_SK = client_login(c_ip)
    client_resources.s_c_session_key_SK = session_key_SK
    while True and server:
        command = input("cmd>")
        if command == "help":
            _log.logging.info(f"Supported command list -> {supported_cmd_list}")
        elif command == "list":
            client_resources.update_remote_client_dict(get_service(server, session_key_SK, command))
            if client_resources.remote_client_dict["list"]  == None:
                continue
            client_resources.show_c_list(client_resources.remote_client_dict["list"])
        elif "user " in command:
            split_string = command.split()
            client_resources.update_remote_client_dict(get_service(server, session_key_SK, "list"))
            user = client_resources.get_user_from_dict(split_string[1])
            if split_string[1] == client_resources.logged_in_user:
                _log.logging.error(f"Can't connect to ownself {user['username']}, check list and try again")
                continue
            if user:
                client_resources.show_c_list(client_resources.remote_client_dict["list"])
                # session_with_user()
                connect_to_remote_user(user,c_ip)
            else:
                _log.logging.error(f"Can't connect to user {user['username']}, check list and try again")
                continue
        elif command == "user":
            pass
        else:
            _log.logging.error(f"Error: Unexpected command {command}")
            _log.logging.info(f"Supported command list -> {supported_cmd_list}")
    cleanup()

def get_interface_ip(interface_name):
    addrs = psutil.net_if_addrs()
    if interface_name in addrs:
        for addr in addrs[interface_name]:
            if addr.family == socket.AF_INET:
                return addr.address
    return None

if __name__ == "__main__":
    _log.logging.debug("============== Client ============== ")
    parser = argparse.ArgumentParser(description="Get network interface info.")
    parser.add_argument(
        '--interface', '-i',
        required=True,
        help='Network interface to query (e.g., eth0)'
    )

    args = parser.parse_args()
    if args.interface:
        ip = get_interface_ip(args.interface)
        if ip == None:
            _log.logging.debug(f"Check interface, retrieved incorrect ip = {ip}")
            exit(0)
    else:
        ip = '0.0.0.0'

    try:
        signal.signal(signal.SIGINT, signal_signint_handler)
        lc.start_listening_client(ip)
        client_resources.create_this_client_rsa_cipher()
        main(ip)
    except Exception as e:
        _log.logging.error(f"[ERROR] {e}")
        traceback.print_exc()
        cleanup()
        raise
