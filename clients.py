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

server_sock = None
logged_in_user = None
def load_config():
    with open("config.json") as f:
        return json.load(f)

def get_user_pass_as_W():
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    # Derive W from password
    W = derive_password_key(password, b'static_salt') # W with len 32 byte
    _log.logging.debug(f"W {W}")
    # To loose password to avoid password leak 
    password = None
    return username,W

def gen_eph_rsa_keys():
    key = RSA.generate(4096)
    c_priv = key.export_key()
    c_pub = key.publickey().export_key()
    return c_priv, c_pub

def load_server_server_pub_key():
    # Load server public RSA key
    with open("server_public.pem", "rb") as f:
        server_pub_key = RSA.import_key(f.read())
    server_rsa_pub_cipher = PKCS1_OAEP.new(server_pub_key)
    return server_rsa_pub_cipher

def client_login():
    global server_sock
    global logged_in_user
    config = load_config()
    username,W = get_user_pass_as_W()    
    server_rsa_pub_cipher = load_server_server_pub_key()

    # Generate ephemeral DH keys
    a, g_a, p, g = generate_dh_parameters()
    # Encrypt g^a mod p using W
    encrypted_ga = aes_encrypt(W, str(g_a).encode())
    b64_enc_ga = b64encode(encrypted_ga).decode()

    #Generate ephemeral RSA keys of clieny
    c_rsa_priv, c_rsa_pub = gen_eph_rsa_keys()

    # 1. Generate AES key for login
    client_login_aes_key = get_random_bytes(32)
    enc_client_login_aes_key = server_rsa_pub_cipher.encrypt(client_login_aes_key)

    # Prepare full RSA-AES-wrapped login payload
    client_login_sub_payload = {
        "username": username,
        "Wga": b64_enc_ga,
        "pKc": b64encode(c_rsa_pub).decode(),
        "c_port": config["client_port"],
        "time": time.time()
    }
    enc_client_login_sub_payload = aes_encrypt(client_login_aes_key, json.dumps(client_login_sub_payload).encode())
    cleint_login_payload = {
        "type": "login",
        "rsa_enc_client_login_aes_key": b64encode(enc_client_login_aes_key).decode(),
        "aes_enc_client_login_sub_payload" : b64encode(enc_client_login_sub_payload).decode()
    }

    # Connect to server and send RSA-wrapped login
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.settimeout(5)  # Optional: set a timeout for connection attempt
    
    try:
        server_sock.connect((config["server_ip"], config["server_port"]))
        _log.logging.info("[✓] Connected to server.")
    except socket.timeout:
        _log.logging.error("⏱ Connection attempt timed out.")
    except ConnectionRefusedError:
        _log.logging.error("[X] Connection refused — is the server running?")
    except OSError as e:
        _log.logging.error(f"[!] OS error occurred: {e}")
        cleanup()

    send_tlv(server_sock, LOGIN_FRAME_T, json.dumps(cleint_login_payload).encode())
    # server_sock.send(json.dumps(cleint_login_payload).encode())
    _log.logging.info("[✓] Successfully transmission of client's login payload")
    #exit()

    '''
    Second Login transaction from server to client
    '''
    c_rsa_priv_key = RSA.import_key(c_rsa_priv)
    client_rsa_priv_cipher = PKCS1_OAEP.new(c_rsa_priv_key)
    # Receive encrypted W{g^b mod p} and server pub key
    server_login_payload = json.loads(server_sock.recv(4096).decode())
    server_login_sub_payload = {}
    try:
        if server_login_payload["type"] == "login":
            _log.logging.info("[✓] Successfully reception of server's login payload")
            '''
            Perfect Forward Secrecy
            '''
            server_login_aes_key = client_rsa_priv_cipher.decrypt(b64decode(server_login_payload["rsa_enc_server_login_aes_key"]))
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
            
            '''
            Proof Of Work
            '''
            # Receive encrypted challenge from server (using K)
            enc_challenge = server_sock.recv(4096)
            challenge_json = json.loads(aes_decrypt(dh_shared_K_bytes, enc_challenge).decode())
            #_log.logging.debug(f"challenge_json {challenge_json}")
            #_log.logging.debug(f"[CHALLENGE] Solve {challenge_json['challenge']} with difficulty {challenge_json['difficulty']}")

            # Solve and respond with encrypted proof
            nonce = solve_proof(challenge_json["challenge"], challenge_json["difficulty"])
            enc_nonce = aes_encrypt(dh_shared_K_bytes, json.dumps({"nonce": nonce}).encode())
            server_sock.send(enc_nonce)
            _log.logging.info("[✓] Successfully Transmission of Proof-Of-Work")

            '''
            Session Key Exchange
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
            server_sock.send(enc_msg1)

            # Step 2: Receive and decrypt server response
            enc_msg2 = server_sock.recv(2048)
            msg2 = json.loads(aes_decrypt(dh_shared_K_bytes, enc_msg2).decode())
            enc_response = b64decode(msg2["enc_response"])
            response = json.loads(aes_decrypt(session_key_SK, enc_response).decode())
    
            if response["c3_check"] != c3 - 1:
                _log.logging.error("[X] c3 verification failed.")
                cleanup()
            c4 = response["c4"]
            
            # Step 3: Send SK_check = c4 - 1 encrypted with SK, then with shared_K
            enc_msg3 = aes_encrypt(session_key_SK, json.dumps({"c4_check": c4 - 1}).encode())
            final_msg = aes_encrypt(dh_shared_K_bytes, json.dumps({"enc_c4_check": b64encode(enc_msg3).decode()}).encode())
            server_sock.send(final_msg)

            _log.logging.info(f"[+] Final session key established: {session_key_SK.hex()}")
            logged_in_user = username
            return server_sock, session_key_SK
        else:
            server_sock.send(b"Error: expecting login type frame from server")
            cleanup()
    except Exception as e:
        _log.logging.error(f"[ERROR] {e}")
        raise
    
def get_list_from_server(server: socket.socket, session_key_SK):
    
    # Send List Command
    request = aes_encrypt(session_key_SK, json.dumps({"command": "list", "time": time.time()}).encode())
    send_tlv(server, LIST_FRAME_T, request)
    type_, msg = recv_tlv(server)
    if type_ == LIST_FRAME_T:
        response = json.loads(aes_decrypt(session_key_SK, msg).decode())
        # _log.logging.debug(f"User List From Server : \n{response}")
        return response
    else:
        _log.logging.error(f"Error: Unexpected resposne from server with type {type_}")
        return None


def get_service(server: socket.socket, session_key_SK, command):
    if command == "list":
        return get_list_from_server(server, session_key_SK)
    else:
        return None
    
def show_c_list(c_dict:dict):
    for user in c_dict.values():
        print(f"Name: {user['username']:<13} IP: {user['ip']:<15} Port: {user['port']:<5}")

supported_cmd_list = ['list', 'user <username>', 'help']
def main():
    server, session_key_SK = client_login()
    while True and server:
        command = input("cmd>")
        if command == "help":
            _log.logging.info(f"Supported command list -> {supported_cmd_list}")
        elif command == "list":
            c_dict = get_service(server, session_key_SK, command)
            if c_dict  == None:
                break
            show_c_list(c_dict)
        elif command == "user":
            pass
        else:
            _log.logging.error(f"Error: Unexpected command {command}")
            _log.logging.info(f"Supported command list -> {supported_cmd_list}")
    cleanup()
    
def cleanup():
    global server_sock
    _log.logging.info("[🧹] Cleaning up resources...")
    if server_sock != None :
        _log.logging.info("[🧹] Closing Server Socket For Graceful Termination")
        server_sock.close()
        time.sleep(1)
    # Close sockets, save files, etc.
    sys.exit(0)

def signal_signint_handler(sig, frame):
    _log.logging.info("🔴 Caught Ctrl+C (SIGINT)")
    cleanup()


if __name__ == "__main__":
    _log.logging.debug("============== Client ============== ")
    try:
        signal.signal(signal.SIGINT, signal_signint_handler)
        main()
    except Exception as e:
        _log.logging.error(f"[ERROR] {e}")
        cleanup()
        raise
