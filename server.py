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

rsa_priv_cipher = None
server_sock = None
# Simulated weak password database for demo (in real systems, this would be hashed and salted)
user_db = [
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

online_users = {}  # username -> {ip, port, ephemeral_pub}
online_users_sharable = {}

def get_user_entry(username):
    for user in user_db:
        if user["username"] == username:
            return user
    return None

def get_user_w(username):
    user = get_user_entry(username)
    if user != None:
        return user["W"]
    return None
    
def decrypt_client_login_aes_key(rsa_enc_aes_key):
    return rsa_priv_cipher.decrypt(rsa_enc_aes_key)

def client_login(conn: socket.socket, addr):
    global online_users
    client_login_sub_payload = {}
    b = None #DH client private key
    g_b = None #DH client public key
    dh_shared_K_bytes = None
    try:
        type, decoded_login_payload  = recv_tlv(conn)
        if type != LOGIN_FRAME_T:
            _log.logging.error("Error: Not A Login Frame")
            conn.close()
            return None
        client_login_payload = json.loads(decoded_login_payload.decode())
        # _log.logging.debug(f"login_payload {client_login_payload}")
        try:
            if client_login_payload["type"] == "login":
                # Get AES Key and decrypt sub payload 
                client_login_aes_key = decrypt_client_login_aes_key(b64decode(client_login_payload["rsa_enc_client_login_aes_key"]))
                #_log.logging.debug(f"aes_key {aes_key}")
                received_client_login_sub_payload = json.loads(aes_decrypt(client_login_aes_key, b64decode(client_login_payload["aes_enc_client_login_sub_payload"])).decode())
                #_log.logging.debug(f"received_sub_payload {received_sub_payload}")

                # Decrypt Sub payload
                client_login_sub_payload["username"] = received_client_login_sub_payload["username"]
                if is_user_in(online_users_sharable, client_login_sub_payload["username"]):
                    _log.logging.error("[X] Error: User Already Logged in")
                    conn.send(b"[X] Error: User Already Logged in")
                    conn.close()
                    return None
                
                # Decrypt ga
                W = get_user_w(client_login_sub_payload["username"])
                if W == None:
                    _log.logging.error("[X] Error: User not found")
                    conn.send(b"Error: User not found")
                    conn.close()
                    return None
                enc_ga = b64decode(received_client_login_sub_payload["Wga"])
                client_login_sub_payload["ga"] = int(aes_decrypt(W,enc_ga))
                
                # Get pKc, port, time
                client_login_sub_payload["pKc"] = b64decode(received_client_login_sub_payload["pKc"])
                client_login_sub_payload["c_port"] = received_client_login_sub_payload["c_port"]
                client_login_sub_payload["time"] = received_client_login_sub_payload["time"]
                #_log.logging.debug(f"client_login_sub_payload {client_login_sub_payload}")
                now = time.time()
                if "time" not in client_login_sub_payload:
                    _log.logging.error("Error: [REPLAY] Timestamp not present.")
                    conn.send(b"Error: Timestamp not present")
                    conn.close()
                    return None
                if is_a_replay(client_login_sub_payload["time"]):
                    _log.logging.error("Error: [REPLAY] Timestamp expired.")
                    conn.send(b"Error: Timestamp too old.")
                    conn.close()
                    return None
                _log.logging.info("[✓] Successfully reception of client's login payload")
                #exit()

                '''
                Second Login transaction from server to client
                '''
                
                '''
                Perfect Forward Secrecy
                '''
                # Generate DH key and compute shared secret
                b, g_b, p, g = generate_dh_parameters()
                #_log.logging.debug(f"gb {g_b}")
                dh_shared_K = compute_shared_secret(client_login_sub_payload["ga"], b, p)
                dh_shared_K_bytes = dh_shared_K.to_bytes((dh_shared_K.bit_length() + 7) // 8, 'big')
                #_log.logging.debug(f"Shared key bit length: {dh_shared_K.bit_length()}")
                # Use hash to standardize size
                dh_shared_K_bytes = hashlib.sha256(dh_shared_K.to_bytes((dh_shared_K.bit_length() + 7) // 8, 'big')).digest()
                #_log.logging.debug(f"dh_shared_k_bytes {dh_shared_K_bytes}")
                if (dh_shared_K_bytes):
                    _log.logging.info("[✓] Shared DH secret K established.")
                # Encrypt g^b as W{g^b}
                encrypted_gb = aes_encrypt(W, str(g_b).encode())
                b64_enc_gb = b64encode(encrypted_gb).decode()

                client_pub_key = RSA.import_key(client_login_sub_payload["pKc"])
                client_rsa_pub_cipher = PKCS1_OAEP.new(client_pub_key)
                server_login_aes_key = get_random_bytes(32)
                #_log.logging.debug(f"server_login_aes_key {server_login_aes_key}")
                enc_server_login_aes_key = client_rsa_pub_cipher.encrypt(server_login_aes_key)

                server_login_sub_payload = {
                    "Wgb": b64_enc_gb,
                    "time": time.time()
                }
                enc_server_login_sub_payload = aes_encrypt(server_login_aes_key, json.dumps(server_login_sub_payload).encode())
                server_login_payload = {
                    "type": "login",
                    "rsa_enc_server_login_aes_key": b64encode(enc_server_login_aes_key).decode(),
                    "aes_enc_server_login_sub_payload" : b64encode(enc_server_login_sub_payload).decode()
                }
                _log.logging.info("[✓] Successfully transmission of server's login payload")
                time.sleep(2)
                # Send response: W{g^b} + optional server pub key
                conn.send(json.dumps(server_login_payload).encode())
                b = g_b = 0 # Forget private and public DH keys for PFS
                
            else:
                _log.logging.error("Error: expecting login type frame")
                conn.send(b"Error: expecting login type frame")
                conn.close()
                return None
            pass
            
            '''
            Proof Of Work
            '''
            # Send encrypted PoW challenge using K
            prefix, difficulty = generate_challenge()
            challenge_data = json.dumps({"challenge": prefix, "difficulty": difficulty}).encode()
            #_log.logging.debug(f"challange_data {challenge_data}")
            enc_challenge = aes_encrypt(dh_shared_K_bytes, challenge_data)
            conn.send(enc_challenge)
            
            # Receive encrypted PoW response and validate
            # tyepe, enc_nonce  = recv_tlv(conn)
            enc_nonce = conn.recv(4096)
            nonce_data = json.loads(aes_decrypt(dh_shared_K_bytes, enc_nonce).decode())
            _log.logging.info("[✓] Successfully Reception of Proof-Of-Work")
            if not validate_proof(prefix, nonce_data.get("nonce"), difficulty):
                _log.logging.error("Error: Invalid PoW")
                conn.send(b"Error: Invalid PoW")
                conn.close()
                return None
            _log.logging.info("[✓] Successfully Verification of Proof-Of-Work")

            '''
            Session Key Exchange
            '''
            # Step 1: Receive {SK, enc_c3} from client
            enc_msg1 = conn.recv(2048)
            #_log.logging.debug(f"enc_msg1 {enc_msg1}")
            msg1 = json.loads(aes_decrypt(dh_shared_K_bytes, enc_msg1).decode())
            session_key_SK = b64decode(msg1["SK"])
            enc_c3 = b64decode(msg1["enc_c3"])
            c3 = json.loads(aes_decrypt(session_key_SK, enc_c3).decode())["c3"]
            #_log.logging.debug(f"c3 {c3}")

            # Step 2: Generate random c4, respond with {SK{c3-1, c4}} double encrypted
            c4 = random.randint(100, 999)
            c3_check_payload = json.dumps({"c3_check": c3 - 1, "c4": c4}).encode()
            enc_payload = aes_encrypt(session_key_SK, c3_check_payload)
            msg2 = json.dumps({"enc_response": b64encode(enc_payload).decode()}).encode()
            enc_msg2 = aes_encrypt(dh_shared_K_bytes, msg2)
            conn.send(enc_msg2)

            # Step 3: Receive and validate {SK{c4-1}} from client
            enc_msg3 = conn.recv(2048)
            msg3 = json.loads(aes_decrypt(dh_shared_K_bytes, enc_msg3).decode())
            enc_c4_check = b64decode(msg3["enc_c4_check"])
            c4_check = json.loads(aes_decrypt(session_key_SK, enc_c4_check).decode())["c4_check"]

            if c4_check != c4 - 1:
                _log.logging.error("[X] c4 verification failed.")
                conn.close()
                return None
            
            if not _log.is_level_debug():
                _log.logging.info(f"[✓] Final session key established")
            else:
                _log.logging.debug(f"[✓] Final session key established with {client_login_sub_payload['username']} : {session_key_SK.hex()}")

            _log.logging.info("[✓] Session key verification completed.")

            # Save user info
            online_users[client_login_sub_payload["username"]] = {
                "username": client_login_sub_payload["username"],
                "ip": addr[0],
                "s_c_port": addr[1],
                "port": client_login_sub_payload["c_port"],
                "ephemeral_pub": b64encode(client_login_sub_payload["pKc"]).decode(),
                "session_key_SK": b64encode(session_key_SK).decode()
            }
            online_users_sharable[client_login_sub_payload["username"]] = {
                "username": client_login_sub_payload["username"],
                "ip": addr[0],
                "port": client_login_sub_payload["c_port"],
                "ephemeral_pub": b64encode(client_login_sub_payload["pKc"]).decode()
            }
            _log.logging.info(f"[+] Authenticated {client_login_sub_payload['username']} with secure session.")

            return 0
        except Exception as e:
            _log.logging.error(f"[ERROR] {e}")
            raise
            
    except Exception as e:
        _log.logging.error(f"[ERROR] {e}")
        raise

def is_user_in(online_users_sharable, u_name):
    for username, user_info in list(online_users_sharable.items()):
        if user_info["username"] == u_name:
            return True
    return False

def get_user_by_ip(ip_address, port):
    for user_info in online_users.values():
        if user_info["ip"] == ip_address and user_info["s_c_port"] == port:
            return user_info
    return None  # If not found

def remove_client_from_online_list(ip_address, port):
    u_name = None
    for username, user_info in list(online_users.items()):
        if user_info["ip"] == ip_address and user_info["s_c_port"] == port:
            u_name = user_info['username']
            online_users.pop(username)

    for username, user_info in list(online_users_sharable.items()):
        if u_name and user_info["username"] == u_name:
            online_users_sharable.pop(username)
    
    _log.logging.info(f"User: {u_name} removed from online list")
    _log.logging.info(f"User: {u_name} went offline")

def serve_to_client(conn : socket.socket, addr):
    # _log.logging.debug(f"clients addr {addr}")
    user = get_user_by_ip(addr[0], addr[1])
    _log.logging.info(f"Serving to User : {user['username']}")
    session_key_SK = b64decode(user["session_key_SK"])
    #_log.logging.debug(f"user list : \n {user}")
    while True and user:
        type_, msg = recv_tlv(conn)
        if type_ == LIST_FRAME_T:
            request = json.loads(aes_decrypt(session_key_SK, msg).decode())
            if request["command"] == "list":
                _log.logging.info(f"Request for list: User {user['username']} with ip {user['ip']}")
                if is_not_a_replay(request["time"]):
                    reply = aes_encrypt(session_key_SK, json.dumps(online_users_sharable).encode())
                    send_tlv(conn,LIST_FRAME_T,reply)
                else:
                    _log.logging.error(f"Error: Replay attack from User {user['username']} with ip {user['ip']}")
                    break;    
            else:
                _log.logging.error(f"Error: Unknown command {request['command'] } from User {user['username']} with ip {user['ip']}")
                break
        else:
            _log.logging.error(f"Error: Unknown frame {type_} from User {user['username']} with ip {user['ip']}")
            break

def handle_client(conn: socket.socket, addr):
    try: 
        response = client_login(conn, addr)
        if response == 0:
            serve_to_client(conn, addr)
        else:
            _log.logging.error("Error: Login Failed from {addr}")
            remove_client_from_online_list(addr[0],addr[1])
    except Exception as e:
        remove_client_from_online_list(addr[0],addr[1])
        conn.close()
    finally:
        remove_client_from_online_list(addr[0],addr[1])
        conn.close()


def start_server():
    global server_sock
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', 9999))
    server_sock.listen()
    _log.logging.info("[SERVER] Listening on port 9999...")
    while True:
        conn, addr = server_sock.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

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
    if not os.path.exists("server_private.pem") or not os.path.exists("server_public.pem"):
        _log.logging.info("[KEYGEN] Generating RSA key pair...")
        key = RSA.generate(4096)
        with open("server_private.pem", "wb") as priv_file:
            priv_file.write(key.export_key())
        with open("server_public.pem", "wb") as pub_file:
            pub_file.write(key.publickey().export_key())
        _log.logging.info("[KEYGEN] Keys saved.")

    with open("server_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    rsa_priv_cipher = PKCS1_OAEP.new(private_key)
    signal.signal(signal.SIGINT, signal_signint_handler)
    start_server()
