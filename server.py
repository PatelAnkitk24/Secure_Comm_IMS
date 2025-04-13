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
import traceback
from Crypto.Protocol.KDF import PBKDF2
import getpass
import logging
import pickle
import server_resources

server_sock = None
# Simulated weak password database for demo (in real systems, this would be hashed and salted)
user_db = None

online_users = {}  # username -> {ip, port, ephemeral_pub}
online_users_sharable = {}
logout_user_dict = {}

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
    
def client_login(conn: socket.socket, addr):
    global online_users
    client_login_sub_payload = {}
    b = None #DH client private key
    g_b = None #DH client public key
    dh_shared_K_bytes = None
    try:
        
        '''
        First Login transaction from client to server
        '''
        type_, decoded_login_payload = recv_tlv(conn)
        if type_ != LOGIN_FRAME_T:
            _log.logging.error("Error: Not A Login Frame")
            send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, b"[X] Error: Not A Login Frame")
            conn.close()
            return None
        client_login_payload = json.loads(decoded_login_payload.decode())
        # _log.logging.debug(f"login_payload {client_login_payload}")
        try:
            if client_login_payload["type"] == "login":
                # Get AES Key and decrypt sub payload 
                client_login_aes_key = server_resources.decrypt_client_login_aes_key(b64decode(client_login_payload["rsa_enc_client_login_aes_key"]))
                #_log.logging.debug(f"aes_key {aes_key}")
                received_client_login_sub_payload = json.loads(aes_decrypt(client_login_aes_key, b64decode(client_login_payload["aes_enc_client_login_sub_payload"])).decode())
                #_log.logging.debug(f"received_sub_payload {received_sub_payload}")

                # Decrypt Sub payload
                client_login_sub_payload["username"] = received_client_login_sub_payload["username"]
                if is_user_in(online_users_sharable, client_login_sub_payload["username"]):
                    _log.logging.error("[X] Error: User Already Logged in")
                    send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, b"[X] Error: User Already Logged in")
                    conn.close()
                    return None
                
                # Decrypt ga
                W = get_user_w(client_login_sub_payload["username"])
                if W == None:
                    _log.logging.error("[X] Error: User not found")
                    send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, (b"Error: User not found"))
                    conn.close()
                    return None
                enc_ga = b64decode(received_client_login_sub_payload["Wga"])
                try:
                    client_login_sub_payload["ga"] = int(aes_decrypt(W,enc_ga))
                except Exception as e:
                    send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, (b"Error: Wrong Password"))
                    # _log.logging.error(f"[ERROR] {e}")
                    _log.logging.error(f"[ERROR]  Wrong Password")
                    conn.close()
                    return None
                    # traceback.print_exc()
                    # raise
                
                # Get pKc, port, time
                client_login_sub_payload["pKc"] = b64decode(received_client_login_sub_payload["pKc"])
                client_login_sub_payload["c_port"] = received_client_login_sub_payload["c_port"]
                client_login_sub_payload["time"] = received_client_login_sub_payload["time"]
                #_log.logging.debug(f"client_login_sub_payload {client_login_sub_payload}")
                
                if is_a_replay(client_login_sub_payload["time"]):
                    _log.logging.error("Error: [REPLAY] Timestamp expired.")
                    send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, (b"Error: Timestamp too old."))
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
                send_tlv(conn, LOGIN_FRAME_T, json.dumps(server_login_payload).encode())
                b = g_b = 0 # Forget private and public DH keys for PFS
                
            else:
                _log.logging.error("Error: expecting login type frame")
                send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, (b"Error: expecting login type frame"))
                conn.close()
                return None
            
            '''
            Proof Of Work
            '''
            # Send encrypted PoW challenge using K
            prefix, difficulty = generate_challenge()
            challenge_data = json.dumps({"challenge": prefix, "difficulty": difficulty}).encode()
            #_log.logging.debug(f"challange_data {challenge_data}")
            enc_challenge = aes_encrypt(dh_shared_K_bytes, challenge_data)
            send_tlv(conn, LOGIN_FRAME_T, enc_challenge)
            
            # Receive encrypted PoW response and validate
            # tyep, enc_nonce  = recv_tlv(conn)
            type_, received_login_payload  = recv_tlv(conn)
            if type_ == LOGIN_ERR_MSG_FRAME_T:
                _log.logging.error(f"[✓] Login Failed With Message From Client : {decoded_login_payload.decode()}")
                conn.close()
                return None
            if type_ != LOGIN_FRAME_T:
                _log.logging.error("Error: Not A Login Frame")
                conn.close()
                return None
            nonce_data = json.loads(aes_decrypt(dh_shared_K_bytes, received_login_payload).decode())
            _log.logging.info("[✓] Successfully Reception of Proof-Of-Work")
            if not validate_proof(prefix, nonce_data.get("nonce"), difficulty):
                _log.logging.error("Error: Invalid PoW-Response")
                send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, (b"Error: Invalid PoW-Response"))
                conn.close()
                return None
            send_tlv(conn, LOGIN_FRAME_T, aes_encrypt(dh_shared_K_bytes,(b"Correct PoW-Response")))
            _log.logging.info("[✓] Successfully Verification of Proof-Of-Work")

            '''
            Transaction form client to server for Session Key Exchange
            '''
            # Step 1: Receive {SK, enc_c3} from client
            type_, received_login_payload  = recv_tlv(conn)
            if type_ == LOGIN_ERR_MSG_FRAME_T:
                _log.logging.error(f"[✓] Login Failed With Message From Client : {decoded_login_payload.decode()}")
                conn.close()
                return None
            if type_ != LOGIN_FRAME_T:
                _log.logging.error("Error: Not A Login Frame")
                conn.close()
                return None
            #_log.logging.debug(f"enc_msg1 {enc_msg1}")
            msg1 = json.loads(aes_decrypt(dh_shared_K_bytes, received_login_payload).decode())
            session_key_SK = b64decode(msg1["SK"])
            enc_c3 = b64decode(msg1["enc_c3"])
            c3 = json.loads(aes_decrypt(session_key_SK, enc_c3).decode())["c3"]
            #_log.logging.debug(f"c3 {c3}")

            '''
            Transaction form server to client for Session Key Exchange
            '''
            # Step 2: Generate random c4, respond with {SK{c3-1, c4}} double encrypted
            c4 = random.randint(100, 999)
            c3_check_payload = json.dumps({"c3_check": c3 - 1, "c4": c4}).encode()
            enc_payload = aes_encrypt(session_key_SK, c3_check_payload)
            msg2 = json.dumps({"enc_response": b64encode(enc_payload).decode()}).encode()
            enc_msg2 = aes_encrypt(dh_shared_K_bytes, msg2)
            send_tlv(conn, LOGIN_FRAME_T, enc_msg2)

            '''
            Transaction form client to server for Session Key Exchange
            '''
            # Step 3: Receive and validate {SK{c4-1}} from client
            type_, received_login_payload  = recv_tlv(conn)
            if type_ == LOGIN_ERR_MSG_FRAME_T:
                _log.logging.error(f"[✓] Login Failed With Message From Client : {decoded_login_payload.decode()}")
                conn.close()
                return None
            if type_ != LOGIN_FRAME_T:
                _log.logging.error("Error: Not A Login Frame")
                conn.close()
                return None
            msg3 = json.loads(aes_decrypt(dh_shared_K_bytes, received_login_payload).decode())
            enc_c4_check = b64decode(msg3["enc_c4_check"])
            c4_check = json.loads(aes_decrypt(session_key_SK, enc_c4_check).decode())["c4_check"]

            if c4_check != c4 - 1:
                _log.logging.error("[X] c4 verification failed.")
                send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, (b"[X] c4 verification failed."))
                conn.close()
                return None
            else:
                send_tlv(conn, LOGIN_FRAME_T, aes_encrypt(session_key_SK,(b"OK")))
            
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
            traceback.print_exc()
            raise
            
    except Exception as e:
        _log.logging.error(f"[ERROR] {e}")
        traceback.print_exc()
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

def get_user_by_name(u_name):
    for user_info in online_users.values():
        if user_info["username"] == u_name:
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
    
    if u_name:
        _log.logging.info(f"User: {u_name} removed from online list")
        _log.logging.info(f"User: {u_name} went offline")

def serve_to_client(conn : socket.socket, addr):
    # _log.logging.debug(f"clients addr {addr}")
    user = get_user_by_ip(addr[0], addr[1])
    _log.logging.info(f"Serving to User : {user['username']}")
    session_key_SK = b64decode(user["session_key_SK"])
    #_log.logging.debug(f"user list : \n {user}")
    while True and user:
        type_, enc_msg = recv_tlv(conn)
        if type_ == LIST_FRAME_T:
            request = json.loads(aes_decrypt(session_key_SK, enc_msg).decode())
            if request["command"] == "list":
                _log.logging.info(f"Request for list: From User {user['username']} with ip {user['ip']}")
                if is_not_a_replay(request["time"]):
                    reply = aes_encrypt(session_key_SK, json.dumps(online_users_sharable).encode())
                    send_tlv(conn,LIST_FRAME_T,reply)
                else:
                    _log.logging.error(f"Error: Replay attack from User {user['username']} with ip {user['ip']}")
                    continue
            else:
                _log.logging.error(f"Error: Unknown command {request['command'] } from User {user['username']} with ip {user['ip']}")
                continue
        elif type_ == LOGOUT_FRAME_1_T:
            request = json.loads(aes_decrypt(session_key_SK, enc_msg).decode())
            if request["command"] != "logout":
                _log.logging.error(f"Error: Unknown command {request['command'] } from User {user['username']} with ip {user['ip']}")
                continue
            if is_a_replay(request["time"]):
                _log.logging.error(f"Error: Logout frame 1 Replay attack from User {user['username']} with ip {user['ip']}")
                continue
                
            if user['username'] != request["username"]:
                e_msg = f"[X] Logout Failed as User {user['username']} Requested logout for {request['username']}"
                _log.logging.error(e_msg)
                msg_bytes = e_msg.encode('utf-8')
                send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, msg_bytes)
            
            if not is_user_in(online_users_sharable, request["username"]):
                e_msg= f"[X] Error: Can't Log out User {request['username']}, as it is Not Logged in"
                _log.logging.error(e_msg)
                msg_bytes = e_msg.encode('utf-8')
                send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, msg_bytes)
                continue
            
            _log.logging.info(f"Request for logout: From User {user['username']} with ip {user['ip']}")
            logout_payload = {
                "command": "logout",
                "username": "server",
                "time": time.time()
            }
            reply = aes_encrypt(session_key_SK, json.dumps(logout_payload).encode())
            send_tlv(conn,LOGOUT_FRAME_1_T,reply)
            logout_user_dict[request["username"]] = 'logout_1'
        elif type_ == LOGOUT_FRAME_2_T:
            request = json.loads(aes_decrypt(session_key_SK, enc_msg).decode())
            if request["command"] != "logout":
                _log.logging.error(f"Error: Unknown command {request['command'] } from User {user['username']} with ip {user['ip']}")
                continue    
            if is_a_replay(request["time"]):
                _log.logging.error(f"Error: Logout frame 2 Replay attack from User {user['username']} with ip {user['ip']}")
                continue 
            
            if request["username"] not in logout_user_dict:
                e_msg= f"[X] Error: Can't Log out User {request['username']}, as frame LOGOUT_FRAME_1_T was not received"
                _log.logging.error(e_msg)
                msg_bytes = e_msg.encode('utf-8')
                send_tlv(conn, LOGIN_ERR_MSG_FRAME_T, msg_bytes)
                continue

            _log.logging.info(f"Request for logout confrimation: From User {user['username']} with ip {user['ip']}")
            logout_payload = {
                "command": "logout",
                "username": "server",
                "time": time.time()
            }
            reply = aes_encrypt(session_key_SK, json.dumps(logout_payload).encode())
            send_tlv(conn,LOGOUT_FRAME_2_T,reply)
            
            del logout_user_dict[request["username"]]
            remove_client_from_online_list(addr[0], addr[1])
        elif type_ == None:
            logging.warning(f"Socket closed or bad data from {user['username']} at {addr[0]}. Closing connection.")
            break
        else:
            _log.logging.error(f"Error: Unknown frame {type_} from User {user['username']} with ip {user['ip']}")
            continue

def handle_client(conn: socket.socket, addr):
    try: 
        response = client_login(conn, addr)
        if response == 0:
            serve_to_client(conn, addr)
            remove_client_from_online_list(addr[0],addr[1])
        else:
            _log.logging.error(f"Error: Login Failed from {addr}")
            remove_client_from_online_list(addr[0],addr[1])
    except Exception as e:
        remove_client_from_online_list(addr[0],addr[1])
        _log.logging.error(f"[ERROR] {e}")
        conn.close()
        traceback.print_exc()
    finally:
        conn.close()


def start_server():
    global server_sock
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((u_config_["server_ip"], u_config_['server_port']))
    server_sock.listen()
    _log.logging.info(f"[SERVER] Listening on port {u_config_['server_port']} ...")
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
    key, password = server_resources.load_keys()
    user_db = server_resources.load_user_db_record(password)
    signal.signal(signal.SIGINT, signal_signint_handler)
    start_server()
