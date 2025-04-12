import socket
import json
import threading
import os
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from crypto_utils import generate_dh_parameters, compute_shared_secret, aes_encrypt, aes_decrypt, derive_password_key
from pow_utils import generate_challenge, validate_proof
import time
import hashlib
rsa_priv_cipher = None

# Simulated weak password database for demo (in real systems, this would be hashed and salted)
user_db = [
    {
        "username": "alice",
        "salt": b"static_salt",
        "W": b'\xea\x87\xc1\xb426\xf2G3\x01\x01\xfd\xb6\x82)\x8a\xf3\x8c\xf6\x91\xd7:z\xd4{4\x89\xecv\xa2\xdf\xd4'
    },
    {
        "username": "bob",
        "salt": b"another_salt",
        "W": "321"
    }
]

online_users = {}  # username -> {ip, port, ephemeral_pub}

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

def handle_client(conn, addr):
    global online_users
    client_login_sub_payload = {}
    b = None #DH client private key
    g_b = None #DH client public key
    dh_shared_K_bytes = None
    try:
        decoded_login_payload = conn.recv(4096).decode()
        client_login_payload = json.loads(decoded_login_payload)
        #print(f"login_payload {login_payload}")
        try:
            if client_login_payload["type"] == "login":
                # Get AES Key and decrypt sub payload 
                client_login_aes_key = decrypt_client_login_aes_key(b64decode(client_login_payload["rsa_enc_client_login_aes_key"]))
                #print(f"aes_key {aes_key}")
                received_client_login_sub_payload = json.loads(aes_decrypt(client_login_aes_key, b64decode(client_login_payload["aes_enc_client_login_sub_payload"])).decode())
                #print(f"received_sub_payload {received_sub_payload}")

                # Decrypt Sub payload
                client_login_sub_payload["username"] = received_client_login_sub_payload["username"]

                # Decrypt ga
                W = get_user_w(client_login_sub_payload["username"])
                if W == None:
                    conn.send(b"Error: User not found")
                    conn.close()    
                    return
                enc_ga = b64decode(received_client_login_sub_payload["Wga"])
                client_login_sub_payload["ga"] = int(aes_decrypt(W,enc_ga))
                
                # Get pKc, port, time
                client_login_sub_payload["pKc"] = b64decode(received_client_login_sub_payload["pKc"])
                client_login_sub_payload["c_port"] = received_client_login_sub_payload["c_port"]
                client_login_sub_payload["time"] = received_client_login_sub_payload["time"]
                now = time.time()
                if "time" not in client_login_sub_payload:
                    print("Error: [REPLAY] Timestamp not present.")
                    conn.send(b"Error: Timestamp not present")
                    conn.close()
                    return
                if abs(now - client_login_sub_payload["time"]) > 10:
                    print("Error: [REPLAY] Timestamp expired.")
                    conn.send(b"Error: Timestamp too old.")
                    conn.close()
                    return
                print("[✓] Successfully reception of client's login payload")
                #exit()

                '''
                Second Login transaction from server to client
                '''
                
                '''
                Perfect Forward Secrecy
                '''
                # Generate DH key and compute shared secret
                b, g_b, p, g = generate_dh_parameters()
                #print(f"gb {g_b}")
                dh_shared_K = compute_shared_secret(client_login_sub_payload["ga"], b, p)
                dh_shared_K_bytes = dh_shared_K.to_bytes((dh_shared_K.bit_length() + 7) // 8, 'big')
                #print(f"Shared key bit length: {dh_shared_K.bit_length()}")
                # Use hash to standardize size
                dh_shared_K_bytes = hashlib.sha256(dh_shared_K.to_bytes((dh_shared_K.bit_length() + 7) // 8, 'big')).digest()
                #print(f"dh_shared_k_bytes {dh_shared_K_bytes}")
                if (dh_shared_K_bytes):
                    print("[✓] Shared DH secret K established.")
                # Encrypt g^b as W{g^b}
                encrypted_gb = aes_encrypt(W, str(g_b).encode())
                b64_enc_gb = b64encode(encrypted_gb).decode()

                client_pub_key = RSA.import_key(client_login_sub_payload["pKc"])
                client_rsa_pub_cipher = PKCS1_OAEP.new(client_pub_key)
                server_login_aes_key = get_random_bytes(32)
                #print(f"server_login_aes_key {server_login_aes_key}")
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
                print("[✓] Successfully transmission of server's login payload")
                time.sleep(2)
                # Send response: W{g^b} + optional server pub key
                conn.send(json.dumps(server_login_payload).encode())
                b = g_b = 0 # Forget private and public DH keys for PFS
                
            else:
                conn.send(b"Error: expecting login type frame")
                conn.close()    
                return
            pass
            
            '''
            Proof Of Work
            '''
            # Send encrypted PoW challenge using K
            prefix, difficulty = generate_challenge()
            challenge_data = json.dumps({"challenge": prefix, "difficulty": difficulty}).encode()
            #print(f"challange_data {challenge_data}")
            enc_challenge = aes_encrypt(dh_shared_K_bytes, challenge_data)
            conn.send(enc_challenge)
            
            # Receive encrypted PoW response and validate
            enc_nonce = conn.recv(4096)
            nonce_data = json.loads(aes_decrypt(dh_shared_K_bytes, enc_nonce).decode())
            print("[✓] Successfully Reception of Proof-Of-Work")
            if not validate_proof(prefix, nonce_data.get("nonce"), difficulty):
                conn.send(b"Error: Invalid PoW")
                conn.close()    
                return
            print("[✓] Successfully Verification of Proof-Of-Work")

            '''
            Session Key Exchange
            '''
            # Step 1: Receive {SK, enc_c3} from client
            enc_msg1 = conn.recv(2048)
            #print(f"enc_msg1 {enc_msg1}")
            msg1 = json.loads(aes_decrypt(dh_shared_K_bytes, enc_msg1).decode())
            session_key_SK = b64decode(msg1["SK"])
            enc_c3 = b64decode(msg1["enc_c3"])
            c3 = json.loads(aes_decrypt(session_key_SK, enc_c3).decode())["c3"]
            #print(f"c3 {c3}")

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
                print("[X] c4 verification failed.")
                conn.close()
                return

            print(f"[✓] Final session key established with {client_login_sub_payload['username']} : {session_key_SK.hex()}")
            print("[✓] Session key verification completed.")

            # Save user info
            online_users[client_login_sub_payload["username"]] = {
                "username": client_login_sub_payload["username"],
                "ip": addr[0],
                "port": client_login_sub_payload["c_port"],
                "ephemeral_pub": client_login_sub_payload["pKc"],
                "session_key_SK": session_key_SK
            }

            print(f"[+] Authenticated {client_login_sub_payload['username']} with secure session.")

            time.sleep(5)
            exit()

        except Exception as e:
            print(f"[ERROR] {e}")
            raise
            
    except Exception as e:
        print(f"[ERROR] {e}")
        raise
    finally:
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))
    server.listen()
    print("[SERVER] Listening on port 9999...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    if not os.path.exists("server_private.pem") or not os.path.exists("server_public.pem"):
        print("[KEYGEN] Generating RSA key pair...")
        key = RSA.generate(4096)
        with open("server_private.pem", "wb") as priv_file:
            priv_file.write(key.export_key())
        with open("server_public.pem", "wb") as pub_file:
            pub_file.write(key.publickey().export_key())
        print("[KEYGEN] Keys saved.")

    with open("server_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    rsa_priv_cipher = PKCS1_OAEP.new(private_key)

    start_server()
