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

def load_config():
    with open("config.json") as f:
        return json.load(f)

def get_user_pass_as_W():
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    # Derive W from password
    W = derive_password_key(password, b'static_salt') # W with len 32 byte
    print(f"W {W}")
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

def main():
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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((config["server_ip"], config["server_port"]))
    s.send(json.dumps(cleint_login_payload).encode())
    print("[✓] Successfully transmission of client's login payload")
    #exit()

    '''
    Second Login transaction from server to client
    '''
    c_rsa_priv_key = RSA.import_key(c_rsa_priv)
    client_rsa_priv_cipher = PKCS1_OAEP.new(c_rsa_priv_key)
    # Receive encrypted W{g^b mod p} and server pub key
    server_login_payload = json.loads(s.recv(4096).decode())
    server_login_sub_payload = {}
    try:
        if server_login_payload["type"] == "login":
            '''
            Perfect Forward Secrecy
            '''
            server_login_aes_key = client_rsa_priv_cipher.decrypt(b64decode(server_login_payload["rsa_enc_server_login_aes_key"]))
            #print(f"server_login_aes_key {server_login_aes_key}")
            received_server_login_sub_payload = json.loads(aes_decrypt(server_login_aes_key, b64decode(server_login_payload["aes_enc_server_login_sub_payload"])).decode())

            enc_gb = b64decode(received_server_login_sub_payload["Wgb"])
            server_login_sub_payload["gb"] = int(aes_decrypt(W,enc_gb))
            dh_shared_K = compute_shared_secret(server_login_sub_payload["gb"], a, p)
            dh_shared_K_bytes = dh_shared_K.to_bytes((dh_shared_K.bit_length() + 7) // 8, 'big')
            #print(f"Shared key bit length: {dh_shared_K.bit_length()}")
            dh_shared_K_bytes = hashlib.sha256(dh_shared_K.to_bytes((dh_shared_K.bit_length() + 7) // 8, 'big')).digest()
            if (dh_shared_K_bytes):
                print("[✓] Shared DH secret K established.")
            #print(f"dh_shared_k_bytes {dh_shared_K_bytes}")
            a = g_a = 0 # Forget private and public DH keys for PFS
            
            server_login_sub_payload["time"] = received_server_login_sub_payload["time"]
            print("[✓] Successfully reception of server's login payload")

            '''
            Proof Of Work
            '''
            # Receive encrypted challenge from server (using K)
            enc_challenge = s.recv(4096)
            challenge_json = json.loads(aes_decrypt(dh_shared_K_bytes, enc_challenge).decode())
            #print(f"challenge_json {challenge_json}")
            #print(f"[CHALLENGE] Solve {challenge_json['challenge']} with difficulty {challenge_json['difficulty']}")

            # Solve and respond with encrypted proof
            nonce = solve_proof(challenge_json["challenge"], challenge_json["difficulty"])
            enc_nonce = aes_encrypt(dh_shared_K_bytes, json.dumps({"nonce": nonce}).encode())
            s.send(enc_nonce)
            print("[✓] Successfully Transmission of Proof-Of-Work")

            '''
            Session Key Exchange
            '''
            
            # Step 1: Generate session key SK and random c3
            session_key_SK = get_random_bytes(32)
            c3 = random.randint(100, 999)
            #print(f"c3 {c3}")
            encrypted_c3 = aes_encrypt(session_key_SK, json.dumps({"c3": c3}).encode())
            msg1 = {
                "SK": b64encode(session_key_SK).decode(),
                "enc_c3": b64encode(encrypted_c3).decode()
            }
            enc_msg1 = aes_encrypt(dh_shared_K_bytes, json.dumps(msg1).encode())
            #print(f"enc_msg1 {enc_msg1}")
            s.send(enc_msg1)

            # Step 2: Receive and decrypt server response
            enc_msg2 = s.recv(2048)
            msg2 = json.loads(aes_decrypt(dh_shared_K_bytes, enc_msg2).decode())
            enc_response = b64decode(msg2["enc_response"])
            response = json.loads(aes_decrypt(session_key_SK, enc_response).decode())
    
            if response["c3_check"] != c3 - 1:
                print("[X] c3 verification failed.")
                s.close()
                return
            c4 = response["c4"]
            
            # Step 3: Send SK_check = c4 - 1 encrypted with SK, then with shared_K
            enc_msg3 = aes_encrypt(session_key_SK, json.dumps({"c4_check": c4 - 1}).encode())
            final_msg = aes_encrypt(dh_shared_K_bytes, json.dumps({"enc_c4_check": b64encode(enc_msg3).decode()}).encode())
            s.send(final_msg)

            print(f"[+] Final session key established: {session_key_SK.hex()}")
            
            time.sleep(5)
            exit()
        else:
            s.send(b"Error: expecting login type frame from server")
            s.close()    
            return
    except Exception as e:
        print(f"[ERROR] {e}")
        raise

    




    


    s.close()

if __name__ == "__main__":
    try: 
        main()
    except Exception as e:
        print(f"[ERROR] {e}")
        raise
