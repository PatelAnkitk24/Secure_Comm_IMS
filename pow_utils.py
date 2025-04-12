# pow_utils.py
import hashlib
import os

def generate_challenge():
    prefix = os.urandom(8).hex()
    difficulty = 3  # leading 3 zeros required
    return prefix, difficulty

def validate_proof(prefix, nonce, difficulty):
    guess = f"{prefix}{nonce}".encode()
    digest = hashlib.sha256(guess).hexdigest()
    return digest.startswith('0' * difficulty)

def solve_proof(prefix, difficulty):
    nonce = 0
    while True:
        if validate_proof(prefix, str(nonce), difficulty):
            return str(nonce)
        nonce += 1
