#!/bin/bash

# Output filenames
PRIVATE_KEY="server_private.pem"
PUBLIC_KEY="server_public.pem"

# Generate private key
openssl genpkey -algorithm RSA -out $PRIVATE_KEY -pkeyopt rsa_keygen_bits:2048

# Generate public key from private key
openssl rsa -pubout -in $PRIVATE_KEY -out $PUBLIC_KEY

echo "✅ RSA key pair generated:"
echo "  - Private key: $PRIVATE_KEY"
echo "  - Public key : $PUBLIC_KEY"
