#!/usr/bin/env python3
import base64
import hashlib
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.backends import default_backend

# Parameters from masterkey.cryptomator
salt = base64.b64decode("UqJNx7ErUi0=")
wrapped_key = base64.b64decode("lHNX7aQFTvOMZcWoux5v+rbY3F3a/mZrSBhq+qu5x+5IDfLfA97EeA==")
N, r, p, dklen = 32768, 8, 1, 32

# Read password list and try each password
with open("password.list", "r") as f:
    for i, password in enumerate(f, 1):
        password = password.strip()
        if not password:
            continue
        print(f"[{i}] Testing password: {password}")
        try:
            # Derive KEK using scrypt
            kek = hashlib.scrypt(password.encode(), salt=salt, n=N, r=r, p=p, dklen=dklen)
            # Unwrap the master key
            masterkey = aes_key_unwrap(kek, wrapped_key, backend=default_backend())
            print(f"[SUCCESS] Password: {password}")
            print(f"Master Key (hex): {masterkey.hex()}")
            print(f"Master Key Length: {len(masterkey)} bytes")
            break  # Stop after finding the correct password
        except Exception as e:
            print(f"[FAILED] Password: {password} (Error: {str(e)})")
