#!/usr/bin/env python3
import base64
import hashlib
import json
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.backends import default_backend

# === Replace these with values from your own masterkey.cryptomator file ===
SCRYPT_SALT = base64.b64decode("UqJNx7ErUi0=")
SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
WRAPPED_KEY = base64.b64decode("lHNX7aQFTvOMZcWoux5v+rbY3F3a/mZrSBhq+qu5x+5IDfLfA97EeA==")

with open("/usr/share/john/password.lst", "r") as f:
    for password in f:
        password = password.strip()
        if not password:
            continue
        try:
            # Derive Key Encryption Key (KEK) using scrypt
            kek = hashlib.scrypt(
                password.encode(),
                salt=SCRYPT_SALT,
                n=SCRYPT_N,
                r=SCRYPT_R,
                p=SCRYPT_P,
                dklen=SCRYPT_DKLEN
            )
            # Attempt to unwrap the master key using AES Key Unwrap
            masterkey = aes_key_unwrap(kek, WRAPPED_KEY, backend=default_backend())
            print(f"[OK] {password}: {masterkey.hex()}")
        except Exception:
            # Most attempts will fail; only print on success
            pass
