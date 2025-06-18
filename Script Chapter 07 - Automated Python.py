#!/usr/bin/env python3
import json, base64, hashlib, sys
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.backends import default_backend

# Load metadata from masterkey.cryptomator
with open("masterkey.cryptomator", "r") as f:
    metadata = json.load(f)

salt = base64.b64decode(metadata["scryptSalt"])
wrapped_key = base64.b64decode(metadata["primaryMasterKey"])

N = metadata["scryptCostParam"]
r = metadata["scryptBlockSize"]
p = metadata.get("scryptParallelization", 1)  # default to 1 if not present
dklen = 32  # Cryptomator always uses 32 bytes for the KEK

with open("/usr/share/john/password.lst", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        password = line.strip()
        if not password:
            continue
        try:
            # Derive the Key Encryption Key (KEK) using scrypt
            kek = hashlib.scrypt(password.encode(), salt=salt, n=N, r=r, p=p, dklen=dklen)
            # Attempt to unwrap the master key using AES Key Unwrap
            masterkey = aes_key_unwrap(kek, wrapped_key, backend=default_backend())
            print(f"[SUCCESS] {password}: {masterkey.hex()}")
        except Exception:
            continue  # Most attempts will fail; only print on success
