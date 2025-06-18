#!/usr/bin/env python3
import json, base64, hashlib, binascii, sys

# Load metadata from masterkey.cryptomator
with open("masterkey.cryptomator", "r") as f:
    metadata = json.load(f)

salt = base64.b64decode(metadata["scryptSalt"])
encrypted = base64.b64decode(metadata["primaryMasterKey"])

N = metadata["scryptCostParam"]
r = metadata["scryptBlockSize"]
p = 1
dklen = 32

def is_probably_valid(data):
    return all(32 <= b <= 126 for b in data[:6])  # printable ASCII

with open("/usr/share/john/password.lst", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        password = line.strip().encode()
        try:
            derived = hashlib.scrypt(password, salt=salt, n=N, r=r, p=p, dklen=dklen)
            decrypted = bytes(a ^ b for a, b in zip(derived, encrypted))
            if is_probably_valid(decrypted):
                print(f"[SUCCESS] {password.decode()}: {binascii.hexlify(decrypted).decode()}")
        except Exception:
            continue
