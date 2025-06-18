#!/usr/bin/env python3
import base64, hashlib
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.backends import default_backend

salt = base64.b64decode("UqJNx7ErUi0=")
wrapped_key = base64.b64decode("lHNX7aQFTvOMZcWoux5v+rbY3F3a/mZrSBhq+qu5x+5IDfLfA97EeA==")

N, r, p, dklen = 32768, 8, 1, 32

with open("/usr/share/john/password.lst", "r") as f:
    for password in f:
        password = password.strip()
        if not password:
            continue
        try:
            kek = hashlib.scrypt(password.encode(), salt=salt, n=N, r=r, p=p, dklen=dklen)
            masterkey = aes_key_unwrap(kek, wrapped_key, backend=default_backend())
            print(f"[OK] {password}: {masterkey.hex()}")
        except Exception:
            pass
