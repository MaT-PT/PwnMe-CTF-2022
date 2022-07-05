#! /usr/bin/env python3

"""
Volatile Storage
PwnMe CTF 2022
https://ctf.pwnme.fr/
"""

import sys
from base64 import b64encode
from hashlib import md5

"""
Generate the password for a given username on https://volatile-storage.pwnme.fr/
"""

if len(sys.argv) > 1:
    username = sys.argv[1]
    print("Username:", username)
else:
    username = input("Username: ")

hash = md5(username.encode())
middle = hash.digest()[4:12].hex()

password = b64encode(middle.encode()).decode()
print("Password:", password)
