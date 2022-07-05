#!/usr/bin/env python3

"""
To Basics
PwnMe CTF 2022
https://ctf.pwnme.fr/
"""

"""
This one is pretty straightforward, the secret used is a single random digit
repeated len(FLAG) times, not a real random number.
To find the flag, we simply try to decrypt it using every possible digit and
printing each value, the correct flag should look like PWNME{xxx}.
"""

FLAG_ENCRYPTED = open("flag-encrypted.txt", "r").read().split(",")

def decrypt(flag: list[str], digit: int):
    return [chr((int(v) - i) ^ ord(str(digit))) for i, v in enumerate(flag)]

for i in range(10):
    print(i)
    print("".join(decrypt(FLAG_ENCRYPTED, i)))
