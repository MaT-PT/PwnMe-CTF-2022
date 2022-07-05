#! /usr/bin/env python3

"""
RsaMadness
PwnMe CTF 2022
https://ctf.pwnme.fr/
"""

"""
This encryption algorithm uses the product of 32 random 32-byte-long primes as
its secret key. This is extremely weak as finding its prime factor decomposition
is literally instant on a modern computer.
I used the program msieve from https://github.com/radii/msieve to find the
factors easily, then hardcoded them into this script.
Once we have the prime factors, it’s trivial to reverse the RSA algorithm by
computing their Carmichael’s totient function and using it to find the modular
inverse.
"""

import math

from Crypto.Util.number import long_to_bytes

n = 7119541149326911263846237336068827035426390978903518184071800577216994524551352495493081918851614130414331517984836350572442636378573029918244826773120934619489882189716217950746021474614776218719283095363211027209022463670918163108226484066350208938841262463820714679754689007199511102068228362022891339
e = 65537
c = 2677813284789904126438760381359441846563302259269282617284434686954175401256426228859726004471829287478436507358546887844300713181475644091802430738029057414949633797451370298947353237612172383915668526623229664084518635473132876673558581857332713891368639409620521533432667125874667705549410188263908117

factors = [2198644891, 2251025417, 2357822911, 2423999881, 2470236277, 2540464159, 2640483821, 2666729449, 2823253471, 2838669527, 2865747971, 2899467931, 2988954343, 3003972773, 3172761587, 3246135349, 3316767901, 3359522891, 3437669927, 3458545777, 3478381031, 3557092417, 3559422193, 3560174803, 3560322977, 3632401841, 3681108461, 3788558861, 3886443779, 3890200829, 4036970099, 4045097149]

def modular_inverse(factors: list[int]) -> int:
    # Carmichael’s totient function
    l = math.lcm(*[x - 1 for x in factors])

    """Compute e⁻¹ mod l
    # Algorithm taken from https://math.stackexchange.com/questions/1090239/fastest-way-to-find-modular-multiplicative-inverse"""

    u = e
    v = l

    x1 = 1
    x2 = 0

    while u != 1:
        q = v // u
        r = v - q * u
        x = x2 - q * x1

        v = u
        u = r
        x2 = x1
        x1 = x

    return x1 % l

d = modular_inverse(factors)
f = pow(c, d, n)
decrypted = long_to_bytes(f)
print("Flag:", decrypted.decode())
