#! /usr/bin/env python3

"""
Exponential Machine
PwnMe CTF 2022
https://ctf.pwnme.fr/
"""

######

"""
Disclaimer:
This is supposed to be a crypto challenge. However, this is not my strong suit,
so I instead treated as a programming challenge.


This code solves the Exponential Machine challenge using clever bruteforcing
by exploiting the fact that (a**x) % n == 1 if x == 0.
Since we are able to divide x by anything we want, this allows us to know if
our number N is greater or lower than x: x // N == 0 iif N > x.

Essentially, we have the following relationships:
* x == 0 => (a**x) % n == 1
* x // N == 0 <=> N > x
Therefore, N > x => (a**(x // N)) == 1
There is a chance that we get a false positive and that the result happens to
be 1 even though N ≤ x, because of modular arithmetic. However, this is quite
unlikely, and it isn’t the case for this challenge, so this is irrelevant here.
For a more general application though, this fact should be taken into account.

We start by finding the number of digits of x by increasing the magnitude of N
until we get 1 as a result.

This code file has two implementations of this algorithm:

- find_size():
The first one is a naive approach that sends 10**c for increasing values of c
until it hits 1 as a result. We then know that 10**(c-1) ≤ x < 10**c, so
len(x) == c (because len(10**c) == c+1).

- find_size_dicho():
The second implementation uses dichotomy by finding between which powers of 2
x lies, and then seeing if it is greater or lower than the middle point.
We repeat that until the interval size is 1. This allows us to close in on x
much faster than with the naive approach.

Now that we know the size of x, we can start finding its digits.
As before, there are two possible algorithms in this file:

- find_x():
Once again, the first one is a naive approach.
By increasing the leftmost digit d of N until N > x, we know that x[0] == d-1.
When this happens, we go on to the second digit, and keep this up until we
reach the end.
There is a special case when d == 9 and N ≤ x, 9 is the right digit and we can
go to the next position.

Examples:
* x = 42:
  We try 10, 20, 30, 40, 50, 41, 42, 43.
  42 ≤ x < 43, so x == 42.
* x = 93:
  We try 10, 20, 30, 40, 50, 60, 70, 80, 90, 91, 92, 93, 94.

- find_x_dicho():
You guessed it, the second version is also a dichotomy.
Like before, we find the first digit before moving on to the next one.
This time though, we use a slightly more optimized way to close in on
the right digit.
We start with d = 5, and depending on whether N is greater or lower than x,
we try another digit that is close to the middle of the remaining interval.

Here is the table used in this implementation:

5 -> 7 -> 8 -> 9
5 -> 7 -> 6
5 -> 2 -> 3 -> 4
5 -> 2 -> 1 -> 0

Examples:
* x = 42:
  We try 50, 20, 30, 40, 45, 42, 43.
* x = 93:
  We try 50, 70, 80, 90, 95, 92, 93, 94.

Once we have x, we can find the flag by interpreting it as a numeric
representation of an ASCII byte string, and boom! Challenge completed.

x = 2618521374154667937700237545820763222764270424716632016643209974500984977412275054927860282493
Flag: PWNME{68dab83e7f2664361e701f5d82bd9be4}

---

Those are the statistics for the value of x used in the challenge:

Nb. of digits in x:  95 attempts for naive implementation (1 -> 10 -> 100 -> …)
                     14 attempts using dichotomy (85% faster!)
Finding value of x: 490 attempts for naive implementation (0 -> 1 -> 2 -> …)
                    313 attempts using dichotomy (36% faster!)

Total: 585 attempts for naive algorithms (original implementation)
       327 attempts for optimized algorithms (dichotomy) -> 44% faster overall!
"""

######

"""
TODO:
There is a lot of repeated code, it should be wrappable in auxilliary functions.
Code should also be split into multiples files.
"""

import re

import pwn  # type: ignore

HOST = "pwn.pwnme.fr"
PORT = 7003
MAX_ATTEMPTS = 64

RE_RESULT = re.compile(r"Result : (\d+)")
RE_ATTEMPTS = re.compile(r"You have only (\d+) attempts")
retry_count = 0
attempt_count = 0

def send_operation(sock: pwn.tube, operator: str, operand: str | int) -> str | None:
    """
    Sends the operator and operand via the given tube.
    Parses and returns the result given by the server, or None if it cannot be found.
    """

    global attempt_count

    print("Trying", operator, operand)
    attempt_count += 1
    sock.sendline(f"{operator}\n{operand}".encode())

    try:
        data: str = sock.recvuntil(b"result : ").decode()
    except EOFError:
        sock.close()
        data = sock.recvall(1).decode()
    print(data)
    match = RE_RESULT.search(data)
    if match:
        return match.group(1)
    else:
        return None

def find_size() -> int:
    """
    Finds the number of digits in x by trying to divide it by successive powers of 10
    until the result is 1 (at which point the divisor is greater than x).
    Complexity: n + 1 -> O(n) [n = number of digits]
    """

    global retry_count

    num = "1"

    while True:
        p = pwn.remote(HOST, PORT)
        data: str = p.recvuntil(b"result : ").decode()
        print(data)

        try:
            max_attempts_match = RE_ATTEMPTS.search(data)
            if max_attempts_match:
                max_attempts = int(max_attempts_match.group(1))
                print("Max attempts:", max_attempts)
        except:
            max_attempts = MAX_ATTEMPTS

        for _ in range(max_attempts):
            size = len(num)
            print(f"{size = }")

            result = send_operation(p, "/", num)
            if result:
                if result == "1":
                    return size - 1
                else:
                    num += "0"
            else:
                print("NO RESULT")
                retry_count += 1
        p.close()

def find_size_dicho() -> int:
    """
    Finds the number of digits in x by trying to divide it by powers of 10
    until the result is 1 (at which point the divisor is greater than x).
    This implementation uses a dichotomy method to minimize the number of requests.
    Complexity: 2 * (1 + int(log2(n))) -> O(log(n)) [n = number of digits]
    """

    global retry_count

    size = 1
    min_size = 0
    max_size = size

    while True:
        p = pwn.remote(HOST, PORT)
        data: str = p.recvuntil(b"result : ").decode()
        print(data)

        try:
            max_attempts_match = RE_ATTEMPTS.search(data)
            if max_attempts_match:
                max_attempts = int(max_attempts_match.group(1))
                print("Max attempts:", max_attempts)
        except:
            max_attempts = MAX_ATTEMPTS

        for _ in range(max_attempts):
            num = "1" + "0" * (size - 1)
            print(f"{size = }, {min_size = }, {max_size = }")

            result = send_operation(p, "/", num)
            if result:
                if result == "1":
                    if min_size > 0:
                        max_size = size
                        size = min_size + (max_size - min_size) // 2
                    else:
                        min_size = size // 2
                        size -= min_size // 2
                else:
                    if min_size > 0:
                        min_size = size
                        size += (max_size - min_size) // 2
                    else:
                        size *= 2
                        max_size = size

                if max_size - min_size <= 1:
                    return min_size
            else:
                print("NO RESULT")
                retry_count += 1
        p.close()

def find_x(size: int) -> int:
    """
    Finds the value of x by dividing it by a number whose digits we increment
    successively from left to right until the result is 1.
    When it happens, we know that x is between this number and the previous one,
    so we keep the first digits of the previous number and move on to the next digit.
    """

    global retry_count

    num = "0" * size
    digit = 1
    pos = 0
    next_pos = False

    while True:
        p = pwn.remote(HOST, PORT)
        data: str = p.recvuntil(b"result : ").decode()
        print(data)

        try:
            max_attempts_match = RE_ATTEMPTS.search(data)
            if max_attempts_match:
                max_attempts = int(max_attempts_match.group(1))
                print("Max attempts:", max_attempts)
        except:
            max_attempts = MAX_ATTEMPTS

        for _ in range(max_attempts):
            # Convert number to the list of its digits in order to change them (as str is immutable)
            num_list = list(num)
            num_list[pos] = str(digit)

            if next_pos:
                pos += 1
                if pos >= size:
                    num = "".join(num_list)
                    return int(num)
                digit = 1
                num_list[pos] = str(digit)

            num = "".join(num_list)

            result = send_operation(p, "/", num)
            if result:
                print(f"Before: {digit = }, {pos = }")
                if result == "1":
                    if digit > 0:
                        digit -= 1
                    next_pos = True
                else:
                    if digit < 9:
                        digit += 1
                        next_pos = False
                    else:
                        next_pos = True

                print(f"After:  {digit = }, {pos = }")
            else:
                print("NO RESULT")
                next_pos = False
                retry_count += 1
        p.close()

def find_x_dicho(size: int) -> int:
    """
    Finds the value of x by dividing it by a number whose digits we change
    successively from left to right until the result is 1, using dichotomy
    to optimize the number of attempts.
    """

    global retry_count

    num = "0" * size
    digit = 5
    pos = 0
    next_pos = False

    while True:
        p = pwn.remote(HOST, PORT)
        data: str = p.recvuntil(b"result : ").decode()
        print(data)

        try:
            max_attempts_match = RE_ATTEMPTS.search(data)
            if max_attempts_match:
                max_attempts = int(max_attempts_match.group(1))
                print("Max attempts:", max_attempts)
        except:
            max_attempts = MAX_ATTEMPTS

        for _ in range(max_attempts):
            num_list = list(num)
            num_list[pos] = str(digit)

            if next_pos:
                pos += 1
                if pos >= size:
                    num = "".join(num_list)
                    return int(num)
                digit = 5
                num_list[pos] = str(digit)

            num = "".join(num_list)

            result = send_operation(p, "/", num)
            if result:
                print(f"Before: {digit = }, {pos = }")
                if result == "1": # num ≥ x,
                    # digit is too big
                    print("LESS")
                    match digit:
                        case 1 | 3 | 4 | 6 | 8 | 9:
                            digit -= 1
                            next_pos = True
                        case 2 | 7:
                            digit -= 1
                            next_pos = False
                        case 5:
                            digit = 2
                            next_pos = False
                else: # num < x
                    # digit is good or too low
                    print("MORE")
                    match digit:
                        case 0 | 1 | 4 | 6 | 9:
                            next_pos = True
                        case 2 | 3 | 7 | 8:
                            digit += 1
                            next_pos = False
                        case 5:
                            digit = 7
                            next_pos = False

                print(f"After:  {digit = }, {pos = }")
            else:
                print("NO RESULT")
                next_pos = False
                retry_count += 1
        p.close()

def main() -> None:
    #size = find_size()
    size = find_size_dicho()
    print(f"FOUND SIZE: x is {size} digits long")
    print(f"This took {attempt_count} attempts with {retry_count} retries")

    #x = find_x(size)
    x = find_x_dicho(size)
    print(f"ANSWER FOUND: {x = }")
    print(f"This took {attempt_count} attempts with {retry_count} retries")

    # Flag is raw ASCII bytes represented as an integer
    flag = x.to_bytes((x.bit_length() + 7) // 8, byteorder="big").decode()
    print(">>> FLAG:", flag)

if __name__ == "__main__":
    main()
