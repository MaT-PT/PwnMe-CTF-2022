#! /usr/bin/env python3

"""
On My Way 1/3
PwnMe CTF 2022
https://ctf.pwnme.fr/
"""

from utils import get_e_s_coords, on_my_way

HOST = "pwn.pwnme.fr"
PORT = 7000

def solve_distance(layers: list[list[bytes]]) -> int | None:
    """
    Compute the Manhattan distance between E and S in the given 3D matrix
    """

    pos_e, pos_s = get_e_s_coords(layers)
    print("E:", pos_e)
    print("S:", pos_s)

    if pos_e and pos_s:
        # Sum of the absolute distances between each pair of coordinates
        return sum(abs(s - e) for e, s in zip(pos_e, pos_s))
    else:
        return None

def main() -> None:
    on_my_way(HOST, PORT, solve_distance)
            
if __name__ == "__main__":
    main()
