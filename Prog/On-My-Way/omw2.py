#! /usr/bin/env python3

"""
On My Way 2/3
PwnMe CTF 2022
https://ctf.pwnme.fr/
"""

from utils import get_e_s_coords, on_my_way, sign

HOST = "pwn.pwnme.fr"
PORT = 7001

def solve_path(layers: list[list[bytes]]) -> str | None:
    """
    Compute the shortest path between E and S in the given 3D matrix
    """

    pos_e, pos_s = get_e_s_coords(layers)
    print("E:", pos_e)
    print("S:", pos_s)

    if pos_e and pos_s:
        # Get the difference between each pair of coordinates
        diff_x, diff_y, diff_z = [s - e for e, s in zip(pos_e, pos_s)]
        sign_x, sign_y, sign_z = sign(diff_x), sign(diff_y), sign(diff_z)

        res_list  = [f"x{sign_x}"] * abs(diff_x)
        res_list += [f"y{sign_y}"] * abs(diff_y)
        res_list += [f"z{sign_z}"] * abs(diff_z)
        return ";".join(res_list)
    else:
        return None

def main() -> None:
    on_my_way(HOST, PORT, solve_path)
            
if __name__ == "__main__":
    main()
