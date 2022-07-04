#! /usr/bin/env python3

"""
On My Way 3/3
PwnMe CTF 2022
https://ctf.pwnme.fr/
"""

import dijkstra3d  # type: ignore
import numpy as np

from utils import ENTREE, SORTIE, on_my_way, sign

HOST = "pwn.pwnme.fr"
PORT = 7002

BLOCK  = ord("X")

def solve_pathfind(layers: list[list[bytes]]) -> str | None:
    """
    Compute a valid path between E and S that avoids obstacles (X) in the given 3D matrix,
    using a Dijkstra path finding algorithm
    """

    size = len(layers)
    # Initialize a 3D array with 1 in each cell (meaning its weight is minimal)
    field = np.ones((size, size, size), dtype=np.int32)
    pos_e = None
    pos_s = None
    for i_z, layer in enumerate(layers):
        for i_y, line in enumerate(layer[::-1]):
            for i_x, char in enumerate(line):
                if char == BLOCK:
                    # If it's an X, give it the maximum weight to make it impassable
                    field[i_x][i_y][i_z] = 2147483647
                elif char == ENTREE:
                    pos_e = (i_x, i_y, i_z)
                elif char == SORTIE:
                    pos_s = (i_x, i_y, i_z)
    print("E:", pos_e)
    print("S:", pos_s)

    if pos_e and pos_s:
        # Pathfind between E and S, using connectivity=6 because we don't want diagonals
        path: list[list[np.int32]] = dijkstra3d.dijkstra(field, pos_e, pos_s, connectivity=6)
        res_list = []
        for (x1, y1, z1), (x2, y2, z2) in zip(path, path[1:]):
            x = int(x2) - int(x1)
            y = int(y2) - int(y1)
            z = int(z2) - int(z1)
            sign_x, sign_y, sign_z = sign(x), sign(y), sign(z)

            if x != 0:
                res_list.append(f"x{sign_x}")
            elif y != 0:
                res_list.append(f"y{sign_y}")
            elif z != 0:
                res_list.append(f"z{sign_z}")
        return ";".join(res_list)
    else:
        return None

def main() -> None:
    on_my_way(HOST, PORT, solve_pathfind)
            
if __name__ == "__main__":
    main()
