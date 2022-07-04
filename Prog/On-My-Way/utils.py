from typing import Callable, Literal

import pwn  # type: ignore

ENTREE = ord("E")
SORTIE = ord("S")

def parse_data(data: bytes) -> list[list[bytes]] | None:
    """
    Parse the data sent by the server and returns it as a matrix of bytes
    """

    layers = [x.strip() for x in data.split(b"\n-\n")]
    if b"Answer" in layers[-1]:
        return [matrix.split(b"\n") for matrix in layers[:-1]]
    else:
        return None

def sign(x: int) -> Literal["+", "-"]:
    """
    Returns "+" or "-" depending on the sign of x
    """

    if x >= 0:
        return "+"
    else:
        return "-"

def get_e_s_coords(layers: list[list[bytes]]) -> tuple[tuple[int, int, int] | None, tuple[int, int, int] | None]:
    """
    Returns the coordinates of E and S as a couple of triplets (x, y, z), returning early if both are found before the end
    """

    pos_e = None
    pos_s = None
    for i_z, layer in enumerate(layers):
        for i_y, line in enumerate(layer[::-1]):
            for i_x, char in enumerate(line):
                if char == ENTREE:
                    pos_e = (i_x, i_y, i_z)
                elif char == SORTIE:
                    pos_s = (i_x, i_y, i_z)
                if pos_e and pos_s:
                    return pos_e, pos_s
    return pos_e, pos_s

def on_my_way(host: str, port: int, solver: Callable[[list[list[bytes]]], int | str | None]) -> None:
    """
    Connect to the server and solve the maze using the given solving function
    """

    p = pwn.remote(host, port)

    while True:
        try:
            data: bytes = p.recvuntil(b">> ")
        except EOFError:
            # If we reach EOF from server, it means we either got the flag or there was a problem
            # Either way, print the remaining data before closing
            print(p.recvall().decode())
            p.close()
            break

        print(data.decode())
        layers = parse_data(data)
        if layers:
            result = solver(layers)
            print("RESULT:", result)
            if not result:
                print("Error: Could not calculate result :c")
                print("Layers:", layers)
                return
            p.sendline(str(result).encode())
        else:
            break
