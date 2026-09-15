import json
import socket
import struct
import sys

import numpy as np
from PIL import Image

from dh_2105169 import (generate_parameters, generate_private_key, compute_public_value, compute_shared_secret, derive_aes_key,)
from aes_2105169 import get_key_expansion, get_round_keys, aes_ecb_encrypt, aes_cbc_encrypt

HOST = "127.0.0.1"
PORT = 65432
K_BITS = 128
DEFAULT_IMAGE_PATH = "Input_Image/2_60x60.png"


def send_msg(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">Q", len(payload)) + payload)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed before expected data arrived")
        buf.extend(chunk)
    return bytes(buf)


def recv_msg(sock: socket.socket) -> bytes:
    (length,) = struct.unpack(">Q", recv_exact(sock, 8))
    return recv_exact(sock, length)


def load_image(path: str):
    with Image.open(path) as img:
        img = img.convert("RGB")
        pixel_data = np.array(img)
        height, width, _ = pixel_data.shape
        return pixel_data.tobytes(), width, height, img.mode


def main():
    image_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IMAGE_PATH

    try:
        flat_pixels, width, height, mode = load_image(image_path)
    except FileNotFoundError:
        print(f"Image file not found: {image_path}")
        return

    print(f"Connecting to Bob at {HOST}:{PORT} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((HOST, PORT))
        except ConnectionRefusedError:
            print("Could not connect to Bob. Is bob.py running?")
            return
        print("Connected to Bob")

        P, g = generate_parameters(K_BITS)
        Ka = generate_private_key(K_BITS)
        A = compute_public_value(Ka, g, P)

        handshake = {
            "P": P, "g": g, "A": A,
            "width": width, "height": height, "mode": mode,
        }
        send_msg(sock, json.dumps(handshake).encode("utf-8"))

        reply = json.loads(recv_msg(sock).decode("utf-8"))
        B = reply["B"]

        shared_secret = compute_shared_secret(B, Ka, P)
        print(f"Shared secret: {shared_secret}")

        aes_key = derive_aes_key(shared_secret, K_BITS)
        key_expansion = get_key_expansion(aes_key)
        round_keys = get_round_keys(key_expansion)

        
        ecb_ciphertext = aes_ecb_encrypt(flat_pixels, round_keys)
        print(f"ecb_ciphertex: {len(ecb_ciphertext)}")
        send_msg(sock, ecb_ciphertext)

        print(f"Sent {len(flat_pixels)} bytes of plaintext ({width}x{height} RGB image)")
        print(f"Sent {len(ecb_ciphertext)} bytes of ciphertext")


        # cbc_ciphertext = aes_cbc_encrypt(flat_pixels, round_keys)
        # print(f"cbc_ciphertex: {len(cbc_ciphertext)}")
        # send_msg(sock, cbc_ciphertext)

        # print(f"Sent {len(flat_pixels)} bytes of plaintext ({width}x{height} RGB image)")
        # print(f"Sent {len(cbc_ciphertext)} bytes of ciphertext")


if __name__ == "__main__":
    main()