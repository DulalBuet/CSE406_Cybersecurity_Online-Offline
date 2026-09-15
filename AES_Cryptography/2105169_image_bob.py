import json
import socket
import struct

import numpy as np
from PIL import Image

from dh_2105169 import (generate_private_key, compute_public_value, compute_shared_secret, derive_aes_key)
from aes_2105169 import get_key_expansion, get_round_keys, aes_ecb_decrypt, aes_cbc_decrypt

HOST = "127.0.0.1"
PORT = 65432
K_BITS = 128
ECB_Encrypted_IMAGE_PATH = "Output_Image/ecb_encrypted_image_2_60x60.png"
ECB_Decrypted_IMAGE_PATH = "Output_Image/ecb_decrypted_image_2_60x60.png"
CBC_Encrypted_IMAGE_PATH = "Output_Image/cbc_encrypted_image_2_60x60.png"
CBC_Decrypted_IMAGE_PATH = "Output_Image/cbc_decrypted_image_2_60x60.png"


def send_msg(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">Q", len(payload)) + payload)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes, raising if the peer closes the connection early."""
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


def main():
    print(f"[BOB] Listening on {HOST}:{PORT} ...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)
        conn, address = server_sock.accept()

        with conn:
            print(f"Bob connected from {address}")

            params = json.loads(recv_msg(conn).decode("utf-8"))
            P, g, A = params["P"], params["g"], params["A"]
            width, height, mode = params["width"], params["height"], params["mode"]

            # --- Diffie-Hellman key exchange ---
            Kb = generate_private_key(K_BITS)
            B = compute_public_value(Kb, g, P)
            send_msg(conn, json.dumps({"B": B}).encode("utf-8"))

            shared_secret = compute_shared_secret(A, Kb, P)
            print(f"Shared secret: {shared_secret}")

            aes_key = derive_aes_key(shared_secret, K_BITS)
            key_expansion = get_key_expansion(aes_key)
            round_keys = get_round_keys(key_expansion)

            
            try:
                ecb_ciphertext = recv_msg(conn)
            except ConnectionError:
                print("Alice disconnected before sending an image.")
                return
            

            print(f"Received {len(ecb_ciphertext)} bytes of ciphertext")

            expected_len = width * height * 3
            pixel_bytes = ecb_ciphertext[:expected_len]
            pixel_data = np.frombuffer(pixel_bytes, dtype=np.uint8).reshape((height, width, 3))
            Image.fromarray(pixel_data, mode).save(ECB_Encrypted_IMAGE_PATH)
            print(f"Encrypted image saved to {ECB_Encrypted_IMAGE_PATH}")
        
            ecb_plaintext = aes_ecb_decrypt(ecb_ciphertext, round_keys)

            # ECB pads plaintext to a multiple of the block size, so trim any
            # trailing padding before reshaping into an image array.
            pixel_bytes = ecb_plaintext[:expected_len]
            pixel_data = np.frombuffer(pixel_bytes, dtype=np.uint8).reshape((height, width, 3))

            Image.fromarray(pixel_data, mode).save(ECB_Decrypted_IMAGE_PATH)
            print(f"Decrypted image saved to {ECB_Decrypted_IMAGE_PATH}")
            

            # try:
            #     cbc_ciphertext = recv_msg(conn)
            # except ConnectionError:
            #     print("Alice disconnected before sending an image.")
            #     return
            
            # print(f"Received {len(cbc_ciphertext)} bytes of ciphertext")


            # expected_len = width * height * 3
            # pixel_bytes = cbc_ciphertext[:expected_len]
            # pixel_data = np.frombuffer(pixel_bytes, dtype=np.uint8).reshape((height, width, 3))
            # Image.fromarray(pixel_data, mode).save(CBC_Encrypted_IMAGE_PATH)
            # print(f"Encrypted image saved to {CBC_Encrypted_IMAGE_PATH}")


            # cbc_plaintext = aes_cbc_decrypt(cbc_ciphertext, round_keys)

            # pixel_bytes = cbc_plaintext[:expected_len]
            # pixel_data = np.frombuffer(pixel_bytes, dtype=np.uint8).reshape((height, width, 3))
            # Image.fromarray(pixel_data, mode).save(CBC_Decrypted_IMAGE_PATH)
            # print(f"Decrypted image saved to {CBC_Decrypted_IMAGE_PATH}")


if __name__ == "__main__":
    main()