import socket
import struct
import json

from dh_2105169 import generate_prime, generate_parameters, generate_private_key, compute_public_value, compute_shared_secret, derive_aes_key
from aes_2105169 import get_key_expansion, get_round_keys, aes_cbc_encrypt, aes_cbc_decrypt, aes_ecb_decrypt

HOST = "127.0.0.1"
PORT = 65432
K_BITS = 256    


def send_msg(sock: socket.socket, payload: bytes):
    sock.sendall(struct.pack(">Q", len(payload)) + payload)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed before expected data arrived")
        buf += chunk
    return buf


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
                    #print(f"P : {P}, g: {g}, A: {A}")

                    Kb = generate_private_key(K_BITS)
                    #print(f"Kb: {Kb}")

                    B = compute_public_value(Kb, g, P)
                    #print(f"B: {B}")

                    send_msg(conn, json.dumps({"B": B}).encode("utf-8"))

                    shared_secret = compute_shared_secret(A, Kb, P)
                    print(f"Shared secret key: {shared_secret}")

                    aes_key = derive_aes_key(shared_secret, K_BITS)
                    #print(f"AES key (hex): {aes_key.hex()}")

                    key_expansion = get_key_expansion(aes_key)
                    round_keys = get_round_keys(key_expansion)
                    # print(f"Round key: {round_keys}")
                    
                    while True:
                        cbc_ciphertext = recv_msg(conn)
                        print(f"cbc ciphertext: {cbc_ciphertext.hex()}")

                        cbc_plaintext = aes_cbc_decrypt(cbc_ciphertext, round_keys)
                        print(f"cbc recovered plaintext: {cbc_plaintext.decode('utf-8')}")

                        ecb_ciphertext = recv_msg(conn)
                        print(f"ecb ciphertext: {ecb_ciphertext.hex()}")
                        ecb_plaintext = aes_ecb_decrypt(ecb_ciphertext, round_keys)
                        print(f"ecb recoverd Plaintext: {ecb_plaintext.decode('utf-8')}")



if __name__ == "__main__":
    main()