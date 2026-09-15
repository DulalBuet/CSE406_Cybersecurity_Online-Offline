import socket
import struct
import json

from dh_2105169 import generate_prime, generate_parameters, generate_private_key, compute_public_value, compute_shared_secret, derive_aes_key
from aes_2105169 import get_key_expansion, get_round_keys, aes_cbc_encrypt, aes_cbc_decrypt, aes_ecb_encrypt, aes_ecb_decrypt

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
    print(f"Alice connected to Bob at {HOST}:{PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
    
        P, g = generate_parameters(K_BITS)
        #print(f"P = {P}, g = {g}")

        Ka = generate_private_key(K_BITS)
        #print(f"Ka = {Ka}")

        A = compute_public_value(Ka, g, P)
        #print(f"A = {A}")

        send_msg(sock, json.dumps({"P": P, "g": g, "A": A}).encode("utf-8"))

        reply = json.loads(recv_msg(sock).decode("utf-8"))
        B = reply["B"]

        shared_secret = compute_shared_secret(B, Ka, P)
        print(f"shared secret value = {shared_secret}")

        aes_key = derive_aes_key(shared_secret, K_BITS)
        #print(f"AES - kye: {aes_key.hex()}") 

        key_expansion = get_key_expansion(aes_key)
        #print(f"key expansion= {key_expansion}")

        round_keys = get_round_keys(key_expansion)
        #print(f"Round keys: {round_keys}")

        while True: 
            plaintext = input("Enter plaintext to send to Bob: ")
            # print(f"Plaintext: {plaintext}")

            encoded_text = plaintext.encode("utf-8")
            #print(f"Hex code: {encoded_text.hex()}")

            cbc_ciphertext = aes_cbc_encrypt(encoded_text, round_keys)
            send_msg(sock, cbc_ciphertext)
            print(f"Plaintext: {plaintext}")
            print(f"cbc ciphertext: {cbc_ciphertext.hex()}")
            
            ebc_ciphertext = aes_ecb_encrypt(encoded_text, round_keys)
            send_msg(sock, ebc_ciphertext)
            print(f"ebc ciphertext: {ebc_ciphertext.hex()}")


if __name__ == "__main__":
    main()