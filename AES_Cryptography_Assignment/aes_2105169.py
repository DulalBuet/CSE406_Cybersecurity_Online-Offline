import os
import time
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult

def sub_word(word):
    t = []
    for b in word:
        t.append(Sbox[b])

    return t


def rot_word(word):
    return word[1:] + word[:1]


def sub_bytes(matrix):
    result = []
    for r in range(4):
        row = []
        for c in range(4):
            row.append(Sbox[matrix[r][c]])
        result.append(row)

    return result


def inv_sub_bytes(state):
    new_state = [[0] * 4 for _ in range(4)]

    for r in range(4):
        for c in range(4):
            new_state[r][c] = InvSbox[state[r][c]]

    return new_state


def xor_bytes(a: bytes, b: bytes) -> bytes:
    result = []

    for x, y in zip(a, b):
        result.append(x ^ y)

    return bytes(result)


def shift_rows(matrix):
    new_matrix = [row[:] for row in matrix]
    for r in range(1, 4):
        new_matrix[r] = matrix[r][r:] + matrix[r][:r]

    return new_matrix


def inv_shift_rows(matrix):
    new_matrix = [[0] * 4 for _ in range(4)]
    for j in range(4):
        new_matrix[0][j] = matrix[0][j]

    for r in range(1, 4):
        for j in range(4):
            new_col = (j + r) % 4
            new_matrix[r][new_col] = matrix[r][j]

    return new_matrix


def mix_columns(matrix):
    new_matrix = []
    for i in range(4):
        new_matrix.append([0, 0, 0, 0])
    for c in range(4):
        col = []
        for r in range(4):
            col.append(matrix[r][c])
        for r in range(4):
            new_matrix[r][c] = (gf_mult(Mixer[r][0], col[0]) ^ gf_mult(Mixer[r][1], col[1]) ^ gf_mult(Mixer[r][2], col[2]) ^ gf_mult(Mixer[r][3], col[3]))
    
    return new_matrix



def inv_mix_columns(matrix):
    new_matrix = [[0] * 4 for _ in range(4)]

    for c in range(4):
        col = [0] * 4
        for r in range(4):
            col[r] = matrix[r][c]

        for r in range(4):
            value = 0
            for k in range(4):
                value = value ^ gf_mult(InvMixer[r][k], col[k])
            new_matrix[r][c] = value

    return new_matrix


def key_schedule_params(key: bytes):
    """
    Map a raw AES key to (Nk, Nr):
        16 bytes (128 bit) -> Nk=4,  Nr=10   (AES-128)
        24 bytes (192 bit) -> Nk=6,  Nr=12   (AES-192)
        32 bytes (256 bit) -> Nk=8,  Nr=14   (AES-256)
    """
    Nk = len(key) // 4
    if Nk not in (4, 6, 8) or len(key) % 4 != 0:
        raise ValueError(f"Unsupported AES key length: {len(key)} bytes (need 16, 24, or 32)")

    Nr = {4: 10, 6: 12, 8: 14}[Nk]
    return Nk, Nr


def get_key_expansion(key: bytes, Nk: int = None, Nr: int = None) -> list:
    Nb = 4

    # Auto-detect Nk / Nr from the key length when not given explicitly,
    # so the same call site works for AES-128, AES-192 and AES-256.
    if Nk is None or Nr is None:
        Nk, Nr = key_schedule_params(key)

    w = []
    for i in range(Nk):
        row = []
        for j in range(4):
            row.append(key[4*i+j])
        w.append(row)

    total_words = Nb * (Nr + 1)
    for i in range(Nk, total_words):
        temp = w[i - 1][:]
        if i % Nk == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= Rcon[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            # Extra SubWord step required only for AES-256 (Nk=8)
            temp = sub_word(temp)
        row = []
        for j in range(4):
            row.append(w[i - Nk][j] ^ temp[j])
        
        w.append(row)

    return w


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size 

    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding")
    
    return data[:-pad_len]


def bytes_to_matrix(block: bytes) -> list:
    matrix = []

    for i in range(4):
        matrix.append([0, 0, 0, 0])

    for i in range(16):
        matrix[i % 4][i // 4] = block[i]

    return matrix


def matrix_to_bytes(state: list) -> bytes:
    out = [0] * 16
    for i in range(16):
        out[i] = state[i % 4][i // 4]

    return bytes(out)


def get_round_keys(words: list, Nr: int = None) -> list:
    # Nr can be inferred from how many key-schedule words we were given:
    # there are always Nb*(Nr+1) = 4*(Nr+1) words in total.
    if Nr is None:
        Nr = len(words) // 4 - 1

    round_keys = []
    for r in range(Nr + 1):
        flat = []
        for i in range(4):
            for j in range(4):
                flat.append(words[r*4 + i][j])
        round_keys.append(flat)

    return round_keys


def add_round_key(matrix, round_key_flat):
    rk_matrix = bytes_to_matrix(bytes(round_key_flat))

    result = []
    for r in range(4):
        row = []
        for c in range(4):
            row.append(matrix[r][c] ^ rk_matrix[r][c])
        
        result.append(row)

    return result


def encrypt_block(block: bytes, round_keys: list, Nr: int = None) -> bytes:
    # Number of rounds is just "how many round keys we have, minus one" -
    # this is the same for 10 (AES-128), 12 (AES-192) or 14 (AES-256) rounds.
    if Nr is None:
        Nr = len(round_keys) - 1

    matrix = bytes_to_matrix(block)
    matrix = add_round_key(matrix, round_keys[0])

    for rnd in range(1, Nr):
        matrix = sub_bytes(matrix)
        matrix = shift_rows(matrix)
        matrix = mix_columns(matrix)
        matrix = add_round_key(matrix, round_keys[rnd])

    # Final round: no mixColumns
    matrix = sub_bytes(matrix)
    matrix = shift_rows(matrix)
    matrix = add_round_key(matrix, round_keys[Nr])

    return matrix_to_bytes(matrix)


def aes_cbc_encrypt(plaintext: bytes, round_keys: list) -> bytes:
    iv = os.urandom(16)
    padded = pkcs7_pad(plaintext)

    ciphertext = b""
    prev = iv
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        xored = xor_bytes(block, prev)
        enc = encrypt_block(xored, round_keys)
        ciphertext += enc
        prev = enc

    return iv + ciphertext


def decrypt_block(block: bytes, round_keys: list, Nr: int = None) -> bytes:
    if Nr is None:
        Nr = len(round_keys) - 1

    matrix = bytes_to_matrix(block)
    matrix = add_round_key(matrix, round_keys[Nr])
    matrix = inv_shift_rows(matrix)
    matrix = inv_sub_bytes(matrix)

    for rnd in range(Nr - 1, 0, -1):
        matrix = add_round_key(matrix, round_keys[rnd])
        matrix = inv_mix_columns(matrix)
        matrix = inv_shift_rows(matrix)
        matrix = inv_sub_bytes(matrix)  

    matrix = add_round_key(matrix, round_keys[0])

    return matrix_to_bytes(matrix)  


def aes_cbc_decrypt(iv_and_ciphertext: bytes, round_keys: list) -> bytes:
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]
    plaintext_padded = b""
    prev = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = decrypt_block(block, round_keys)
        plaintext_padded += xor_bytes(dec, prev)
        prev = block
    
    return pkcs7_unpad(plaintext_padded)


def aes_ecb_encrypt(plaintext: bytes, round_keys: list) -> bytes:
    padded = pkcs7_pad(plaintext)
    ciphertext = b""
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        ciphertext += encrypt_block(block, round_keys)

    return ciphertext


def aes_ecb_decrypt(ciphertext: bytes, round_keys: list) -> bytes:
    plaintext_padded = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        plaintext_padded += decrypt_block(block, round_keys)

    return pkcs7_unpad(plaintext_padded)


def prepare_key(user_key: str, key_len_bytes: int = 16) -> bytes:
    key_bytes = user_key.encode('ascii')

    if len(key_bytes) > key_len_bytes:
        key_bytes = key_bytes[:key_len_bytes]
    elif len(key_bytes) < key_len_bytes:
        key_bytes = key_bytes + bytes(key_len_bytes - len(key_bytes))

    return key_bytes


def run_demo(mode: str, plaintext: str, user_key: str, key_bits: int = 128):
    if key_bits not in (128, 192, 256):
        raise ValueError("key_bits must be 128, 192, or 256")

    key = prepare_key(user_key, key_len_bytes=key_bits // 8)

    t0 = time.perf_counter()
    key_expansion = get_key_expansion(key)
    round_keys = get_round_keys(key_expansion)
    t1 = time.perf_counter()

    pt_bytes = plaintext.encode('utf-8')

    t2 = time.perf_counter()
    if mode == "ECB":
        ct = aes_ecb_encrypt(pt_bytes, round_keys)
    else:
        ct = aes_cbc_encrypt(pt_bytes, round_keys)
    t3 = time.perf_counter()

    if mode == "ECB":
        recovered = aes_ecb_decrypt(ct, round_keys)
    else:
        recovered = aes_cbc_decrypt(ct, round_keys)
    t4 = time.perf_counter()

    print(f"\n===== AES-{key_bits} | Mode: {mode} =====")
    print(f"Key (hex):            {key.hex()}")
    print(f"Rounds (Nr):          {len(round_keys) - 1}")
    print(f"Plaintext (ASCII):    {plaintext}")
    print(f"Plaintext (hex):      {pt_bytes.hex()}")
    print(f"Ciphertext (hex):     {ct.hex()}")
    print(f"Recovered (ASCII):    {recovered.decode('utf-8', errors='replace')}")
    print(f"Recovered (hex):      {recovered.hex()}")
    print(f"Match original?       {recovered == pt_bytes}")
    print(f"Key-schedule time:    {(t1 - t0)*1000:.4f} ms")
    print(f"Encryption time:      {(t3 - t2)*1000:.4f} ms")
    print(f"Decryption time:      {(t4 - t3)*1000:.4f} ms")


def benchmark(plaintext: str, user_key: str, key_sizes=(128, 192, 256), trials: int = 5):
    print(f"\nTiming benchmark (average over {trials} trials)")
    print(f"{'bits':>5} | {'schedule (ms)':>14} | {'encrypt (ms)':>13} | {'decrypt (ms)':>13}")
    print("-" * 56)

    pt_bytes = plaintext.encode('utf-8')
    results = {}
    for bits in key_sizes:
        key = prepare_key(user_key, key_len_bytes=bits // 8)

        sched_times, enc_times, dec_times = [], [], []
        for _ in range(trials):
            t0 = time.perf_counter()
            key_expansion = get_key_expansion(key)
            round_keys = get_round_keys(key_expansion)
            t1 = time.perf_counter()

            ct = aes_cbc_encrypt(pt_bytes, round_keys)
            t2 = time.perf_counter()

            aes_cbc_decrypt(ct, round_keys)
            t3 = time.perf_counter()

            sched_times.append((t1 - t0) * 1000)
            enc_times.append((t2 - t1) * 1000)
            dec_times.append((t3 - t2) * 1000)

        avg_sched = sum(sched_times) / trials
        avg_enc = sum(enc_times) / trials
        avg_dec = sum(dec_times) / trials
        results[bits] = (avg_sched, avg_enc, avg_dec)
        print(f"{bits:>5} | {avg_sched:>14.4f} | {avg_enc:>13.4f} | {avg_dec:>13.4f}")

    return results


if __name__ == "__main__":
    user_key = input("Enter encryption key : ")
    plaintext = input("Enter plaintext: ")

    for key_bits in (128, 192, 256):
        run_demo("ECB", plaintext, user_key, key_bits)
        run_demo("CBC", plaintext, user_key, key_bits)

    benchmark(plaintext, user_key)