import random
import hashlib
import time


_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]

def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    r = 0
    d = n-1
    while d%2==0:
        d //= 2
        r += 1
    
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True    

def generate_prime(bits: int) -> int:
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate

def generate_parameters(k: int):
    P = generate_prime(k)
    for g in (2, 3, 5, 7, 11):
        if 1 < g < P and pow(g, (P - 1) // 2, P) != 1:
            return P, g
    return P, 2


def generate_private_key(k: int) -> int:
    return random.getrandbits(k) | (1 << (k - 1))

def compute_public_value(private_key: int, g: int, P: int) -> int:
    return pow(g, private_key, P)

def compute_shared_secret(their_public: int, my_private: int, P: int) -> int:
    return pow(their_public, my_private, P)

def derive_aes_key(s: int, k: int) -> bytes:
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8 or 1, byteorder='big')
    digest = hashlib.sha256(s_bytes).digest()
    return digest[:k // 8]


def run_demo(k: int):
    print(f"Diffie-Hellman demo (k = {k} bits)")

    P, g = generate_parameters(k)
    print(f"P (hex): {hex(P)}")
    print(f"g:       {g}")

    Ka = generate_private_key(k)
    Kb = generate_private_key(k)

    A = compute_public_value(Ka, g, P)
    B = compute_public_value(Kb, g, P)
    print(f"Alice's public A: {hex(A)}")
    print(f"Bob's public B:   {hex(B)}")

    s_alice = compute_shared_secret(B, Ka, P)
    s_bob = compute_shared_secret(A, Kb, P)
    print(f"Shared secret matches on both sides: {s_alice == s_bob}")

    aes_key = derive_aes_key(s_alice, k)
    print(f"Derived AES key (hex): {aes_key.hex()}")



def benchmark(key_sizes=(128, 192, 256), trials: int = 5):
    print(" Timing benchmark (average over {trials} trials)")
    print(f"{'k':>5} | {'A time (ms)':>12} | {'B time (ms)':>12} | {'s time (ms)':>12}")
    print("-" * 52)

    results = {}
    for k in key_sizes:
        P, g = generate_parameters(k)

        a_times, b_times, s_times = [], [], []
        for _ in range(trials):
            Ka = generate_private_key(k)
            Kb = generate_private_key(k)

            t0 = time.perf_counter()
            A = compute_public_value(Ka, g, P)
            t1 = time.perf_counter()

            B = compute_public_value(Kb, g, P)
            t2 = time.perf_counter()

            s = compute_shared_secret(B, Ka, P)
            t3 = time.perf_counter()

            a_times.append((t1 - t0) * 1000)
            b_times.append((t2 - t1) * 1000)
            s_times.append((t3 - t2) * 1000)

        avg_a = sum(a_times) / trials
        avg_b = sum(b_times) / trials
        avg_s = sum(s_times) / trials
        results[k] = (avg_a, avg_b, avg_s)
        print(f"{k:>5} | {avg_a:>12.4f} | {avg_b:>12.4f} | {avg_s:>12.4f}")

    return results


if __name__ == "__main__":
    for bits in (128, 192, 256):
        run_demo(bits)

    benchmark()