import random
import hashlib
import time


PRIMES = _SMALL_PRIMES = [
    1000000007,
    1000000009,
    1000000033,
    1000000087,
    1000000093,
    1000000097,
    1000000103,
    1000000123,
    1000000181,
    1000000207,
    1000000223,
    1000000241,
    1000000271,
    1000000289,
    1000000297,
    1000000321,
    1000000349,
    1000000363,
    1000000403,
    1000000409,
    1000000411,
    1000000427,
    1000000433,
    1000000439,
    1000000447,
    1000000453,
    1000000459,
    1000000483,
    1000000513,
    1000000531,
    1000000541,
    1000000571,
    1000000577,
    1000000607,
    1000000613,
    1000000633,
    1000000663,
    1000000667,
    1000000679,
    1000000691,
    1000000721,
    1000000753,
    1000000787,
    1000000801,
    1000000811,
    1000000829,
    1000000837,
    1000000871,
    1000000891,
    1000000907,
    1000000933,
    1000000997,
    1000001011,
    1000001021,
    1000001023,
    1000001033,
    1000001063,
    1000001087,
    1000001093,
    1000001099,
    1000001117,
    1000001119,
    1000001123,
    1000001137,
    1000001153,
    1000001159,
    1000001167,
    1000001173,
    1000001203,
    1000001213,
    1000001237,
    1000001263,
    1000001273,
    1000001279,
    1000001293,
    1000001303,
    1000001311,
    1000001333,
    1000001363,
    1000001407,
    1000001411,
    1000001437,
    1000001443,
    1000001449,
    1000001453,
    1000001471,
    1000001489,
    1000001491,
    1000001503,
    1000001531,
    1000001533,
    1000001537,
    1000001549,
    1000001551,
    1000001567,
    1000001573,
    1000001597,
    1000001603,
    1000001611,
    1000001617,
    1000001621,
    1000001633,
    1000001647,
    1000001653,
    1000001669,
    1000001681,
    1000001687,
    1000001699,
    1000001701,
    1000001723,
    1000001729,
    1000001737,
    1000001741,
    1000001747,
    1000001753,
    1000001777,
    1000001789,
    1000001801,
    1000001813,
    1000001821,
    1000001833,
    1000001837,
    1000001861,
    1000001873,
    1000001879,
    1000001887,
    1000001903,
    1000001911,
    1000001923,
    1000001933,
    1000001947,
    1000001951,
    1000001963,
    1000001969,
    1000001977,
    1000001981,
    1000001993,
    1000002011,
    1000002017,
    1000002023,
    1000002047,
    1000002049,
    1000002071,
    1000002077,
    1000002083,
    1000002089,
    1000002103,
    1000002113,
    1000002131,
    1000002143,
    1000002149
]

  

def generate_prime(bits: int) -> int:
    return random.choice(PRIMES)


def generate_parameters(k: int):
    P = random.choice(PRIMES)

    # Choose a different prime as G
    G = random.choice([p for p in PRIMES if p != P])
    if(G>P):
        temp = G
        G = P
        P = temp
    

    return P, G



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