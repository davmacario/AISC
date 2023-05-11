from AISC_03 import *
from random import randint
import os
import time


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x


def miller_rabin(p, k=100):
    s = 0
    r = p - 1
    while True:
        r //= 2
        s = s + 1
        if r % 2 != 0:
            break
    assert (p - 1) == pow(2, s) * r
    for i in range(0, k):
        a = randint(2, p - 1)
        x = pow(a, r, p)
        if x != 1 and x != p - 1:
            j = 1
            while j < s and x != p - 1:
                x = pow(x, 2, p)
                if x == 1:
                    return False
                j = j + 1
            if x != p - 1:
                return False
    return True


def rsa_encrypt(message, pk):
    """
    rsa_encrypt
    ---
    Encrypt the message with RSA using a specified public key.

    The public key must be in the format: (N, e)
    """
    if isinstance(message, int):
        return pow(message, pk[1], pk[0])
    elif isinstance(message, list):
        out = []
        for m in message:
            out.append(pow(m, pk[1], pk[0]))
        return out


def rsa_decrypt(ciphertext, sk):
    """
    rsa_decrypt
    ---
    Encrypt the message with RSA using a specified private key.

    The private key should be in the format: (N, d)
    """
    if isinstance(ciphertext, int):
        return pow(ciphertext, sk[1], sk[0])
    elif isinstance(ciphertext, list):
        out = []
        for c in ciphertext:
            out.append(pow(c, sk[1], sk[0]))
        return out


def get_p_q_N(keylen):
    """
    get_p_q_N
    ---
    Find 2 prime numbers p and q having specified bit length and
    derive N for RSA.

    ### Input parameters
    - keylen: number of bits of N; p and q will have half this
    amount
    """
    found = False
    while found == False:
        p = generate_prime_candidate(keylen // 2)
        found = miller_rabin(p)
    found = False
    while found == False:
        q = generate_prime_candidate(keylen // 2)
        found = miller_rabin(q)

    N = p * q

    return p, q, N


def keygen_rsa(keylen):
    """
    keygen_rsa
    ---
    Generate the keys for RSA given a security parameter
    """
    p, q, N = get_p_q_N(keylen)

    # assert N.bit_length() == security_param, f"N has {N.bit_length()}!"

    # Evaluate e (prime wrt totient of N) and d, inverse of e, mod totient(N)
    totient = (p - 1) * (q - 1)
    M = 2 ^ 16 + 1  # Upper bound of e

    found = False
    while not found:
        e = randint(3, M)
        g, x, y = egcd(e, totient)
        # When g == 1, x is the multiplicative inverse modulo totient(N)
        if g == 1:  # found!
            found = True
            d = x % totient

    return N, e, d


def main(prnt=False):
    # Adjust position
    path = "/".join(__file__.split("/")[:-1])

    # Red input file
    input_file = os.path.join(path, "text.txt")

    with open(input_file, "r") as f:
        plaintext = f.read()  # String

    pt_len = len(plaintext)

    # Evaluate p, q, N
    security_param = 1024  # Number of bits of N

    t_0 = time.time()

    N, e, d = keygen_rsa(security_param)

    t_keygen = time.time() - t_0

    out_pub = os.path.join(path, "rsa_pub.txt")
    out_private = os.path.join(path, "rsa_pri.txt")

    # Store them on files
    with open(out_pub, "w") as f:
        f.write("e: " + str(e) + "\nN: " + str(N))

    with open(out_private, "w") as f:
        f.write("d: " + str(d) + "\nN: " + str(N))

    # Map the plaintext onto the message space
    bitlen = N.bit_length()
    msg = encodeText(plaintext, bitlen)

    t_1 = time.time()

    cipher = rsa_encrypt(msg, (N, e))

    t_encr = time.time() - t_1

    if prnt:
        print("Cphertext: ", cipher)

    t_2 = time.time()

    msg_dec = rsa_decrypt(cipher, (N, d))

    t_decr = time.time() - t_2

    rx_plaintext = decodeText(msg_dec, bitlen)

    if prnt:
        print(rx_plaintext)

    print(
        f"Results:\n> Time for key generation: {t_keygen} s\n> Time for encryption: {t_encr} s\n> Time for decryption: {t_decr} s"
    )


if __name__ == "__main__":
    main(prnt=False)
