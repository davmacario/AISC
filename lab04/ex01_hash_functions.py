import hashlib
import os
import secrets
import random


def sha256Encrypt(message, out_len_bytes=32):
    """
    sha256Encrypt
    ---
    Wrapper for sha256 encryption via hashlib.
    """
    assert isinstance(message, bytes), "The provided message is not a bytes object"
    assert (
        out_len_bytes <= 32 and out_len_bytes >= 1
    ), f"Specified output len {out_len_bytes} is invalid"

    m = hashlib.sha256()
    m.update(message)
    hashvalue = m.digest()

    return hashvalue[:out_len_bytes]


def findHashCollisions(hash_func, hash_size_bytes, counts=False, verb=False):
    """
    findHashCollisions
    ---
    Efficient algorithm for finding collisions in hash functions.
    """
    n = hash_size_bytes
    x0_int = secrets.randbits(n * 8 + 1)  # Add one bit
    x0 = x0_int.to_bytes(n + 1, byteorder="little")
    x1 = hash_func(x0, n)
    x2 = hash_func(x1, n)

    c1 = 0
    while x1 != x2:
        x1 = hash_func(x1, n)
        x2 = hash_func(hash_func(x2, n), n)
        c1 += 1

    # Here, x1 == x2
    x2 = x0
    c2 = 0
    while hash_func(x1, n) != hash_func(x2, n):
        x1 = hash_func(x1, n)
        x2 = hash_func(x2, n)
        c2 += 1

    # At the end of the loop, we have found a collisio
    if verb:
        print(f"Loop 1 iterations: {c1}\nLoop 2 iterations: {c2}\n")

    if counts:
        return x1, x2, c1, c2
    else:
        return x1, x2


def findCollisionsLoop(H):
    # Repeat the experiment for 10 times for each output length in bytes
    byte_len = [1, 2, 3, 4]
    iterations = 10

    counts_lists1 = []
    counts_lists2 = []

    for b in byte_len:
        print(f"\n+----- {b} bytes -----+")
        print(f"2^(n / 2) = {2**((b*8)/2)}")
        sublist1 = []
        sublist2 = []
        for i in range(iterations):
            x1, x2, c1, c2 = findHashCollisions(H, b, counts=True)
            sublist1.append(c1)
            sublist2.append(c2)

        counts_lists1.append(sublist1)
        counts_lists2.append(sublist2)

        print(f"Loop 1: {sum(sublist1)/len(sublist1)}")
        print(f"Loop 2: {sum(sublist2)/len(sublist2)}")


if __name__ == "__main__":
    msg = b"hello"

    # print(f"SHA-256 digest:\n{sha256Encrypt(msg)}")

    x1, x2 = findHashCollisions(sha256Encrypt, 4, verb=True)

    print(f"Hash of {x1}:\n{sha256Encrypt(x1, 4)}")
    print("")
    print(f"Hash of {x2}:\n{sha256Encrypt(x2, 4)}")

    findCollisionsLoop(sha256Encrypt)
