import hashlib
import os
import secrets
import random

from AISC_04 import *
from ex01_hash_functions import findCollisionsLoop, findHashCollisions


def universalHash(m, bytelen=20):
    """
    universalHash
    ---
    Universal hash function implementation.
    The output digest has size <= 20 bytes.

    The operation done on the message m (big integer) is:

            h = am + b mod(q)

    ### Input parameters
    - m: message, it may be either a bytes object or int
    - bytelen: length of the output digest, in range [1, 20] bytes
    """
    assert bytelen <= 20 and bytelen >= 1, f"Specified output len {bytelen} is invalid"

    q = qDSA
    a = aU
    b = bU

    if isinstance(m, bytes):
        msg = int.from_bytes(m, byteorder="big")
    elif isinstance(m, int):
        msg = m
    else:
        raise ValueError(
            "The provided message is not of valid format!\nValid formats: bytes, int"
        )

    h = ((a * msg) + b) % q
    hashvalue = h.to_bytes(20, byteorder="big")
    return hashvalue[:bytelen]


def findPremimage(h):
    """
    findPremimage
    ---
    Find the preimage of the value h, obtained from universalHash.
    """
    assert isinstance(h, bytes), "The provided value is not a bytes object!"

    q = qDSA
    a = aU
    b = bU

    inv_a = modinv(a, q)
    h_int = int.from_bytes(h, byteorder="big")
    m = (((h_int - b) % q) * inv_a) % q

    return m.to_bytes(m.bit_length() // 8 + 1, byteorder="big")


if __name__ == "__main__":
    m = b"SHA-256 is a cryptographic hash function"
    print(f"Message: {m}")
    print(f"Universal hash digest:\n{universalHash(m)}")

    # Finding collisions
    findCollisionsLoop(universalHash)

    # Finding preimages
    m = b"Hello, world!"
    m_prime = findPremimage(universalHash(m))

    print(f"Original message: {m}")
    print(f"Recovered message: {m_prime}")

    # Producing collision for 20-bytes long sequence
    x1, x2 = findHashCollisions(universalHash, 20)

    print(f"Colliding messages for universal hash:\n> {x1}\n> {x2}")
