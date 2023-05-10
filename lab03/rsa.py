from AISC_03 import *
from random import randint


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


def rsa_encrypt(message, pk, print_times=False):
    """
    rsa_encrypt
    ---
    Encrypt the message with RSA using a specified public key.
    """
    pass


def rsa_decrypt(ciphertext, sk):
    """
    rsa_decrypt
    ---
    Encrypt the message with RSA using a specified private key.
    """
    pass
