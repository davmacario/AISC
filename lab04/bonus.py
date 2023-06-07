import hashlib
import os
import secrets

from AISC_04 import qDSA, pDSA, gDSA, aU, bU, modinv
from universal_hash import universalHash, findPremimage


def myUniversalHash(m):
    m = int.from_bytes(m, "big")
    m = (aU*m + bU) % qDSA
    m = m.to_bytes(getByteLen(m), 'big')
    return m

def getByteLen(a):
    return int((a.bit_length() + 7) // 8.0)


def computeSignature(m, x, hash):
    """
    Simplified Schnorr signature scheme.

    ### Parameters:
    - m: message
    - x: private key
    - hash: hash function
    """
    k = secrets.randbelow(qDSA - 2) + 1
    I = pow(gDSA, k, pDSA)
    nbytes = (pDSA.bit_length() + 7) // 8
    Ibytes = I.to_bytes(nbytes, byteorder="big")

    a = Ibytes + m
    rbytes = hash(a)

    r = int.from_bytes(rbytes, "big") % qDSA
    s = (k - r * x) % qDSA
    return r, s


def verifySignature(r, s, y, m, hash):
    """
    Verification for the Simplified Schnorr signature scheme

    ## Parameters:
    - r: signature (1)
    - s: signature (2)
    - y: public-key for signature verification
    - m: message (that was signed)
    - hash: hash function (single input)
    """
    I = (pow(gDSA, s, pDSA) * pow(y, r, pDSA)) % pDSA
    nbytes = (pDSA.bit_length() + 7) // 8
    Ibytes = I.to_bytes(nbytes, byteorder="big")

    a = Ibytes + m
    rbytes = hash(a)
    print("Hash : ", rbytes)

    r_prime = int.from_bytes(rbytes, "big") % qDSA

    return r == r_prime


if __name__ == "__main__":
    # The function 'universalHash' produces by default a 20-byte output

    x = secrets.randbelow(qDSA - 2) + 1
    y = pow(gDSA, x, pDSA)

    print("private key: ", x)
    print("public key: ", y)

    m = b"This group is composed by Umberto Brozzo Doda, Davide Macario and Stefano Agnetta"

    # r, s = computeSignature(m, x, universalHash)
    r, s = computeSignature(m, x, myUniversalHash)

    # valid = verifySignature(r, s, y, m, universalHash)
    valid = verifySignature(r, s, y, m, myUniversalHash)
    print("message : ", m)

    print("r: ", r)
    print("s: ", s)
    print("Valid? ", valid)

    # Here, I have the valid signature of the message 'm'

    # To produce a valid signature it is possible to select a message such that the value of r is the same as before
    # If this happens, also the value of s will be valid

    m2 = b'This is another message'
    int_m1 = int.from_bytes(m, "big")
    int_m2 = int.from_bytes(m2, "big")

    int_m2 = int_m2 << (20*8)
    m2 = int_m2.to_bytes(getByteLen(int_m2), 'big')


    I = (pow(gDSA, s, pDSA) * pow(y, r, pDSA)) % pDSA
    nbytes = (pDSA.bit_length() + 7) // 8
    Ibytes = I.to_bytes(nbytes, byteorder="big")



    t1 = (aU*int.from_bytes(Ibytes+m, 'big')) % qDSA
    t2 = (aU*int.from_bytes(Ibytes+m2, 'big')) % qDSA

    print('t1: ',t1)
    print('t2: ',t2)

    t = (t1 - t2) % qDSA

    at = modinv(aU, qDSA)

    int_m2 = int_m2 + t*at

    m2 = int_m2.to_bytes(getByteLen(int_m2), 'big')

    t3 = (aU*int.from_bytes(Ibytes+m2, 'big')) % qDSA
    print('t3: ',t3)

    # valid = verifySignature(r, s, y, m2, universalHash)
    valid = verifySignature(r, s, y, m2, myUniversalHash)
    print("Valid? ", valid)



