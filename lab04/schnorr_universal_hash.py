import hashlib
import os
import secrets

from AISC_04 import qDSA, pDSA, gDSA, aU, bU, modinv
from universal_hash import universalHash, findPremimage


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

    r_prime = int.from_bytes(rbytes, "big") % qDSA

    return r == r_prime


if __name__ == "__main__":
    # The function 'universalHash' produces by default a 20-byte output

    x = secrets.randbelow(qDSA - 2) + 1
    y = pow(gDSA, x, pDSA)

    print("private key: ", x)
    print("public key: ", y)

    m = b"This group is composed by Umberto Brozzo Doda, Davide Macario and Stefano Agnetta"

    r, s = computeSignature(m, x, universalHash)

    valid = verifySignature(r, s, y, m, universalHash)
    print("message : ", m)

    print("r: ", r)
    print("s: ", s)
    print("Valid? ", valid)

    # Here, I have the valid signature of the message 'm'

    # To produce a valid signature it is possible to select a message such that the value of r is the same as before
    # If this happens, also the value of s will be valid

    g = gDSA
    p = pDSA

    # Then the goal is to find a preimage of r

    # I can be found as for the verification
    I = (pow(g, s, p) * pow(y, r, p)) % p

    # print(I)

    I_bytes = I.to_bytes(getByteLen(I), byteorder="big")

    I_cat_msg = I_bytes + m

    print(I_cat_msg)

    r1 = r
    r1_bytes = r.to_bytes(20, byteorder="big")

    my_msg = b"This is my malicious message"
    my_msg_int = int.from_bytes(my_msg, byteorder="big")
    I_cat_myMsg = I_bytes + my_msg
    print(I_cat_myMsg)
    int_I_cat_myMsg = int.from_bytes(I_cat_myMsg, byteorder="big")
    int_I_cat_myMsg_transl = int_I_cat_myMsg << 20
    I_cat_myMsg_transl = int_I_cat_myMsg_transl.to_bytes(
        getByteLen(int_I_cat_myMsg_transl), byteorder="big"
    )

    r2_byte = universalHash(I_cat_myMsg_transl)
    r2 = int.from_bytes(r2_byte, byteorder="big")
    inv_a = modinv(aU, qDSA)

    offset = ((r1 - r2) * inv_a) % qDSA

    fake_msg_int = int_I_cat_myMsg_transl + offset
    fake_msg = fake_msg_int.to_bytes(getByteLen(fake_msg_int), byteorder="big")

    print("")
    print(r1_bytes)
    print(universalHash(fake_msg))

    #
    #
    #
    #

    pre_I_cat_message = findPremimage(r1_bytes)
    pre_I_int = int.from_bytes(pre_I_cat_message, byteorder="big")

    tmp = aU * pre_I_int + bU
    tmp = tmp & (2 ** (8 * len(m) + 1) - 1)
    m_int = int.from_bytes(m, byteorder="big")
    helpme = aU * m_int + bU

    print("########")
    print(tmp % qDSA)
    print(helpme % qDSA)
    print("########")

    # Find I: remove the message from the preimage
    n_bytes_m = len(m)
    print(f"Length in bytes of m: {n_bytes_m}")

    I = (pre_I_int - int.from_bytes(m, byteorder="big")) >> (len(m) * 8)

    print(I)
