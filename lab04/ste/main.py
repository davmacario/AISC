import hashlib as hl
from lab04.AISC_04 import *

def encodeSHA(msg, outlen=0):
    m = hl.sha256()
    m.update(msg)
    if outlen == 0:
        outlen = 32

    return m.digest()[:outlen]

def naive_collision_search(H, nbytes):
    x0 = int.to_bytes(secrets.randbits(8*(nbytes + 1)),
                      byteorder='little',
                      length=nbytes + 1)
    x1 = H(x0, nbytes)
    x2 = H(x1, nbytes)
    c1 = 0
    while x1 != x2:
        c1 += 1
        x1 = H(x1, nbytes)
        x2 = H(H(x2, nbytes), nbytes)
    x2 = x0
    c2 = 0
    while H(x1, nbytes) != H(x2, nbytes):
        c2 += 1
        x1 = H(x1, nbytes)
        x2 = H(x2, nbytes)

    return x1, x2, c1, c2

def encodeUniversal(msg, outlen=0):
    m = int.from_bytes(msg, byteorder='big')
    h = (aU * m + bU) % qDSA
    if outlen == 0:
        outlen = 20

    return h.to_bytes(length=20, byteorder='big')[:outlen]

def findPreimageUniversal(hash):
    # TODO
    h = int.from_bytes(hash, byteorder='big')
    m = h
    return m.to_bytes(length=m.bit_length() // 8 + 1, byteorder='big')


def averageHashComparison(H):
    N = 10
    for i in range(1, 5):
        C1, C2, c1, c2 = 0, 0, 0, 0
        for n in range(0, N):
            c1, c2 = naive_collision_search(H, i)[2:4]
            C1 += c1
            C2 += c2
        C1 /= N
        C2 /= N
        print("Average (C1, C2) on %d tests: (%g, %g). Comparison with 2^%d: %g" % (N, C1, C2, i, 2**(8*i / 2)))

def part3():
    message = b"SHA-256 is a cryptographic hash function"
    # print(encodeUniversal(message, 13))

    h = encodeUniversal(message)
    h2 = encodeUniversal(findPreimageUniversal(h))
    print(h)
    print(h2)
    if h == h2:
        print("Preimage successfully found!")
    else:
        print("Finding preimage failed")

# bytes like objects
if __name__ == "__main__":
    # PART 1
    # averageHashComparison(encodeSHA)

    # PART 2
    # averageHashComparison(encodeUniversal)

    # PART 3
    part3()
