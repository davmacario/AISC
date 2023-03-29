from AISC_02 import *
import lazyfuncs as lazy
import random

nTimes = 1000


def exp1(ntimes, nrounds, lazyness):
    if lazyness:
        enc = lazy.encryptLazy
        dec = lazy.decryptLazy
    else:
        enc = encrypt2
        dec = decrypt2
    sumdist = 0
    currkey = 0b1111111111111111
    for i in range(0, ntimes):
        x = random.getrandbits(16)
        err = 1 << random.randrange(16)
        y = err ^ x
        assert hamming(x, y) == 1
        keyExp(currkey)
        xenc = enc(x, nrounds)
        assert dec(xenc, nrounds) == x
        yenc = enc(y, nrounds)
        assert dec(yenc, nrounds) == y
        sumdist += hamming(xenc, yenc)
    sumdist /= ntimes
    lazymsg = "" if lazyness == 0 else "(LAZY) " if lazyness == 1 else "(VERY LAZY) "
    print(f"Experiment 1 using {lazymsg}{nrounds}-round AES")
    print(f"Key: {currkey}")
    print(f"Average hamming distance in {ntimes} tests: {sumdist}\n")


def exp2(ntimes, nrounds, lazyness):
    enc = encrypt2 if lazyness == 0 else lazy.encryptLazy if lazyness == 1 else lazy.encryptVeryLazy
    plaintext = 0b1010101010101010
    sumdist = 0
    for i in range(0, ntimes):
        key1 = random.getrandbits(16)
        err = 1 << random.randrange(16)
        key2 = err ^ key1
        assert hamming(key1, key2) == 1
        keyExp(key1)
        enc1 = enc(plaintext, nrounds)
        keyExp(key2)
        enc2 = enc(plaintext, nrounds)
        sumdist += hamming(enc1, enc2)
    sumdist /= ntimes
    lazymsg = "" if lazyness == 0 else "(LAZY) " if lazyness == 1 else "(VERY LAZY) "
    print(f"Experiment 2 using {lazymsg}{nrounds}-round AES")
    print(f"Plaintext: {plaintext}")
    print(f"Average hamming distance in {ntimes} tests: {sumdist}\n")


def encrypt2(ptext, nrounds):
    """Encrypt plaintext block (n rounds)"""

    il = 0
    ir = 1
    # first AddKey
    state = addKey(intToVec((w[il] << 8) + w[ir]), intToVec(ptext))
    for i in range(1, nrounds):
        # i-th round
        il += 2
        ir += 2
        state = computeRound(w[il], w[ir], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    il += 2
    ir += 2
    state = addKey(intToVec((w[il] << 8) + w[ir]), state)

    return vecToInt(state)


def decrypt2(ctext, nrounds):
    """Decrypt ciphertext block (n rounds)"""

    il = nrounds * 2
    ir = nrounds * 2 + 1
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[il] << 8) + w[ir]), intToVec(ctext))
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    for i in range(1, nrounds):
        # invert i-th round
        il -= 2
        ir -= 2
        state = computeInvRound(w[il], w[ir], state)
    # invert first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), state)

    return vecToInt(state)


if __name__ == '__main__':
    exp1(nTimes, 2, 0)
    exp2(nTimes, 2, 0)
    exp1(nTimes, 3, 0)
    exp2(nTimes, 3, 0)
    exp1(nTimes, 4, 0)
    exp2(nTimes, 4, 0)
    exp1(nTimes, 4, 1)
    exp2(nTimes, 4, 1)
    exp1(nTimes, 4, 2)
    exp2(nTimes, 4, 2)
