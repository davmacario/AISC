from AISC_02 import *


def computeRoundLazy(subkey0, subkey1, state):
    # generic round: NS-SR-MC-AK
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((subkey0 << 8) + subkey1), state)
    return state


def computeInvRoundLazy(subkey0, subkey1, state):
    # generic inverse round: AK-MC-SR-NS
    state = addKey(intToVec((subkey0 << 8) + subkey1), state)
    state = sub4NibList(sBoxI, state)
    return state


def encryptLazy(ptext, nrounds):
    """Lazy encrypt plaintext block (n rounds)"""

    il = 0
    ir = 1
    # first AddKey
    state = addKey(intToVec((w[il] << 8) + w[ir]), intToVec(ptext))
    for i in range(1, nrounds):
        # i-th round
        il += 2
        ir += 2
        state = computeRoundLazy(w[il], w[ir], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    il += 2
    ir += 2
    state = addKey(intToVec((w[il] << 8) + w[ir]), state)

    return vecToInt(state)

def decryptLazy(ctext, nrounds):
    """Lazy decrypt ciphertext block (n rounds)"""

    il = nrounds * 2
    ir = nrounds * 2 + 1
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[il] << 8) + w[ir]), intToVec(ctext))
    state = sub4NibList(sBoxI, state)
    for i in range(1, nrounds):
        # invert i-th round
        il -= 2
        ir -= 2
        state = computeInvRoundLazy(w[il], w[ir], state)
    # invert first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), state)

    return vecToInt(state)



def encryptVeryLazy(ptext, nrounds):
    """Lazy encrypt plaintext block (n rounds)"""

    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    for i in range(1, nrounds):
        # i-th round
        state = computeRoundLazy(w[0], w[1], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[0] << 8) + w[1]), state)

    return vecToInt(state)

def decryptVeryLazy(ctext, nrounds):
    """Lazy decrypt ciphertext block (n rounds)"""

    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ctext))
    state = sub4NibList(sBoxI, state)
    for i in range(1, nrounds):
        # invert i-th round
        state = computeInvRoundLazy(w[0], w[1], state)
    # invert first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), state)

    return vecToInt(state)
