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

def encrypt3(ptext):
    """Encrypt plaintext block (3 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first & second round
    state = computeRound(w[2], w[3], state)
    state = computeRound(w[4], w[5], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = addKey(intToVec((w[6] << 8) + w[7]), state)
    
    return vecToInt(state)

def decrypt3(ctext):
    """Decrypt ciphertext block (3 rounds)"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[6] << 8) + w[7]), intToVec(ctext))
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    # invert first & second round
    state = computeInvRound(w[4], w[5], state)
    state = computeInvRound(w[2], w[3], state)
    # invert first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)

def encrypt4(ptext):
    """Encrypt plaintext block (4 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first, second & third round
    state = computeRound(w[2], w[3], state)
    state = computeRound(w[4], w[5], state)
    state = computeRound(w[6], w[7], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = addKey(intToVec((w[8] << 8) + w[9]), state)
    
    return vecToInt(state)

def decrypt4(ctext):
    """Decrypt ciphertext block (4 rounds)"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[8] << 8) + w[9]), intToVec(ctext))
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    # invert first, second & third round
    state = computeInvRound(w[6], w[7], state)
    state = computeInvRound(w[4], w[5], state)
    state = computeInvRound(w[2], w[3], state)
    # invert first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)

def encrypt_lazy(ptext):
    """Encrypt plaintext block (4 rounds lazy)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first, second & third round
    state = computeRoundLazy(w[2], w[3], state)
    state = computeRoundLazy(w[4], w[5], state)
    state = computeRoundLazy(w[6], w[7], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[8] << 8) + w[9]), state)
    
    return vecToInt(state)

def decrypt_lazy(ctext):
    """Decrypt ciphertext block (4 rounds lazy)"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[8] << 8) + w[9]), intToVec(ctext))
    state = sub4NibList(sBoxI, state)
    # invert first, second & third round
    state = computeInvRoundLazy(w[6], w[7], state)
    state = computeInvRoundLazy(w[4], w[5], state)
    state = computeInvRoundLazy(w[2], w[3], state)
    # invert first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)

def encrypt_very(ptext):
    """Encrypt plaintext block (4 rounds lazy)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first, second & third round
    state = computeRoundLazy(w[0], w[1], state)
    state = computeRoundLazy(w[0], w[1], state)
    state = computeRoundLazy(w[0], w[1], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)

def decrypt_very(ctext):
    """Decrypt ciphertext block (4 rounds lazy)"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ctext))
    state = sub4NibList(sBoxI, state)
    # invert first, second & third round
    state = computeInvRoundLazy(w[0], w[1], state)
    state = computeInvRoundLazy(w[0], w[1], state)
    state = computeInvRoundLazy(w[0], w[1], state)
    # invert first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)

