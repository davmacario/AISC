# Simplified AES using multiple rounds.
# Simplified AES maps 16-bit words in 16-bit words using a 16-bit key
# It's internal state is a 2x2 matrix of 4-bit values (nibbles)
# The input is copied onto the initial state and modified using
# AES-like transforms: AddKey, NibbleSubstitute, ShiftRow, MixColumns
# Derived from Python 3 implementation in:
#
# Author: Joao H de A Franco (jhafranco@acm.org)
#
# Description: Simplified AES implementation in Python 3
#
# Date: 2012-02-11
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================
import sys
import random
import base64
 
# S-Box
sBox  = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]
 
# Inverse S-Box
sBoxI = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
         0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]
 
# Round keys: K0 = w0 + w1; K1 = w2 + w3; K2 = w4 + w5; K3 = w6 + w7; K4 = w8 + w9;
w = [None] * 10
 
def mult(p1, p2):
    """Multiply two polynomials in GF(2^4)/x^4 + x + 1"""
    p = 0
    while p2:
        # at ith iteration, if ith coeff of p2 is set, add p1*x^i mod x^4+x+1 to result
        if p2 & 0b1:
            p ^= p1
        # compute p1 = p1*x mod x^4+x+1
        p1 <<= 1
        # if degree of p1 is > 3, subtract x^4+x+1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111
 
def intToVec(n):
    """Convert a 2-byte integer into a 4-nibble vector"""
    # Explaination:
    # Each number is divided into 4 x 4-bit nibbles
    # The bits are shifted by a suitable amount (by 12 to get first 4 bits, by 4 to get third nibble)
    # The AND (&) with 0xf is needed to only isolate 4 bits from each shift!
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]
 
def vecToInt(m):
    """Convert a 4-nibble vector into 2-byte integer"""
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]
 
def addKey(s1, s2):
    """Add two keys in GF(2^4)"""
    return [i ^ j for i, j in zip(s1, s2)]
     
def sub4NibList(sbox, s):
    """Nibble substitution function"""
    return [sbox[e] for e in s]
     
def shiftRow(s):
    """ShiftRow function"""
    return [s[0], s[1], s[3], s[2]]
    
def mixCol(s):
    """Defined as [1 4; 4 1] * [s[0] s[1]; s[2] s[3]] in GF(2^4)/x^4 + x + 1"""
    return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]), s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]

def iMixCol(s):
    """Defined as [9 2; 2 9] * [s[0] s[1]; s[2] s[3]] in GF(2^4)/x^4 + x + 1"""
    return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]), mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]
 
def keyExp(key):
    """Generate the round keys (up to 4 rounds)"""
    def sub2Nib(b):
        """Swap each nibble and substitute it using sBox"""
        return sBox[b >> 4] + (sBox[b & 0x0f] << 4)
 
    Rcon1, Rcon2, Rcon3, Rcon4 = 0b10000000, 0b00110000, 0b01100000, 0b11000000
    w[0] = (key & 0xff00) >> 8
    w[1] = key & 0x00ff
    w[2] = w[0] ^ Rcon1 ^ sub2Nib(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ Rcon2 ^ sub2Nib(w[3])
    w[5] = w[4] ^ w[3]
    w[6] = w[4] ^ Rcon3 ^ sub2Nib(w[5])
    w[7] = w[6] ^ w[5]
    w[8] = w[6] ^ Rcon4 ^ sub2Nib(w[7])
    w[9] = w[8] ^ w[7]
    

def computeRound(subkey0, subkey1, state):
    # generic round: NS-SR-MC-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = mixCol(state)
    state = addKey(intToVec((subkey0 << 8) + subkey1), state)
    return state
    
def computeInvRound(subkey0, subkey1, state):
    # generic inverse round: AK-MC-SR-NS
    state = addKey(intToVec((subkey0 << 8) + subkey1), state)
    state = iMixCol(state)
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    return state
    
 
def encrypt(ptext):
    """Encrypt plaintext block (2 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = computeRound(w[2], w[3], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = addKey(intToVec((w[4] << 8) + w[5]), state)
    
    return vecToInt(state)
     
     
def decrypt(ctext):
    """Decrypt ciphertext block (2 rounds)"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[4] << 8) + w[5]), intToVec(ctext))
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    # invert first round
    state = computeInvRound(w[2], w[3], state)
    # invert first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)

    
def encrypt_foo(ptext):
    """Encrypt plaintext block"""
        
    # last round: NS-SR-AK
    state = sub4NibList(sBox, intToVec(ptext))
    state = shiftRow(state)
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)
     
def decrypt_foo(ctext):
    """Decrypt ciphertext block"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ctext))
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    
    return vecToInt(state)


def hamming (x, y):
    return bin(x ^ y).count('1')
    
 
if __name__ == '__main__':
    # Test vectors from "Simplified AES" (Steven Gordon)
    # (http://hw.siit.net/files/001283.pdf)
     
    plaintext = 0b1101011100101000
    key = 0b0100101011110101
    ciphertext = 0b0010010011101100
    keyExp(key)
    try:
        assert encrypt(plaintext) == ciphertext
    except AssertionError:
        print("Encryption error")
        print(encrypt(plaintext), ciphertext)
        sys.exit(1)
    print("Test ok!")
    
    plaintext = random.getrandbits(16)
    error = 1 << random.randrange(16)
    plaintext2 = plaintext ^ error
    assert hamming(plaintext, plaintext2) == 1
    
    print("{0:016b} : plaintext".format(plaintext))
    print("{0:016b} : bit flip".format(error))
    print("{0:016b} : changed plaintext".format(plaintext2))
    ciphertext = encrypt(plaintext)
    ciphertext2 = encrypt(plaintext2)
    print("{0:016b} : ciphertext".format(ciphertext))
    print("{0:016b} : changed ciphertext".format(ciphertext2))

    # example of encryption of arbitrary text
    message = "This is a sample text "
    key = 0b1111111111111111
    keyExp(key)

    # initialize encryption buffer
    encryption = bytearray()

    # read pairs of characters from message
    for c0, c1 in zip(*[iter(message)] * 2):
        # convert (c0, c1) in 16-bit plaintext
        plaintext = (ord(c0) << 8) + ord(c1)
        ciphertext = encrypt_foo(plaintext)
        # extract bytes from 16-bit ciphertext and append them to encryption buffer
        encryption.append((ciphertext & 0xff00) >> 8)
        encryption.append(ciphertext & 0x00ff)

    # write encryption buffer in base64 encoding
    base64encryption = base64.b64encode(encryption).decode("utf-8")
    # decode base64 encoding
    encryption2 = base64.b64decode(base64encryption)
    # initialize decryption buffer
    rec_message = ""

    # read pairs of bytes from encryption buffer
    for b0, b1 in zip(*[iter(encryption2)] * 2):
        # convert (b0, b1) in 16-bit ciphertext
        ciphertext = (b0 << 8) + b1
        plaintext = decrypt_foo(ciphertext)
        # extract characters from 16-bit plaintext and append them to decryption buffer
        rec_message += chr((plaintext & 0xff00) >> 8)
        rec_message += chr(plaintext & 0x00ff)

    print('plaintext message:', message)
    print('encrypted message (base64):', base64encryption)
    print('decrypted message:', rec_message)
       
    sys.exit()




