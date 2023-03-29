from AISC_02 import *
from myFunctions import *
import random
import numpy as np
import pandas as pd

def main():

    random.seed(0)
    length = 16
    maxIter = 1000

    results = np.zeros([5,2])

    for i in range(0, maxIter):

        key1 = random.getrandbits(length)
        keyExp(key1)
        plaintext1 = random.getrandbits(length)

        ciphertext1_2 = encrypt(plaintext1)
        ciphertext1_3 = encrypt3(plaintext1)
        ciphertext1_4 = encrypt4(plaintext1)
        ciphertext1_lazy = encrypt_lazy(plaintext1)
        ciphertext1_very = encrypt_very(plaintext1)

        error = 1 << random.randrange(length)
        plaintext2 = plaintext1^error
        assert hamming(plaintext1, plaintext2) ==1

        ciphertext2_2 = encrypt(plaintext2)
        ciphertext2_3 = encrypt3(plaintext2)
        ciphertext2_4 = encrypt4(plaintext2)
        ciphertext2_lazy = encrypt_lazy(plaintext2)
        ciphertext2_very = encrypt_very(plaintext2)

        results[0,0] += hamming(ciphertext1_2, ciphertext2_2)
        results[1,0] += hamming(ciphertext1_3, ciphertext2_3)
        results[2,0] += hamming(ciphertext1_4, ciphertext2_4)
        results[3,0] += hamming(ciphertext1_lazy, ciphertext2_lazy)
        results[4,0] += hamming(ciphertext1_very, ciphertext2_very)

        error = 1 << random.randrange(length)
        key2 = key1^error
        assert hamming(key1, key2) ==1
        keyExp(key2)

        ciphertext2_2 = encrypt(plaintext1)
        ciphertext2_3 = encrypt3(plaintext1)
        ciphertext2_4 = encrypt4(plaintext1)
        ciphertext2_lazy = encrypt_lazy(plaintext1)
        ciphertext2_very = encrypt_very(plaintext1)

        results[0,1] += hamming(ciphertext1_2, ciphertext2_2)
        results[1,1] += hamming(ciphertext1_3, ciphertext2_3)
        results[2,1] += hamming(ciphertext1_4, ciphertext2_4)
        results[3,1] += hamming(ciphertext1_lazy, ciphertext2_lazy)
        results[4,1] += hamming(ciphertext1_very, ciphertext2_very)

    results = results/maxIter
    columns = ["Changing plaintext", "Changing key"]
    rows = ["2 rounds", "3 rounds", "4 rounds", "lazy", "very lazy"]
    data=pd.DataFrame(results, columns=columns, index=rows)
    print(data)

    known_plaintext = 0b0111001001101110
    known_cipher = 0b0001111001100101 

if __name__=="__main__":
    main()