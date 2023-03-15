import numpy as np
import sys
from AISC_01 import crypto_freq, periodic_corr, Vigenere_decrypt, ENGLISH_LETTER_FREQS

"""
# Vigenere cipher, key length is 'm'

## Estimating the key length:

Need a function to:

- Extract letters at 'keylen' distance - get subsequences (> 100 chars)
- Compute subfrequencies (frequency of each char in every subsequence) - use crypto_freq
- Evaluate score: sum the squares of the frequencies for the 


"""

SCORE_ENGLISH = 0.065

def estimKeyLen(cryptogram, score=SCORE_ENGLISH, thresh_score=0.01):
    """
    Estimate the key length in a Vigenère cipher
    """
    # Get the maximum tried keylength
    max_keylen = round(len(cryptogram)/100)
    print(f"Maximum keylength: {max_keylen}")

    # 'good' stores the good key length values
    last_good = 10
    good = -1

    # Need to make sure all subsequences are of the same length, 
    # else shorter sequences contain more noise and the score 
    # value tends to increase with longer tested keys

    for kl in range(2, max_keylen):
        S_list = []
        len_sublist = round(len(cryptogram)/kl)
        for i in range(kl):
            subsequence_full = cryptogram[i::kl]
            subsequence = subsequence_full[:len_sublist]
            Q = crypto_freq(subsequence)

            S_list.append(sum(Q**2))

        S_avg = sum(S_list)/len(S_list)

        print(f"For key length {kl}, the score is {S_avg}")

        # The difference between the estimated score needs to 
        # be at least the theoretical one for english minus a threshold
        if abs(S_avg - score) < last_good:
            # Then it has a good probability of being the correct key length
            last_good = abs(S_avg - score)
            good = kl
    
    return good

def crackVigenere(cipher, keylen):
    """
    Crack the Vigenere encryption, given the ciphertext 
    (cipher) and provided a key length (keylen)
    """

    key = []

    # Cycle over all possible offsets (0 to keylen-1)
    for j in range(keylen):
        # Extract subsequence
        subseq = cipher[j::keylen]
        
        # Compute relative frequncies
        Q_j = crypto_freq(subseq)

        # Compute circular correlation
        R_j = periodic_corr(Q_j, ENGLISH_LETTER_FREQS)

        # Find the max correlation
        # Since the key must be lowercase (for function Vigenere_decrypt):
        k_j = chr(ord('a') + np.argmax(R_j))

        key.append(k_j)
    
    return key


if __name__ == "__main__":
    
    if len(sys.argv) == 3:
        in_file = str(sys.argv[1])
        out_file = str(sys.argv[2])
    else:
        in_file = "cryptogram02.txt"
        out_file = "message02.txt"

    with open(in_file, 'r') as f:
        ciphertext = f.read()

    #keylen = max(estimKeyLen(ciphertext))
    keylen = estimKeyLen(ciphertext)

    print(f"The estimated key length is {keylen}")

    key_broken = ''.join(crackVigenere(ciphertext, keylen))
    print(f"Key: {key_broken}")

    decr_msg = Vigenere_decrypt(ciphertext, key_broken)

    print(decr_msg)

    with open(out_file, 'w') as f:
        f.write(decr_msg)
        f.close()





