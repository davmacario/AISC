import numpy as np
from AISC_01 import monogram_ranking, digram_ranking, trigram_ranking, crypto_freq, ENGLISH_LETTER_FREQS

if __name__ == "__main__":
    """ 
    The first ciphertext is in the file “cryptogram01.txt” and has 
    been obtained using a monoalphabetic cipher, i.e., each plaintext
    letter is mapped to a ciphertext letter according to a fixed 
    one-to-one mapping. Since there are 26! possible mappings, brute
    force does not help in this case. However, assuming that the 
    plaintext is English text, a frequency analysis should easily 
    reveal the most likely plaintext. 
    """

    # Open file
    in_file = "cryptogram01.txt"
    with open(in_file) as f:
        cryptogram = f.read()

    print(monogram_ranking(cryptogram, 10))
    print(digram_ranking(cryptogram, 5))
    print(trigram_ranking(cryptogram, 5))

    print(np.argsort([-1*v for v in ENGLISH_LETTER_FREQS])[:10])

    my_guess = cryptogram.replace('M', 't').replace('W', 'h').replace('I', 'e')
    my_guess = my_guess.replace('Y', 'a').replace('K', 'n').replace('S', 'd')
    my_guess = my_guess.replace('X', 'i').replace('N', 'g')
    my_guess = my_guess.replace('D', 's').replace('L', 'o').replace('P', 'r')
    my_guess = my_guess.replace('H', 'w').replace('Q', 'm').replace('Z', 'x')
    my_guess = my_guess.replace('A', 'l').replace('F', 'u').replace('V', 'p')
    my_guess = my_guess.replace('J', 'k').replace('U', 'v').replace('G', 'c')
    my_guess = my_guess.replace('E', 'y').replace('R', 'f').replace('C', 'b')
    my_guess = my_guess.replace('B', 'j').replace('O', 'z')

    #print(my_guess)
    #print('\n')

    my_guess_2 = ''.join(x if x.islower() else '-' if x.isupper() else x for x in my_guess)

    print(my_guess_2)

    out_file = 'message01.txt'
    with open(out_file, 'w') as f:
        f.write(my_guess_2)
