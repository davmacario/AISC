# Lab 01

## Ex 1

The first ciphertext is in the file “cryptogram01.txt” and has
been obtained using a monoalphabetic cipher, i.e., each plaintext
letter is mapped to a ciphertext letter according to a fixed
one-to-one mapping. Since there are 26! possible mappings, brute
force does not help in this case. However, assuming that the
plaintext is English text, a frequency analysis should easily
reveal the most likely plaintext.

## Ex 2 - attacking Vigenère encryption

The key length is 'm' but it is not known a priori: need to estimate the length first.

### Estimating the key length

Need a function to:

- Extract letters at 'keylen' distance - get subsequences (> 100 chars)
- Compute subfrequencies (frequency of each char in every subsequence) - use crypto_freq
- Evaluate score: sum the squares of the frequencies for the current subsequence
- The most likely key length is the one for which the score is closest to the ideal one for the English language (0.065)

By taking the value which is closest to this, it is possible to obtain the 'most likely' key length.

### Cracking the key

For each offset between 0 and the estimated key length -1, extract the subsequence and find the subfrequencies of the letters.
Then, evaluate the circular correlation between this and the actual vector of frequencies for english words, considering that the subsequence corresponds to a 'Generic Caesar' cipher - meaning all letters have been translated by the same amount, indicated by the corresponding letter in the encryption key.
By doing this for each value of the offset, it is possible to recover information about each letter in the key.

The final key for cryptogram 2 is `nowyouseethekey`.

## Answers

- Describing the strategy for monoalphabetic cipher
  - Function to automate process?
- Estimating complexity for breaking Vigenere
- More or less difficult than monoalphabetic (if by hand)?

- Bonus 1: cryptogram03.txt - Vigenère with 21-char key
- Bonus 2: how to use Vigenere for cracking steam cipher where key was reused for multiple encryptions?
