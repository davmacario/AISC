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
- Evaluate score: sum the squares of the frequencies for the
