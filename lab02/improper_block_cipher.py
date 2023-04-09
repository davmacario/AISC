from AISC_02 import *


if __name__ == "__main__":
    file_cipher = "ciphertext.txt"

    known_plain = 0b0111001001101110
    known_cipher = 0b0001111001100101

    print(bin(known_plain))     # Initial state
    
    s1 = sub4NibList(sBox, intToVec(known_plain))
    print(bin(vecToInt(s1)))    # After S-Box

    s2 = shiftRow(s1)
    print(bin(vecToInt(s2)))

    # s2 is what is obtained after the s boxes and ShiftRows

    # Up to now, the key has NOT BEEN USED! (Our result is the same as the one obtained by the original transmitter)

    # Knowing the ciphertext, the XORed subkey is simply the xor of s2 and the ciphertext

    est_subkey = known_cipher ^ vecToInt(s2)     # XOR
    print("Estimated subkey",bin(est_subkey))

    # The subkey is generated trivially... The subkey is the same as the key!

    print("Check: ")
    keyExp(est_subkey)

    cip = encrypt_foo(known_plain)

    print(">  Observed cipher: ", bin(known_cipher))
    print(">  Derived cipher: ", bin(cip))
    
    try:
        with open(file_cipher) as f:
            cipher = f.read()
            encryption = base64.b64decode(cipher)
    except:
        with open("lab02/" + file_cipher) as f:
            cipher = f.read()
            encryption = base64.b64decode(cipher)

    # Decryption with the estimated key
    k = est_subkey
    keyExp(k)

    out_str = ""

    for i in range(0, len(encryption), 2):
        c0 = encryption[i]
        c1 = encryption[i+1]
        
        sixteen_bits = (c0 << 8) + c1

        decryption = decrypt_foo(sixteen_bits)

        out_str += chr((decryption & 0xff00) >> 8)
        out_str += chr(decryption & 0x00ff)

    # Write out. file
    decrypt_path = "plaintext.txt"

    with open(decrypt_path, "w") as f:
        f.write(out_str)
