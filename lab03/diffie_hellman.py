from AISC_03 import pDH, gDH, qDH, encryptAESCTR, decryptAESCTR
import os
import base64
import time

# Parameters
p = pDH             # Large Prime - Hard to evaluate the log_g (security assumption)
g = gDH             # Root of cyclic group
q = qDH             # Order of subgroup

try:
    f = open("dh_keys.txt", "r")

    x = int(f.readline().split(" ")[-1].split("\n")[0])
    pk = int(f.readline().split(" ")[-1].split("\n")[0])

    print("Keys retrieved!")
    print(f"Private key: {x}\n")
    print(f"Public key: {pk}\n")

except:
    # No file with key pair

    # Random generation of private key
    t_0 = time.time()
    sk_ok = False
    while not sk_ok:
        x = int.from_bytes(os.urandom(256), byteorder='little')
        if x > 1 and x < q-1:
            sk_ok = True


    # Create public key
    pk = pow(g, x, p)
    key_pair_gen_time = time.time() - t_0
    print(f"> Time to generate (pk, sk) pair: {key_pair_gen_time}")

    print(f"Public key: \n{pk}\n")

    with open("dh_keys.txt", "w") as f:
        f.write(f"Private key: {x}\n")
        f.write(f"Public key: {pk}\n")

#### Having received the key from others:
pk_prof = 231496621204370508895931748857755688773955557370722566546524279241681783924615459222281328781846958709671178933550268979137824811356380142723458582689238338881602937866599482596517635627201490862987705580528580122030574292913825460656414418530301010266004326589419172467364887958500892750202983947301330827393531207626744229962720413918512823808690023548441036635272327523845223428985955360366428904878223170012768633135103661638106507748637163377957664799771569021118234716556142527020139132381453117289393367071863842364636961374713484929024198420198291374856545022707013121483896955505081060905509151197548949686

t_0 = time.time()
shared_k_prof = pow(pk_prof, x, p)
shared_key_gen_time = time.time() - t_0

print(f"> Time to generate shared key: {shared_key_gen_time}")

print(f"Shared key - professor: \n{shared_k_prof}\n")

# Obtain actual 128-bit key - key generation:
key_prof = (shared_k_prof & ((1 << 128) - 1)).to_bytes(16, byteorder='little')

print(f"128-bit key: {int.from_bytes(key_prof, byteorder='little')}")
print(f"128-bit key in bytes: {key_prof}")

# Message exchange:
s = 'Hello, we are group 3!'

plaintext = s.encode('utf-8')
(iv, ciphertext) = encryptAESCTR(key_prof, plaintext)

iv_str = base64.b64encode(iv).decode("utf-8")
cipher_str = base64.b64encode(ciphertext).decode("utf-8")

print(f"IV: {iv_str}\nCiphertext: {cipher_str}")

# Message decoding:
# iv_prof = 
# ciphertext_prof = 

# iv_2 = base64.b64decode(iv_prof)
# ct_2 = base64.b64decode(ciphertext_prof)

# pt_2 = decryptAESCTR(key_prof, iv_2, ct_2)

# plaintext_prof = pt_2.decode('utf-8')
# print(f"Prof. plaintext")
