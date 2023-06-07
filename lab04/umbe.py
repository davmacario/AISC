import hashlib
import os
import secrets


     
aU = int.from_bytes(b"it is the constant a", byteorder='little')
bU = int.from_bytes(b"it is the constant b", byteorder='big')


# sample DSA parameters for 1024-bit key from RFC 6979

pDSA = 0x86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779

qDSA = 0x996F967F6C8E388D9E28D01E205FBA957A5698B1

gDSA = 0x07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA417BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD



def myHash(message, out_len_bytes=32):
    assert isinstance(message, bytes), "The provided message is not a byte object"
    assert (
        out_len_bytes<=32 and out_len_bytes>=1 
    ), f"spcified output len {out_len_bytes} is invalid"

    m = hashlib.sha256()
    m.update(message)
    hashvalue = m.digest()

    return hashvalue[:out_len_bytes]





def egcd(a, b):
    """computes g, x, y such that g = GCD(a, b) and x*a + y*b = g"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)
    


def modinv(a, m):
    """computes a^(-1) mod m"""
    g, x, y = egcd(a % m, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

    

def main():
    print('(p-1) mod q:', (pDSA - 1) % qDSA)
    print('g^q mod p:', pow(gDSA, qDSA, pDSA))
    
    message = b"SHA-256 is a cryptographic hash function"
    m = hashlib.sha256()
    m.update(message)
    hashvalue = m.digest()
    
    print('hash of', message, 'is:', hashvalue)
    print('32 bit hash is:', hashvalue[:4])
    print('64 bit hash is:', hashvalue[:8])



def computeSignature(m, x):
    k = secrets.randbelow(qDSA - 2) + 1
    I = pow(gDSA, k, pDSA)
    nbytes = (pDSA.bit_length()+7)//8
    Ibytes = I.to_bytes(nbytes, byteorder='big')

    a = Ibytes + m
    rbytes = myHash(a)

    r = int.from_bytes(rbytes, "big") % qDSA
    s = (k - r*x) % qDSA
    return r, s



def verifySignature(r, s, y, m):
    I = (pow(gDSA, s, pDSA)*pow(y, r, pDSA)) % pDSA
    nbytes = (pDSA.bit_length()+7)//8
    Ibytes = I.to_bytes(nbytes, byteorder='big')

    a = Ibytes + m
    rbytes = myHash(a)

    r_prime = int.from_bytes(rbytes, "big") % qDSA

    return r == r_prime



def myMain():
    x = secrets.randbelow(qDSA-2) + 1
    y = pow(gDSA, x, pDSA)

    print("private key: ", x)
    print("public key: ", y)

    m = b'This group is composed by Umberto Brozzo Doda, Davide Macario and Stefano Agnetta'

    r, s = computeSignature(m, x)

    valid = verifySignature(r, s, y, m)
    print("message : ", m)

    print("r: ", r)
    print("s: ", s)
    print("Valid? ", valid)



def myMain2():
    y = 27525017356668663052130079649017791341554773236583466677751639531680977216324794145960929175985614403693367729392401730018156951002325535442849657214948871712613090760830616854276763777045277973012166444898278932523394058911120151730195618798115985682912109254680669214795009010416348388142643429753460386073

    m1 = b'first message'
    r1 = 333782349848021509213940566064641535942895778978
    s1 = 247718250152856981202165151423538037190262575445

    m2 = b'second message'
    r2 = 205385639164345406596767187202560781874246547859
    s2 = 646276722049325349392814631031100151699004012685

    delta = 101
    myM = b'We manage to find the private key. -Group3'

    for d in range(delta):
        num = (s2 - s1 - d)
        den = modinv(r1 - r2, qDSA)
        x = num*den
        r, s = computeSignature(myM, x)
        valid = verifySignature(r, s, y, myM)

        if valid == True:
            print(d, x)
            break

    print('forged_message = ', myM)
    print('(r,s) = (', r, ' , ', s, ')')


    
   

if __name__ == '__main__':
    myMain2()
