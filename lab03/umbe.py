from AISC_03 import *
from random import randint


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x


def miller_rabin(p, k=100):
    s = 0
    r = p - 1
    while True:
        r //= 2
        s = s + 1
        if r % 2 != 0:
            break
    assert (p - 1) == pow(2, s) * r
    for i in range(0, k):
        a = randint(2, p - 1)
        x = pow(a, r, p)
        if x != 1 and x != p - 1:
            j = 1
            while j < s and x != p - 1:
                x = pow(x, 2, p)
                if x == 1:
                    return False
                j = j + 1
            if x != p - 1:
                return False
    return True


def main():
    N = 84679728665601623534964724907925515929006540043189517481604602443064696359792213876789134073333039587280256381629121330309212710075084136072434602842735932397920567074126295940793758270599694063151970957022891161811181118800418280560581409959172714364916927401331291518944188508877716559336163266657183044021
    e = 65537
    s = "This group is composed by Stefano Agnetta, Umberto Brozzo Doda nad Davide Macario"

    bitlen = N.bit_length()

    m = encodeText(s, bitlen)

    c = pow(m[0], e, N)
    print("c: ", c)

    # Test primality-checking function
    print(
        miller_rabin(
            110726941258106613165182448269850102236786629354458149980228894972416575667359
        )
    )
    print(
        miller_rabin(
            81116712346948063995695516399923130132965396377321265571871460960105500481321
        )
    )

    keylen = 1024

    found = False
    while found == False:
        p = generate_prime_candidate(keylen // 2)
        found = miller_rabin(p)
    found = False
    while found == False:
        q = generate_prime_candidate(keylen // 2)
        found = miller_rabin(q)

    N = p * q

    try:
        assert N.bit_length() == keylen
    except AssertionError:
        print("N generation error:")
        print("size of N is", N.bit_length(), "bits instead of", keylen)
        sys.exit(1)

    print("p: ", p)
    print("q: ", q)
    print("N: ", N)

    phi = (p - 1) * (q - 1)

    M = 2 ^ 16 + 1

    found = False
    while found == False:
        e = randint(3, M)
        g, x, y = egcd(e, phi)
        if g == 1:
            found = True
        else:
            found = False
    d = x % phi

    print("e: ", e)
    print("d: ", d)

    N = 148130618023985480673845216738878752131089137736084036130967887251564542754118593331740936778879886665119557767007210094983768821396495865829633849021983868546066979196808070332916907953346989106700230856307557008478829000662397691558342492226527045405150869024517235871725499677021196351743492599434573995139
    e = 7
    d = 21161516860569354381977888105554107447298448248012005161566841035937791822016941904534419539839983809302793966715315727854824117342356552261376264145997692028823665208138643381136929032321336350779113201150451044225977972810890701117768897179448378661568928615778655873608465012553074479509471948040498751183

    c = 342478911541572405414900174942959678995982599596991680443243536714635729271712009965782080606067227291872633571795648397020917168192222394295425368432661163316809168485804053879157073290220083182181650623178765105987764705476725089223065343048061841333902030225408
    m = []
    m.append(pow(c, d, N))
    s = decodeText(m, bitlen)

    print("s: ", s)


if __name__ == "__main__":
    main()
