import secrets
import random


def modular_power(x, y, m):
    res = 1

    x = x % m
    while y > 0:
        if y % 2 == 1:
            res = (res * x) % m

        y = y >> 1

        x = (x * x) % m

    return res


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def extended_euclidian_algorithm(a, b):
    x = 0
    y = 1
    lx = 1
    ly = 0
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    return lx, ly


def miller_rabin_test(n, num_of_tests):
    s = 0
    t = n - 1
    while t % 2 == 1:
        t = t >> 1
        s += 1

    for i in range(num_of_tests):
        a = random.randrange(2, n)
        b = modular_power(a, t, n)
        if b == 1 or b == n - 1:
            continue
        return False
    return True



def generate_prime(bits):
    candidate = secrets.randbits(bits)
    candidate |= 1


    while not miller_rabin_test(candidate, 64):
        candidate = secrets.randbits(bits)
        candidate |= 1

    return candidate


def generate_e(phi):
    e = secrets.randbelow(phi - 2) + 2
    while gcd(e, phi) > 1:
        e = secrets.randbelow(phi - 2) + 2
    return e


def generate_key_pair(p, q):
    if (p == q):
        raise ValueError("Numbers p and q cannot be equal.")

    n = p * q
    phi = (p - 1) * (q - 1)
    e = generate_e(phi)
    d, x = extended_euclidian_algorithm(e, phi)
    priv = d % phi
    return (n, e), priv


def rsa_encrypt(public_key, plain_text):
    n, e = public_key
    cipher_text = modular_power(plain_text, e, n)
    return cipher_text


def rsa_decrypt(private_key, cipher_text, p, q):
    dp = private_key % (p-1)
    dq = private_key % (q-1)

    mp = modular_power(cipher_text, dp, p)
    mq = modular_power(cipher_text, dq, q)

    yp, yq = extended_euclidian_algorithm(p, q)

    plain_text = (mp * yq * q + mq * yp * p) % (p % q)
    return plain_text



def text_to_num(text):
    r = 0
    for char in text:
        r = (r << 8) + ord(char)
    return r


def num_to_text(num):
    r = ""
    while num != 0:
        r += chr(num % (2 ** 8))
        num = num >> 8
    return r[::-1]


p = generate_prime(1024)
q = generate_prime(1024)
publick, privatek = generate_key_pair(p, q)
print(f"A generált prímek: {p, q}")

print(f"Publikus kulcs: {publick}")
print(f"Privát kulcs: {privatek}")
m = "Hello RSA"
print(f"A titkosítandó üzenet: {m}")
m = text_to_num(m)
c = rsa_encrypt(publick, m)
print(f"A titkosított üzenet: {c}")
d = rsa_decrypt(privatek, c, p, q)
d = num_to_text(d)
print(f"Visszafejtett üzenet: {d} ")

