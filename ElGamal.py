from Cryptodome.Random import random
import Const

# Compute modular exponentiation a^b%n
def powerMod(a, b, n):
    return pow(a, b, n)

# Compute extended greatest common divisor
def xgcd(a,b):
    prevx, x = 1, 0; prevy, y = 0, 1
    while b:
        q = a/b
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, a % b
    return a, prevx, prevy

# Compute modular moltiplicative inverse
def modinv(a, m):
    g, x, y = xgcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# Elgamal encryption
def encrypt(m, h):
    y = random.randint(1, Const.P-1)
    c1 = powerMod(Const.G, y, Const.P)
    s = powerMod(h, y, Const.P)
    c2 = m*s % Const.P
    return (int)(c1), (int)(c2)

# Elgamal decryption
def decrypt(c1, c2, x):
    x %= Const.P
    s = powerMod(c1, x, Const.P)
    inv_s = modinv(s, Const.P)
    m = (c2 * inv_s) % Const.P
    return m
