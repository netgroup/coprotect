from Cryptodome.Random import random
import Const

# Compute (a * b) % mod
def mulmod(a, b, mod):
    res = 0  # Initialize result
    a = a % mod
    while (b > 0):
        # If b is odd, add 'a' to result
        if (b % 2 == 1):
            res = (res + a) % mod
        # Multiply 'a' with 2
        a = (a * 2) % mod
        # Divide b by 2
        b //= 2
    # Return result
    return res % mod

# Compute modular exponentiation (a ^ b) % n
def powerMod(a, b, mod):
    return pow(a, b, mod)

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
    c2 = mulmod(m,s, Const.P)
    return (int)(c1), (int)(c2)

# Elgamal decryption
def decrypt(c1, c2, x):
    x %= Const.P
    s = powerMod(c1, x, Const.P)
    inv_s = modinv(s, Const.P)
    m = mulmod(c2, inv_s, Const.P)
    return m
