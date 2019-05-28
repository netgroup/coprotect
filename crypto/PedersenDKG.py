from Cryptodome.Random import random
import Const, ElGamal

class PedersenDKG:

    id = 0      # peer id in DKG scheme
    h = 0       # public key share
    y = 0       # full share
    s = 0       # private key share
    pubKey = 0  # public key
    poly = []   # polynomial coefficients
    shares = [] # partial shares
    delta = 1.0 # Lagrange coefficient

    def setParams(self, id):
        self.id = id

    # Create random polynomial
    def create_polynomial(self, degree, mod):
        self.poly = []
        for i in range(degree):
            self.poly.append(random.randint(1, mod-1))

    # Compute partial shares
    def compute_shares(self, coeff, max_degree, num, mod):
        self.shares = []
        for i in range(1, num+1):
            share = 0
            for j in range(max_degree):
                share += ElGamal.mulmod(coeff[j], pow(i,j), mod)
            self.shares.append(share % mod)

    # Compute public key share
    def compute_pubKeyShare(self, g, exp):
        self.h = ElGamal.powerMod(g, exp, Const.P)

    # Compute full share for decryption
    def compute_fullShare(self, otherShares):
        self.y = self.shares[self.id-1]
        for share in otherShares:
            self.y += share
        self.y % Const.Q

    # Set public key
    def setPubKey(self, key):
        self.pubKey = key % Const.P

    # Compute Lagrange coefficient
    def compute_delta(self, shares):
        self.delta = 1.0
        for i in shares:
            if i != self.id:
                num = -i % Const.Q
                den = ElGamal.modinv(self.id-i, Const.Q)
                self.delta = ElGamal.mulmod(num, den, Const.Q)

    # Compute private key share
    def compute_privKeyShare(self):
        self.s = (long)(ElGamal.mulmod(self.y, self.delta, Const.Q))

    # Class constructor
    def __init__(self, id, poly):
        self.setParams(id)
        if poly is not None:
            self.poly = poly
        else:
            self.create_polynomial(Const.T, Const.Q)
        self.compute_shares(self.poly, Const.T, Const.N, Const.Q)
        self.compute_pubKeyShare(Const.G, self.poly[0])
