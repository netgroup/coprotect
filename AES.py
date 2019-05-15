from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Random import random

# Generate a random key
def getKey(m):
    m_bytes = "".join(chr((m >> (i * 8)) & 0xFF) for i in range(AES.block_size))
    key = SHA256.new(data=m_bytes)
    return key.hexdigest()[:32]

# Generate initialization vector for AES
def getIV():
    return ''.join([chr(random.randint(0, 0xFF)) for i in range(AES.block_size)])

# Add padding for block to encrypt
def addPadding(data):
    n = len(data)
    if n % AES.block_size != 0:
        data += ' ' * (AES.block_size - n % AES.block_size)  # padded with spaces
    return data

# Encrypt data
def encrypt(cipher, data):
    data = addPadding(data)
    encd = cipher.encrypt(data)
    return encd

# Decrypt data
def decrypt(cipher, encData):
    return cipher.decrypt(encData)
