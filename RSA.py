from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
import Const, base64, os

# Create RSA public and private keys and save them on different files
def createRSAKeys(outfile):
    if os.path.isfile(outfile) is False:
        key = RSA.generate(Const.RSA_BITS)
        privKey = key.export_key()
        file_out = open(outfile+"_private.pem", "wb")
        file_out.write(privKey)
        pubKey = key.publickey().export_key()
        file_out = open(outfile+"_receiver.pem", "wb")
        file_out.write(pubKey)
        return key.n, key.e
    else:
        key = RSA.import_key(open(outfile + "_receiver.pem").read())
        return key.n, key.e

# Encrypt data with the public RSA key
def encryptRSA(data, infile, comps):
    if infile is not None:
        key = RSA.import_key(open(infile+"_receiver.pem").read())
    else:
        key = RSA.construct(comps, consistency_check=True).publickey()
    # Encrypt data with the public RSA key
    cipherRSA = PKCS1_OAEP.new(key)
    encData = ""
    while len(bytes(data)) > Const.RSA_MAX_BYTES_LEN:
        encData += cipherRSA.encrypt(data[:Const.RSA_MAX_BYTES_LEN])
        data = data[Const.RSA_MAX_BYTES_LEN:]
    encData += cipherRSA.encrypt(data)
    return encData

# Decrypt data with the private RSA key
def decryptRSA(data, infile):
    private_key = RSA.import_key(open(infile+"_private.pem").read())
    # Decrypt the session key with the private RSA key
    cipherRSA = PKCS1_OAEP.new(private_key)
    decData = ""
    while len(bytes(data)) > 256:#Const.RSA_MAX_BYTES_LEN:
        s = data[:256]#Const.RSA_MAX_BYTES_LEN]
        decData += cipherRSA.decrypt(s)
        data = data[256:]#Const.RSA_MAX_BYTES_LEN:]
    decData += cipherRSA.decrypt(data)
    return decData

def generateMessageForSign(data):
    message = ""
    for i in range(len(data)):
        if i == 0:
            message += data[i]
        else:
            message += "," + data[i]
    return message

# Create signature
def sign(message, infile):
    digest = SHA256.new(message)
    # Read shared key from file
    with open(infile+"_private.pem", "r") as fin:
        private_key = RSA.importKey(fin.read())
    # Load private key and sign message
    sign = pkcs1_15.new(private_key).sign(digest)
    return sign

def generateSign(data, signer):
    message = generateMessageForSign(data)
    sig = base64.encodestring(sign(message, signer))
    return sig

# Load public key and verify message
def verifySign(comps, message, sign):
    key = RSA.construct(comps, consistency_check=True).publickey()
    verifier = pkcs1_15.new(key)
    digest = SHA256.new(message)
    verified = verifier.verify(digest, sign)
    if verified:
        print "Signature verification failed"
        return verified
    return True
