from Cryptodome.Cipher import AES
from Cryptodome.Random import random
from tkinter import *
import ClientGUI
import base64, Const, ElGamal, json, os, requests, struct
import RSA as rsa
import AES as aes

# Cryptographic keys
PubKeyComp = None
ClientPubKeyN = None
ClientPubKeyE = None
CloudProviderPubKeyN = None
CloudProviderPubKeyE = None
CompPubKeyN = None
CompPubKeyE = None
#hashEndKey = None
#hashDate = None

# To compute (a * b) % mod
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

# Save configuration file
#def saveConfig(outfile, hashDate):
def saveConfig(outfile):
    # data = {Const.CLIENT+"_"+Const.NE: ClientPubKeyN, Const.CLIENT+"_"+Const.E: ClientPubKeyE,
    #         Const.CloudProvider+"_"+Const.NE: CloudProviderPubKeyN, Const.CloudProvider+"_"+Const.E: CloudProviderPubKeyE, Const.Comp+"_"+Const.NE: CompPubKeyN,
    #         Const.Comp+"_"+Const.E: CompPubKeyE, Const.Comp_PUBKEY: PubKeyComp, Const.START_KEY: hashEndKey,
    #         Const.DATE: hashDate.strftime("%Y-%m-%d")}
    data = {Const.CLIENT + "_" + Const.NE: ClientPubKeyN, Const.CLIENT + "_" + Const.E: ClientPubKeyE,
            Const.CLOUD_PROVIDER + "_" + Const.NE: CloudProviderPubKeyN, Const.CLOUD_PROVIDER + "_" + Const.E: CloudProviderPubKeyE,
            Const.COMP + "_" + Const.NE: CompPubKeyN,
            Const.COMP + "_" + Const.E: CompPubKeyE, Const.COMP_PUBKEY: PubKeyComp}
    with open(outfile, 'w') as fout:
        json.dump(data, fout, sort_keys=True)

# Load data from configuration file
def loadConfig(infile):
    if os.path.isfile(infile) is True:
        # global ClientPubKeyN, ClientPubKeyE, CloudProviderPubKeyN, CloudProviderPubKeyE, CompPubKeyN, CompPubKeyE, PubKeyComp, hashEndKey,\
        #     hashDate
        global ClientPubKeyN, ClientPubKeyE, CloudProviderPubKeyN, CloudProviderPubKeyE, CompPubKeyN, CompPubKeyE, PubKeyComp
        with open(infile, 'r') as fin:
            # Read data from file
            data = json.load(fin)
            # Get fields from json
            ClientPubKeyN = data[Const.CLIENT+"_"+Const.NE]
            ClientPubKeyE = data[Const.CLIENT+"_"+Const.E]
            CloudProviderPubKeyN = data[Const.CLOUD_PROVIDER+"_"+Const.NE]
            CloudProviderPubKeyE = data[Const.CLOUD_PROVIDER+"_"+Const.E]
            CompPubKeyN = (int)(data[Const.COMP+"_"+Const.NE])
            CompPubKeyE = (int)(data[Const.COMP+"_"+Const.E])
            PubKeyComp = data[Const.COMP_PUBKEY]
            #hashEndKey = str(data[Const.START_KEY])
            #hashDate = datetime.strptime(data[Const.DATE], "%Y-%m-%d")

# Obtain Companization public key from CloudProvider server
def getPubKeyComp(n, e):
    if PubKeyComp is None:
        global PubKeyComp, CloudProviderPubKeyN, CloudProviderPubKeyE, CompPubKeyN, CompPubKeyE
        # Create signature for sent data
        sign = rsa.generateSign([str(n), str(e)], Const.CLIENT)
        data = json.dumps({Const.NE: n, Const.E: e, Const.SIGN: sign})
        # Create POST request
        headers = {'Content-Type': 'application/json'}
        response = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.COMP_PUBKEY, data=data, headers=headers)
        if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
            return response.content
        # Get request response
        data = json.loads(response.content)
        PubKeyComp = data[Const.COMP_PUBKEY]
        CloudProviderPubKeyN = data[Const.NE]
        CloudProviderPubKeyE = data[Const.E]
        CompPubKeyN = data[Const.COMP+"_"+Const.NE]
        CompPubKeyE = data[Const.COMP+"_"+Const.E]
        sign = base64.decodestring(data[Const.SIGN])
        message = rsa.generateMessageForSign([str(PubKeyComp), str(CompPubKeyN), str(CompPubKeyE), str(CloudProviderPubKeyN), str(CloudProviderPubKeyE)])
        # Verify response
        if rsa.verifySign([CloudProviderPubKeyN, CloudProviderPubKeyE], message, sign) is True:
            return PubKeyComp
        else:
            return Const.ERROR
    else:
        return PubKeyComp

# Decrypt metadata in file and ask decryption to CloudProvider
# def getDecryptionData(encfile, sz):
#     with open(encfile, 'rb') as fin:
#         # Read size of plain text
#         size = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
#         #sizeDate = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
#         iv = fin.read(AES.block_size)
#         #protDate = datetime.strptime(fin.read(sizeDate), "%Y-%m-%d")
#         # if hashEndKey is None:
#         #     key, date = computeHashChainKey(ClientPubKeyN, ClientPubKeyE)
#         #     if date is None:
#         #         return Const.ERROR
#         # key = getHashKey(hashEndKey, hashDate, protDate)
#         # Create cipher
#         #aesCipher = AES.new(key, AES.MODE_CBC, iv)
#         dec = ""
#         while True:
#             # Read encrypted data from file
#             data = fin.read(sz)
#             n = len(data)
#             if n == 0:
#                 break
#             # Decrypy data
#             decd = aes.decrypt(aesCipher, data)
#             n = len(decd)
#             if size > n:
#                 dec += decd
#             else:
#                 dec += decd[:size]  # Remove padding on last block
#             size -= n
#         # Get fields from decrypted data
#         data = dec.split()
#         c1 = data[0][1:-1]
#         c2 = data[1][0:-1]
#         # Create POST request
#         sign = rsa.generateSign([str(ClientPubKeyN), str(ClientPubKeyE), str(c1), str(c2), str(protDate)], Const.CLIENT)
#         data = json.dumps({Const.NE: ClientPubKeyN, Const.E: ClientPubKeyE, Const.C1: c1, Const.C2: c2,
#                            Const.DATE: str(protDate), Const.SIGN: sign})
#         headers = {'Content-Type': 'application/json'}
#         response = requests.post("http://"+Const.CloudProvider_ADDR+":"+Const.CloudProvider_PORT+"/"+Const.DECRYPT, data=data, headers=headers)
#         if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
#             return Const.ERROR
#         data = json.loads(response.content)
#         # Get request response
#         m = rsa.decryptRSA(base64.decodestring(data[Const.M]), Const.CLIENT)
#         sign = base64.decodestring(data[Const.SIGN])
#         message = rsa.generateMessageForSign([m])
#         # Verify response
#         if rsa.verifySign([CompPubKeyN, CompPubKeyE], message, sign) is True:
#             return (long)(m)
#         else:
#             return Const.ERROR

# Generate random int for asymmetric encryption
def generateKey():
    print "P = (", len(bytes(Const.P)), ")", bytes(Const.P)
    print "Q = (", len(bytes(Const.Q)), ")", bytes(Const.Q)
    m = random.randint(1, Const.P - 1)
    print "m = (", len(bytes(m)), ")", bytes(m)
    return m

# Create encrypted metadata file with hash chain key
# def createHeaderFile(m, pubKeyComp, encfile, key):
#     c1, c2 = ElGamal.encrypt(m, pubKeyComp)
#     data = [c1, c2]
#     protDate = str(date.today())
#     # Get initialization vector
#     iv = aes.getIV()
#     aesCipher = AES.new(key, AES.MODE_CBC, iv)
#     size = len(bytes(data))
#     sizeDate = len(bytes(protDate))
#     # Encrypt header data
#     with open(encfile+'.bin', 'wb') as fout:
#         fout.write(struct.pack('<Q', size))
#         fout.write(struct.pack('<Q', sizeDate))
#         fout.write(iv)
#         fout.write(protDate)
#         encData = aes.encrypt(aesCipher, str(data))
#         fout.write(encData)

# Generate key from reverse hash chain
# def getHashKey(hashString, endWeekDate, currentDate):
#     # Compute number of days from Sunday of this week
#     delta = endWeekDate - currentDate
#     hashIterations = delta.days
#     # Compute key with hash chain
#     key = SHA256.new(data=hashString)
#     for i in range(hashIterations):
#         key.update(key.hexdigest())
#     return key.hexdigest()[:32]

# Ask Companization server the initial hash chain key
# def computeHashChainKey(n, e):
#     if CompPubKeyN is None:
#         global CompPubKeyN, CompPubKeyE, hashEndKey, hashDate
#         # Create POST request
#         sign = rsa.generateSign([str(n), str(e)], Const.CLIENT)
#         data = json.dumps({Const.NE: n, Const.E: e, Const.SIGN: sign})
#         headers = {'Content-Type': 'application/json'}
#         response = requests.post("http://"+Const.Comp_ADDR+":"+Const.Comp_PORT+"/"+Const.START_KEY, data=data,
#                                  headers=headers)
#         if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
#             return response.content, None
#         # Get request response
#         data = json.loads(response.content)
#         hashEndKey = rsa.decryptRSA(base64.decodestring(data[Const.START_KEY]), Const.CLIENT)
#         hashDate = rsa.decryptRSA(base64.decodestring(data[Const.DATE]), Const.CLIENT)
#         CompPubKeyN = data[Const.NE]
#         CompPubKeyE = data[Const.E]
#         sign = base64.decodestring(data[Const.SIGN])
#         message = rsa.generateMessageForSign([str(CompPubKeyN), str(CompPubKeyE), hashEndKey, hashDate])
#         # Verify response
#         if rsa.verifySign([CompPubKeyN, CompPubKeyE], message, sign) is True:
#             hashDate = datetime.strptime(hashDate, "%Y-%m-%d")
#         else:
#             return Const.ERROR, None
#     hashChainKey = getHashKey(str(hashEndKey), hashDate.date(), date.today())
#     return hashChainKey, hashDate

# Encrypt data in infile to encfile
def encryptFile(infile, encfile):
    global ClientPubKeyN, ClientPubKeyE
    if ClientPubKeyN is None:
        # Get public and private keys for asymmetric encryption
        ClientPubKeyN, ClientPubKeyE = rsa.createRSAKeys(Const.CLIENT)
    # Get public Companization key
    pubKeyComp = getPubKeyComp(ClientPubKeyN, ClientPubKeyE)
    if pubKeyComp is Const.BAD_REQ or pubKeyComp is Const.NO_METHOD or pubKeyComp is Const.ERROR:
        return pubKeyComp
    # Create file encryption key
    m = generateKey()
    # Compute hash chain key for encrypt file
    #hashKey, hashDate = computeHashChainKey(ClientPubKeyN, ClientPubKeyE)
    # if hashDate is None:
    #     return hashKey
    # Create file with metadata for file decryption
    #createHeaderFile(m, pubKeyComp, encfile, hashKey)

    c1, c2 = ElGamal.encrypt(m, pubKeyComp)
    data = [c1, c2]
    # protDate = str(date.today())
    # # Get initialization vector
    # hashIV = aes.getIV()
    # aesCipher = AES.new(hashKey, AES.MODE_CBC, hashIV)
    size = len(bytes(data))
    #sizeDate = len(bytes(protDate))
    #encData = aes.encrypt(aesCipher, str(data))
    # Get a random key
    key = aes.getKey(m)
    # Get initialization vector
    iv = aes.getIV()
    aesCipher = AES.new(key, AES.MODE_CBC, iv)
    fsz = os.path.getsize(infile)
    # Encrypt header and file data
    with open(encfile, 'wb') as fout:
        # Write header
        fout.write(struct.pack('<Q', size))
    #    fout.write(struct.pack('<Q', sizeDate))
    #    fout.write(hashIV)
    #    fout.write(protDate)
    #    fout.write(encData)
        fout.write(str(data))
        # Write file
        fout.write(struct.pack('<Q', fsz))
        fout.write(iv)
        with open(infile, 'rb') as fin:
            while True:
                data = fin.read(Const.RSA_BITS)
                n = len(data)
                if n == 0:
                    break
                encData = aes.encrypt(aesCipher, data)
                fout.write(encData)
    #saveConfig(Const.CLIENT + "_" + Const.CONFIG + '.json', hashDate)
    saveConfig(Const.CLIENT+"_"+Const.CONFIG+'.json')
    return None

# Decrypt file
def decryptFile(encfile, decfile):
    # Get key for asymmetric encryption
    #m = getDecryptionData(encfile, sz)

    with open(encfile, 'rb') as fin:
        # Read size of plain text
        size = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        #sizeDate = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        #hashIV = fin.read(AES.block_size)
        # protDate = datetime.strptime(fin.read(sizeDate), "%Y-%m-%d")
        # if hashEndKey is None:
        #     key, date = computeHashChainKey(ClientPubKeyN, ClientPubKeyE)
        #     if date is None:
        #         return Const.ERROR
        # key = getHashKey(hashEndKey, hashDate, protDate)
        # Create cipher
        #aesCipher = AES.new(key, AES.MODE_CBC, hashIV)
        #dec = ""
        data = ""
        while size > 0:
            # Read encrypted data from file
            readBytes = fin.read(AES.block_size)
            n = len(readBytes)
            if n == 0:
                break
            # Decrypy data
            #decd = aes.decrypt(aesCipher, data)
            #n = len(decd)
            if size > n:
                data += readBytes
            else:
                data += readBytes[:size]  # Remove padding on last block
            size -= n
        # Get fields from decrypted data
        data = data.split()
        c1 = int(data[0][1:-2])
        c2 = int(data[1][0:-2])
        # Create POST request
        # sign = rsa.generateSign([str(ClientPubKeyN), str(ClientPubKeyE), str(c1), str(c2), str(protDate)], Const.CLIENT)
        # data = json.dumps({Const.NE: ClientPubKeyN, Const.E: ClientPubKeyE, Const.C1: c1, Const.C2: c2,
        #                    Const.DATE: str(protDate), Const.SIGN: sign})
        # Ask decryption to Cloud Provider server
        sign = rsa.generateSign([str(ClientPubKeyN), str(ClientPubKeyE), str(c1), str(c2)], Const.CLIENT)
        data = json.dumps(
            {Const.NE: ClientPubKeyN, Const.E: ClientPubKeyE, Const.C1: c1, Const.C2: c2, Const.SIGN: sign})
        headers = {'Content-Type': 'application/json'}
        responseCloudProvider = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.DECRYPT, data=data, headers=headers)
        if (responseCloudProvider.content is Const.NO_METHOD) or (responseCloudProvider.content is Const.BAD_REQ):
            return Const.ERROR
        data = json.loads(responseCloudProvider.content)
        # Get request response
        mCP = rsa.decryptRSA(base64.decodestring(data[Const.M]), Const.CLIENT)
        sign = base64.decodestring(data[Const.SIGN])
        message = rsa.generateMessageForSign([mCP])
        # Verify response
        if rsa.verifySign([CloudProviderPubKeyN, CloudProviderPubKeyE], message, sign) is not True:
            return Const.ERROR
        # Ask decryption to Company server
        sign = rsa.generateSign([str(ClientPubKeyN), str(ClientPubKeyE), str(c1), str(c2)], Const.CLIENT)
        data = json.dumps({Const.NE: ClientPubKeyN, Const.E: ClientPubKeyE, Const.C1: c1, Const.C2: c2, Const.SIGN: sign})
        headers = {'Content-Type': 'application/json'}
        responseCompany = requests.post("http://"+Const.COMP_ADDR+":"+Const.COMP_PORT+"/"+Const.DECRYPT,data=data,headers=headers)
        if (responseCompany.content is Const.NO_METHOD) or (responseCompany.content is Const.BAD_REQ):
            return Const.ERROR
        data = json.loads(responseCompany.content)
        # Get request response
        mComp = rsa.decryptRSA(base64.decodestring(data[Const.M]), Const.CLIENT)
        sign = base64.decodestring(data[Const.SIGN])
        message = rsa.generateMessageForSign([mComp])
        # Verify response
        if rsa.verifySign([CompPubKeyN, CompPubKeyE], message, sign) is not True:
            return Const.ERROR
        m = mulmod(long(mCP), long(mComp), Const.P)
        print "m = (", len(str(m)) ,")", m
        key = aes.getKey(m)
        # Read size of plain text
        fsz = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        iv = fin.read(AES.block_size)
        aesCipher = AES.new(key, AES.MODE_CBC, iv)
        with open(decfile, 'wb') as fout:
            while True:
                data = fin.read(Const.RSA_BITS)
                print "Ho letto ", data
                n = len(data)
                if n == 0:
                    break
                # Decrypt data
                decd = aes.decrypt(aesCipher, data)
                n = len(decd)
                if fsz > n:
                    fout.write(decd)
                else:
                    fout.write(decd[:fsz]) # Remove padding on last block
                fsz -= n
    return None


if __name__ == "__main__":
    loadConfig(Const.CLIENT+"/"+Const.CLIENT+"_"+Const.CONFIG+'.json')
    root = Tk()
    gui = ClientGUI.ClientGUI(root)
    root.mainloop()
