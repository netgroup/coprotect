from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Random import random
from datetime import date, datetime
from tkinter import *
import ClientGUI
import base64, Const, ElGamal, json, os, requests, struct, sys
import RSA as rsa
import AES as aes

# Cryptographic keys
PubKeyCompany = None
ClientPubKeyN = None
ClientPubKeyE = None
CloudProviderPubKeyN = None
CloudProviderPubKeyE = None
CompanyPubKeyN = None
CompanyPubKeyE = None
m = None
hashEndKey = None
hashDate = None

# Save configuration file
#def saveConfig(outfile, hashDate):
def saveConfig(outfile):
    # data = {Const.CLIENT+"_"+Const.NE: ClientPubKeyN, Const.CLIENT+"_"+Const.E: ClientPubKeyE,
    #         Const.CLOUD_PROVIDER+"_"+Const.NE: CloudProviderPubKeyN, Const.CLOUD_PROVIDER+"_"+Const.E: CloudProviderPubKeyE, Const.COMPANY+"_"+Const.NE: CompanyPubKeyN,
    #         Const.COMPANY+"_"+Const.E: CompanyPubKeyE, Const.COMPANY_PUBKEY: PubKeyCompany, Const.START_KEY: hashEndKey,
    #         Const.DATE: hashDate.strftime("%Y-%m-%d")}
    data = {Const.CLIENT + "_" + Const.NE: ClientPubKeyN, Const.CLIENT + "_" + Const.E: ClientPubKeyE,
            Const.CLOUD_PROVIDER + "_" + Const.NE: CloudProviderPubKeyN,
            Const.CLOUD_PROVIDER + "_" + Const.E: CloudProviderPubKeyE, Const.COMPANY + "_" + Const.NE: CompanyPubKeyN,
            Const.COMPANY + "_" + Const.E: CompanyPubKeyE, Const.COMPANY_PUBKEY: PubKeyCompany}
    with open(outfile, 'w') as fout:
        json.dump(data, fout, sort_keys=True)

# Load data from configuration file
def loadConfig(infile):
    if os.path.isfile(infile) is True:
        # global ClientPubKeyN, ClientPubKeyE, CloudProviderPubKeyN, CloudProviderPubKeyE, CompanyPubKeyN, CompanyPubKeyE, PubKeyCompany, hashEndKey,\
        #     hashDate
        global ClientPubKeyN, ClientPubKeyE, CloudProviderPubKeyN, CloudProviderPubKeyE, CompanyPubKeyN, CompanyPubKeyE, PubKeyCompany
        with open(infile, 'r') as fin:
            # Read data from file
            data = json.load(fin)
            # Get fields from json
            #print "Dati in loadConfig =", data
            ClientPubKeyN = data[Const.CLIENT+"_"+Const.NE]
            ClientPubKeyE = data[Const.CLIENT+"_"+Const.E]
            CloudProviderPubKeyN = data[Const.CLOUD_PROVIDER+"_"+Const.NE]
            CloudProviderPubKeyE = data[Const.CLOUD_PROVIDER+"_"+Const.E]
            CompanyPubKeyN = (long)(data[Const.CLOUD_PROVIDER+"_"+Const.NE])
            CompanyPubKeyE = (int)(data[Const.CLOUD_PROVIDER+"_"+Const.E])
            PubKeyCompany = data[Const.COMPANY_PUBKEY]
            # hashEndKey = str(data[Const.START_KEY])
            # hashDate = datetime.strptime(data[Const.DATE], "%Y-%m-%d")

# Obtain organization public key from Cloud Provider server
def getPubKeyCompany(n, e):
    if PubKeyCompany is None:
        global PubKeyCompany, CloudProviderPubKeyN, CloudProviderPubKeyE, CompanyPubKeyN, CompanyPubKeyE
        # Create signature for sent data
        sign = rsa.generateSign([str(n), str(e)], Const.CLIENT)
        data = json.dumps({Const.NE: n, Const.E: e, Const.SIGN: sign})
        # Create POST request
        headers = {'Content-Type': 'application/json'}
        response = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.COMPANY_PUBKEY, data=data, headers=headers)
        if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
            return response.content
        # Get request response
        data = json.loads(response.content)
        PubKeyCompany = data[Const.COMPANY_PUBKEY]
        CloudProviderPubKeyN = data[Const.NE]
        CloudProviderPubKeyE = data[Const.E]
        CompanyPubKeyN = data[Const.COMPANY + "_" + Const.NE]
        CompanyPubKeyE = data[Const.COMPANY + "_" + Const.E]
        sign = base64.decodestring(data[Const.SIGN])
        # message = rsa.generateMessageForSign([str(PubKeyOrg), str(CloudProviderPubKeyN), str(CloudProviderPubKeyE)])
        message = rsa.generateMessageForSign(
            [str(PubKeyCompany), str(CompanyPubKeyN), str(CompanyPubKeyE), str(CloudProviderPubKeyN), str(CloudProviderPubKeyE)])
        # Verify response
        if rsa.verifySign([CloudProviderPubKeyN, CloudProviderPubKeyE], message, sign) is True:
            return PubKeyCompany
        else:
            return Const.ERROR
    else:
        return PubKeyCompany

# Decrypt metadata in file and ask decryption to Cloud Provider
# def getDecryptionData(encfile, sz):
#     with open(encfile, 'rb') as fin:
#         # Read size of plain text
#         size = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
#         sizeDate = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
#         iv = fin.read(AES.block_size)
#         protDate = datetime.strptime(fin.read(sizeDate), "%Y-%m-%d")
#         if hashEndKey is None:
#             key, date = computeHashChainKey(ClientPubKeyN, ClientPubKeyE)
#             if date is None:
#                 return Const.ERROR
#         key = getHashKey(hashEndKey, hashDate, protDate)
#         # Create cipher
#         aesCipher = AES.new(key, AES.MODE_CBC, iv)
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
#         response = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.DECRYPT, data=data, headers=headers)
#         if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
#             return Const.ERROR
#         data = json.loads(response.content)
#         # Get request response
#         m = rsa.decryptRSA(base64.decodestring(data[Const.M]), Const.CLIENT)
#         sign = base64.decodestring(data[Const.SIGN])
#         message = rsa.generateMessageForSign([m])
#         # Verify response
#         if rsa.verifySign([OrgPubKeyN, OrgPubKeyE], message, sign) is True:
#             return (long)(m)
#         else:
#             return Const.ERROR

# Generate random int for asymmetric encryption
def generateKey():
    global m
    m = random.randint(1, Const.P - 1)
    return m

# Create encrypted metadata file with hash chain key
# def createHeaderFile(m, pubKeyOrg, encfile, key):
#     c1, c2 = ElGamal.encrypt(m, pubKeyOrg)
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

# Ask organization server the initial hash chain key
# def computeHashChainKey(n, e):
#     if CompanyPubKeyN is None:
#         global CompanyPubKeyN, CompanyPubKeyE, hashEndKey, hashDate
#         # Create POST request
#         sign = rsa.generateSign([str(n), str(e)], Const.CLIENT)
#         data = json.dumps({Const.NE: n, Const.E: e, Const.SIGN: sign})
#         headers = {'Content-Type': 'application/json'}
#         response = requests.post("http://"+Const.COMPANY_ADDR+":"+Const.COMPANY_PORT+"/"+Const.START_KEY, data=data,
#                                  headers=headers)
#         if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
#             return response.content, None
#         # Get request response
#         data = json.loads(response.content)
#         hashEndKey = rsa.decryptRSA(base64.decodestring(data[Const.START_KEY]), Const.CLIENT)
#         hashDate = rsa.decryptRSA(base64.decodestring(data[Const.DATE]), Const.CLIENT)
#         CompanyPubKeyN = data[Const.NE]
#         CompanyPubKeyE = data[Const.E]
#         sign = base64.decodestring(data[Const.SIGN])
#         message = rsa.generateMessageForSign([str(CompanyPubKeyN), str(CompanyPubKeyE), hashEndKey, hashDate])
#         # Verify response
#         if rsa.verifySign([CompanyPubKeyN, CompanyPubKeyE], message, sign) is True:
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
    # Get public organization key
    pubKeyCompany = getPubKeyCompany(ClientPubKeyN, ClientPubKeyE)
    if pubKeyCompany is Const.BAD_REQ or pubKeyCompany is Const.NO_METHOD or pubKeyCompany is Const.ERROR:
        return pubKeyCompany
    # Create file encryption key
    m = generateKey()
    print "m =", m
    # Compute hash chain key for encrypt file
    # hashKey, hashDate = computeHashChainKey(ClientPubKeyN, ClientPubKeyE)
    # if hashDate is None:
    #     return hashKey
    # Create file with metadata for file decryption
    #createHeaderFile(m, pubKeyOrg, encfile, hashKey)

    c1, c2 = ElGamal.encrypt(m, pubKeyCompany)
    data = [c1, c2]
    # protDate = str(date.today())
    # # Get initialization vector
    # hashIV = aes.getIV()
    # aesCipher = AES.new(hashKey, AES.MODE_CBC, hashIV)
    size = len(bytes(data))
    # sizeDate = len(bytes(protDate))
    # encData = aes.encrypt(aesCipher, str(data))
    # Get a random key
    key = aes.getKey(m)
    # Get initialization vector
    iv = aes.getIV()
    aesCipher = AES.new(key, AES.MODE_CBC, iv)
    fsz = os.path.getsize(infile)
    #print "m=",m,"\nc1=",c1,"\nc2=",c2,"\nsize=",size,"\nsizeDate=",sizeDate,"\nhashIV=",hashIV,"\nprotDate=",protDate,"\nfsz=",fsz,"\niv=",iv
    # Encrypt header and file data
    with open(encfile, 'wb') as fout:
        # Write header
        fout.write(struct.pack('<Q', size))
        # fout.write(struct.pack('<Q', sizeDate))
        # fout.write(hashIV)
        # fout.write(protDate)
        # fout.write(encData)
        fout.write(str(data))
        # print "Scrivo c1 c2: ", encData
        # Write file
        fout.write(struct.pack('<Q', fsz))
        fout.write(iv)
        with open(infile, 'rb') as fin:
            while True:
                data = fin.read(Const.RSA_BITS)
                n = len(data)
                if n == 0:
                    break
                #print "Scrivo file: ", data
                encData = aes.encrypt(aesCipher, data)
                fout.write(encData)
    #saveConfig(Const.CLIENT + "_" + Const.CONFIG + '.json', hashDate)
    saveConfig(Const.CLIENT + "_" + Const.CONFIG + '.json')
    return None

# Decrypt file
def decryptFile(encfile, decfile):
    # Get key for asymmetric encryption
    #m = getDecryptionData(encfile, sz)

    with open(encfile, 'rb') as fin:
        # Read size of plain text
        size = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        # sizeDate = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        # hashIV = fin.read(AES.block_size)
        # protDate = datetime.strptime(fin.read(sizeDate), "%Y-%m-%d")
        # if hashEndKey is None:
        #     key, date = computeHashChainKey(ClientPubKeyN, ClientPubKeyE)
        #     if date is None:
        #         return Const.ERROR
        # key = getHashKey(hashEndKey, hashDate, protDate)
        # # Create cipher
        # aesCipher = AES.new(key, AES.MODE_CBC, hashIV)
        # dec = ""
        data = ""
        while size > 0:
            # Read encrypted data from file
            readBytes = fin.read(size)
            n = len(readBytes)
            if n == 0:
                break
            # Decrypy data
            # print "Leggo c1 c2: ", data
            # decd = aes.decrypt(aesCipher, data)
            # n = len(decd)
            if size > n:
                data += readBytes
            else:
                data += readBytes[:size]  # Remove padding on last block
            size -= n
        # Get fields from decrypted data
        data = data.split()
        c1 = data[0][1:-1]
        c2 = data[1][0:-1]
        # Create POST request
        # sign = rsa.generateSign([str(ClientPubKeyN), str(ClientPubKeyE), str(c1), str(c2), str(protDate)], Const.CLIENT)
        # data = json.dumps({Const.NE: ClientPubKeyN, Const.E: ClientPubKeyE, Const.C1: c1, Const.C2: c2,
        #                    Const.DATE: str(protDate), Const.SIGN: sign})
        sign = rsa.generateSign([str(ClientPubKeyN), str(ClientPubKeyE), str(c1), str(c2)], Const.CLIENT)
        data = json.dumps(
            {Const.NE: ClientPubKeyN, Const.E: ClientPubKeyE, Const.C1: c1, Const.C2: c2, Const.SIGN: sign})
        headers = {'Content-Type': 'application/json'}
        response = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.DECRYPT, data=data, headers=headers)
        if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
            return Const.ERROR
        data = json.loads(response.content)
        # Get request response
        m = rsa.decryptRSA(base64.decodestring(data[Const.M]), Const.CLIENT)
        # mCP = data[Const.M]
        sign = base64.decodestring(data[Const.SIGN])
        message = rsa.generateMessageForSign([m])
        # Verify response
        if rsa.verifySign([CloudProviderPubKeyN, CloudProviderPubKeyE], message, sign) is not True:
            return Const.ERROR
        # Ask decryption to Company server
        sign = rsa.generateSign([str(ClientPubKeyN), str(ClientPubKeyE), str(c1), str(m)], Const.CLIENT)
        data = json.dumps(
            {Const.NE: ClientPubKeyN, Const.E: ClientPubKeyE, Const.C1: c1, Const.C2: m, Const.SIGN: sign})
        headers = {'Content-Type': 'application/json'}
        responseCompany = requests.post("http://" + Const.COMPANY_ADDR + ":" + Const.COMPANY_PORT + "/" + Const.DECRYPT,
                                        data=data, headers=headers)
        if (responseCompany.content is Const.NO_METHOD) or (responseCompany.content is Const.BAD_REQ):
            return Const.ERROR
        data = json.loads(responseCompany.content)
        # Get request response
        m = rsa.decryptRSA(base64.decodestring(data[Const.M]), Const.CLIENT)
        # mCompany = data[Const.M]
        sign = base64.decodestring(data[Const.SIGN])
        message = rsa.generateMessageForSign([m])
        # Verify response
        if rsa.verifySign([CompanyPubKeyN, CompanyPubKeyE], message, sign) is not True:
            return Const.ERROR
        key = aes.getKey((long)(m))
        # Read size of plain text
        fsz = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        iv = fin.read(AES.block_size)
        aesCipher = AES.new(key, AES.MODE_CBC, iv)
        with open(decfile, 'wb') as fout:
            while True:
                data = fin.read(Const.RSA_BITS)
                n = len(data)
                if n == 0:
                    break
                # Decrypt data
                print "Leggo file:", data
                decd = aes.decrypt(aesCipher, data)
                print "Ho decifrato:", decd
                n = len(decd)
                if fsz > n:
                    fout.write(decd)
                else:
                    fout.write(decd[:fsz]) # Remove padding on last block
                fsz -= n
    return None


if __name__ == "__main__":
    loadConfig(Const.CLIENT + "_" + Const.CONFIG + '.json')
    root = Tk()
    gui = ClientGUI.ClientGUI(root)
    root.mainloop()
