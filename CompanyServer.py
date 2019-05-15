from flask import Flask, request
from datetime import date
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Random import random
import base64, Const, ElGamal, json, requests
from PedersenDKG import PedersenDKG
import RSA as rsa
import AES as aes

# Cryptographic keys and shares
#RootChainKey = 65536
PubKeyComp = 0
CompPubKeyN = 0
CompPubKeyE = 0
protShare = 0

# Generate key from reverse hash chain
# def getHashKey():
#     # Compute number of days from first day of the year
#     today = date.today()
#     weekOffset = 6 - today.weekday()
#     endWeekDate = date(today.year, today.month, today.day + weekOffset)
#     delta = date(today.year, 12, 31) - endWeekDate
#     hashIterations = delta.days + 1
#     # Compute key with hash chain
#     key = SHA256.new(data=str(RootChainKey))
#     for i in range(hashIterations):
#         key.update(key.hexdigest())
#     return key.hexdigest()[:32], endWeekDate

# Decrypt data received from CloudProvider obtaining full decryption
def decryptData(data, clientPubKeyN, clientPubKeyE):
    global dkg1, dkg2, otherShares1, otherShares2, PubKeyComp
    dkg1 = PedersenDKG(Const.CLIENT_DKG_ID1, poly1)
    dkg2 = PedersenDKG(Const.CLIENT_DKG_ID2, poly2)
    dkg1.compute_fullShare(otherShares1)
    dkg2.compute_fullShare(otherShares2)
    dkg1.setPubKey(PubKeyComp)
    dkg2.setPubKey(PubKeyComp)
    c1 = (int)(data[Const.C1])
    c2 = (int)(data[Const.C2])
    #protShare = base64.decodestring(data[Const.PROT_SHARE])
    sign = base64.decodestring(data[Const.SIGN])
    message = rsa.generateMessageForSign([str(clientPubKeyN), str(clientPubKeyE), str(c1), str(c2)])
    # Verify signature
    if rsa.verifySign([clientPubKeyN, clientPubKeyE], message, sign) is True:
        aesCipher = AES.new(aesKey, AES.MODE_CBC, aesIV)
        dkg1.y = (int)(aes.decrypt(aesCipher, protShare))
        dkg1.compute_delta([Const.CLOUD_PROVIDER_DKG_ID])
        dkg1.compute_privKeyShare()
        # Decrypt data
        m = ElGamal.decrypt(c1, c2, dkg1.s)
        return m
    else:
        return Const.BAD_REQ

# Send data to CloudProvider for Pedersen exchanges
def sendDataToCloudProvider(dkg1, dkg2, CompPubKeyN, CompPubKeyE):
    id = Const.CLOUD_PROVIDER_DKG_ID
    share1 = dkg1.shares[id-1]
    share2 = dkg2.shares[id-1]
    CompPubKeyShare = dkg1.h * dkg2.h
    sign = rsa.generateSign([str(CompPubKeyN), str(CompPubKeyE), str(share1), str(share2), str(CompPubKeyShare)], Const.COMP)
    data = json.dumps({Const.NE: CompPubKeyN, Const.E: CompPubKeyE, Const.SHARE1: share1, Const.SHARE2: share2,
                       Const.COMP_PUBKEY_SHARE: CompPubKeyShare, Const.SIGN: sign})
    headers = {'Content-Type': 'application/json'}
    response = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.SHARES, data=data, headers=headers)
    if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
        print "[ERROR] Cannot send shares to cloud provider server!"
    else:
        return json.loads(response.content)

# Compute full share and send shared protected one to CloudProvider server
def computeFullShares(data, dkg1, dkg2, key, iv):
    global otherShares1, otherShares2, PubKeyComp, protShare
    CloudProviderPubKeyN = data[Const.NE]
    CloudProviderPubKeyE = data[Const.E]
    #other1 = rsa.decryptRSA(base64.decodestring(data[Const.SHARE1]), Const.Comp)
    other1 = data[Const.SHARE1]
    #other2 = rsa.decryptRSA(base64.decother1 = rsa.decryptRSA(base64.decodestring(data[Const.SHARE1]), Const.Comp)
    other2 = data[Const.SHARE2]
    pub = data[Const.COMP_PUBKEY]
    sign = base64.decodestring(data[Const.SIGN])
    message = rsa.generateMessageForSign([str(CloudProviderPubKeyN), str(CloudProviderPubKeyE), str(other1), str(other2), str(pub)])
    # Verify signature
    if rsa.verifySign([CloudProviderPubKeyN, CloudProviderPubKeyE], message, sign) is True:
        otherShares1 = [dkg2.shares[dkg1.id-1], (int)(other1)]
        otherShares2 = [dkg1.shares[dkg2.id-1], (int)(other2)]
        PubKeyComp = (int)(pub)
        dkg1.compute_fullShare(otherShares1)
        dkg2.compute_fullShare(otherShares2)
        aesCipher = AES.new(key, AES.MODE_CBC, iv)
        protShare = aes.encrypt(aesCipher, str(dkg1.y))
        sign = rsa.generateSign([str(CompPubKeyN), str(CompPubKeyE), protShare], Const.COMP)
        # Create POST request
        data = json.dumps({Const.NE: CompPubKeyN, Const.E: CompPubKeyE, Const.PROT_SHARE: base64.encodestring(protShare),
                           Const.SIGN: sign})
        headers = {'Content-Type': 'application/json'}
        response = requests.post("http://" + Const.CLOUD_PROVIDER_ADDR + ":" + Const.CLOUD_PROVIDER_PORT + "/" + Const.PROT_SHARE, data=data,
                                 headers=headers)
        if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
            print "[ERROR] Cannot send protected share to cloud provider server!"

# Encrypt data for client
def encryptClientData(data, clientPubKeyN, clientPubKeyE):
    comps = [clientPubKeyN, clientPubKeyE]
    encd = base64.encodestring(rsa.encryptRSA(data, None, comps))
    return encd

################# FLASK SERVER #################
app = Flask(__name__)

@app.route("/"+Const.DECRYPT, methods=['POST'])
def decrypt():
    if request.method == 'POST':
        # Partial decryption
        content = request.get_json()
        clientPubKeyN = (int)(content[Const.NE])
        clientPubKeyE = (int)(content[Const.E])
        m = decryptData(content, clientPubKeyN, clientPubKeyE)
        if m is Const.BAD_REQ:
            return Const.BAD_REQ
        m = str(m)
        sign = rsa.generateSign([m], Const.COMP)
        m = encryptClientData(m, clientPubKeyN, clientPubKeyE)
        return json.dumps({Const.M: m, Const.SIGN: sign})
    else:
        return Const.NO_METHOD

# @app.route("/"+Const.START_KEY, methods=['POST'])
# def startKey():
#     if request.method == 'POST':
#         # Send to client initial hash chain key
#         content = request.get_json(force=True)
#         clientPubKeyN = (long)(content[Const.NE])
#         clientPubKeyE = (long)(content[Const.E])
#         sign = base64.decodestring(content[Const.SIGN])
#         message = rsa.generateMessageForSign([str(clientPubKeyN), str(clientPubKeyE)])
#         # Verify signature
#         if rsa.verifySign([clientPubKeyN, clientPubKeyE], message, sign) is True:
#             startKey, startDate = getHashKey()
#             sign = rsa.generateSign([str(CompPubKeyN), str(CompPubKeyE), str(startKey), str(startDate)], Const.Comp)
#             startKey = encryptClientData(startKey, clientPubKeyN, clientPubKeyE)
#             startDate = encryptClientData(str(startDate), clientPubKeyN, clientPubKeyE)
#             # Create response
#             response = json.dumps({Const.NE: CompPubKeyN, Const.E: CompPubKeyE, Const.START_KEY: startKey,
#                                    Const.DATE: startDate, Const.SIGN: sign})
#             return response
#         else:
#             return Const.BAD_REQ
#     else:
#         return Const.NO_METHOD

if __name__ == "__main__":
    global dkg1, dkg2, CompPubKeyN, CompPubKeyE, aesKey, aesIV, poly1, poly2
    # Create Pedersen objects
    dkg1 = PedersenDKG(Const.CLIENT_DKG_ID1, None)
    dkg2 = PedersenDKG(Const.CLIENT_DKG_ID2, None)
    poly1 = dkg1.poly
    poly2 = dkg2.poly
    # Create public and private keys for asymmetric encryption
    CompPubKeyN, CompPubKeyE = rsa.createRSAKeys(Const.COMP)
    aesKey = aes.getKey(random.randint(1, Const.G))
    aesIV = aes.getIV()
    # Pedersen exchanges
    response = sendDataToCloudProvider(dkg1, dkg2, CompPubKeyN, CompPubKeyE)
    computeFullShares(response, dkg1, dkg2, aesKey, aesIV)
    # Run Flask server
    app.run(host=Const.COMP_ADDR, port=Const.COMP_PORT)
