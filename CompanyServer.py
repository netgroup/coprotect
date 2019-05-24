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
RootChainKey = 65536
PubKeyCompany = None
CompanyPubKeyN = None
CompanyPubKeyE = None
protShare = None

# Decrypt data received from Cloud Provider obtaining full decryption
def decryptData(data, clientPubKeyN, clientPubKeyE):
    global dkg1, dkg2, otherShares1, otherShares2, PubKeyCompany
    logMessage = "COMPANY: Starting decryption\n"
    c1 = (int)(data[Const.C1])
    c2 = (int)(data[Const.C2])
    sign = base64.decodestring(data[Const.SIGN])
    message = rsa.generateMessageForSign([str(clientPubKeyN), str(clientPubKeyE), str(c1), str(c2)])
    # Verify signature
    logMessage += "\t\t\t\t\t\t\t\tCOMPANY: Verifying request signature\n"
    if rsa.verifySign([clientPubKeyN, clientPubKeyE], message, sign) is True:
        logMessage += "\t\t\t\t\t\t\t\tCOMPANY: Request signature verified\n\t\t\t\t\t\t\t\tCOMPANY: Recovering Company private key share\n"
        dkg1 = PedersenDKG(Const.CLIENT_DKG_ID1, poly1)
        dkg2 = PedersenDKG(Const.CLIENT_DKG_ID2, poly2)
        dkg1.compute_fullShare(otherShares1)
        dkg2.compute_fullShare(otherShares2)
        dkg1.setPubKey(PubKeyCompany)
        dkg2.setPubKey(PubKeyCompany)
        aesCipher = AES.new(aesKey, AES.MODE_CBC, aesIV)
        dkg1.y = (int)(aes.decrypt(aesCipher, protShare))
        dkg1.compute_delta([Const.CLOUD_PROVIDER_DKG_ID])
        dkg1.compute_privKeyShare()
        # Decrypt data
        logMessage += "\t\t\t\t\t\t\t\tCOMPANY: Company private key share built\n\t\t\t\t\t\t\t\tCOMPANY: Decrypting data\n"
        m = ElGamal.decrypt(c1, c2, dkg1.s)
        return m, logMessage
    else:
        logMessage += "\t\t\t\t\t\t\t\tCOMPANY: Error in signature!"
        return Const.BAD_REQ, logMessage

# Encrypt data for client
def encryptClientData(data, clientPubKeyN, clientPubKeyE):
    comps = [clientPubKeyN, clientPubKeyE]
    encd = base64.encodestring(rsa.encryptRSA(data, None, comps))
    return encd

# Send data to Cloud Provider for Pedersen exchanges
def sendDataToCloudProvider(dkg1, dkg2, CompanyPubKeyN, CompanyPubKeyE):
    id = Const.CLOUD_PROVIDER_DKG_ID
    share1 = dkg1.shares[id-1]
    share2 = dkg2.shares[id-1]
    companyPubKeyShare = ElGamal.mulmod(dkg1.h, dkg2.h, Const.P)
    sign = rsa.generateSign([str(CompanyPubKeyN), str(CompanyPubKeyE), str(share1), str(share2), str(companyPubKeyShare)], Const.COMPANY)
    data = json.dumps({Const.NE: CompanyPubKeyN, Const.E: CompanyPubKeyE, Const.SHARE1: share1, Const.SHARE2: share2,
                       Const.COMPANY_PUBKEY_SHARE: companyPubKeyShare, Const.SIGN: sign})
    headers = {'Content-Type': 'application/json'}
    response = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.SHARES, data=data, headers=headers)
    if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
        print "[ERROR] Cannot send shares to cloud provider server!"
    else:
        return json.loads(response.content)

# Compute full share and send shared protected one to Cloud Provider server
def computeFullShares(data, dkg1, dkg2, key, iv):
    global otherShares1, otherShares2, PubKeyCompany, protShare
    CloudProviderPubKeyN = data[Const.NE]
    CloudProviderPubKeyE = data[Const.E]
    other1 = base64.decodestring(data[Const.SHARE1])
    other2 = base64.decodestring(data[Const.SHARE2])
    pub = data[Const.COMPANY_PUBKEY]
    sign = base64.decodestring(data[Const.SIGN])
    message = rsa.generateMessageForSign([str(CloudProviderPubKeyN), str(CloudProviderPubKeyE), str(other1), str(other2), str(pub)])
    # Verify signature
    if rsa.verifySign([CloudProviderPubKeyN, CloudProviderPubKeyE], message, sign) is True:
        otherShares1 = [dkg2.shares[dkg1.id-1], (int)(other1)]
        otherShares2 = [dkg1.shares[dkg2.id-1], (int)(other2)]
        PubKeyCompany = (int)(pub)
        dkg1.compute_fullShare(otherShares1)
        dkg2.compute_fullShare(otherShares2)
        aesCipher = AES.new(key, AES.MODE_CBC, iv)
        protShare = aes.encrypt(aesCipher, str(dkg1.y))
        sign = rsa.generateSign([str(CompanyPubKeyN), str(CompanyPubKeyE), protShare], Const.COMPANY)
        # Create POST request
        data = json.dumps({Const.NE: CompanyPubKeyN, Const.E: CompanyPubKeyE, Const.PROT_SHARE: base64.encodestring(protShare),
                           Const.SIGN: sign})
        headers = {'Content-Type': 'application/json'}
        response = requests.post("http://" + Const.CLOUD_PROVIDER_ADDR + ":" + Const.CLOUD_PROVIDER_PORT + "/" + Const.PROT_SHARE, data=data,
                                 headers=headers)
        if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
            print "[ERROR] Cannot send protected share to cloud provider server!"

################# FLASK SERVER #################
app = Flask(__name__)

@app.route("/"+Const.DECRYPT, methods=['POST'])
def decrypt():
    if request.method == 'POST':
        # Decrypt data received from Cloud Provider
        content = request.get_json()
        clientPubKeyN = (long)(content[Const.NE])
        clientPubKeyE = (long)(content[Const.E])
        m, message = decryptData(content, clientPubKeyN, clientPubKeyE)
        if m is Const.BAD_REQ:
            return Const.BAD_REQ
        m = str(m)
        message += "\t\t\t\t\t\t\t\tCOMPANY: Partial decryption successful"
        sign = rsa.generateSign([m], Const.COMPANY)
        #m = encryptClientData(m, clientPubKeyN, clientPubKeyE)
        return json.dumps({Const.M: m, Const.LOG: message, Const.SIGN: sign})
    else:
        return Const.NO_METHOD

if __name__ == "__main__":
    global dkg1, dkg2, aesKey, aesIV, poly1, poly2
    # Create Pedersen objects
    dkg1 = PedersenDKG(Const.CLIENT_DKG_ID1, None)
    dkg2 = PedersenDKG(Const.CLIENT_DKG_ID2, None)
    poly1 = dkg1.poly
    poly2 = dkg2.poly
    # Create public and private keys for asymmetric encryption
    CompanyPubKeyN, CompanyPubKeyE = rsa.createRSAKeys(Const.COMPANY)
    aesKey = aes.getKey(random.randint(1, Const.G))
    aesIV = aes.getIV()
    # Pedersen exchanges
    response = sendDataToCloudProvider(dkg1, dkg2, CompanyPubKeyN, CompanyPubKeyE)
    computeFullShares(response, dkg1, dkg2, aesKey, aesIV)
    # Run Flask server
    app.run(host=Const.COMPANY_ADDR, port=Const.COMPANY_PORT)
