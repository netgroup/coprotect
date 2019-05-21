from flask import Flask, request
from PedersenDKG import PedersenDKG
import base64, Const, ElGamal, json, requests
import RSA as rsa

# Cryptographic keys and shares
CloudProviderPubKeyN = None
CloudProviderPubKeyE = None
CompanyPubKeyN = None
CompanyPubKeyE = None
PubKeyCompany = None
protShare = None
dkg = None
poly = None
otherShares = None

# Create Pedersen object
def setPedersenDKG(share1, share2, companyPubShare):
    global dkg, otherShares, PubKeyCompany
    otherShares = [share1, share2]
    # Set public key
    dkg.setPubKey(ElGamal.mulmod(dkg.h, companyPubShare, Const.P))
    PubKeyCompany = dkg.pubKey
    return dkg

# Decrypt data received from client obtaining a partial decryption
def decryptData(data, clientPubKeyN, clientPubKeyE):
    global dkg, otherShares, PubKeyCompany
    dkg = PedersenDKG(Const.CLOUD_PROVIDER_DKG_ID, poly)
    dkg.compute_fullShare(otherShares)
    dkg.setPubKey(PubKeyCompany)
    dkg.compute_delta([Const.CLIENT_DKG_ID1])
    dkg.compute_privKeyShare()
    c1 = long(data[Const.C1])
    c2 = long(data[Const.C2])
    # protDate = data[Const.DATE]
    sign = base64.decodestring(data[Const.SIGN])
    # message = rsa.generateMessageForSign([str(clientPubKeyN), str(clientPubKeyE), str(int(c1)), str(int(c2)), str(protDate)])
    message = rsa.generateMessageForSign([str(clientPubKeyN), str(clientPubKeyE), str(int(c1)), str(int(c2))])
    # Verify signature
    if rsa.verifySign([clientPubKeyN, clientPubKeyE], message, sign) is True:
        # Partial decryption
        m = ElGamal.decrypt(c1, c2, dkg.s)
        return c1, m
    else:
        return Const.BAD_REQ, 0

# Send to client company public key
def sendPubKeyCompany(key):
    # global CloudProviderPubKeyN, CloudProviderPubKeyE
    # message = str(key)+","+str(CloudProviderPubKeyN)+","+str(CloudProviderPubKeyE)
    # sign = base64.encodestring(rsa.sign(message, Const.CLOUD_PROVIDER))
    # data = json.dumps({Const.COMPANY_PUBKEY: key, Const.NE: CloudProviderPubKeyN, Const.E: CloudProviderPubKeyE, Const.SIGN: sign}, sort_keys=True)
    global CloudProviderPubKeyN, CloudProviderPubKeyE, CompanyPubKeyN, CompanyPubKeyE
    sign = rsa.generateSign(
        [str(key), str(CompanyPubKeyN), str(CompanyPubKeyE), str(CloudProviderPubKeyN), str(CloudProviderPubKeyE)],
        Const.CLOUD_PROVIDER)
    data = json.dumps(
        {Const.COMPANY_PUBKEY: key, Const.COMPANY + "_" + Const.NE: CompanyPubKeyN, Const.COMPANY + "_" + Const.E: CompanyPubKeyE,
         Const.NE: CloudProviderPubKeyN, Const.E: CloudProviderPubKeyE, Const.SIGN: sign}, sort_keys=True)
    return data

################# FLASK SERVER #################
app = Flask(__name__)

@app.route("/"+Const.COMPANY_PUBKEY, methods=['POST'])
def companyPubKey():
    if request.method == 'POST':
        global PubKeyCompany
        content = request.get_json(force=True)
        clientPubKeyN = (long)(content[Const.NE])
        clientPubKeyE = (long)(content[Const.E])
        sign = base64.decodestring(content[Const.SIGN])
        message = rsa.generateMessageForSign([str(clientPubKeyN), str(clientPubKeyE)])
        # Verify signature
        if rsa.verifySign([clientPubKeyN, clientPubKeyE], message, sign) is True:
            # Send company public key
            response = sendPubKeyCompany(PubKeyCompany)
            return response
        else:
            return Const.BAD_REQ
    else:
        return Const.NO_METHOD

# Encrypt data for client
def encryptClientData(data, clientPubKeyN, clientPubKeyE):
    comps = [clientPubKeyN, clientPubKeyE]
    encd = base64.encodestring(rsa.encryptRSA(data, None, comps))
    return encd

@app.route("/"+Const.SHARES, methods=['POST'])
def shares():
    if request.method == 'POST':
        global CompanyPubKeyN, CompanyPubKeyE
        # Send to company its partial shares
        content = request.get_json(force=True)
        CompanyPubKeyN = content[Const.NE]
        CompanyPubKeyE = content[Const.E]
        share1 = content[Const.SHARE1]
        share2 = content[Const.SHARE2]
        companyPubShare = content[Const.COMPANY_PUBKEY_SHARE]
        sign = base64.decodestring(content[Const.SIGN])
        message = rsa.generateMessageForSign([str(CompanyPubKeyN), str(CompanyPubKeyE), str(share1), str(share2), str(companyPubShare)])
        # Verify request response
        if rsa.verifySign([CompanyPubKeyN, CompanyPubKeyE], message, sign) is True:
            dkg = setPedersenDKG(share1, share2, companyPubShare)
            share1 = dkg.shares[Const.CLIENT_DKG_ID1-1]
            share2 = dkg.shares[Const.CLIENT_DKG_ID2-1]
            pub = dkg.pubKey
            sign = rsa.generateSign([str(CloudProviderPubKeyN), str(CloudProviderPubKeyE), str(share1), str(share2), str(pub)], Const.CLOUD_PROVIDER)
            share1 = base64.encodestring(str(share1))
            share2 = base64.encodestring(str(share2))
            response = json.dumps({Const.NE: CloudProviderPubKeyN, Const.E: CloudProviderPubKeyE, Const.SHARE1: share1, Const.SHARE2: share2,
                                   Const.COMPANY_PUBKEY: pub, Const.SIGN: sign})
            return response
        else:
            return Const.BAD_REQ
    else:
        return Const.NO_METHOD

@app.route("/"+Const.PROT_SHARE, methods=['POST'])
def protShare():
    if request.method == 'POST':
        # Get shared protected decryption share
        global protShare
        content = request.get_json(force=True)
        companyPubKeyN = content[Const.NE]
        companyPubKeyE = content[Const.E]
        protShare = base64.decodestring(content[Const.PROT_SHARE])
        sign = base64.decodestring(content[Const.SIGN])
        message = rsa.generateMessageForSign([str(companyPubKeyN), str(companyPubKeyE), protShare])
        # Verify signature
        if rsa.verifySign([companyPubKeyN, companyPubKeyE], message, sign) is True:
            return Const.OK
        else:
            return Const.BAD_REQ
    else:
        return Const.NO_METHOD

@app.route("/"+Const.DECRYPT, methods=['POST'])
def decrypt():
    if request.method == 'POST':
        # Partial decryption and ask company for full decryption
        content = request.get_json(force=True)
        clientPubKeyN = (int)(content[Const.NE])
        clientPubKeyE = (int)(content[Const.E])
        c1, m = decryptData(content, clientPubKeyN, clientPubKeyE)
        if c1 is Const.BAD_REQ:
            return Const.BAD_REQ
        # sign = rsa.generateSign([str(CloudProviderPubKeyN), str(CloudProviderPubKeyE), str(clientPubKeyN), str(clientPubKeyE), str(c1),
        #                          str(m), protShare], Const.CLOUD_PROVIDER)
        # data = json.dumps({Const.NE: CloudProviderPubKeyN, Const.E: CloudProviderPubKeyE, Const.CLIENT+"_"+Const.NE: clientPubKeyN,
        #                    Const.CLIENT+"_"+Const.E: clientPubKeyE, Const.C1: c1, Const.C2: m,
        #                    Const.PROT_SHARE: base64.encodestring(protShare), Const.SIGN: sign})
        # headers = {'Content-Type': 'application/json'}
        # response = requests.post("http://"+Const.COMPANY_ADDR+":"+Const.COMPANY_PORT+"/"+Const.DECRYPT, data=data, headers=headers)
        # return response.content
        m = str(m)
        sign = rsa.generateSign([m], Const.CLOUD_PROVIDER)
        #m = encryptClientData(m, clientPubKeyN, clientPubKeyE)
        return json.dumps({Const.M: m, Const.SIGN: sign})
    else:
        return Const.NO_METHOD

if __name__ == "__main__":
    # Create Pedersen object
    dkg = PedersenDKG(Const.CLOUD_PROVIDER_DKG_ID, None)
    poly = dkg.poly
    # Create public and private keys for asymmetric encryption
    CloudProviderPubKeyN, CloudProviderPubKeyE = rsa.createRSAKeys(Const.CLOUD_PROVIDER)
    # Run Flask server
    app.run(host=Const.CLOUD_PROVIDER_ADDR, port=Const.CLOUD_PROVIDER_PORT)
