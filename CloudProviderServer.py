from flask import Flask, request
from PedersenDKG import PedersenDKG
import base64, Const, ElGamal, json, requests
import RSA as rsa

# Cryptographic keys and shares
CloudProviderPubKeyN = None
CloudProviderPubKeyE = None
CompPubKeyN = None
CompPubKeyE = None
PubKeyComp = None
protShare = None
dkg = None
poly = None
otherShares = None

# Create Pedersen object
def setPedersenDKG(share1, share2, CompPubShare):
    global dkg, otherShares, PubKeyComp
    otherShares = [share1, share2]
    # Set public key
    dkg.setPubKey(dkg.h * CompPubShare)
    PubKeyComp = dkg.pubKey
    return dkg

# Decrypt data received from client obtaining a partial decryption
def decryptData(data, clientPubKeyN, clientPubKeyE):
    global dkg, otherShares, PubKeyComp
    dkg = PedersenDKG(Const.CLOUD_PROVIDER_DKG_ID, poly)
    dkg.compute_fullShare(otherShares)
    dkg.setPubKey(PubKeyComp)
    dkg.compute_delta([Const.CLIENT_DKG_ID1])
    dkg.compute_privKeyShare()
    c1 = data[Const.C1]
    c2 = data[Const.C2]
    #protDate = data[Const.DATE]
    sign = base64.decodestring(data[Const.SIGN])
    #message = rsa.generateMessageForSign([str(clientPubKeyN), str(clientPubKeyE), str(c1), str(c2), str(protDate)])
    message = rsa.generateMessageForSign([str(clientPubKeyN), str(clientPubKeyE), str(c1), str(c2)])
    # Verify signature
    if rsa.verifySign([clientPubKeyN, clientPubKeyE], message, sign) is True:
        # Partial decryption
        m = ElGamal.decrypt(c1, c2, dkg.s)
        return m
    else:
        return Const.BAD_REQ

# Send to client Companization public key
def sendPubKeyComp(key):
    global CloudProviderPubKeyN, CloudProviderPubKeyE, CompPubKeyN, CompPubKeyE
    sign = rsa.generateSign([str(key),str(CompPubKeyN),str(CompPubKeyE),str(CloudProviderPubKeyN),str(CloudProviderPubKeyE)], Const.CLOUD_PROVIDER)
    data = json.dumps({Const.COMP_PUBKEY: key, Const.COMP+"_"+Const.NE: CompPubKeyN, Const.COMP+"_"+Const.E: CompPubKeyE,
                       Const.NE: CloudProviderPubKeyN, Const.E: CloudProviderPubKeyE, Const.SIGN: sign}, sort_keys=True)
    return data

# Encrypt data for client
def encryptClientData(data, clientPubKeyN, clientPubKeyE):
    comps = [clientPubKeyN, clientPubKeyE]
    encd = base64.encodestring(rsa.encryptRSA(data, None, comps))
    return encd

################# FLASK SERVER #################
app = Flask(__name__)

@app.route("/"+Const.COMP_PUBKEY, methods=['POST'])
def CompPubKey():
    if request.method == 'POST':
        global PubKeyComp
        content = request.get_json(force=True)
        clientPubKeyN = (long)(content[Const.NE])
        clientPubKeyE = (long)(content[Const.E])
        sign = base64.decodestring(content[Const.SIGN])
        message = rsa.generateMessageForSign([str(clientPubKeyN), str(clientPubKeyE)])
        # Verify signature
        if rsa.verifySign([clientPubKeyN, clientPubKeyE], message, sign) is True:
            # Send Companization public key
            response = sendPubKeyComp(PubKeyComp)
            return response
        else:
            return Const.BAD_REQ
    else:
        return Const.NO_METHOD

@app.route("/"+Const.SHARES, methods=['POST'])
def shares():
    if request.method == 'POST':
        global CompPubKeyN, CompPubKeyE
        # Send to Companization its partial shares
        content = request.get_json(force=True)
        CompPubKeyN = content[Const.NE]
        CompPubKeyE = content[Const.E]
        share1 = content[Const.SHARE1]
        share2 = content[Const.SHARE2]
        CompPubShare = content[Const.COMP_PUBKEY_SHARE]
        sign = base64.decodestring(content[Const.SIGN])
        message = rsa.generateMessageForSign([str(CompPubKeyN), str(CompPubKeyE), str(share1), str(share2), str(CompPubShare)])
        # Verify request response
        if rsa.verifySign([CompPubKeyN, CompPubKeyE], message, sign) is True:
            dkg = setPedersenDKG(share1, share2, CompPubShare)
            share1 = dkg.shares[Const.CLIENT_DKG_ID1-1]
            share2 = dkg.shares[Const.CLIENT_DKG_ID2-1]
            print "(", len(bytes(share1)), ") ", share1, "\n", bytes(share1)
            print "(", len(bytes(share2)), ") ", share2, "\n", bytes(share2)
            pub = dkg.pubKey
            sign = rsa.generateSign([str(CloudProviderPubKeyN), str(CloudProviderPubKeyE), str(share1), str(share2), str(pub)], Const.CLOUD_PROVIDER)
            #share1 = base64.encodestring(rsa.encryptRSA(str(share1), None, [CompPubKeyN, CompPubKeyE]))
            #share2 = base64.encodestring(rsa.encryptRSA(str(share2), None, [CompPubKeyN, CompPubKeyE]))
            response = json.dumps({Const.NE: CloudProviderPubKeyN, Const.E: CloudProviderPubKeyE, Const.SHARE1: share1, Const.SHARE2: share2,
                                   Const.COMP_PUBKEY: pub, Const.SIGN: sign})
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
        CompPubKeyN = content[Const.NE]
        CompPubKeyE = content[Const.E]
        protShare = base64.decodestring(content[Const.PROT_SHARE])
        sign = base64.decodestring(content[Const.SIGN])
        message = rsa.generateMessageForSign([str(CompPubKeyN), str(CompPubKeyE), protShare])
        # Verify signature
        if rsa.verifySign([CompPubKeyN, CompPubKeyE], message, sign) is True:
            return Const.OK
        else:
            return Const.BAD_REQ
    else:
        return Const.NO_METHOD

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
        sign = rsa.generateSign([m], Const.CLOUD_PROVIDER)
        m = encryptClientData(m, clientPubKeyN, clientPubKeyE)
        return json.dumps({Const.M: m, Const.SIGN: sign})
    else:
        return Const.NO_METHOD

if __name__ == "__main__":
    global dkg, CloudProviderPubKeyN, CloudProviderPubKeyE, poly
    # Create Pedersen object
    dkg = PedersenDKG(Const.CLOUD_PROVIDER_DKG_ID, None)
    poly = dkg.poly
    # Create public and private keys for asymmetric encryption
    CloudProviderPubKeyN, CloudProviderPubKeyE = rsa.createRSAKeys(Const.CLOUD_PROVIDER)
    # Run Flask server
    app.run(host=Const.CLOUD_PROVIDER_ADDR, port=Const.CLOUD_PROVIDER_PORT)
