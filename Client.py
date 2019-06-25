from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Random import random
from datetime import datetime
from flask import Flask, request, render_template, Blueprint
from flask_restplus import Resource, Api
from crypto import Const, ElGamal, RSA as rsa, AES as aes
import base64, json, os, random, requests, struct

# Cryptographic keys
PubKeyCompany = None
ClientPubKeyN = None
ClientPubKeyE = None
CloudProviderPubKeyN = None
CloudProviderPubKeyE = None
CompanyPubKeyN = None
CompanyPubKeyE = None
m = None

# Write message in log file
def log(message):
    with open(Const.LOG+".txt", 'a') as fout:
        message = "["+str(datetime.now())+"] "+message+"\n"
        fout.write(message)

# Save configuration file
def saveConfig(outfile):
    data = {Const.CLIENT + "_" + Const.NE: ClientPubKeyN, Const.CLIENT + "_" + Const.E: ClientPubKeyE,
            Const.CLOUD_PROVIDER + "_" + Const.NE: CloudProviderPubKeyN,
            Const.CLOUD_PROVIDER + "_" + Const.E: CloudProviderPubKeyE, Const.COMPANY + "_" + Const.NE: CompanyPubKeyN,
            Const.COMPANY + "_" + Const.E: CompanyPubKeyE, Const.COMPANY_PUBKEY: PubKeyCompany}
    with open(outfile, 'w') as fout:
        json.dump(data, fout, sort_keys=True)
        log("CLIENT: Saved configuration settings in "+outfile)

# Load data from configuration file
def loadConfig(infile):
    if os.path.isfile(infile) is True:
        global ClientPubKeyN, ClientPubKeyE, CloudProviderPubKeyN, CloudProviderPubKeyE, CompanyPubKeyN, CompanyPubKeyE, PubKeyCompany
        with open(infile, 'r') as fin:
            # Read data from file
            data = json.load(fin)
            # Get fields from json
            ClientPubKeyN = data[Const.CLIENT+"_"+Const.NE]
            ClientPubKeyE = data[Const.CLIENT+"_"+Const.E]
            CloudProviderPubKeyN = data[Const.CLOUD_PROVIDER+"_"+Const.NE]
            CloudProviderPubKeyE = data[Const.CLOUD_PROVIDER+"_"+Const.E]
            CompanyPubKeyN = (long)(data[Const.CLOUD_PROVIDER+"_"+Const.NE])
            CompanyPubKeyE = (int)(data[Const.CLOUD_PROVIDER+"_"+Const.E])
            PubKeyCompany = data[Const.COMPANY_PUBKEY]
            log("CLIENT: Loaded configuration settings from "+infile)

# Obtain organization public key from Cloud Provider server
def getPubKeyCompany(n, e):
    global PubKeyCompany, CloudProviderPubKeyN, CloudProviderPubKeyE, CompanyPubKeyN, CompanyPubKeyE
    if PubKeyCompany is None:
        log("CLIENT: RETRIEVING COMPANY PUBLIC KEY")
        # Create signature for sent data
        sign = rsa.generateSign([str(n), str(e)], Const.CLIENT)
        data = json.dumps({Const.NE: n, Const.E: e, Const.SIGN: sign})
        # Create POST request
        log("CLIENT: Making POST request for company public key to Cloud Provider")
        headers = {'Content-Type': 'application/json'}
        response = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.COMPANY_PUBKEY, data=data, headers=headers)
        if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
            log("CLIENT: Error in Company public key request!")
            return response.content
        # Get request response
        log("CLIENT: Parsing request response")
        data = json.loads(response.content)
        PubKeyCompany = data[Const.COMPANY_PUBKEY]
        CloudProviderPubKeyN = data[Const.NE]
        CloudProviderPubKeyE = data[Const.E]
        CompanyPubKeyN = data[Const.COMPANY + "_" + Const.NE]
        CompanyPubKeyE = data[Const.COMPANY + "_" + Const.E]
        logMessage = data[Const.LOG]
        log(logMessage)
        sign = base64.decodestring(data[Const.SIGN])
        message = rsa.generateMessageForSign([str(PubKeyCompany), str(CompanyPubKeyN), str(CompanyPubKeyE), str(CloudProviderPubKeyN), str(CloudProviderPubKeyE)])
        # Verify response
        log("CLIENT: Verifying response signature")
        if rsa.verifySign([CloudProviderPubKeyN, CloudProviderPubKeyE], message, sign) is True:
            log("CLIENT: Response signature verified")
            return PubKeyCompany
        else:
            log("CLIENT: Error in signature!")
            return Const.ERROR
    else:
        log("CLIENT: Company public key already exists")
        return PubKeyCompany

# Generate random int for asymmetric encryption
def generateKey():
    global m
    csprng = random.SystemRandom()
    m = csprng.randint(1, Const.P - 1)
    # m = random.randint(1, Const.P - 1)
    log("CLIENT: Generated random int for asymmetric encryption")
    return m

# Encrypt data in infile to encfile
def encryptFile(infile, encfile):
    global ClientPubKeyN, ClientPubKeyE
    log("CLIENT: ENCRYPTION REQUESTED")
    if ClientPubKeyN is None:
        # Get public and private keys for asymmetric encryption
        ClientPubKeyN, ClientPubKeyE = rsa.createRSAKeys(Const.CLIENT)
        #log("CLIENT: Generated RSA keys")
    # Get public organization key
    pubKeyCompany = getPubKeyCompany(ClientPubKeyN, ClientPubKeyE)
    if pubKeyCompany is Const.BAD_REQ or pubKeyCompany is Const.NO_METHOD or pubKeyCompany is Const.ERROR:
        log("CLIENT: Error "+pubKeyCompany+ " getting company public key")
        return Const.ERROR
    # Create file encryption key
    m = generateKey()
    c1, c2 = ElGamal.encrypt(m, pubKeyCompany)
    log("CLIENT: Encrypted random int with ElGamal")
    data = [c1, c2]
    # size = len(bytes(data))
    # Get a random key
    key = aes.getKey(m)
    log("CLIENT: Generated key from random int")
    # Get initialization vector
    iv = aes.getIV()
    aesCipher = AES.new(key, AES.MODE_CBC, iv)
    # Create temporary plain file
    infile.save('./tmp/file')
    fsz = os.stat('./tmp/file').st_size
    # Encrypt header and file data
    with open(encfile, 'wb') as fout:
        # Write header
        log("CLIENT: Writing header of encrypted file")
        # fout.write(struct.pack('<Q', size))
        fout.write(str(data))
        # Write file
        log("CLIENT: Writing encrypted file data")
        fout.write(struct.pack('<Q', fsz))
        fout.write(iv)
        with open('./tmp/file', 'rb') as fin:
            while True:
                log("CLIENT: Reading data from input file")
                data = fin.read(Const.RSA_BITS)
                n = len(data)
                if n == 0:
                    break
                log("CLIENT: Encrypting read data")
                encData = aes.encrypt(aesCipher, data)
                log("CLIENT: Writing encrypted data")
                fout.write(encData)
    saveConfig(Const.CLIENT + "_" + Const.CONFIG + '.json')
    fout = open(encfile, "r")
    if fout.mode == "r":
        result = base64.encodestring(fout.read())
        log("CLIENT: Successful encryption!")
    else:
        result = Const.ERROR
        log("CLIENT: Encryption failed!")
    log("CLIENT: Deleting temporary files")
    os.remove('./tmp/file')
    os.remove(encfile)
    log("CLIENT: Temporary files deleted")
    return result

# Decrypt file
def decryptFile(encfile, decfile):
    log("CLIENT: DECRYPTION REQUESTED")
    with open('./tmp/enc_file', 'w') as fout:
        fout.write(base64.decodestring(encfile.read()))
    # Decrypt file
    with open("./tmp/enc_file", 'rb') as fin:
        # Read size of plain text
        log("CLIENT: Reading file header")
        # size = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        # data = ""
        # while size > 0:
        readBytes = fin.read(1)
        data = readBytes
        while readBytes != ']':
            # Read encrypted data from file
            # readBytes = fin.read(size)
            readBytes = fin.read(1)
            # n = len(readBytes)
            # if n == 0:
            #     break
            # # Decrypy data
            # if size > n:
            #     data += readBytes
            # else:
            #     data += readBytes[:size]  # Remove padding on last block
            # size -= n
            data += readBytes
        # Get fields from decrypted data
        log("CLIENT: Getting encrypted fields")
        data = data.split()
        c1 = data[0][1:-1]
        c2 = data[1][0:-1]
        if c1[-1:] is "L":
            c1 = c1[:-1]
        if c2[-1:] is "L":
            c2 = c2[:-1]
        # Create POST request
        sign = rsa.generateSign([str(ClientPubKeyN), str(ClientPubKeyE), str(c1), str(c2)], Const.CLIENT)
        data = json.dumps(
            {Const.NE: ClientPubKeyN, Const.E: ClientPubKeyE, Const.C1: c1, Const.C2: c2, Const.SIGN: sign})
        headers = {'Content-Type': 'application/json'}
        log("CLIENT: Asking partial decryption to Cloud Provider")
        response = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.DECRYPT, data=data, headers=headers)
        if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
            log("CLIENT: Error during Cloud Provider decryption")
            return Const.ERROR
        data = json.loads(response.content)
        # Get request response
        # m = rsa.decryptRSA(base64.decodestring(data[Const.M]), Const.CLIENT)
        m = data[Const.M]
        logMessage = data[Const.LOG]
        sign = base64.decodestring(data[Const.SIGN])
        log(logMessage)
        message = rsa.generateMessageForSign([str(m)])
        # Verify response
        log("CLIENT: Verifying response signature")
        if rsa.verifySign([CloudProviderPubKeyN, CloudProviderPubKeyE], message, sign) is not True:
            log("CLIENT: Error in signature!")
            return Const.ERROR
        log("CLIENT: Response signature verified")
        # Ask decryption to Company server
        sign = rsa.generateSign([str(ClientPubKeyN), str(ClientPubKeyE), str(c1), str(m)], Const.CLIENT)
        data = json.dumps(
            {Const.NE: ClientPubKeyN, Const.E: ClientPubKeyE, Const.C1: c1, Const.C2: m, Const.SIGN: sign})
        headers = {'Content-Type': 'application/json'}
        log("CLIENT: Asking final decryption to Company")
        responseCompany = requests.post("http://" + Const.COMPANY_ADDR + ":" + Const.COMPANY_PORT + "/" + Const.DECRYPT,
                                        data=data, headers=headers)
        if (responseCompany.content is Const.NO_METHOD) or (responseCompany.content is Const.BAD_REQ):
            log("CLIENT: Error during Company decryption")
            return Const.ERROR
        data = json.loads(responseCompany.content)
        # Get request response
        # m = rsa.decryptRSA(base64.decodestring(data[Const.M]), Const.CLIENT)
        m = data[Const.M]
        logMessage = data[Const.LOG]
        sign = base64.decodestring(data[Const.SIGN])
        log(logMessage)
        message = rsa.generateMessageForSign([str(m)])
        # Verify response
        log("CLIENT: Verifying response signature")
        if rsa.verifySign([CompanyPubKeyN, CompanyPubKeyE], message, sign) is not True:
            log("CLIENT: Error in signature!")
            return Const.ERROR
        log("CLIENT: Response signature verified")
        log("CLIENT: Generating asymmetric encryption key")
        key = aes.getKey((long)(m))
        # Read size of plain text
        fsz = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        iv = fin.read(AES.block_size)
        aesCipher = AES.new(key, AES.MODE_CBC, iv)
        with open(decfile, 'wb') as fout:
            log("CLIENT: Decrypting file data")
            while True:
                data = fin.read(Const.RSA_BITS)
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
    fout = open(decfile, "r")
    if fout.mode == "r":
        result = base64.encodestring(fout.read())
        log("CLIENT: Successful decryption!")
    else:
        result = Const.ERROR
        log("CLIENT: Decryption failed!")
    log("CLIENT: Deleting temporary files")
    os.remove('./tmp/enc_file')
    os.remove(decfile)
    log("CLIENT: Temporary files deleted")
    return result


################# FLASK SERVER #################
app = Flask(__name__, root_path='/app/web') #template_folder="/app/static", static_folder="static")   # Create a Flask WSGI application
api = Api(app)                                                  # Create a Flask-RESTPlus API

crypto_ns = api.namespace('crypto', description='Operations related to data protection')
log_ns = api.namespace('log', description='Operations related to operations logging')

parser = api.parser()
parser.add_argument('in_file', type=file, location='file')

@app.route("/index", methods=['GET'])
def index():
    return render_template("index.html")

@crypto_ns.route("/encrypt")
class Encrypt(Resource):

    @api.expect(parser)
    @api.response(200, "File successfully encrypted")
    @api.response(500, "File encryption failed")
    def post(self):
        """
        Encrypt sent file (it needs a form with enctype as "multipart/form-data" for file sending).
        :return: String containing encrypted file
        """
        f = request.files['file[0]']
        enc_f = encryptFile(f,"enc_file")
        if enc_f is Const.ERROR:
            return None, 500
        return enc_f, 200

@crypto_ns.route("/decrypt")
class Decrypt(Resource):

    @api.expect(parser)
    @api.response(200, "File successfully decrypted")
    @api.response(500, "File decryption failed")
    def post(self):
        """
        Decrypt sent file (it needs a form with enctype as "multipart/form-data" for file sending).
        :return: String containing decrypted file
        """
        f = request.files['file[0]']
        dec_f = decryptFile(f, "dec_file")
        if dec_f is Const.ERROR:
            return None, 500
        return dec_f, 200

@log_ns.route("/getLog")
class Log(Resource):

    @api.response(200, "Log successfully sent")
    @api.response(500, "Log sending failed")
    def get(self):
        """
        Send log data
        :return: String containing log data
        """
        fout = open(Const.LOG+".txt", "r")
        if fout.mode == "r":
            return fout.read(), 200
        return None, 500

def initialize_app(flask_app):
    blueprint = Blueprint('api', __name__, url_prefix='/api')
    api.init_app(blueprint)
    api.add_namespace(crypto_ns)
    api.add_namespace(log_ns)
    flask_app.register_blueprint(blueprint)

if __name__ == "__main__":
    loadConfig(Const.CLIENT + "_" + Const.CONFIG + '.json')
    initialize_app(app)
    app.run(host=Const.CLIENT_ADDR, port=Const.CLIENT_PORT)
