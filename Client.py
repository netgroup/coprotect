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
        fout.write(message)

# Save configuration file
def saveConfig(outfile):
    data = {Const.CLIENT + "_" + Const.NE: ClientPubKeyN, Const.CLIENT + "_" + Const.E: ClientPubKeyE,
            Const.CLOUD_PROVIDER + "_" + Const.NE: CloudProviderPubKeyN,
            Const.CLOUD_PROVIDER + "_" + Const.E: CloudProviderPubKeyE, Const.COMPANY + "_" + Const.NE: CompanyPubKeyN,
            Const.COMPANY + "_" + Const.E: CompanyPubKeyE, Const.COMPANY_PUBKEY: PubKeyCompany}
    with open(outfile, 'w') as fout:
        json.dump(data, fout, sort_keys=True)
        log(Const.getCurrentTime()+"CLIENT: Saved configuration settings in "+outfile+"\n")

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
            log(Const.getCurrentTime()+"CLIENT: Loaded configuration settings from "+infile+"\n")

# Obtain organization public key from Cloud Provider server
def getPubKeyCompany(n, e):
    global PubKeyCompany, CloudProviderPubKeyN, CloudProviderPubKeyE, CompanyPubKeyN, CompanyPubKeyE
    if PubKeyCompany is None:
        log(Const.getCurrentTime()+"CLIENT: RETRIEVING COMPANY PUBLIC KEY\n")
        # Create signature for sent data
        sign = rsa.generateSign([str(n), str(e)], Const.CLIENT)
        data = json.dumps({Const.NE: n, Const.E: e, Const.SIGN: sign})
        # Create POST request
        log(Const.getCurrentTime()+"CLIENT: Making POST request for company public key to Cloud Provider\n")
        headers = {'Content-Type': 'application/json'}
        response = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.COMPANY_PUBKEY, data=data, headers=headers)
        if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
            log(Const.getCurrentTime()+"CLIENT: Error in Company public key request!\n")
            return response.content
        # Get request response
        log(Const.getCurrentTime()+"CLIENT: Parsing request response\n")
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
        log(Const.getCurrentTime()+"CLIENT: Verifying response signature\n")
        if rsa.verifySign([CloudProviderPubKeyN, CloudProviderPubKeyE], message, sign) is True:
            log(Const.getCurrentTime()+"CLIENT: Response signature verified\n")
            return PubKeyCompany
        else:
            log(Const.getCurrentTime()+"CLIENT: Error in signature!\n")
            return Const.ERROR
    else:
        log(Const.getCurrentTime()+"CLIENT: Company public key already exists\n")
        return PubKeyCompany

# Generate random int for asymmetric encryption
def generateKey():
    global m
    csprng = random.SystemRandom()
    m = csprng.randint(1, Const.P - 1)
    # m = random.randint(1, Const.P - 1)
    log(Const.getCurrentTime()+"CLIENT: Generated random int for asymmetric encryption\n")
    return m

# Encrypt data in infile to encfile
def encryptFile(infile):
    global ClientPubKeyN, ClientPubKeyE
    log(Const.getCurrentTime()+"CLIENT: ENCRYPTION REQUESTED\n")
    if ClientPubKeyN is None:
        # Get public and private keys for asymmetric encryption
        ClientPubKeyN, ClientPubKeyE = rsa.createRSAKeys(Const.CLIENT)
        #log(Const.getCurrentTime()+"CLIENT: Generated RSA keys\n")
    # Get public organization key
    pubKeyCompany = getPubKeyCompany(ClientPubKeyN, ClientPubKeyE)
    if pubKeyCompany is Const.BAD_REQ or pubKeyCompany is Const.NO_METHOD or pubKeyCompany is Const.ERROR:
        log(Const.getCurrentTime()+"CLIENT: Error "+pubKeyCompany+" getting company public key\n")
        return Const.ERROR
    # Create file encryption key
    m = generateKey()
    c1, c2 = ElGamal.encrypt(m, pubKeyCompany)
    log(Const.getCurrentTime()+"CLIENT: Encrypted random int with ElGamal\n")
    data = [c1, c2]
    # size = len(bytes(data))
    # Get a random key
    key = aes.getKey(m)
    log(Const.getCurrentTime()+"CLIENT: Generated key from random int\n")
    # Get initialization vector
    iv = aes.getIV()
    aesCipher = AES.new(key, AES.MODE_CBC, iv)
    # Get file name
    file_name = str(infile).split('\'')[1].split('\'')[0]
    # Create temporary plain file
    tmp_path = './tmp/'+file_name
    infile.save(tmp_path)
    fsz = os.stat(tmp_path).st_size
    encfile = 'enc_'+file_name
    # Encrypt header and file data
    with open(encfile, 'wb') as fout:
        # Write header
        log(Const.getCurrentTime()+"CLIENT: Writing header of encrypted file\n")
        # fout.write(struct.pack('<Q', size))
        fout.write(str(data))
        # Write file
        log(Const.getCurrentTime()+"CLIENT: Writing encrypted file data\n")
        fout.write(struct.pack('<Q', fsz))
        fout.write(iv)
        with open(tmp_path, 'rb') as fin:
            while True:
                log(Const.getCurrentTime()+"CLIENT: Reading data from input file\n")
                data = fin.read(Const.RSA_BITS)
                n = len(data)
                if n == 0:
                    break
                log(Const.getCurrentTime()+"CLIENT: Encrypting read data\n")
                encData = aes.encrypt(aesCipher, data)
                log(Const.getCurrentTime()+"CLIENT: Writing encrypted data\n")
                fout.write(encData)
    saveConfig(Const.CLIENT + "_" + Const.CONFIG + '.json')
    fout = open(encfile, "rb")
    if fout.mode == "rb":
        f = fout.read()
        result = base64.encodestring(f)
        print "RESULT: ", len(f), " (in base64", len(result), ") ", f
        # result = base64.encodestring(fout.read())
        log(Const.getCurrentTime()+"CLIENT: Successful encryption!\n")
    else:
        result = Const.ERROR
        log(Const.getCurrentTime()+"CLIENT: Encryption failed!\n")
    log(Const.getCurrentTime()+"CLIENT: Deleting temporary files\n")
    # os.remove(tmp_path)
    # os.remove(encfile)
    log(Const.getCurrentTime()+"CLIENT: Temporary files deleted\n")
    return result

# Decrypt file
def decryptFile(encfile):
    log(Const.getCurrentTime()+"CLIENT: DECRYPTION REQUESTED\n")
    # Get file name
    file_name = str(encfile).split('\'')[1].split('\'')[0]
    # Create temporary plain file
    tmp_path = './tmp/' + file_name
    decfile = 'dec_' + file_name
    with open(tmp_path, 'wb') as fout:
        f = encfile.read()
        s = base64.decodestring(f)
        print "File cifrato lungo:", len(f), " (in base64 ", len(s), ")"
        # fout.write(base64.decodestring(encfile.read()))
        fout.write(base64.decodestring(f))
    # Decrypt file
    with open(tmp_path, 'rb') as fin:
        # Read size of plain text
        log(Const.getCurrentTime()+"CLIENT: Reading file header\n")
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
        log(Const.getCurrentTime()+"CLIENT: Getting encrypted fields\n")
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
        log(Const.getCurrentTime()+"CLIENT: Asking partial decryption to Cloud Provider\n")
        response = requests.post("http://"+Const.CLOUD_PROVIDER_ADDR+":"+Const.CLOUD_PROVIDER_PORT+"/"+Const.DECRYPT, data=data, headers=headers)
        if (response.content is Const.NO_METHOD) or (response.content is Const.BAD_REQ):
            log(Const.getCurrentTime()+"CLIENT: Error during Cloud Provider decryption\n")
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
        log(Const.getCurrentTime()+"CLIENT: Verifying response signature\n")
        if rsa.verifySign([CloudProviderPubKeyN, CloudProviderPubKeyE], message, sign) is not True:
            log(Const.getCurrentTime()+"CLIENT: Error in signature!\n")
            return Const.ERROR
        log(Const.getCurrentTime()+"CLIENT: Response signature verified\n")
        # Ask decryption to Company server
        sign = rsa.generateSign([str(ClientPubKeyN), str(ClientPubKeyE), str(c1), str(m)], Const.CLIENT)
        data = json.dumps(
            {Const.NE: ClientPubKeyN, Const.E: ClientPubKeyE, Const.C1: c1, Const.C2: m, Const.SIGN: sign})
        headers = {'Content-Type': 'application/json'}
        log(Const.getCurrentTime()+"CLIENT: Asking final decryption to Company\n")
        responseCompany = requests.post("http://" + Const.COMPANY_ADDR + ":" + Const.COMPANY_PORT + "/" + Const.DECRYPT,
                                        data=data, headers=headers)
        if (responseCompany.content is Const.NO_METHOD) or (responseCompany.content is Const.BAD_REQ):
            log(Const.getCurrentTime()+"CLIENT: Error during Company decryption\n")
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
        log(Const.getCurrentTime()+"CLIENT: Verifying response signature\n")
        if rsa.verifySign([CompanyPubKeyN, CompanyPubKeyE], message, sign) is not True:
            log(Const.getCurrentTime()+"CLIENT: Error in signature!\n")
            return Const.ERROR
        log(Const.getCurrentTime()+"CLIENT: Response signature verified\n")
        log(Const.getCurrentTime()+"CLIENT: Generating asymmetric encryption key\n")
        key = aes.getKey((long)(m))
        # Read size of plain text
        fsz = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        iv = fin.read(AES.block_size)
        aesCipher = AES.new(key, AES.MODE_CBC, iv)
        with open(decfile, 'wb') as fout:
            log(Const.getCurrentTime()+"CLIENT: Decrypting file data\n")
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
    fout = open(decfile, "rb")
    if fout.mode == "rb":
        result = base64.encodestring(fout.read())
        log(Const.getCurrentTime()+"CLIENT: Successful decryption!\n")
    else:
        result = Const.ERROR
        log(Const.getCurrentTime()+"CLIENT: Decryption failed!\n")
    log(Const.getCurrentTime()+"CLIENT: Deleting temporary files\n")
    os.remove(tmp_path)
    os.remove(decfile)
    log(Const.getCurrentTime()+"CLIENT: Temporary files deleted\n")
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
        enc_f = encryptFile(f)
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
        dec_f = decryptFile(f)
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
        file_out = open(Const.LOG+".txt", "r")
        if file_out.mode == "r":
            return file_out.read(), 200
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
