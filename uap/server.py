from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, MD5
from Crypto.Cipher import ChaCha20
from cherrypy import _cperror
import requests
import cherrypy
import hashlib
import sqlite3
import os.path
import base64
import random
import string
import socket
import json


class serve(object):

    @cherrypy.expose
    def index(self, service=None, addr=None, prt=None):
        cherrypy.session["service"] = service
        cherrypy.session["address"] = addr
        cherrypy.session["port"] = prt
        return open("resources/login.html")

    @cherrypy.expose
    def logout(self):
        cleanup()
        raise cherrypy.HTTPRedirect("/")

    @cherrypy.expose
    def signup(self):
        return open("resources/signup.html")

    @cherrypy.expose
    def vault(self, username):
        if cherrypy.session.id in cherrypy.session and cherrypy.session.get(cherrypy.session.id) == username:
            return open("resources/vault.html")
        else:
            notfound(status, message, traceback, version)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def login_validation(self):
        input = cherrypy.request.json
        username = decode64(bytes(input["username"], "utf-8")).decode("utf-8")
        hash = decode64(bytes(input["hash"], "utf-8")).decode("utf-8")

        response = logger(username, hash)

        return json.dumps(response)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def signup_validation(self):
        input = cherrypy.request.json
        username = decode64(bytes(input["username"], "utf-8")).decode("utf-8")
        hash = decode64(bytes(input["hash"], "utf-8")).decode("utf-8")

        db = sqlite3.connect("login.db")
        cur = db.cursor()

        com = """SELECT * FROM users WHERE username= ?"""
        arg = (username,)
        match = cur.execute(com, arg)

        response = {"success": 1, "message": "Welcome to the Vault !"}

        if match.fetchone() != None:
            response = {
                "success": 0,
                "message": "Username " + str(username) + " já existe",
            }
        else:
            nonce = get_random_bytes(24)
            key = PBKDF2(hash, nonce, 32, count=1000000,
                         hmac_hash_module=SHA512)
            cipher = ChaCha20.new(key=key, nonce=nonce)
            secret = cipher.encrypt(nonce)

            path = database_builder(username)
            com = """INSERT INTO users (username, database) VALUES (?,?)"""
            arg = (username, path)
            cur.execute(com, arg)
            db.commit()

            cherrypy.session[cherrypy.session.id] = username
            cherrypy.session["database"] = path
            cherrypy.session["hash"] = hash

            database_encryptor()

        db.close()
        return json.dumps(response)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def service_validation(self):
        input = cherrypy.request.json
        username = decode64(bytes(input["username"], "utf-8")).decode("utf-8")
        hash = decode64(bytes(input["hash"], "utf-8")).decode("utf-8")

        service = cherrypy.session.get("service")
        address = cherrypy.session.get("address")
        port = int(cherrypy.session.get("port"))

        response = logger(username, hash)
        if response["success"] == 1:
            hashs = getHashs(service)
            cherrypy.session["hashs"] = hashs

            if len(hashs) == 0:
                response["message"] = "UAP does not have credentials for this service"
                response["mux"] = 0
            elif len(hashs) > 1:
                response["message"] = "Please choose an account"
                response["mux"] = 1;
                response["usernames"] = []
                for i in hashs:
                    response["usernames"].append(i[0])
            else:
                response["message"], response["key"] = socket_connection(
                    address, port, service, hashs[0][0], hashs[0][1])
        
        return json.dumps(response)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def service_validation_afch(self):
        input = cherrypy.request.json
        username = decode64(bytes(input["username"], "utf-8")).decode("utf-8")

        hashs = cherrypy.session.get("hashs")
        service = cherrypy.session.get("service")
        address = cherrypy.session.get("address")
        port = int(cherrypy.session.get("port"))

        response = {}
        hash = None
        for i in hashs:
            if i[0] == username:
                hash = i[1]
        
        response["message"], response["key"] = socket_connection(address, port, service, username, hash)

        return json.dumps(response)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def loadData(self):
        data_loader()
        return json.dumps(cherrypy.session.get("data"))

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def newCredentials(self):
        input = cherrypy.request.json
        id = decode64(bytes(input["id"], "utf-8")).decode("utf-8")
        username = decode64(bytes(input["username"], "utf-8")).decode("utf-8")
        password = decode64(bytes(input["password"], "utf-8")).decode("utf-8")
        service = decode64(bytes(input["service"], "utf-8")).decode("utf-8")

        database_decryptor()

        db = sqlite3.connect(cherrypy.session.get("database"))
        cur = db.cursor()

        com = """SELECT * FROM credentials WHERE id = ?"""
        arg = (id,)
        match = cur.execute(com, arg)
        r = match.fetchone()

        response = {"success": 0, "message": "", "new": 0}

        if r != None:
            com = """UPDATE credentials SET service = ?, username = ?, password = ? WHERE id = ?"""
            arg = (service, username, password, id)
            cur.execute(com, arg)
            db.commit()
            db.close()

            response = {"success": 1,
                        "message": "Credentials updated!", "new": 0}
        else:
            com = """INSERT INTO credentials (id, service, username, password) VALUES (?,?,?,?)"""
            arg = (id, service, username, password)
            cur.execute(com, arg)
            db.commit()
            db.close()

            response = {"success": 1,
                        "message": "New credentials added !", "new": 1}

        database_encryptor()

        return json.dumps(response)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def deleteSelection(self):
        input = cherrypy.request.json
        data = input["ids"]

        database_decryptor()

        db = sqlite3.connect(cherrypy.session.get("database"))
        cur = db.cursor()

        for i in data:
            id = decode64(bytes(i, "utf-8")).decode("utf-8")
            com = """DELETE FROM credentials WHERE id = ?"""
            arg = (id,)
            cur.execute(com, arg)
            db.commit()
        db.close()

        response = {"success": 1, "message": "Credentials deleted"}

        database_encryptor()

        return json.dumps(response)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getPassword(self):
        input = cherrypy.request.json
        id = decode64(bytes(input["id"], "utf-8")).decode("utf-8")

        database_decryptor()

        db = sqlite3.connect(cherrypy.session.get("database"))
        cur = db.cursor()

        com = """SELECT password FROM credentials WHERE id = ?"""
        arg = (id,)
        match = cur.execute(com, arg)
        r = match.fetchone()
        db.close()

        response = {"success": 1, "password": encode64(
            bytes(r[0], "utf-8")).decode("utf-8")}

        database_encryptor()

        return json.dumps(response)

def socket_connection(address, port, service,username, hash):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((address, port))

    key = None
    try:
        server_socket.send(username.encode("utf-8"))
        challenge = server_socket.recv(1024)
        res = response(challenge, hash)
        n = 8
        server_socket.send(bytes([n]))

        passed = True
        for x in range(n, int(len(res)), int(2*n)):
            a_res = server_socket.recv(1024)      
             
            if a_res == res[x-n:x] and passed:
                server_socket.send(res[x:x+n])
            else:
                passed = False
                w = get_random_bytes(int(n/8))
                client_socket.send(bytes(bin(w[0])[2:], "utf-8"))

        if passed:
            salt = server_socket.recv(1024)
            key = PBKDF2(hash, salt, 32, count=1000000,
                        hmac_hash_module=SHA512)
            server_socket.close()
            return "Secure login approved", encode64(key).decode("utf-8")
    except (socket.timeout, socket.error):
        print('Server error. Done!')

    server_socket.close()
    return "Secure login revogued", None

def response(challenge, hash):
    a = PBKDF2(hash, challenge, 64, count=1000000, hmac_hash_module=SHA512)
    b = base64.b64encode(a).decode("utf-8")
    response = "".join(format(ord(i), "08b") for i in b)
    return response.encode("utf-8")

def getHashs(service):
    database_decryptor()
    db = sqlite3.connect(cherrypy.session.get("database"))
    cur = db.cursor()

    com = """SELECT username, password FROM credentials WHERE service=?"""
    arg = (service,)
    match = cur.execute(com,arg)
    r = match.fetchall()
    db.close()
    database_encryptor()

    out = []
    for i in r:
        ins = []
        ins.append(i[0])
        ins.append(hashlib.sha3_512(i[1].encode("utf-8")).hexdigest())
        out.append(ins)

    return out


def logger(username, hash):
    db = sqlite3.connect("login.db")
    cur = db.cursor()

    com = """SELECT secret, nonce, database FROM users WHERE username = ?"""
    arg = (username,)
    match = cur.execute(com, arg)
    r = match.fetchone()

    response = {"success": 0, "message": "Username ou password incorrect"}

    if r != None:
        secret = decode64(r[0])
        nonce = decode64(r[1])
        database = r[2]

        key = PBKDF2(hash, nonce, 32, count=1000000,
                     hmac_hash_module=SHA512)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        reveal = cipher.decrypt(secret)

        if reveal == nonce:
            cherrypy.session[cherrypy.session.id] = username
            cherrypy.session["database"] = database
            cherrypy.session["nonce"] = nonce
            cherrypy.session["hash"] = hash

            response = {"success": 1, "message": "Welcome to the Vault"}

    db.close()
    return response


def database_builder(name):
    h = MD5.new()
    h.update(bytes(name, "utf-8"))
    path = "resources/databases/" + h.hexdigest() + ".db"
    db = sqlite3.connect(path)
    cur = db.cursor()
    com = """CREATE TABLE 'credentials' ('id' TEXT, 'service' TEXT, 'username' TEXT, 'password' TEXT)"""
    cur.execute(com)
    db.commit()
    db.close()
    return path


def data_loader():
    database_decryptor()
    db = sqlite3.connect(cherrypy.session.get("database"))
    cur = db.cursor()

    com = """SELECT * FROM credentials"""
    match = cur.execute(com)
    r = match.fetchall()

    data = {"creds": []}
    out = {"out":[]}
    for row in r:
        a = {"id": encode64(bytes(row[0], "utf-8")).decode("utf-8"), "service": encode64(bytes(row[1], "utf-8")).decode("utf-8"),
             "username": encode64(bytes(row[2], "utf-8")).decode("utf-8"), "password": encode64(bytes(row[3], "utf-8")).decode("utf-8")}
        data["creds"].append(a)

    cherrypy.session["data"] = data
    db.close()
    database_encryptor()
    return out


def database_encryptor():
    database = cherrypy.session.get("database")
    hash = cherrypy.session.get("hash")

    nonce = get_random_bytes(24)
    key = PBKDF2(hash, nonce, 32, count=1000000,
                 hmac_hash_module=SHA512)
    cipher = ChaCha20.new(key=key, nonce=nonce)

    secret = cipher.encrypt(nonce)

    db = sqlite3.connect("login.db")
    cur = db.cursor()
    com = """UPDATE users SET secret=?, nonce=? WHERE username=?"""
    arg = (encode64(secret).decode("utf-8"), encode64(nonce).decode("utf-8"),
           cherrypy.session.get(cherrypy.session.id),)
    cur.execute(com, arg)
    db.commit()
    db.close()

    data = None
    with open(database, "rb") as file:
        r_d = file.read()
        data = cipher.encrypt(r_d)
    with open(database, "wb") as file:
        file.write(data)

    cherrypy.session["nonce"] = nonce


def database_decryptor():
    database = cherrypy.session.get("database")
    nonce = cherrypy.session.get("nonce")
    hash = cherrypy.session.get("hash")
    key = PBKDF2(hash, nonce, 32, count=1000000,
                 hmac_hash_module=SHA512)
    cipher = ChaCha20.new(key=key, nonce=nonce)

    cipher.seek(24)

    data = None
    with open(database, "rb") as file:
        r_d = file.read()
        data = cipher.decrypt(r_d)
    with open(database, "wb") as file:
        file.write(data)


def encode64(word):
    b = base64.b64encode(word)
    return b


def decode64(word):
    b = base64.b64decode(word)
    return b


def cleanup():
    cherrypy.session.clear()
    cherrypy.session.regenerate()


def notfound(status, message, traceback, version):
    return "Where are you ? \/('.')\/"


if __name__ == "__main__":
    conf = {
        "/": {
            "tools.sessions.on": True,
            "tools.staticdir.on": True,
            "tools.staticdir.dir": os.path.abspath("./"),
            "error_page.default": notfound,
        }
    }
    cherrypy.config.update(
        {

            "server.ssl_module": "builtin",
            "server.ssl_certificate": "cert.pem",
            "server.ssl_private_key": "privkey.pem",

            "server.socket_port": 8080,

            "tools.sessions.secure": "True",
            "tools.sessions.httponly": "True",
        }
    )
    cherrypy.quickstart(serve(), "/", conf)
