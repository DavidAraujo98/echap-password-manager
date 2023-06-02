from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from cherrypy import _cperror
import threading
import requests
import cherrypy
import os.path
import hashlib
import sqlite3
import random
import string
import base64
import socket
import json


class serve(object):
    @cherrypy.expose
    def index(self):
        return open("resources/index.html")

    @cherrypy.expose
    def stockman(self):
        if cherrypy.session.id in cherrypy.session and cherrypy.session[cherrypy.session.id] == "admin":
            return open("resources/stockman.html")
        else:
            notfound(status, message, traceback, version)

    @cherrypy.expose
    def products(self, id=0):
        if id == 0:
            return open("resources/products.html")
        else:
            return open("resources/productdisplay.html")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def prod_list(self):
        db = sqlite3.connect("database.db")
        cur = db.cursor()

        response = cur.execute("SELECT * FROM products").fetchall()

        db.commit()
        db.close()

        return json.dumps(response)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def prod_remove(self):
        input = cherrypy.request.json

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        for x in input:
            id = decode64(x["id"])
            com = """ DELETE FROM products WHERE id=? """
            arg = (id,)
            cur.execute(com, arg)

        db.commit()
        db.close()

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def prod_add(self):
        input = cherrypy.request.json
        name = decode64(input["name"])
        detail = decode64(input["detail"])
        price = decode64(input["price"])
        quantity = decode64(input["quantity"])

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """INSERT INTO products (name, detail, price, quantity) VALUES (?,?,?,?)"""
        arg = (name, detail, price, quantity)
        match = cur.execute(com, arg)

        db.commit()
        db.close()

    @cherrypy.expose
    def img_add(self, image):
        path = "resources/assets/products/" + image.filename
        f = open(path, "wb")
        while True:
            data = image.file.read(8192)
            if not data:
                f.close()
                break
            f.write(data)

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """SELECT id FROM products ORDER BY id DESC LIMIT 1;"""
        match = cur.execute(com)
        id = match.fetchone()[0]

        print(id)

        com = """UPDATE products SET image=? WHERE id=?"""
        args = (path, id)
        match = cur.execute(com, args)

        db.commit()
        db.close()

        raise cherrypy.HTTPRedirect("stockman")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def product_display(self):
        input = cherrypy.request.json
        id = decode64(input["id"])

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """SELECT * FROM products WHERE id= ?"""
        arg = (id,)
        match = cur.execute(com, arg)
        data = match.fetchone()

        db.commit()
        db.close()
        return json.dumps(data)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def product_reviews(self):
        input = cherrypy.request.json
        id = decode64(input["id"])

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """SELECT * FROM reviews WHERE product_id= ?"""
        arg = (id,)
        match = cur.execute(com, arg)
        data = match.fetchall()

        db.commit()
        db.close()
        return json.dumps(data)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def post_review(self):
        input = cherrypy.request.json
        comment = decode64(input["comment"])
        username = cherrypy.session[cherrypy.session.id]
        product_id = decode64(input["product_id"])

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """INSERT INTO reviews (product_id, username, comment) VALUES (?,?,?)"""
        arg = (product_id, username, comment)
        match = cur.execute(com, arg)

        db.commit()
        db.close()

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def buy(self):
        input = cherrypy.request.json

        value = decode64(input["value"])
        username = cherrypy.session[cherrypy.session.id]

        product_id = decode64(input["product_id"])
        quantity = decode64(input["quantity"])

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """ SELECT quantity FROM products WHERE id=? """
        arg = (product_id,)
        match = cur.execute(com, arg)
        old_quantity = match.fetchone()[0]

        new_quantity = old_quantity - abs(int(quantity))

        com = """UPDATE products SET quantity=? WHERE id=?"""
        arg = (new_quantity, product_id)
        cur.execute(com, arg)

        com = """ SELECT credit FROM users WHERE username=? """
        arg = (username,)
        match = cur.execute(com, arg)
        old_credit = match.fetchone()[0]

        new_credit = round(old_credit - abs(float(value)), 2)

        com = """ UPDATE users SET credit=? WHERE username=? """
        arg = (new_credit, username)
        cur.execute(com, arg)

        db.commit()
        db.close()

        response = {"success": 1,
                    "message": "Produto adquirido e valor deduzido do credito"}
        return json.dumps(response)

    @cherrypy.expose
    def login(self, uap=None):
        if uap != None:
            cherrypy.session["uapr"] = uap.replace(" ", "+")
        return open("resources/login.html")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def login_validation(self):
        input = cherrypy.request.json
        username = decode64(input["username"])
        hash = decode64(input["hash"])

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """SELECT hash, admin, credit FROM users WHERE username= ?"""
        arg = (username,)
        match = cur.execute(com, arg)
        data = match.fetchone()
        db_hash = data[0]
        admin = data[1]
        credit = data[2]

        response = None
        if db_hash == hash:
            cherrypy.session[cherrypy.session.id] = username
            if admin == 1:
                cherrypy.session["admin"] = 1
                response = {"success": 1, "message": "Bem-vindo " +
                            username + "!", "admin": 1, "stocklink": "stockman", "credit": credit}
            else:
                cherrypy.session["admin"] = 0
                response = {"success": 1, "message": "Bem-vindo " +
                            username + "!", "admin": 0, "credit": credit}

        else:
            response = {"success": 0,
                        "message": "Username ou password incorretos"}

        db.close()
        return json.dumps(response)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def uap_validation(self):
        ip_addr = "127.0.0.1"
        tcp_port = 5005
        response = {"address": ip_addr, "port": tcp_port}

        client_handler = threading.Thread(
            target=socket_connection, args=(ip_addr, tcp_port), daemon=True)
        client_handler.start()

        return json.dumps(response)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def uap_logger(self):
        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """SELECT username, credit, admin FROM users WHERE uap = ?"""
        arg = (cherrypy.session.get("uapr"),)
        match = cur.execute(com, arg)
        data = match.fetchone()

        com = """UPDATE users SET uap=NULL WHERE uap = ?"""
        arg = (cherrypy.session.get("uapr"),)
        match = cur.execute(com, arg)
        db.commit()

        if data != None:
            cherrypy.session[cherrypy.session.id] = data[0]
            response = {"success": 1, "message": "Bem-vindo " +
                        data[0] + "!", "admin": 0, "credit": data[1]}

            if data[2] == 1:
                cherrypy.session["admin"] = 1
                response["admin"] = 1
                response["stocklink"] = "stockman"
        else:
            response = {"success": 0,
                        "message": "Username ou password incorretos"}
        db.close()
        return json.dumps(response)

    @cherrypy.expose
    def signup(self):
        return open("resources/signup.html")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def signup_validation(self):
        input = cherrypy.request.json
        username = decode64(input["username"])
        email = decode64(input["email"])
        hash = decode64(input["hash"])
        credit = abs(round(float(decode64(input["credit"])), 2))

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """SELECT * FROM users WHERE username= ? OR email= ?"""
        arg = (username, email)
        match = cur.execute(com, arg)

        response = {"success": 1, "message": "Registo efetuado com sucesso !"}

        if match.fetchone() != None:
            response = {
                "success": 0,
                "message": "Username " + str(username) + " já existe",
            }
        else:
            com = """INSERT INTO users (username,email,hash,credit) VALUES (?,?,?,?)"""
            arg = (username, email, hash, credit)
            cur.execute(com, arg)
            db.commit()

        db.close()
        return json.dumps(response)

    @cherrypy.expose
    def reset(self):
        return open("resources/reset.html")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def reset_validation(self):
        input = cherrypy.request.json
        username = decode64(input["username"])

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """SELECT email FROM users WHERE username= ?"""
        arg = (username,)
        match = cur.execute(com, arg)
        r = match.fetchone()

        response = None
        if r != None:
            email = r[0]

            ran = "".join(random.choices(
                string.ascii_uppercase + string.digits, k=64))

            com = """ UPDATE users SET reset=? WHERE username= ?"""
            arg = (ran, username)
            cur.execute(com, arg)
            db.commit()

            repo_email = "/newpassword?id=" + ran

            print("\n<--- Simulação email --->\n\nSent to: " + email + "\n\nReposition url: " +
                  repo_email + "\n\n<--- Simulação email --->\n")

            response = {
                "success": 1,
                "message": "Verifique o seu email pelo link de reposicao",
            }
        else:
            response = {"success": 0, "message": "Username inexistente"}

        db.close()
        return json.dumps(response)

    @cherrypy.expose
    def newpassword(self, id):
        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """ SELECT * FROM users WHERE reset=? """
        arg = (id,)
        match = cur.execute(com, arg)

        if match.fetchone()[0] == None:
            return "Ops, this record doesn't exists"
        else:
            return open("resources/newpassword.html")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def newpassword_validation(self):
        input = cherrypy.request.json
        resetid = decode64(input["resetid"])
        hash = decode64(input["hash"])

        db = sqlite3.connect("database.db")
        cur = db.cursor()

        com = """ UPDATE users SET hash=?, reset=NULL WHERE reset= ? """
        arg = (
            hash,
            resetid,
        )
        cur.execute(com, arg)

        db.commit()
        db.close()

        response = {"message": "Password atualizada com sucesso"}

        return json.dumps(response)

def socket_connection(ip_addr, tcp_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip_addr, tcp_port))
    server.listen(5)
    client_socket, address = server.accept()

    challenge = get_random_bytes(32)
    try:
        username = client_socket.recv(1024).decode('utf-8')
        client_socket.send(challenge)
        res = response(challenge, getHash(username))
        n = int.from_bytes(client_socket.recv(1024), "big")
        
        passed = True
        client_socket.send(res[0:n])
        for x in range(0, int(len(res))-n, int(2*n)):
            a_res = client_socket.recv(1024)
            nn = int(2*n + x)
            
            if a_res == res[x+n:nn] and passed:
                client_socket.send(res[nn:nn+n])
            else:
                passed = False
                w = get_random_bytes(int(n/8))
                client_socket.send(bytes(bin(w[0])[2:], "utf-8"))
        
        if passed:
            salt = get_random_bytes(16)
            uap_token(salt, username)
            client_socket.send(salt) 
    except (socket.timeout, socket.error):
        print('Client {} error. Done!'.format(address))

    client_socket.close()

def getHash(username):
    db = sqlite3.connect("database.db")
    cur = db.cursor()

    com = """SELECT hash FROM users WHERE username= ?"""
    arg = (username,)
    match = cur.execute(com, arg)
    data = match.fetchone()
    return data[0]

def response(challenge, hash):
    a = PBKDF2(hash, challenge, 64, count=1000000, hmac_hash_module=SHA512)
    b = base64.b64encode(a).decode("utf-8")
    response = "".join(format(ord(i), "08b") for i in b)
    return response.encode("utf-8")


def uap_token(salt, username):
    db = sqlite3.connect("database.db")
    cur = db.cursor()

    com = """SELECT hash FROM users WHERE username=?"""
    arg = (username,)
    match = cur.execute(com, arg)
    hash = match.fetchone()
    key = PBKDF2(hash[0], salt, 32, count=1000000, hmac_hash_module=SHA512)
    b = base64.b64encode(key)
    key = b.decode("utf-8")
    com = """UPDATE users SET uap=? WHERE username=?"""
    arg = (key, username)
    match = cur.execute(com, arg)
    db.commit()
    db.close()


def encode64(word):
    a = word.encode("utf-8")
    b = base64.b64encode(a)
    result = b.decode("utf-8")
    return result


def decode64(word):
    a = word.encode("utf-8")
    b = base64.b64decode(a)
    result = b.decode("utf-8")
    return result


def notfound(status, message, traceback, version):
    return "Ops, you shouldn't be here"


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

            "server.socket_port": 9090,

            "tools.sessions.secure": "True",
            "tools.sessions.httponly": "True",
        }
    )
    cherrypy.quickstart(serve(), "/", conf)
