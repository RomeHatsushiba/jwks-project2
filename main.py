from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import time

hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db"


def int_to_base64(value):
    value_hex = format(value, "x")
    if len(value_hex) % 2 == 1:
        value_hex = "0" + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b"=")
    return encoded.decode("utf-8")


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def private_key_to_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def seed_keys():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]

    if count == 0:
        valid_key = generate_private_key()
        expired_key = generate_private_key()

        valid_pem = private_key_to_pem(valid_key)
        expired_pem = private_key_to_pem(expired_key)

        now = int(time.time())
        valid_exp = now + 3600
        expired_exp = now - 3600

        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (valid_pem, valid_exp)
        )
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (expired_pem, expired_exp)
        )

        conn.commit()

    conn.close()


def get_signing_key(use_expired=False):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = int(time.time())

    if use_expired:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1",
            (now,)
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1",
            (now,)
        )

    row = cursor.fetchone()
    conn.close()
    return row


def get_valid_keys():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = int(time.time())

    cursor.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid",
        (now,)
    )

    rows = cursor.fetchall()
    conn.close()
    return rows


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            use_expired = "expired" in params
            row = get_signing_key(use_expired)

            if not row:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No signing key found")
                return

            kid, pem_bytes, key_exp = row

            headers = {
                "kid": str(kid)
            }

            if use_expired:
                token_exp = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
            else:
                token_exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

            token_payload = {
                "username": "userABC",
                "password": "password123",
                "exp": token_exp
            }

            encoded_jwt = jwt.encode(
                token_payload,
                pem_bytes,
                algorithm="RS256",
                headers=headers
            )

            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(encoded_jwt.encode("utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            rows = get_valid_keys()

            keys = {"keys": []}

            for kid, pem_bytes, exp in rows:
                private_key = serialization.load_pem_private_key(
                    pem_bytes,
                    password=None,
                )
                public_numbers = private_key.public_key().public_numbers()

                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(keys).encode("utf-8"))
            return

        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":
    init_db()
    seed_keys()
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()