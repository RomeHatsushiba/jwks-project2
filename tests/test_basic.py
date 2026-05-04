import os
import threading
import time
import uuid

os.environ.setdefault("NOT_MY_KEY", "test-only-encryption-secret")

import requests
from http.server import HTTPServer
from main import MyServer, hostName, serverPort, init_db, seed_keys, DB_FILE

server = None
thread = None


def setup_module():
    global server, thread
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    init_db()
    seed_keys()
    server = HTTPServer((hostName, serverPort), MyServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)


def teardown_module():
    global server
    if server:
        server.shutdown()
        server.server_close()
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)


def test_jwks_returns_keys():
    r = requests.get("http://localhost:8080/.well-known/jwks.json")
    assert r.status_code == 200
    assert "keys" in r.json()


def test_register_returns_password():
    r = requests.post(
        "http://localhost:8080/register",
        json={"username": f"testuser-{uuid.uuid4()}", "email": f"test-{uuid.uuid4()}@test.com"}
    )
    assert r.status_code == 201
    assert "password" in r.json()


def test_auth_returns_jwt():
    r = requests.post("http://localhost:8080/auth")
    assert r.status_code == 200
    assert len(r.text.split(".")) == 3  # JWT = header.payload.signature


def test_auth_expired_returns_jwt():
    r = requests.post("http://localhost:8080/auth?expired=true")
    assert r.status_code == 200
    assert len(r.text.split(".")) == 3


def test_rate_limiter_triggers_429():
    # fire 15 concurrent requests so they all land inside the 1-second window
    results = []

    def hit():
        results.append(requests.post("http://localhost:8080/auth").status_code)

    threads = [threading.Thread(target=hit) for _ in range(15)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert 429 in results
