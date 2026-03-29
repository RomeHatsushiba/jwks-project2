import os
import threading
import time
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
    time.sleep(1)


def teardown_module():
    global server
    if server:
        server.shutdown()
        server.server_close()
        time.sleep(0.5)


def test_jwks_endpoint():
    r = requests.get("http://localhost:8080/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)


def test_auth_valid():
    r = requests.post("http://localhost:8080/auth")
    assert r.status_code == 200
    assert len(r.text.split(".")) == 3


def test_auth_expired():
    r = requests.post("http://localhost:8080/auth?expired=true")
    assert r.status_code == 200
    assert len(r.text.split(".")) == 3


def test_put_not_allowed():
    r = requests.put("http://localhost:8080/auth")
    assert r.status_code == 405


def test_patch_not_allowed():
    r = requests.patch("http://localhost:8080/auth")
    assert r.status_code == 405


def test_delete_not_allowed():
    r = requests.delete("http://localhost:8080/auth")
    assert r.status_code == 405


def test_head_not_allowed():
    r = requests.head("http://localhost:8080/auth")
    assert r.status_code == 405


def test_unknown_get_not_allowed():
    r = requests.get("http://localhost:8080/not-real")
    assert r.status_code == 405


def test_unknown_post_not_allowed():
    r = requests.post("http://localhost:8080/not-real")
    assert r.status_code == 405