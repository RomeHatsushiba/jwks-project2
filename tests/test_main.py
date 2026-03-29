import os
import sqlite3
from cryptography.hazmat.primitives import serialization
from main import (
    init_db,
    seed_keys,
    get_signing_key,
    get_valid_keys,
    DB_FILE,
    int_to_base64,
    generate_private_key,
    private_key_to_pem,
)


def setup_module():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    init_db()
    seed_keys()


def teardown_module():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)


def test_db_created():
    assert os.path.exists(DB_FILE)


def test_keys_table_exists():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")
    row = cursor.fetchone()
    conn.close()
    assert row is not None


def test_seed_keys_only_once():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM keys")
    before = cursor.fetchone()[0]
    conn.close()

    seed_keys()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM keys")
    after = cursor.fetchone()[0]
    conn.close()

    assert before == after


def test_valid_key_exists():
    row = get_signing_key(False)
    assert row is not None
    assert row[0] is not None


def test_expired_key_exists():
    row = get_signing_key(True)
    assert row is not None
    assert row[0] is not None


def test_valid_keys_list():
    rows = get_valid_keys()
    assert isinstance(rows, list)
    assert len(rows) >= 1


def test_int_to_base64_small_value():
    result = int_to_base64(65537)
    assert isinstance(result, str)
    assert len(result) > 0


def test_generate_private_key_and_pem():
    key = generate_private_key()
    pem = private_key_to_pem(key)

    assert isinstance(pem, bytes)
    loaded = serialization.load_pem_private_key(pem, password=None)
    assert loaded is not None