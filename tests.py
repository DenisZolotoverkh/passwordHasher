import re

from fastapi.testclient import TestClient

from crypto import mask_hash
from hashers import PBKDF2PasswordHasher
from main import app, HASH_ROUTE, VERIFY_ROUTE, SAFE_SUMMARY_ROUTE

client = TestClient(app)

TEST_PASSWORD = "securePassword321"


def test_hash_password_success():
    response = client.post(
        HASH_ROUTE,
        params={
            "password": TEST_PASSWORD
        }
    )
    regex = re.compile(r"^(pbkdf2_sha256\$[0-9]+\$.+\$.+)$")
    assert response.status_code == 200
    assert regex.match(response.json().get("encoded"))


def test_verify_password_success():
    hasher = PBKDF2PasswordHasher()
    salt = hasher.salt()
    encoded_password = hasher.encode(TEST_PASSWORD, salt)

    response = client.post(
        VERIFY_ROUTE,
        params={
            "password": TEST_PASSWORD,
            "encoded": encoded_password
        }
    )
    assert response.status_code == 200
    assert response.json().get("verified")


def test_verify_password_wrong_password():
    hasher = PBKDF2PasswordHasher()
    salt = hasher.salt()
    encoded_password = hasher.encode("wrong_password((", salt)

    response = client.post(
        VERIFY_ROUTE,
        params={
            "password": TEST_PASSWORD,
            "encoded": encoded_password
        }
    )
    assert response.status_code == 200
    assert not response.json().get("verified")


def test_verify_password_bad_encoded_password():
    encoded_password = "garbage"

    response = client.post(
        VERIFY_ROUTE,
        params={
            "password": TEST_PASSWORD,
            "encoded": encoded_password
        }
    )
    assert response.status_code == 400


def test_safe_summary_success():
    hasher = PBKDF2PasswordHasher()
    salt = hasher.salt()
    encoded_password = hasher.encode(TEST_PASSWORD, salt)
    response = client.get(
        SAFE_SUMMARY_ROUTE,
        params={
            "password": TEST_PASSWORD,
            "encoded": encoded_password
        }
    )
    decoded = hasher.decode(encoded_password)
    expected = {
        "algorithm": decoded["algorithm"],
        "iterations": decoded["iterations"],
        "salt": mask_hash(decoded["salt"]),
        "hash": mask_hash(decoded["hash"]),
    }
    assert response.status_code == 200
    assert expected == response.json()


def test_safe_summary_bad_encoded_password():
    encoded_password = "garbage"
    response = client.get(
        SAFE_SUMMARY_ROUTE,
        params={
            "password": TEST_PASSWORD,
            "encoded": encoded_password
        }
    )
    assert response.status_code == 400
