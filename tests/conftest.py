import re

import pytest
from werkzeug.security import generate_password_hash

from labcore import DEMO_PASSWORD, init_db, seed_demo
from secure.app import create_app as secure_app
from vulnerable.app import create_app as vulnerable_app


def make_lab(mode, tmp_path):
    config = {"TESTING": True, "DATABASE": str(tmp_path / f"{mode}.sqlite3")}
    if mode == "secure":
        config["SECRET_KEY"] = "test-fixture-only-" + "x" * 32
    app = (secure_app if mode == "secure" else vulnerable_app)(config)
    with app.app_context():
        init_db()
        seed_demo(generate_password_hash if mode == "secure" else lambda value: value)
    return app


@pytest.fixture(params=["vulnerable", "secure"])
def lab(request, tmp_path):
    mode = request.param
    return mode, make_lab(mode, tmp_path)


@pytest.fixture
def fixed(tmp_path):
    return make_lab("secure", tmp_path)


def token(client, path="/login"):
    response = client.get(path)
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True))
    return match.group(1) if match else None


def post(client, path, data=None, token_path="/login"):
    values = dict(data or {})
    csrf = token(client, token_path)
    if csrf:
        values["csrf_token"] = csrf
    return client.post(path, data=values)


def login(client, username="alice", password=DEMO_PASSWORD):
    response = post(client, "/login", {"username": username, "password": password})
    assert response.status_code == 302
    return response
