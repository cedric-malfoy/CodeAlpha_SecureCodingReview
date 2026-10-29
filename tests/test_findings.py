"""Paired evidence: baseline flaws reproduce; corrected code blocks the same inputs."""
import pytest
from flask import Flask
from werkzeug.security import check_password_hash

from conftest import login, post
from labcore import DEMO_PASSWORD, get_db

XSS = '<script>window.__xssProbe="executed"</script>'


def test_scr01_sql_injection_login(lab, record_property):
    mode, app = lab
    client = app.test_client()
    response = post(client, "/login", {"username": "alice' --", "password": "incorrect"})
    record_property("response_status", response.status_code)
    assert response.status_code == (302 if mode == "vulnerable" else 401)
    with client.session_transaction() as state:
        assert (state.get("user_id") == 1) is (mode == "vulnerable")


def test_scr02_stored_xss(lab, record_property):
    mode, app = lab
    client = app.test_client()
    login(client)
    response = post(client, "/notes/new", {"title": "XSS proof", "body": XSS}, "/notes/new")
    html = client.get(response.location).get_data(as_text=True)
    record_property("raw_script_in_response", XSS in html)
    if mode == "vulnerable":
        assert XSS in html
    else:
        assert XSS not in html
        assert '&lt;script&gt;window.__xssProbe=' in html


@pytest.mark.parametrize("action", ["read", "edit_form", "edit", "delete"])
def test_scr03_cross_user_access(lab, action, record_property):
    mode, app = lab
    client = app.test_client()
    login(client, "alice")
    if action == "read":
        response = client.get("/notes/2")
    elif action == "edit_form":
        response = client.get("/notes/2/edit")
    elif action == "edit":
        response = post(client, "/notes/2/edit", {"title": "Changed by Alice", "body": "Unauthorized change"})
    else:
        response = post(client, "/notes/2/delete")
    record_property("response_status", response.status_code)
    expected = (200 if action in ("read", "edit_form") else 302) if mode == "vulnerable" else 404
    assert response.status_code == expected
    with app.app_context():
        note = get_db().execute("SELECT * FROM notes WHERE id = 2").fetchone()
        if mode == "secure":
            assert note["body"] == "Bob's private draft."
        elif action == "edit":
            assert note["body"] == "Unauthorized change"
        elif action == "delete":
            assert note is None


def test_scr04_password_storage(lab, record_property):
    mode, app = lab
    client = app.test_client()
    response = post(client, "/register", {"username": "carol", "password": DEMO_PASSWORD}, "/register")
    assert response.status_code == 302
    with app.app_context():
        stored = get_db().execute("SELECT password FROM users WHERE username = 'carol'").fetchone()[0]
    record_property("stored_as_plaintext", stored == DEMO_PASSWORD)
    if mode == "vulnerable":
        assert stored == DEMO_PASSWORD
    else:
        assert stored != DEMO_PASSWORD and check_password_hash(stored, DEMO_PASSWORD)
    login(client, "carol")


@pytest.mark.parametrize("action", ["create", "edit", "delete", "logout"])
def test_scr05_missing_csrf(lab, action, record_property):
    mode, app = lab
    client = app.test_client()
    login(client)
    path, data = {
        "create": ("/notes/new", {"title": "Forged form", "body": "No CSRF token"}),
        "edit": ("/notes/1/edit", {"title": "Forged edit", "body": "No CSRF token"}),
        "delete": ("/notes/1/delete", {}),
        "logout": ("/logout", {}),
    }[action]
    response = client.post(path, data=data)
    record_property("response_status", response.status_code)
    assert response.status_code == (302 if mode == "vulnerable" else 400)
    if mode == "secure":
        with app.app_context():
            row = get_db().execute("SELECT body FROM notes WHERE id = 1").fetchone()
            assert row[0] == "Alice's private draft."
            assert get_db().execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 2
        with client.session_transaction() as state:
            assert state["user_id"] == 1


def test_scr06_predictable_key_allows_session_forgery(lab, record_property):
    mode, app = lab
    attacker = Flask("offline-forgery-proof")
    attacker.secret_key = "public-training-key-do-not-use"  # Public baseline fixture.
    forged = attacker.session_interface.get_signing_serializer(attacker).dumps({"user_id": 2})
    client = app.test_client()
    client.set_cookie(app.config["SESSION_COOKIE_NAME"], forged)
    response = client.get("/notes/2")
    record_property("response_status", response.status_code)
    assert response.status_code == (200 if mode == "vulnerable" else 302)
    assert app.debug is (mode == "vulnerable")


def test_scr06_session_cookie_flags(lab, record_property):
    mode, app = lab
    response = login(app.test_client())
    cookie = response.headers["Set-Cookie"]
    record_property("httponly", "HttpOnly" in cookie)
    assert ("HttpOnly" in cookie) is (mode == "secure")
    assert ("SameSite=Lax" in cookie) is (mode == "secure")
