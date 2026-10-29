import pytest
from werkzeug.security import check_password_hash

from conftest import login, post, token
from labcore import DEMO_PASSWORD, get_db, init_db, seed_demo
from secure.app import create_app


def test_complete_registration_and_note_lifecycle(fixed):
    client = fixed.test_client()
    assert post(client, "/register", {"username": "new_learner", "password": DEMO_PASSWORD}, "/register").status_code == 302
    login(client, "new_learner")
    response = post(client, "/notes/new", {"title": "My idea", "body": "First draft"}, "/notes/new")
    location = response.location
    assert response.status_code == 302
    assert "First draft" in client.get(location).get_data(as_text=True)
    assert post(client, location + "/edit", {"title": "Better idea", "body": "Second draft"}, location + "/edit").status_code == 302
    assert "Second draft" in client.get(location).get_data(as_text=True)
    assert post(client, location + "/delete").status_code == 302
    assert client.get(location).status_code == 404
    assert post(client, "/logout").status_code == 302
    assert client.get("/notes").status_code == 302


def test_bad_credentials_and_quoted_username_are_handled(fixed):
    client = fixed.test_client()
    for name in ("alice", "doesnotexist", "o'brien"):
        assert post(client, "/login", {"username": name, "password": "wrong"}).status_code == 401


@pytest.mark.parametrize("values", [
    {"username": "ab", "password": DEMO_PASSWORD},
    {"username": "a" * 31, "password": DEMO_PASSWORD},
    {"username": "bad'name", "password": DEMO_PASSWORD},
    {"username": "carol", "password": "short"},
    {"username": "carol", "password": "a" * 129},
])
def test_registration_validation(fixed, values):
    assert post(fixed.test_client(), "/register", values, "/register").status_code == 400


def test_duplicate_registration_preserves_existing_account(fixed):
    client = fixed.test_client()
    assert post(client, "/register", {"username": "alice", "password": "DifferentPass!123"}, "/register").status_code == 409
    login(client)


@pytest.mark.parametrize("values", [
    {"title": "", "body": "text"}, {"title": "note", "body": "  "},
    {"title": "x" * 121, "body": "text"}, {"title": "note", "body": "x" * 10001},
])
def test_note_validation(fixed, values):
    client = fixed.test_client()
    login(client)
    assert post(client, "/notes/new", values).status_code == 400


@pytest.mark.parametrize("path", ["/notes", "/notes/1", "/notes/1/edit", "/notes/new"])
def test_anonymous_access_requires_login(fixed, path):
    assert fixed.test_client().get(path).status_code == 302


@pytest.mark.parametrize("path", ["/notes/999", "/notes/0", "/notes/-1", "/notes/not-an-id", "/notes/999/edit"])
def test_invalid_or_absent_identifiers(fixed, path):
    client = fixed.test_client()
    login(client)
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("path", ["/login", "/register"])
def test_csrf_also_protects_authentication_forms(fixed, path):
    assert fixed.test_client().post(path, data={"username": "alice", "password": DEMO_PASSWORD}).status_code == 400


def test_invalid_and_other_session_csrf_tokens(fixed):
    first, second = fixed.test_client(), fixed.test_client()
    first_token = token(first)
    for invalid in ("invalid", first_token):
        assert second.post("/login", data={"username": "alice", "password": DEMO_PASSWORD, "csrf_token": invalid}).status_code == 400


def test_successful_login_clears_pre_authentication_session(fixed):
    client = fixed.test_client()
    with client.session_transaction() as state:
        state["untrusted_marker"] = "must disappear"
    login(client)
    with client.session_transaction() as state:
        assert "untrusted_marker" not in state
        assert state["user_id"] == 1 and state["_permanent"] is True
    assert client.get("/logout").status_code == 405
    post(client, "/logout")
    with client.session_transaction() as state:
        assert "user_id" not in state


@pytest.mark.parametrize("value", [None, "", "too-short"])
def test_missing_or_short_secret_fails_startup(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    else:
        monkeypatch.setenv("APP_SECRET_KEY", value)
    with pytest.raises(RuntimeError, match="APP_SECRET_KEY"):
        create_app()


def test_secret_can_be_supplied_through_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_SECRET_KEY", "environment-fixture-" + "z" * 32)
    app = create_app({"DATABASE": str(tmp_path / "fresh.sqlite3")})
    assert app.debug is False
    assert app.config["SESSION_COOKIE_NAME"] == "secure_session"


def test_security_headers_on_success_and_errors(fixed):
    client = fixed.test_client()
    for response in (client.get("/login"), client.get("/not-found"), client.post("/login")):
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "script-src 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["Cache-Control"] == "no-store"


def test_large_request_rejected(fixed):
    assert fixed.test_client().post("/login", data={"padding": "x" * 70000}).status_code == 413


def test_database_setup_is_repeatable_and_hashes_seed_passwords(fixed):
    from werkzeug.security import generate_password_hash
    with fixed.app_context():
        init_db()
        seed_demo(generate_password_hash)
        users = get_db().execute("SELECT * FROM users").fetchall()
        assert len(users) == 2
        assert all(check_password_hash(user["password"], DEMO_PASSWORD) for user in users)
        assert get_db().execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 2
    assert fixed.test_cli_runner().invoke(args=["init-db", "--seed"]).exit_code == 0
