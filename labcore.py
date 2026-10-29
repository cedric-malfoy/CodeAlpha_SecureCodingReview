"""Shared presentation and database plumbing, without authentication policy."""
from functools import wraps
from pathlib import Path
import re
import sqlite3

import click
from flask import abort, current_app, g, redirect, session, url_for

ROOT = Path(__file__).resolve().parent
DEMO_PASSWORD = "LabPassword!2026"  # Public fixture, never a real credential.


def get_db():
    if "db" not in g:
        path = Path(current_app.config["DATABASE"])
        path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def init_db():
    get_db().executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
    """)
    get_db().commit()


def seed_demo(password_encoder):
    db = get_db()
    for name in ("alice", "bob"):
        if db.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone():
            continue
        cursor = db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                            (name, password_encoder(DEMO_PASSWORD)))
        db.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
                   (cursor.lastrowid, f"{name.title()}'s draft", f"{name.title()}'s private draft."))
    db.commit()


def init_support(app, password_encoder, mode):
    @app.teardown_appcontext
    def close_db(_error):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.before_request
    def load_user():
        user_id = session.get("user_id")
        g.user = get_db().execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone() if type(user_id) is int else None

    @app.context_processor
    def presentation():
        return {"lab_mode": mode, "current_user": g.get("user")}

    @app.cli.command("init-db")
    @click.option("--seed", is_flag=True, help="Add two fictional lab users and notes; preserves existing data.")
    def init_db_command(seed):
        init_db()
        if seed:
            seed_demo(password_encoder)
        click.echo(f"Initialized {mode} database. Existing data preserved.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def account_values(form):
    username = form.get("username", "").strip().lower()
    password = form.get("password", "")
    if not re.fullmatch(r"[a-z0-9_]{3,30}", username):
        abort(400, "Use 3–30 letters, numbers, or underscores for your username.")
    if not 12 <= len(password) <= 128:
        abort(400, "Use a password of 12–128 characters.")
    return username, password


def note_values(form):
    title, body = form.get("title", "").strip(), form.get("body", "").strip()
    if not 1 <= len(title) <= 120 or not 1 <= len(body) <= 10000:
        abort(400, "A note needs a title (1–120 characters) and text (1–10,000 characters).")
    return title, body
