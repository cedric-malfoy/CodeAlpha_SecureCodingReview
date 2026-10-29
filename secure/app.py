"""Corrected notes application. See the report for evidence and limitations."""
from datetime import timedelta
import os
import sqlite3

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from labcore import ROOT, account_values, get_db, init_support, login_required, note_values


def create_app(test_config=None):
    app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
    app.config.update(
        SECRET_KEY=os.environ.get("APP_SECRET_KEY"),
        DEBUG=False,
        DATABASE=str(ROOT / "instance" / "secure" / "notes.sqlite3"),
        SESSION_COOKIE_NAME="secure_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Local HTTP requires False. A real HTTPS deployment must set True.
        SESSION_COOKIE_SECURE=False,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=64 * 1024,
        WTF_CSRF_TIME_LIMIT=3600,
    )
    if test_config:
        app.config.update(test_config)
    if not isinstance(app.config["SECRET_KEY"], str) or len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("APP_SECRET_KEY must be set to a random value of at least 32 characters.")

    CSRFProtect(app)
    init_support(app, generate_password_hash, "secure")

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'none'; style-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def home():
        return redirect(url_for("notes" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username, password = account_values(request.form)
            try:
                get_db().execute("INSERT INTO users (username, password) VALUES (?, ?)",
                                 (username, generate_password_hash(password)))
                get_db().commit()
            except sqlite3.IntegrityError:
                abort(409, "That username is already registered.")
            return redirect(url_for("login"))
        return render_template("auth.html", registering=True)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            password = request.form.get("password", "")
            user = get_db().execute("SELECT id, password FROM users WHERE username = ?", (username,)).fetchone()
            if not user or not check_password_hash(user["password"], password):
                return render_template("auth.html", registering=False, error="Username or password was incorrect."), 401
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(url_for("notes"))
        return render_template("auth.html", registering=False)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/notes")
    @login_required
    def notes():
        rows = get_db().execute("SELECT id, title FROM notes WHERE owner_id = ? ORDER BY id DESC", (g.user["id"],)).fetchall()
        return render_template("notes.html", notes=rows)

    @app.route("/notes/new", methods=["GET", "POST"])
    @login_required
    def new_note():
        if request.method == "POST":
            title, body = note_values(request.form)
            cursor = get_db().execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)", (g.user["id"], title, body))
            get_db().commit()
            return redirect(url_for("view_note", note_id=cursor.lastrowid))
        return render_template("edit.html", note=None)

    def find_note(note_id):
        note = get_db().execute("SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, g.user["id"])).fetchone()
        if note is None:
            # Nonexistent and non-owned notes deliberately have the same response.
            abort(404)
        return note

    @app.get("/notes/<int:note_id>")
    @login_required
    def view_note(note_id):
        note = find_note(note_id)
        return render_template("note.html", note=note, note_content=note["body"])

    @app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_note(note_id):
        note = find_note(note_id)
        if request.method == "POST":
            title, body = note_values(request.form)
            get_db().execute("UPDATE notes SET title = ?, body = ? WHERE id = ? AND owner_id = ?",
                             (title, body, note_id, g.user["id"]))
            get_db().commit()
            return redirect(url_for("view_note", note_id=note_id))
        return render_template("edit.html", note=note)

    @app.post("/notes/<int:note_id>/delete")
    @login_required
    def delete_note(note_id):
        find_note(note_id)
        get_db().execute("DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, g.user["id"]))
        get_db().commit()
        return redirect(url_for("notes"))

    return app
