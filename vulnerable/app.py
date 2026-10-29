"""Six deliberate weaknesses for an educational code review. Do not deploy."""
import sqlite3

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from markupsafe import Markup

from labcore import ROOT, account_values, get_db, init_support, login_required, note_values


def create_app(test_config=None):
    app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
    app.config.update(
        SECRET_KEY="public-training-key-do-not-use",  # SCR-06: deliberately predictable.
        DEBUG=True,  # SCR-06: deliberately unsafe debug configuration.
        DATABASE=str(ROOT / "instance" / "vulnerable" / "notes.sqlite3"),
        SESSION_COOKIE_NAME="vulnerable_session",
        SESSION_COOKIE_HTTPONLY=False,
        SESSION_COOKIE_SAMESITE=None,
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    init_support(app, lambda value: value, "vulnerable")

    @app.get("/")
    def home():
        return redirect(url_for("notes" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username, password = account_values(request.form)
            try:
                # SCR-04: deliberately stores the password without hashing.
                get_db().execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                get_db().commit()
            except sqlite3.IntegrityError:
                abort(409, "That username is already registered.")
            return redirect(url_for("login"))
        return render_template("auth.html", registering=True)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username, password = request.form.get("username", ""), request.form.get("password", "")
            # SCR-01: deliberately interpolates untrusted input into SQL.
            user = get_db().execute(f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'").fetchone()
            if not user:
                return render_template("auth.html", registering=False, error="Username or password was incorrect."), 401
            session["user_id"] = user["id"]
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
        # SCR-03: authentication without an ownership check is insufficient.
        note = get_db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
        if note is None:
            abort(404)
        return note

    @app.get("/notes/<int:note_id>")
    @login_required
    def view_note(note_id):
        note = find_note(note_id)
        # SCR-02: deliberately trusts stored user text as HTML.
        return render_template("note.html", note=note, note_content=Markup(note["body"]))

    @app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_note(note_id):
        note = find_note(note_id)
        if request.method == "POST":
            title, body = note_values(request.form)
            get_db().execute("UPDATE notes SET title = ?, body = ? WHERE id = ?", (title, body, note_id))
            get_db().commit()
            return redirect(url_for("view_note", note_id=note_id))
        return render_template("edit.html", note=note)

    @app.post("/notes/<int:note_id>/delete")
    @login_required
    def delete_note(note_id):
        find_note(note_id)
        get_db().execute("DELETE FROM notes WHERE id = ?", (note_id,))
        get_db().commit()
        return redirect(url_for("notes"))

    # SCR-05: deliberately omits global CSRF protection on every POST route.
    return app
