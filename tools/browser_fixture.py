"""Temporary, isolated loopback servers owned and stopped by the browser tests."""
from pathlib import Path
import json
import secrets
import sys
from tempfile import TemporaryDirectory
from threading import Thread

from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from labcore import init_db, seed_demo
from secure.app import create_app as secure_app
from vulnerable.app import create_app as vulnerable_app


def main():
    servers, threads = [], []
    with TemporaryDirectory(prefix="codealpha-browser-") as directory:
        urls = {}
        try:
            for mode, factory in (("vulnerable", vulnerable_app), ("secure", secure_app)):
                config = {"DATABASE": str(Path(directory) / f"{mode}.sqlite3"), "TESTING": True}
                if mode == "secure":
                    config["SECRET_KEY"] = secrets.token_hex(32)
                app = factory(config)
                with app.app_context():
                    init_db()
                    seed_demo(generate_password_hash if mode == "secure" else lambda value: value)
                server = make_server("127.0.0.1", 0, app, threaded=True)
                thread = Thread(target=server.serve_forever, daemon=True)
                servers.append(server)
                threads.append(thread)
                thread.start()
                urls[mode] = f"http://127.0.0.1:{server.server_port}"
            print(json.dumps(urls), flush=True)
            sys.stdin.read()
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=5)


if __name__ == "__main__":
    main()
