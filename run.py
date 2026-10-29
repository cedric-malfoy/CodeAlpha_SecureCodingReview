"""Start one local teaching app; the corrected implementation is the default."""
import argparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerable", action="store_true", help="Explicitly select the intentionally insecure baseline.")
    args = parser.parse_args()
    if args.vulnerable:
        from vulnerable.app import create_app
        print("Intentional vulnerabilities enabled. Local fictional-data training only.")
        port = 5001
    else:
        from secure.app import create_app
        port = 5000
    app = create_app()
    # Localhost binding is intentional and cannot be overridden through this CLI.
    # Disable the reloader so the demonstration owns exactly one process.
    app.run(host="127.0.0.1", port=port, debug=app.config["DEBUG"], use_reloader=False)


if __name__ == "__main__":
    main()
