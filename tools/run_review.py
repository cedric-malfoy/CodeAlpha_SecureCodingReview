"""Regenerate the review's machine evidence; returns nonzero for failed checks."""
import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "evidence")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    # These bytes identify what was actually checked, even if the working tree is edited.
    relevant = [ROOT / name for name in ("labcore.py", "run.py", "requirements.txt", "requirements-dev.txt", "package.json", "package-lock.json", "pytest.ini")]
    for directory in ("vulnerable", "secure", "templates", "static", "tests", "tools"):
        relevant.extend(path for path in (ROOT / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts)
    source_hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(relevant)}
    commands = [
        ("pytest", [sys.executable, "-m", "pytest", "-v", "--tb=short", f"--junitxml={out / 'pytest.xml'}"], (0,)),
        ("baseline-bandit", [sys.executable, "-m", "bandit", "--ignore-nosec", "-r", "vulnerable", "labcore.py", "-f", "json", "-o", str(out / "baseline-bandit.json")], (1,)),
        ("secure-bandit-raw", [sys.executable, "-m", "bandit", "--ignore-nosec", "-r", "secure", "labcore.py", "run.py", "-f", "json", "-o", str(out / "secure-bandit-raw.json")], (1,)),
        ("secure-bandit", [sys.executable, "-m", "bandit", "-r", "secure", "labcore.py", "run.py", "-f", "json", "-o", str(out / "secure-bandit.json")], (0,)),
        ("runtime-dependencies", [sys.executable, "-m", "pip_audit", "-r", "requirements.txt", "--no-deps", "--disable-pip", "--strict", "--progress-spinner", "off", "-f", "json", "-o", str(out / "runtime-dependencies.json")], (0,)),
        ("development-dependencies", [sys.executable, "-m", "pip_audit", "-r", "requirements-dev.txt", "--no-deps", "--disable-pip", "--strict", "--progress-spinner", "off", "-f", "json", "-o", str(out / "development-dependencies.json")], (0,)),
        ("browser", ["node", "--test", "tests/browser.test.cjs"], (0,)),
    ]
    results = []
    for name, command, expected in commands:
        print(f"Running {name}...", flush=True)
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=240)
            exit_code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            exit_code, stdout, stderr = 124, "", "Check exceeded 240 seconds; not a passing result."
        # Tool-only output, synthetic fixtures, no environment or cookie dumps.
        transcript = (stdout + "\n" + stderr).replace(str(ROOT), "<project>")
        (out / f"{name}.txt").write_text(transcript)
        passed = exit_code in expected
        results.append({"check": name, "command": ["python" if part == sys.executable else part.replace(str(ROOT), "<project>") for part in command], "exit_code": exit_code, "expected_exit_codes": list(expected), "passed": passed})
        print(f"{name}: exit {exit_code}, {'expected' if passed else 'FAILED'}", flush=True)
    browser_evidence = ROOT / "artifacts" / "browser-observations.json"
    if browser_evidence.exists() and next(item for item in results if item["check"] == "browser")["passed"]:
        (out / "browser-observations.json").write_bytes(browser_evidence.read_bytes())
    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": commit,
        "python": platform.python_version(),
        "tools": {name: version(name) for name in ("Flask", "Flask-WTF", "Werkzeug", "pytest", "bandit", "pip-audit", "reportlab")},
        "source_sha256": source_hashes,
        "checks": results,
        "note": "Baseline warnings are expected. Raw secure scan retains the public fixture warning; the narrowly triaged secure scan must pass. Exit success is not a claim of exhaustive security.",
    }
    (out / "verification.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return 0 if all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
