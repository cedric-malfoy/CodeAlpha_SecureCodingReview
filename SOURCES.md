# References and review method

These sources support the recommendations. The application, review text, fictional accounts, demonstrations, and tests were created for this project. No real organization or user's data was audited.

- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/): use manual review alongside tools; identify trust boundaries and security-sensitive data flows.
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html): parameterized queries.
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html): context-appropriate output encoding; CSP as additional protection.
- [OWASP Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html): authorization for each requested object.
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): adaptive password hashing and salts.
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html): CSRF tokens and SameSite limitations.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): session lifecycle and cookie attributes.
- [Flask security considerations](https://flask.palletsprojects.com/en/stable/web-security/): escaping, browser security headers, resource limits, and session cookies.
- [Flask-WTF CSRF documentation](https://flask-wtf.readthedocs.io/en/1.2.x/csrf/): global CSRF protection and form tokens; the installed version is recorded in the manifest.
- [Werkzeug password helpers](https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security): `generate_password_hash` and `check_password_hash`.
- [Bandit documentation](https://bandit.readthedocs.io/en/latest/): Python AST analysis and narrow suppression of reviewed false positives.
- [pip-audit documentation](https://pypi.org/project/pip-audit/): known dependency advisories; results depend on the advisory database and scan time.

Finding classifications use [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), [CWE-256](https://cwe.mitre.org/data/definitions/256.html), [CWE-352](https://cwe.mitre.org/data/definitions/352.html), [CWE-321](https://cwe.mitre.org/data/definitions/321.html), and the related configuration weaknesses identified in the report.

Severity is qualitative and specific to the teaching application's hypothetical exposure. No CVSS score or third-party certification is claimed. Functional tests, local browser checks, manual source inspection, Bandit, and pip-audit provide complementary evidence.
