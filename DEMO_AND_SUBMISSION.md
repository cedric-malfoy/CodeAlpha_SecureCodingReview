# Three-minute video and submission guide

## Prepare

Follow the README to install dependencies, generate a local signing key, initialize both databases, and start the corrected and vulnerable applications in separate terminals. Use only the published fictional users. Keep the terminal containing environment variables and any GitHub authentication out of the recording.

Have the Markdown or PDF report open, along with the two application tabs and the source repository. Re-run tests before recording if you have changed the code. The automated browser checks use fresh databases, so they do not alter your demonstration notes.

## Video outline

| Time | Show | Explain |
| --- | --- | --- |
| 0:00–0:25 | README and application | “This is CodeAlpha Task 3, a secure coding review of a local Python/Flask notes app. The baseline flaws are intentional.” |
| 0:25–0:55 | Report summary and baseline login | Enter username `alice' --` with an arbitrary password. Explain how raw SQL allows sign-in without the correct password. |
| 0:55–1:20 | Baseline source and corrected login | Compare SQL interpolation with parameterized lookup and hash verification. The same injection is rejected in the corrected version. |
| 1:20–1:50 | Alice viewing Bob's note | On a fresh seeded baseline, visit `/notes/2` as Alice. Repeat on the corrected app to show 404. Explain ownership checks for read, edit, and delete. |
| 1:50–2:20 | Stored-XSS evidence and remaining findings | Show the browser observations and report. The harmless script marker runs in Bob's baseline note after Alice edits it; corrected code blocks the edit and escapes note text. Mention password hashing, CSRF, and session configuration. |
| 2:20–2:45 | Test and scan evidence | Show pytest, browser results, and Bandit triage. Explain why the published seed password warning is a reviewed fixture and why static analysis missed some logic flaws. |
| 2:45–3:00 | GitHub repository and limitations | Point to the PDF, reproducible commands, and project ZIP. State that this is a local training lab, with production controls listed separately. |

Do not demonstrate debugger execution, send requests to other systems, or use actual personal notes. The XSS proof only sets `window.__xssProbe`; it does not send data anywhere. Stop local servers with Ctrl+C after recording.

The ID assumptions in the video require a fresh seed database: Alice owns note 1 and Bob owns note 2. If you already created accounts or notes, inspect the local data or use the isolated automated tests instead of assuming IDs. The initialization command preserves existing data.

## Suggested video caption

“Completed CodeAlpha Cyber Security Task 3: Secure Coding Review. I reviewed a Python/Flask teaching app, documented six intentional security weaknesses, implemented fixes, and verified them using manual inspection, Bandit, dependency auditing, and automated tests. The repository contains the report, vulnerable baseline, corrected code, and reproduction instructions.”

Add your repository link: https://github.com/cedric-malfoy/CodeAlpha_SecureCodingReview

Tag CodeAlpha as requested in your internship brief. Describe the baseline as intentionally vulnerable; do not imply that these were discoveries in a production service.

## Submission checklist

- Confirm the public GitHub repository opens while signed out.
- Read the report and run the corrected application yourself before explaining it.
- Record and publish your explanation video on your LinkedIn account, including the GitHub link and CodeAlpha tag.
- Keep the report PDF and ZIP ready if the form requests attachments.
- Submit the GitHub and video links through the official form shared in your internship WhatsApp group.
- Check the form's actual requirements and deadline; no submission URL was supplied in the brief.

This project prepares the materials. LinkedIn posting and the internship submission are manual and are not performed by these scripts.
