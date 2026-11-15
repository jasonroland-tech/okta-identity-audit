# Lab guide: Okta identity audit with Python

**Time:** about 60 minutes. **Cost:** free.
**Why this lab:** 14 of 18 job posts want Python or PowerShell against identity APIs, and most want audit evidence. This script does both with a read only token.

Uses the Okta org from Lab 1. 📸 = screenshot.

**1. Try it with sample data first.** In VS Code's terminal:
```bash
cd ~/Documents/GitHub && git clone https://github.com/jasonroland-tech/okta-identity-audit.git && cd okta-identity-audit
python3 -m pip install -r requirements.txt
python3 -m pytest -q
python3 okta_audit.py --mock
```
Open `reports/okta_audit_<date>.md` (right click > Open Preview). 📸 the summary table.
*Why:* you can show the logic works before touching a real org.

**2. Read the code for 10 minutes.** Look at `classify()`. Each finding is one `if`. Be ready to explain in your Loom why each one matters: inactive accounts get taken over, staged accounts were never claimed, service accounts without an owner never get cleaned up.

**3. Give the org something to find.** In your Okta org (admin console):
- Directory > People > Add person: `svc-reporting@lakeviewhealth.example`, uncheck "Send user activation email", Save (stays **Staged**).
- Add one more person and leave them never signed in.

**4. Create a least privilege API token.**
- Add person `svc-audit@lakeviewhealth.example`, set a password, activate.
- Security > Administrators > Add administrator > `svc-audit` > role **Read-only Administrator**.
- Sign in as `svc-audit` in a private window > Security > API > Tokens > Create token `okta-audit`. Copy it.

*Why:* tokens act with the rights of whoever created them. A read only admin means the script can't change anything even if the token leaks. 📸 the role assignment.

**5. Run it live.**
```bash
export OKTA_ORG_URL="https://integrator-1234567.okta.com"
export OKTA_API_TOKEN="paste-token"
python3 okta_audit.py --check-admins --pending-days 0
```
`--pending-days 0` flags today's staged account so you see results in a new org. 📸 the terminal output and the report.

**6. Fix the findings.** Activate or delete the staged user, give `svc-audit` an owner (set its Manager attribute to yourself), then rerun. Fewer findings = remediation evidence. 📸 before and after.

**7. Revoke the token** when you're done: Security > API > Tokens > Revoke. Unused tokens are a finding too.

**8. Push.** Reports are ignored by Git because they contain real logins. Commit a redacted copy as `reports/example-redacted.md` if you want one in the repo.
```bash
git add . && git commit -m "Live audit run and remediation" && git push
```
GitHub Actions runs the tests on every push. 📸 the green check.
