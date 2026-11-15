# Lab guide: Okta identity audit with Python

**Time:** 35 to 40 min. **Cost:** free.
**Skills:** Python against an identity API, read only automation, machine identity hygiene, audit evidence.

Uses the Okta org from Lab 1. 📸 = screenshot.

## Before you start

**Accounts**
- [ ] **Okta org from Lab 1** (Integrator Free Plan). You'll create a read only admin and an API token in it.

**Software on your Mac** (run each check in Terminal; install only what's missing)
| Tool | Check | Install if missing |
| --- | --- | --- |
| Python 3.9 or newer | `python3 --version` | `brew install python` |
| pip | `python3 -m pip --version` | comes with Homebrew Python |
| Git and VS Code | from Lab 1 | |
| VS Code extension (optional) | | Python (by Microsoft) |

The script's packages (`requests`, `pytest`) install in Step 1.

## Steps

**1. Run it on sample data.** In VS Code's terminal:
```bash
cd ~/Documents/GitHub && git clone https://github.com/jasonroland-tech/okta-identity-audit.git && cd okta-identity-audit
python3 -m pip install -r requirements.txt
python3 -m pytest -q
python3 okta_audit.py --mock
```
Open `reports/okta_audit_<date>.md` (right click > Open Preview). 📸 the summary table.
*Why:* proves the logic works before it touches a real org.

**2. Know the code (5 min).** Read `classify()`. Each finding is one `if`. For your Loom: inactive accounts get taken over, staged accounts were never claimed, and service accounts without an owner never get cleaned up.

**3. Give the org something to find.** Okta admin > Directory > People > Add person `svc-reporting@lakeviewhealth.example`, uncheck the activation email, Save (stays **Staged**).

**4. Least privilege token.** Add person `svc-audit@lakeviewhealth.example` with a password. Security > Administrators > Add administrator > `svc-audit` > **Read-only Administrator**. 📸 Sign in as `svc-audit` (private window) > Security > API > Tokens > Create token. Copy it.
*Why:* a token has the rights of whoever made it. Read only means a leaked token can't change anything.

**5. Run it live.**
```bash
export OKTA_ORG_URL="https://integrator-1234567.okta.com"
export OKTA_API_TOKEN="paste-token"
python3 okta_audit.py --check-admins --pending-days 0
```
`--pending-days 0` flags today's staged account so a new org has results. 📸 the output and report.

**6. Fix one finding and rerun.** Set `svc-audit`'s **Manager** attribute to yourself (its profile > Edit), run step 5 again: `SERVICE_NO_OWNER` disappears for it. 📸 before and after.

**7. Revoke the token** (Security > API > Tokens > Revoke) and push:
```bash
git add . && git commit -m "Live audit run" && git push
```
Live reports are git ignored because they contain real logins.
