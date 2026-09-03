# SOC101 Home Lab — Detection & Response Playbook

**Environment:** Kali (attacker, 192.168.1.5) → Ubuntu 24.04 "SOC101-ubuntu" (target, 192.168.1.4)
**SIEM:** Sumo Logic (free trial), ingesting `auth.log` (`linux/auth`) and `syslog` (`linux/syslog`)
**Author:** Marty Dickerson | github.com/MartyDickerson

This playbook documents each detection built in the lab so far as a standalone incident response entry: what triggers it, what it means, and what an analyst should do about it. It's written the way a real SOC runbook would be written, so it can double as portfolio evidence of detection engineering + IR thinking, not just query-writing.

---

## How to use this playbook

Each entry follows the same shape:
- **Trigger** — what the Sumo Logic monitor fires on
- **MITRE ATT&CK mapping**
- **Severity**
- **Why it matters** — the attacker behavior behind the signal
- **Investigation steps** — what to check before deciding it's real
- **Response steps** — what to do if it's confirmed
- **False positive notes**

---

## Playbook 1 — SSH Brute Force

**Trigger:** Monitor #1. Repeated "Failed password" entries in `auth.log` from the same source IP within a short window.
**MITRE:** T1110.001 (Brute Force: Password Guessing)
**Severity:** Medium → High if it succeeds

**Why it matters:** An attacker (e.g., using Hydra + rockyou.txt) is systematically guessing SSH credentials. Volume is the signal — a handful of failures is normal; a burst is not.

**Investigation steps:**
1. Identify the source IP and confirm it isn't an internal misconfigured service or scheduled job.
2. Check the target username(s) being tried — one account repeatedly, or many accounts (spray)?
3. Cross-reference with Playbook 3 (Successful SSH Login) for the same window — did any attempt succeed?

**Response steps:**
1. Block/deny the source IP at the firewall or `hosts.deny`.
2. If any related login succeeded, escalate immediately to Playbook 3 and treat the account as compromised.
3. Force a password reset on the targeted account(s) as a precaution even if all attempts failed.
4. Document source IP, timestamps, and attempt count for the incident record.

**False positive notes:** Legitimate users mistyping passwords rarely generate more than 2–3 failures. Automated backup/monitoring tools with stale credentials are a common false-positive source — verify against known internal IPs first.

---

## Playbook 2 — Unknown Username Attempts

**Trigger:** Monitor #2. "Failed password for invalid user" entries in `auth.log`.
**MITRE:** T1589 / T1110 (Reconnaissance feeding Brute Force)
**Severity:** Low → Medium

**Why it matters:** The attacker is guessing usernames that don't exist on the box, which usually means they don't have prior recon on this host (or are running a generic wordlist blindly). It's often the earliest signal of an opportunistic scan.

**Investigation steps:**
1. List the usernames attempted — are any close to real accounts (e.g., `admin`, `cyberintel` vs. `cyberintelhq`)?
2. Check whether the same source IP later pivots to valid usernames (escalation into Playbook 1).

**Response steps:**
1. Treat as low-severity recon; log and monitor.
2. If the source pivots to real usernames or increases in volume, escalate to Playbook 1 handling.

**False positive notes:** Very low — legitimate users don't typo entire usernames. This is one of the cleaner signals in the lab.

---

## Playbook 3 — Successful SSH Login (Password-Based)

**Trigger:** Monitor #3. "Accepted password" entries in `auth.log`, especially following a Playbook 1 burst.
**MITRE:** T1078 (Valid Accounts)
**Severity:** High if preceded by brute force; Informational otherwise

**Why it matters:** This is the "did they get in" signal. On its own it's just a normal login, but correlated with a brute-force burst it means an account was likely compromised.

**Investigation steps:**
1. Correlate timestamp against Playbook 1 alerts for the same account/IP.
2. Confirm with the actual user (in a real environment) whether the login was legitimate.
3. Check for any follow-on activity: privilege escalation (Playbook 4) or new SSH key usage (Playbook 5).

**Response steps:**
1. If correlated with brute force: disable the account, force password reset, and terminate active sessions.
2. Review shell history and `sudo` activity for the session (`last`, `.bash_history`, auth.log around that timestamp).
3. Check for persistence mechanisms planted during the session (Playbooks 5 and 6).

**False positive notes:** None if properly correlated — the risk here is *not* correlating it with brute-force activity and missing the compromise entirely.

---

## Playbook 4 — Sudo / Privilege Escalation Watch

**Trigger:** Monitor #4. Watchlist query on high-risk commands: `useradd`, `usermod`, `passwd`, `visudo`, `chmod`, references to `/etc/shadow` or `/etc/sudoers`, or `su`. Threshold: `_count > 0` (even one hit alerts).
**MITRE:** T1098 (Account Manipulation) / T1548 (Abuse Elevation Control Mechanism)
**Severity:** Critical

**Why it matters:** These commands modify who has access and what they can do. A single occurrence is inherently suspicious — this isn't a volume-based detection like brute force, because even one unauthorized privilege change can hand an attacker full control.

**Investigation steps:**
1. Identify exactly which command ran and by which user/session.
2. Check whether it correlates with an unexplained login (Playbook 3) or a session that shouldn't have admin rights.
3. Confirm the change against expected admin activity (change tickets, known maintenance windows).

**Response steps:**
1. Treat as a confirmed incident until proven otherwise — this is a Critical-severity alert by design.
2. If unauthorized: revert the privilege change immediately (remove from sudo group, reset password, restore `/etc/sudoers`).
3. Audit for additional accounts created or modified in the same session.
4. Resolve the alert manually in Sumo Logic (Alert Detail → Resolve) once remediated — recovery is set to 0 minutes so stale Critical instances don't linger.

**False positive notes:** Legitimate sysadmin work will trigger this constantly in a real environment — this monitor needs a suppression list for known admin accounts/change windows in production use. In the lab, every hit is expected to be either a test or real.

**Automation attempted:** Built a Sumo Logic Automation Playbook ("Sudo Privilege Escalation Response") triggered directly off this monitor's alert, with a Send Alert Email action for immediate analyst notification. Execution logs (Automation → Playbook Executions) confirm the trigger fires correctly on every alert and the workflow reaches the Send Alert Email node, but the action fails with `ERROR: Unexpected error during automatic action execution: Action 'send_email' is not available for your account type` — the `send_email` action under Basic Tools requires a paid Sumo Logic tier and isn't available on the free trial. The monitor's Text Playbook field still surfaces the full response checklist to any analyst viewing the alert, so response guidance is delivered even without the automated email. This is documented as a platform licensing limitation, not a workflow design error — the trigger, wiring, and logic all verified as correct via the execution log before the tier restriction was identified.

---

## Playbook 5 — SSH Public Key Authentication Watch

**Trigger:** Monitor #5. "Accepted publickey" entries in `auth.log`, distinguished from "Accepted password" entries.
**MITRE:** T1098.004 (Account Manipulation: SSH Authorized Keys)
**Severity:** High

**Why it matters:** This is the detection half of the SSH key backdoor scenario. Planting a key produces **no log entry at all** — the only visibility is when the planted key is actually *used* to log in. If public-key auth shows up on an account that has never used it before, that's a strong backdoor signal.

**Investigation steps:**
1. Confirm whether this account normally authenticates via password or key. A first-time key login on a password-only account is the red flag.
2. Check `~/.ssh/authorized_keys` on the target for unexpected entries (key comments, fingerprints, timestamps on the file itself).
3. Look for a preceding privilege-escalation event (Playbook 4) that could have been used to plant the key.

**Response steps:**
1. Remove the unauthorized key from `authorized_keys` immediately.
2. Rotate credentials and re-issue legitimate keys for the affected account.
3. Check for persistence beyond the key itself — see Playbook 6, since a self-healing cron job can silently re-add a removed key.
4. Document the key fingerprint and first-seen timestamp for the incident record.

**False positive notes:** New employee/admin onboarding legitimately using keys for the first time. Always verify against change records before treating as hostile.

---

## Playbook 6 — Cron-Based Self-Healing Key Persistence (in progress)

**Trigger:** Not yet built as a monitor. Target signal: `CRON` execution lines in `syslog` corresponding to a job that re-appends an SSH key every ~5 minutes, or file-integrity changes to the crontab file itself.
**MITRE:** T1053.003 (Scheduled Task/Job: Cron) + T1098.004 (SSH Authorized Keys)
**Severity:** Critical (once confirmed — this defeats simple remediation)

**Why it matters:** This is a step beyond Playbook 5. A one-time planted key can be removed and the incident is over. A cron job that *re-adds* the key every few minutes means removing the key alone doesn't fix anything — the attacker regains access almost immediately. Standard `auth.log`/`syslog` content doesn't expose *what* a cron job actually does, only that it ran, which is the core detection gap.

**Investigation steps (once a Monitor #6 query exists):**
1. Correlate repeated `authorized_keys` modification timestamps with `CRON` execution log lines at matching intervals.
2. Pull the crontab for the affected user/account (`crontab -l`, and root's crontab) to identify the malicious entry.
3. Check file modification time on `authorized_keys` — repeated writes every ~5 minutes is the signature.

**Response steps:**
1. Remove the malicious cron entry first — removing the key without removing the cron job means it just comes back.
2. Then remove the planted key and rotate credentials.
3. Add file-integrity monitoring (e.g., watch `crontab` files and `authorized_keys` for changes) since log-based detection alone has a documented blind spot here.
4. Treat this as a "lessons learned" candidate for the PDF guide: log-based SIEM detection has a real limit, and this scenario demonstrates why FIM is a necessary complement, not a redundant control.

**Status:** Detection query for this pattern is still being drafted. This entry exists in the playbook as a placeholder so the gap is documented and testable next.

---

## Escalation summary table

| # | Detection | MITRE | Severity | Status |
|---|-----------|-------|----------|--------|
| 1 | SSH Brute Force | T1110.001 | Medium/High | Live |
| 2 | Unknown Username | T1589/T1110 | Low/Medium | Live |
| 3 | Successful SSH Login | T1078 | High/Info | Live |
| 4 | Sudo/Privilege Escalation | T1098/T1548 | Critical | Live |
| 5 | SSH Public Key Auth | T1098.004 | High | Live |
| 6 | Cron Self-Healing Persistence | T1053.003/T1098.004 | Critical | In progress |

---

## Portfolio note

This playbook format — trigger, ATT&CK mapping, investigation, response, false-positive notes — mirrors what a real SOC runbook looks like, and pairs well with the PDF guide's technical build-out chapters. Consider linking this file from the GitHub repo README as the "how an analyst would actually use these monitors" companion piece to the technical chapters.
