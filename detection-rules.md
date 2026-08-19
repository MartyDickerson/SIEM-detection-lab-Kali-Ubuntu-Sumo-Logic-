# Detection Rules

Detailed logic, thresholds, and reasoning for each Sumo Logic Monitor in the lab. Replace/merge this with your existing detection-suite write-up (Markdown/PDF) if you want the fuller version in the repo.

## 1. SSH Brute Force Monitor

- **Trigger:** Failed password count from the same source IP exceeds a defined threshold within a 5-minute window.
- **Log source:** `linux/auth` (`/var/log/auth.log`)
- **MITRE ATT&CK:** T1110 — Brute Force
- **Detection method:** Logs type monitor, Static threshold (built under *Data Management → Monitoring → Monitors*, not Scheduled Search — Scheduled Search only supports "alert if any results exist," not threshold-based logic)
- **Validated via:** Hydra brute-force run from Kali against the Ubuntu target

## 2. Unknown Username Login Attempt

- **Trigger:** Any single `Invalid user` event
- **Log source:** `linux/auth`
- **Purpose:** Surfaces reconnaissance/credential-guessing attempts using usernames that don't exist on the target
- **Note:** `"Failed password for invalid user X"` and `"Failed password for X"` are distinct syslog phrasings — separate parse patterns (or a regex with an optional group) are needed to catch both.

## 3. Successful SSH Login

- **Trigger:** Any `Accepted password` event
- **Log source:** `linux/auth`
- **Purpose:** Not malicious on its own, but critical for correlation — cross-referencing this against brute-force alerts by `src_ip` confirms whether an attack succeeded.

## 4. Sudo / Privilege Escalation Watch (in progress)

- **Trigger (planned):** Sudo command execution patterns from `linux/syslog`
- **MITRE ATT&CK:** T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **Confirmed log line format:**
  ```
  sudo: cyberintelhq : TTY=pts/1 ; PWD=/home/cyberintelhq ; USER=root ; COMMAND=/usr/bin/whoami
  ```
- **Status:** Rule logic not yet built.

## Manual correlation technique

Brute-force and successful-login alert emails are cross-referenced by matching `src_ip`. If a `src_ip` appears in both a brute-force alert and a successful-login alert, that indicates a likely successful compromise rather than a failed attack attempt.

## Known blind spots

- **Low-and-slow attacks:** Failed attempts spaced out enough to stay under the 5-minute-window threshold are not caught by the brute-force rule. Confirmed via testing.

## Build gotchas (Sumo Logic query syntax)

- `parse` silently drops non-matching lines by default — append `nodrop` to preserve them.
- Wildcard `*` in parse patterns is greedy and must be bounded by a stopping term to avoid over-capture.
- `_sourceCategory` is the primary search handle for scoping queries to a log source.
- **Monitor UI quirk:** The Name field doesn't appear on initial monitor creation — it only surfaces as "Monitor Details" (Step 5) after triggering the name-empty validation error and clicking Retry.
- **Recovery setting:** Default recovery settings can leave a monitor in Critical state for extended periods. Setting recovery to 0 minutes triggers immediate recovery on the first clean evaluation cycle.

## Environment notes

- Cloud SIEM module (Rules, Insights, Signals) is not available on the trial account — the sidebar link leads to a marketing upsell rather than the actual app. Threshold-based detections are built under *Data Management → Monitoring → Monitors* instead.
- In multi-VM labs, always verify host identity with `hostnamectl` before running commands to avoid VM identity confusion.
