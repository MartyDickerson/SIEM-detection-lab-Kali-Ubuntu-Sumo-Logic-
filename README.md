# 🔐 SOC101 Home Lab — SIEM Detection Engineering (Sumo Logic)

This repository documents a home lab for building an end-to-end **SIEM detection pipeline** using:

- **Kali Linux** — attacker/red team VM (Hydra, rockyou.txt)
- **Ubuntu 24.04** — target/blue team VM (Sumo Logic Collector installed)
- **Sumo Logic** — SIEM platform (log ingestion, threshold-based Monitors, alerting)

Logs from `/var/log/auth.log` and `/var/log/syslog` are shipped via the Sumo Logic Collector → ingested as `linux/auth` and `linux/syslog` → detection logic runs as Sumo Logic Monitors → alerts validated by cross-referencing source IPs.

---

## 🚀 Lab Architecture

```
[ Kali Linux VM — 192.168.1.5 ]
 └─ Hydra (SSH brute force) ──────────► attack traffic

[ Ubuntu 24.04 VM — SOC101-ubuntu, 192.168.1.4 ]
 ├─ /var/log/auth.log ──► Sumo Logic Collector ──► linux/auth
 └─ /var/log/syslog   ──► Sumo Logic Collector ──► linux/syslog

[ Sumo Logic (trial, core logging tier) ]
 ├─ Monitors (Logs type, Static threshold)
 │   ├─ SSH Brute Force Monitor
 │   ├─ Unknown Username Login Attempt
 │   ├─ Successful SSH Login
 │   └─ Sudo / Privilege Escalation Watch (in progress)
 └─ Alert emails ──► manual correlation by src_ip
```

---

## 📊 Detection Status

| # | Monitor | Trigger | MITRE ATT&CK | Status |
|---|---|---|---|---|
| 1 | SSH Brute Force | Failed password count from same src IP exceeds threshold within 5-min window | T1110 | ✅ Live & validated |
| 2 | Unknown Username Login Attempt | Any `Invalid user` event | T1110.001 | ✅ Live & validated |
| 3 | Successful SSH Login | Any `Accepted password` event | — | ✅ Live & validated |
| 4 | Sudo / Privilege Escalation Watch | `sudo` command execution pattern | T1548.003 | 🚧 In progress |

---

## 📖 Documentation

👉 Full detection rule write-up (thresholds, MITRE mapping, build gotchas):
[docs/detection-rules.md](docs/detection-rules.md)

👉 Sumo Logic parse query reference:
[queries/sumo-logic-parse-queries.md](queries/sumo-logic-parse-queries.md)

---

## 🖼 Screenshots

Save your screenshots into the [`screenshots/`](screenshots/) folder. Suggested naming:

- `00_vbox_vms.png` — Kali + Ubuntu VM setup in VirtualBox
- `01_hydra_attack.png` — Hydra brute-force run against target
- `02_collector_setup.png` — Sumo Logic Collector install on Ubuntu
- `03_source_config.png` — Log source config (`linux/auth`, `linux/syslog`)
- `04_monitor_ssh_bruteforce.png` — SSH Brute Force Monitor config
- `05_alert_email.png` — Triggered alert email
- `06_correlation.png` — Manual src_ip correlation across alerts

---

## ⚠️ Known Limitations

- **Low-and-slow attacks:** failed attempts spaced below the 5-minute threshold window evade the brute-force rule (confirmed via testing).
- **Cloud SIEM tier** (Rules, Insights, Signals mapped to MITRE ATT&CK) is not provisioned on the trial account — this lab uses core Monitors instead. See `docs/detection-rules.md` for details.

---

## 🎯 Roadmap

- [ ] Finish Sudo/Privilege Escalation Watch monitor
- [ ] Explore Cloud SIEM tier access
- [ ] Continue toward Sumo Logic certification

---

## ⚠️ Disclaimer

This lab is for **educational and research purposes only**. Not intended for production use.
