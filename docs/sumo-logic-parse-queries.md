# Sumo Logic Parse Queries

Reference syntax used for each monitor's search. Fill in your exact working queries here — placeholders below reflect the general pattern based on the log formats and gotchas documented in `docs/detection-rules.md`.

## SSH Brute Force

```
_sourceCategory=linux/auth "Failed password"
| parse "Failed password for * from *" as user, src_ip nodrop
| count by src_ip
```

## Unknown Username Login Attempt

```
_sourceCategory=linux/auth "Invalid user"
| parse "Invalid user * from *" as user, src_ip nodrop
```

## Successful SSH Login

```
_sourceCategory=linux/auth "Accepted password"
| parse "Accepted password for * from *" as user, src_ip nodrop
```

## Sudo / Privilege Escalation Watch (planned)

```
_sourceCategory=linux/syslog "sudo:"
| parse "sudo: * : TTY=* ; PWD=* ; USER=* ; COMMAND=*" as sudo_user, tty, pwd, target_user, command nodrop
```

### Notes

- `nodrop` keeps non-matching lines instead of silently discarding them — useful while validating a new parse pattern.
- Bound wildcards with a stopping delimiter (e.g. `from *` not just `*`) to avoid greedy over-capture.
- Two distinct phrasings exist for failed logins — `"Failed password for invalid user X"` vs `"Failed password for X"` — handle both if you want a single unified parse rule.
