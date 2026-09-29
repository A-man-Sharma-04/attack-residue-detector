# Verification evidence — 2026-09-29

Instructor follow-up task: demonstrate the four steps on the `bot-farm`
target. Every claim below is backed by a file in this directory, captured on
the target itself.

Target: `bot-farm` (Ubuntu 26.04 LTS), reachable only over SSH. The demo app is
served on `127.0.0.1:8081` and is **not** exposed to the internet.

| # | Task | Artifact |
|---|------|----------|
| 1 | Clean baseline before any attack | `baseline-local-20260929T083817Z.json` |
| 2 | Self-contained compromise simulation | `STEP2-compromise-output.txt` |
| 3 | Proof the attacker is gone | `STEP3-attacker-gone.txt` |
| 4 | Residue detection | `STEP4-residue-scan.txt`, `residue-scan-20260929T084605Z.txt` |
| 4 | Incident + Auditd correlation | `STEP4-forensic-report.txt`, `incident-INC-0001-*.{txt,json}` |
| 4 | Raw Auditd lines cited by the report | `incident-INC-0001-*-auditd-evidence.txt` |

## Timeline

```
08:38:17  baseline recorded (manifest verified)
08:38:22  detector correctly reported ZERO residue on clean state
08:45:57  single compromise run planted all three artefacts
08:51:12  "attacker is gone" checks captured
08:46:05  residue scan -> 3 residues
```

## The three required residues, all detected

| Type | Path | Corroborating Auditd evidence |
|------|------|------------------------------|
| `new_service` | `/etc/systemd/system/update-service.service` | `key="service_changes"`, `nametype=CREATE`, `comm=python3` |
| `new_executable` | `/opt/.cache/update` | `key="opt_changes"`, `nametype=CREATE`, then `chmod` |
| `file_modified` | `/var/www/college/index.php` | `key="web_changes"`, sha256 `8330ff8c…` → `bc3127c1…` |

## Reconstructed attack path

```
Web Request -> Process Execution -> File Modification -> Persistence
```

Web-request evidence comes from the vhost access log
(`audit_key=web_request`), process execution from real `execve` records
(`key="process_execution"`), and the two write stages from the filesystem
watch keys. The path is built from the single 0.6s burst at 08:45:57 that
actually created the current residue.

Incident state: **CORROBORATED** (3 residue artifacts, each backed by >=2
related Auditd events inside a 10-minute window, within a 24h lookback).

## Two things stated honestly rather than optimistically

1. **The injected PHP is still executable.** `curl ".../index.php?cmd=id"`
   returns `SIMULATED: id`, because PHP-FPM executes the modified file. No
   process is exercising it — all requests for that URL came from `127.0.0.1`
   with `curl/8.18.0`, i.e. my own verification. So there is no live attack,
   but the *capability* survives on disk. That is the argument for residue
   detection, and the report does not pretend otherwise.
2. **The 24h lookback contains earlier bursts.** Repeated test runs wrote the
   same paths, so the incident lists 36 corroborating events while marking the
   0.6s attack window. The report states how many events fall outside that
   window rather than quietly trimming them.

## Reproducing

```bash
./deploy/deploy.sh botfarm
ssh botfarm 'cd /opt/residue-system && sudo python3 -m residue_system.cli baseline create'
ssh botfarm 'cd /opt/residue-system && sudo python3 attack/compromise_sim.py --reset'
ssh botfarm 'cd /opt/residue-system && sudo python3 attack/compromise_sim.py --i-understand-this-plants-artifacts'
ssh botfarm 'cd /opt/residue-system && sudo python3 -m residue_system.cli residue scan'
ssh botfarm 'cd /opt/residue-system && sudo python3 -m residue_system.cli forensic correlate'
```

The simulation is inert by construction: the dropped unit is never enabled or
started, and the payload is a self-labelling placeholder containing no exploit.

## Sanitisation

Scanned before commit: no private keys, passwords, API keys or tokens. The
Auditd excerpt contains host paths, PIDs and the `ubuntu` account name only.
The target's real SSH private key was never copied here.
