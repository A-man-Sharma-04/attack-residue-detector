# Implementation Plan — Attack Residue Detection & Forensic Reconstruction System for Linux

Author: Aman Sharma · Topic: Incident Detection on a Linux Server
Docs this plan derives from: `final_plan` (architecture), `Aman Sharma - Project_Definition_Doc` (requirements)

---

## DECISIONS LOCKED (supersede earlier sections)

Recorded 2026-09-29, after the instructor's scope cut and environment survey.

| # | Decision | Rationale |
|---|---|---|
| D1 | **Target = OCI instance `bot-farm`** (144.24.114.224) | Avoids the local 98%-full disk and the missing hypervisor. Bare metal + working systemd gives *real* service/port evidence. |
| D2 | **Target OS = Ubuntu 26.04 LTS, Python 3.14.4** — deviation accepted with instructor Sarath | 3.12 is not installable from 26.04 apt and a venv cannot downgrade the interpreter. Project is **stdlib-only**, so the instructor's wheel risk (Scapy/sklearn/psutil) does not apply. |
| D3 | **No Wazuh.** Auditd is the sole evidence source | Dropped by instructor as over-scope. Auditd is *better* forensic evidence here: raw kernel records with exact timestamps. |
| D4 | **Parse `/var/log/audit/audit.log` directly — do NOT shell out to `ausearch`** | `ausearch` is broken on this host: `-ts today` returns `<no matches>` despite 258 live SYSCALL records; `-ts <epoch>` throws `Invalid start date`. The log carries pre-interpreted text that breaks its parser. Direct parsing is portable and gives us the audit serial needed for event grouping. |
| D5 | **Group audit records by event serial** (`audit(<epoch>:<serial>)`) | The serial joins SYSCALL + PATH + PROCTITLE into one event — this is how the forensic engine asserts "process X created file Y at time T". |
| D6 | **nginx bound to `127.0.0.1:8081`**, not `0.0.0.0:80` | The instance is internet-reachable. A deliberately-compromised demo app must not be world-scannable, and demo traffic is local `curl` anyway. |
| D7 | **No VirtualBox.** No attacker VM | Instructor dropped the attacker VM in favour of `curl` + a script. Target is D1. |
| D8 | Code repo at `~/attack-residue-detector` on the Kali host; `.gitignore` committed | Instructor requires one repo per student, daily commits to main. |

### Must-not-touch on `bot-farm` (pre-existing workload)

`bot-farm` is a **live production box**, not an empty target. Do not break these:

| Thing | How it runs | Rule |
|---|---|---|
| `telegram-bot.service` | `/usr/bin/python3 telegram-control-bot.py` | never change the interpreter |
| `n8n-sandbox.service` | `/usr/bin/python3 /usr/local/bin/n8n-sandbox.py` | same |
| `daily-autologin.service` | `/usr/bin/python3 auto_logins/runner.py`, daily 00:00 | same — **breakage can trigger account lockouts** |
| `opencode` session | `/usr/bin/python3 /usr/local/bin/opencode`, up ~20 days | same |
| n8n | Docker container `n8nio/n8n:latest` | immune to host Python; leave alone |
| `n8n-tunnel` | `cloudflared` binary | leave alone |

**Hard rule: `/usr/bin/python3` stays 3.14.4.** Their third-party packages
(`requests`, `agentrouter_playwright`, `oauth_checkin`) live in
`~/.local/lib/python3.14/site-packages`, which is selected by *interpreter version*.
Repointing `python3` at 3.12 makes that path vanish and ImportErrors all three services.
This is why a side-by-side 3.12 was considered and then dropped — D2 makes it unnecessary.

### Already done on `bot-farm` (2026-09-29)

- `auditd` installed + active, `enabled 1`, `lost 0`, **18 rules** in `/etc/audit/rules.d/residue.rules`
  (keys: `identity_changes`, `authentication_changes`, `privilege_changes`, `ssh_keys`,
  `service_changes`, `web_changes`, `opt_changes`, `cron_changes`, `log_changes`, `process_execution`)
- `nginx` installed (1.28.3), college vhost on `127.0.0.1:8081`; public :80 closed (D6)
- Verified live capture: `audit(1790662283.599:699) comm="tee" key="web_changes"` +
  `PATH name="/var/www/college/probe.html" nametype=CREATE` — the exact shape the engine consumes
- Clean up the probe: `/var/www/college/probe.html`

---

## 0. Intent Confirmation

**One-line intent:** Detect *past* Linux server compromises by diffing the current host against a trusted
baseline, correlating the unexplained residue with historical security telemetry, and then containing the
affected artifact with preserved evidence.

**The single defensible differentiator** (the thing the basic version does not do):

> Basic version asks *"Is someone attacking right now?"* (`/var/log/auth.log` → 10 failed logins → Fail2ban).
> This system also asks *"The attacker has gone. Is there evidence it happened?"*

Everything else in the architecture is supporting infrastructure. The demo is won or lost on
**Scenario C: Past Web Compromise Detected Through Residue** (`final_plan` §29).

**Non-negotiable spec numbers** (these are the ones an examiner will check):

| Parameter | Value | Source |
|---|---|---|
| Residue scan interval | 60 seconds | PDD §2 |
| Historical correlation lookback | 24 hours | PDD §2 |
| Incident promotion rule | residue + **≥2** related events in a **10-minute** window | PDD §2 |
| Incident states | None / Possible / Corroborated / Contained / Resolved | final_plan §21, §34 |
| Planted demo artifacts | `update-service.service`, `/var/www/college/index.php`, `/opt/.cache/update` | PDD §2 |
| Expected baseline services | `ssh`, `nginx`, `docker` | PDD §2 |
| Expected baseline ports | `22`, `80`, `443` | PDD §2 |
| Authorized-change mechanism | maintenance window, else FP explosion | final_plan §18 |

**Explicitly banned as a claim** (PDD §3c): "more efficient", "user friendly", "real time", "uses AI",
"better dashboard". If it cannot be shown in the demo, it does not count.

---

## 1. Environment Reality Check (measured on `bot-farm`, 2026-09-29)

Target is D1 (`bot-farm`), not the Kali laptop. Measured:

```
host        bot-farm   144.24.114.224   OCI ap-mumbai-1
os          Ubuntu 26.04 LTS ("Resolute Raccoon")
kernel      7.0.0-1009-oracle
python3     3.14.4  (/usr/bin/python3.14)   <- do not change, see must-not-touch
sudo        passwordless
disk        37 G free / 48 G
cpu / ram   2 / 974 MB   (t.n.micro)
pre-existing  telegram bot, n8n (docker), n8n-sandbox, cloudflared tunnel,
              daily-autologin, opencode session   <- production workload
```

The local Kali host (98% full, 3.0 G free, no hypervisor) is now **dev machine only**:
it runs git, the editor, and writes the code. It does not host the target.

### Why no Wazuh, and why not ausearch

- Wazuh is dropped by the instructor (over-scope). That also removes the 3 G disk
  blocker entirely — Wazuh manager + indexer would have needed ~25 G.
- `ausearch` does not work on this host. Measured failure:

```
$ sudo ausearch -k web_changes -ts today
<no matches>                     # yet 258 SYSCALL records exist in audit.log
$ sudo ausearch --input-logs -k web_changes -ts 1790655128
Invalid start date (1790655128). Month, Day, and Year are required.
```

auditd itself is healthy (`enabled 1`, `lost 0`, `backlog 0`) and the raw log is
complete. The log contains pre-interpreted text appended after raw records
(`... key="web_changes" ARCH=x86_64 SYSCALL=execve AUID="ubuntu" ...`), which is
what breaks ausearch's parser. **Direct parsing of the raw log (D4) is the fix.**

### Evidence shape that must be supported

Verified live capture, the exact input the forensic engine consumes:

```
audit(1790662283.599:699)  arch=c000003e ... comm="tee" uid=0 key="web_changes"
  type=PATH  msg=audit(1790662283.599:699): name="/var/www/college/probe.html"
             nametype=CREATE  ouid=0  mode=0100644
  type=EXECVE msg=audit(1790662283.599:699): argc=3 a0="tee" ...
```

Note `nametype` (`CREATE` / `WRITE` / `DELETE`) — the residue classifier needs it to
distinguish "file was planted" from "file was edited".


---

## 2. System Design (module contract)

Four custom Python modules, exactly as the PDD requires. Everything else is a collector or an adapter.

```
residue-system/
├── core/
│   ├── statemodel.py       # normalised State + Residue + Incident + Event dataclasses
│   ├── statemachine.py     # None→Possible→Corroborated→Contained→Resolved
│   └── paths.py            # all filesystem locations, single source of truth
├── collectors/             # READ-ONLY probes of live host state
│   ├── users.py            # /etc/passwd, /etc/group, /etc/sudoers.d
│   ├── sshkeys.py          # ~/.ssh/authorized_keys for every user
│   ├── services.py         # systemctl list-unit-files / list-units
│   ├── cron.py             # /etc/cron*, systemd timers, /var/spool/cron
│   ├── network.py          # ss -lntup  (listening ports)
│   ├── files.py            # watched-path SHA-256 + mode + owner + mtime
│   ├── processes.py        # /proc process table + parent/child lineage
│   ├── containers.py       # docker ps/inspect
│   └── packages.py         # dpkg-query installed set
├── baseline/
│   ├── engine.py           # create / load / diff, versioned manifests
├── residue/
│   ├── detector.py         # 60s loop, baseline diff → typed Residue events
│   ├── classifiers.py      # new_service, modified_file, new_executable, ...
│   └── maintenance.py      # authorized-change window (final_plan §18)
├── evidence/
│   ├── base.py             # EvidenceSource interface
│   ├── auditlog_source.py  # PRIMARY: direct /var/log/audit/audit.log parser (D4)
│   ├── jsonl_source.py     # NDJSON backend (tests + deterministic demo)
│   └── nginx_source.py     # /var/log/nginx/*.log, for the web-stage events
├── forensic/
│   ├── correlator.py       # 24h lookback, 10-min window, ≥2 events rule
│   ├── attackpath.py       # stage taxonomy + ordered path rendering
│   └── timeline.py         # INCIDENT #N report renderer
├── response/
│   ├── evidence_store.py   # copy + hash + signed manifest, out-of-band
│   ├── containment.py      # disable/stop/isolate (guarded)
│   └── verifier.py         # post-action verification loop → Contained or Escalate
├── cli.py                  # single entrypoint: baseline | residue | forensic | response | demo
└── tests/
```

### Key design decisions (and why)

1. **Collectors are read-only and side-effect free.** The residue detector must never mutate host state.
   Containment is the *only* module allowed to change the system, and only under a flag.
2. **Baseline is versioned + content-addressed.** `baselines/<name>/v<N>.json` plus a `manifest.sha256`.
   `final_plan` §15 requires version tracking; it also lets you show "baseline v1 → v2 was an authorized change".
3. **Every Residue carries provenance**: `first_observed`, `last_observed`, `detector_version`, and the
   *delta* against baseline (before/after hash, owner, mode). This feeds evidence preservation (PDD §22).
4. **Correlation is deterministic and unit-tested against a fixture**, not only against a live host.
   The 10-minute / 2-event rule is a pure function — it must be provable without a server.
5. **Containment is verified, never assumed.** `final_plan` §24 is explicit: executing `systemctl disable`
   does not mean "contained". The verifier re-observes state and only then promotes to `Contained`.
6. **Everything simulated is loudly labelled.** Simulated artifacts use a `SIM_` prefix or live under
   `/opt/residue-sim/` so no examiner ever mistakes test residue for a real compromise.

---

## 3. The 4-Day Prototype Plan

**Goal:** prove the differentiating capability end-to-end on this host. Not build all of `final_plan`.

**Definition of done for Day 4** (the acceptance test):

```
$ python3 cli.py demo
[1/6] BASELINE        baseline v1 created — 3 services, ports 22/80/443, N web files hashed
[2/6] ATTACK SIM       planted: new service + modified file + unknown executable
[3/6] ATTACKER GONE    no live connection — verified against ss + ps
[4/6] RESIDUE SCAN     3 residues found (new_service, modified_file, new_executable)
[5/6] FORENSICS        4 correlated historical events → timeline + attack path
[6/6] RESPONSE         evidence preserved, service disabled, verification → CONTAINED

PAST INCIDENT DETECTED          #1042
First evidence      02:14:02
Last evidence       02:18:10
Residues found      3
Historical evidence 4 events
Attack path         Web Application → Process Execution → File Modification → Persistence
Current attacker activity   not observed
Status             CONTAINED
```

---

### Day 1 — Baseline Engine + State Collectors

**Goal:** be able to record the trusted state of a real Linux server and prove the diff works.

| # | Task | Output |
|---|---|---|
| 1.1 | `statemodel.py` — dataclasses for State / Residue / Incident / EvidenceEvent + JSON (de)serialisation | `core/` |
| 1.2 | Collectors: `users`, `services`, `network`, `files`, `sshkeys`, `cron` | 6 collectors |
| 1.3 | `baseline/engine.py` — `create()` snapshots all collectors, stamps version + host fingerprint, writes `baselines/<name>/v1.json` | CLI `baseline create` |
| 1.4 | `baseline diff` — structural diff producing typed deltas (this is the shared core of Day 2) | CLI `baseline diff` |
| 1.5 | Unit tests: synthetic state → expected delta (no host needed) | tests |
| 1.6 | **Run on this host.** Commit `baseline/v1.json`. Record the actual numbers of services/ports/files. | `baselines/local/v1.json` |

**End-of-day check:** `cli.py baseline create && cli.py baseline diff` on an unchanged host prints
*zero* differences. Any non-zero diff is a collector bug — fix it before Day 2 or you inherit 200 false
positives.

**Risk:** over-broad collection (e.g. hashing all of `/usr`) creates slow scans and noisy diffs.
Mitigation: watched-paths are an explicit, small, configurable list.

---

### Day 2 — Residue Detector + Incident Model

**Goal:** reliably find planted artifacts, and reliably stay silent when nothing changed.

| # | Task | Output |
|---|---|---|
| 2.1 | `residue/classifiers.py` — the 13 residue types from `final_plan` §17: `new_user`, `new_ssh_key`, `new_service`, `new_scheduled_task`, `new_port`, `new_process`, `file_modified`, `permission_change`, `new_executable`, `new_container`, `container_change`, `package_added`, `log_tampering` | classifiers |
| 2.2 | `residue/detector.py` — one scan pass; emit typed `Residue` records with provenance | scan engine |
| 2.3 | Severity/scoring model — residue alone ≠ compromise (`final_plan` §17 last line) | scoring |
| 2.4 | `residue/maintenance.py` — maintenance window; changes inside are `authorized`, outside are `residue` | FP control |
| 2.5 | 60-second daemon loop + `--once` mode for demos and tests | `cli.py residue scan --once` |
| 2.6 | Tests: plant N artifacts → expect N residues; unplant → expect 0 (the **false-positive test**) | tests |

**End-of-day check (the demo's credibility hinges on this):**

- plant 3 artifacts → detector reports exactly 3, with correct types
- revert all 3 → detector reports 0  ← *proves the baseline comparison is real, not a hardcoded demo*
- enable maintenance window, make a legit change → reported `authorized`, not `residue`

**Risk:** environment churn (docker, packagekit, NetworkManager) creating phantom deltas.
Mitigation: Day 1's zero-diff check, plus per-collector ignore lists.

---

### Day 3 — Forensic Reconstruction Engine + Response Engine

**Goal:** the two pieces that turn residue into an *incident*, and an incident into a *contained* one.

| # | Task | Output |
|---|---|---|
| 3.1 | `evidence/base.py` interface + `jsonl_source.py` (NDJSON append-only store) | abstraction |
| 3.2 | `evidence/auditlog_source.py` — **direct raw-log parser**; group by event serial (D5); extract `nametype`, `comm`, `exe`, `uid` → `EvidenceEvent` | **real** evidence |
| 3.3 | `evidence/nginx_source.py` — parse `college.access.log` for the web-stage event | evidence |
| 3.4 | ~~Auditd rule set~~ — **already installed and verified on `bot-farm`** (18 rules, see D-section) | ✅ done |
| 3.5 | `forensic/correlator.py` — 24h lookback → filter events related to a residue → cluster in 10-min windows → promote to incident at **≥2** events | **the core rule** |
| 3.6 | `forensic/attackpath.py` — stage taxonomy (`RECON → WEB_REQUEST → PROCESS_EXEC → FILE_MOD → PERSISTENCE → …`) + ordering, so the demo prints the 4-stage path | attack path |
| 3.7 | `forensic/timeline.py` — the `PAST INCIDENT DETECTED` report renderer | report |
| 3.8 | `response/evidence_store.py` — copy artifacts + `sha256sum` + manifest, written outside watched paths | preservation |
| 3.9 | `response/containment.py` — **guarded**: dry-run by default, `--apply` + typed confirmation to disable | safety |
| 3.10 | `response/verifier.py` — post-containment re-observation → `CONTAINED` or `ESCALATED` | `final_plan` §24 |
| 3.11 | `core/statemachine.py` — legal transitions between the 5 incident states | state model |

**End-of-day check:** full chain runs headless from a JSONL fixture — no root, no live host — producing
`Possible` and `Corroborated` incidents deterministically. That test is your regression net for the demo.

---

### Day 4 — Attack Simulator, Dry Run, Demo Script, Documentation

**Goal:** a demo that cannot fail on stage.

| # | Task | Output |
|---|---|---|
| 4.1 | `attacksim.py` — plants the exact 3 spec artifacts + synthetic evidence; **refuses to run unless** `--i-understand-this-plants-artifacts` is passed; uses `SIM_` naming and `/opt/residue-sim/` | simulator |
| 4.2 | `reset.sh` — reverts everything the simulator and containment touched, idempotent | reset |
| 4.3 | Auditd rules install step wrapped as a documented `sudo` step | setup |
| 4.4 | `cli.py demo` — the single command that runs the whole 6-stage sequence | demo entrypoint |
| 4.5 | **Run the full demo dry 3×, fix every rough edge.** A demo that works once is not a demo. | rehearsal |
| 4.6 | README: architecture diagram, install, usage, how the residue mechanism works | `README.md` |
| 4.7 | Slide deck / report: intent, difference, architecture, demo, results, limitations | docs |
| 4.8 | Record a backup video of the demo (in case live stage execution fails) | contingency |

**Stage-day runbook (what you actually do when presenting):**

```
1.  open clean terminal                     "Server is clean. Baseline is v1."
2.  cli.py baseline show                    "ssh, nginx, docker. Ports 22/80/443. Files hashed."
3.  attacksim.py --i-understand-...         "Controlled compromise simulation, three artifacts."
4.  ss -tnp | grep <attacker>  →  empty     "Attacker is GONE. No live session. This is now a cold case."
5.  cli.py residue scan --once              "NEW SERVICE / MODIFIED FILE / UNKNOWN EXECUTABLE"
6.  cli.py forensic correlate --window 24h  "PAST INCIDENT DETECTED #1042"
                                             "02:14 → 02:18, 3 residues, 4 events"
                                             "Web App → Process → File Mod → Persistence"
7.  cli.py response contain --apply         "Evidence preserved. Service disabled."
8.  cli.py response verify                  "STATUS: CONTAINED  (verified, not assumed)"
```

The stage order matters: **step 4 before step 5 is what makes the point.** Prove the attacker is gone
*before* you detect anything. That single beat is the difference between this project and the basic one.

---

## 4. Month Roadmap (post-prototype, 30 days)

| Week | Theme | Deliverables | Gate |
|---|---|---|---|
| **2** | Hardening evidence + real attacks | Auditd rules proven under each residue class (`sudo auditctl -l` → fire a real trigger per key); parse `nginx` access/error logs for the web stage; run real `hydra` SSH brute force from Kali **against a throwaway local VM, never `bot-farm`** (fail2ban is live there and it carries production workload) | Every residue class produces a correlated evidence event |
| **3** | Attack coverage + response | ModSecurity WAF in front of NGINX; real web-compromise scenario (SQLi → webshell drop → service persistence); full containment incl. container isolation; response verification under real conditions | Scenarios A–E from `final_plan` §27–§31 reproduce |
| **4** | Telemetry, metrics, writeup | nftables rules; Fail2ban integration; Promtail → Loki → Grafana for *historical* log search (this directly strengthens §19 correlation); build the evaluation harness for `final_plan` §36 metrics; detect malicious-file-injection attacks; finalize report + presentation | Metrics measured, not asserted |

### Evaluation harness (Week 4 — do not skip)

`final_plan` §36 says metrics should be *evaluated experimentally*. Build a runner that, for each scenario,
plants a known set of residues and records:

- detection latency (plant → first alert)
- residue recall (planted / detected) ← target: 100% on planted artifacts
- **false-positive rate** (benign changes correctly excluded) ← this is the credibility number
- correlation accuracy (correct incident classification)
- time-to-reconstruct a past incident
- response execution time + verification success rate
- CPU/RAM overhead of the 60s loop

An examiner will trust measured numbers far more than a dashboard.

---

## 5. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| **`bot-farm` carries live production workload** | 🔴 a bad residue experiment could take down the telegram bot / n8n / autologin | Target work is confined to `/var/www/college`, `/opt/residue-sim`, and its own `.service`. Never touch `/usr/bin/python3`, Docker, `:8080`, `:111`. Snapshot service PIDs before and after every change. |
| **Kali host 98% full (3 G free)** | 🟠 no VM, no Wazuh | Dev machine only. Free space if a local test VM is ever needed. |
| **OS/Python deviation (26.04 / 3.14 vs 24.04 / 3.12)** | 🟠 inspection risk | Accepted with instructor (D2). Keep the written agreement. Justify with "stdlib-only, no wheel risk". |
| **sudo is interactive** | 🟠 | No unattended daemon ever needs root. Root steps are documented, operator-run, and part of the demo script — which is honest and visible to the examiner. |
| Env churn → false positives | 🟠 | Day 1 zero-diff gate; ignore lists; maintenance window |
| Scope creep into 13 layers | 🟠 | 4-day scope is frozen above. New tool ⇒ it goes in the month roadmap, not Day 1–4. |
| Demo fails live | 🟠 | Rehearse 3×; single `cli.py demo` entrypoint; recorded backup video |
| Banned differentiators creep in | 🟡 | Every claim in the report must map to a demo-visible artifact |
| Claiming Wazuh correlation without Wazuh | 🟡 | The one-sentence description must be rewritten to say **Auditd**, not Wazuh. Never overclaim. |

---

## 6. Non-Goals for the Prototype

Explicitly out of scope until after Day 4:

- Grafana dashboards (and note: "better dashboard" is a banned differentiator anyway)
- Falco, ModSecurity, Loki, Promtail, nftables, Fail2ban
- Real Kali `hydra` attacks (Phase 2 — a simulated, labelled attack is safer and more repeatable on stage)
- Kubernetes / multi-host correlation
- Any ML or "AI" component (banned differentiator, and unnecessary)

---

## 7. Immediate Next Steps

**Already complete:**
- [x] Host tooling: git, VS Code, `.gitignore` committed (`a182862`)
- [x] `auditd` installed + active on `bot-farm`, 18 rules, verified live capture
- [x] `nginx` installed, college vhost on `127.0.0.1:8081`
- [x] OS/Python deviation agreed with instructor (D2)

**Next, in order:**

1. Remove the throwaway probe: `sudo rm -f /var/www/college/probe.html` on `bot-farm`.
2. Write `evidence/auditlog_source.py` first — the raw-log parser with event-serial
   grouping. It is the only component with a hard external dependency, and everything
   downstream (correlator, attack path, timeline) depends on its output shape.
3. `core/statemodel.py` + `collectors/` (users, services, network, files, sshkeys, cron).
4. `baseline create` on `bot-farm`, then `baseline diff` — must return **zero** on an
   unchanged host before anything else is built.
5. `residue scan` → plant the 3 spec artifacts → expect exactly 3 → revert → expect 0.

**The one number that decides whether the prototype succeeded:** after the demo, `residue scan` on a
*reverted* server returns **0**. That is what proves the system compares real state rather than
performing a scripted performance.

**Reminder for the demo script:** never run `hydra`/brute-force against `bot-farm`.
fail2ban is live there and it would ban the presenter out of their own production box.
