# Detection Coverage Matrix

What the All-Round Virus Scanner **actually** detects, by malware category, and —
just as importantly — what it **cannot**. This file is the honest record the
spec asks for: `implemented` means shipped with tests; `partial` means a
feasible sliver only; `out of scope` means the architecture (user-mode Python,
on-demand file scan + real-time file-event monitor) genuinely can't deliver it
and you should not rely on this tool for it.

Legend: ✅ implemented · 🟡 partial · ⛔ out of scope

| # | Category | Detection method | Status | Where |
|---|----------|------------------|--------|-------|
| 1 | **Virus / file infector** | Hash blocklist + YARA | ✅ | `heuristics.py` |
| | | PE overlay: large high-entropy appended data in unsigned binary | ✅ | `detectors/infector.py` |
| | | "Unexpected growth" vs a known baseline | ⛔ | no baseline DB; overlay shape is the proxy |
| 2 | **Worm** | Multi-directory / multi-drive write burst (propagation) | ✅ | `behavior.py` (real-time) |
| | | `autorun.inf` autostart abuse | ✅ | `heuristics.py` |
| | | Outbound network fan-out to many hosts | ⛔ | no network capture in user-mode Python |
| 3 | **Trojan** | Hash + YARA family signatures | ✅ | `heuristics.py` |
| | | System-name impersonation (svch0st.exe; unsigned svchost outside System32) | ✅ | `detectors/trojan.py` |
| 4 | **Ransomware** | Rapid modify+rename burst across many files (+ entropy/ext booster) | ✅ | `behavior.py` (real-time) |
| | | Canary / bait file tripwire | ✅ | `canary.py` + `behavior.py` |
| | | Encrypted-file extension + ransom-note naming | ✅ | `heuristics.py` |
| 5 | **Rootkit** | Unsigned kernel driver (`.sys`) outside the driver store, at rest | 🟡 | `detectors/rootkit.py` |
| | | Active kernel stealth / hooking / hidden-process detection | ⛔ | **needs kernel-level tooling — do not rely on this tool** |
| | | Cross-view directory/process discrepancy | ⛔ | noisy without kernel corroboration |
| 6 | **Spyware / keylogger** | YARA family signatures | 🟡 | `heuristics.py` (rules dir) |
| | | Keyboard/mouse API hooking, live outbound traffic to unknown endpoints | ⛔ | needs live process/API + network inspection |
| 7 | **Adware / PUP** | ClamAV PUA (`--detect-pua`) | ✅ | `engine.py` |
| | | Known adware/bundler installer naming (low severity) | ✅ | `detectors/pup.py` |
| 8 | **Fileless / LOTL** | LOTL launcher patterns in script FILES (encoded PS, download+exec) | 🟡 | `detectors/script.py` |
| | | In-memory PowerShell/WMI, parent/child process-tree anomalies, AMSI/ETW | ⛔ | **later phase — needs process monitoring, not a file scanner** |
| 9 | **Web-delivered** | URL reputation (URLhaus feed) + Mark-of-the-Web download-origin check | ✅ | `web.py` |
| | | Google Safe Browsing origin lookup (opt-in, admin key) | ✅ | `web.py` |

## Severity is category-aware

A single signal does not carry the same weight across categories (see
`detectors/__init__.py::_SEVERITY`): a ransomware canary trip or behavioral burst
is `INFECTED` (weight 10), while an adware installer name is `SUSPICIOUS`
(weight 2) — reported, never auto-quarantined at the aggressiveness of
ransomware/trojans. Only `INFECTED` detections are quarantined; `SUSPICIOUS`
ones are logged and reported for a human to review.

## Tunability (because heuristics are imprecise)

Every non-signature detector exposes an enable switch and, where meaningful, a
`sensitivity` (`low` | `medium` | `high`). Higher sensitivity catches more and
false-positives more.

- Static detectors: `heuristics.detectors.<key>` in `config.yaml`
  (`trojan`, `infector`, `pup`, `fileless_script`, `rootkit_driver`).
- Behavioral detectors: `realtime.behavior` (`sensitivity`, `window_seconds`,
  `cooldown_seconds`, `ransomware_file_threshold`, `worm_dir_threshold`,
  `worm_file_threshold`) and `realtime.canary`.

## Per-detector false-positive tradeoffs

| Detector | Default | FP risk & stance |
|----------|---------|------------------|
| Trojan impersonation (location) | on, medium | Low. Signed copies exempted; portable apps rarely name themselves `svchost.exe`. |
| Trojan typosquat | on, medium | Medium. An unrelated tool could be one edit from a system name → SUSPICIOUS only, off at `low`. |
| Infector PE overlay | on, low | High if naive: installers & Authenticode sigs live in overlays. Requires big + high-entropy + unsigned; SUSPICIOUS only. |
| PUP naming | on, medium | Low. Requires a known adware token, never a bare `setup.exe`. Low severity by design. |
| Fileless script | on, medium | Medium. Admins legitimately use these patterns → needs one strong pattern or several soft ones; SUSPICIOUS only. |
| Rootkit driver | on | Medium on dev/legacy boxes with unsigned drivers → SUSPICIOUS; at-rest signal only. |
| Ransomware burst | on, medium | A bulk extract/import/compile can trip it → SUSPICIOUS unless ransom extensions dominate or a canary trips (then INFECTED). Never auto-deletes user files. |
| Worm burst | on, medium | Same bulk-operation risk → SUSPICIOUS, alert/log only. |
| Canary trip | on | Very low. Only a manual delete of the bait file (or ransomware) trips it. |

## Hard guarantees

- **No real malware, exploit code, or encryption routines** exist anywhere in
  this project, including tests. The only real malicious test artifact is the
  EICAR string; every behavioral test uses synthetic dummy file events.
- Behavioral detection **alerts and logs**; it does not itself delete or encrypt
  a user's files.
- Rootkit and fileless coverage is deliberately **partial** and labeled as such —
  this tool is not a substitute for kernel-level EDR for those two classes.
