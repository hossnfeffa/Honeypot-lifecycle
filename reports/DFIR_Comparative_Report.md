# DFIR Comparative Analysis — CORP-NA01-BP123
## MDE Live Response Investigation Packages (Pre vs. Post)

---

## 1. Baseline Determination

| Package | Collection Start (UTC) | Collection GUID |
|---|---|---|
| `PreBreachMDE_Investigation_Package.zip` | **2026-08-14T19:25:24Z** | dc15e549-6a81-45ca-8394-7395aa41de7a |
| `PostBreachMDE_Investigation_Package.zip` | **2026-08-19T15:27:54Z** | 39bce588-fea0-4515-9983-f0f511963f90 |

Both packages carry a `Forensics Collection Summary.csv` with per-command execution timestamps. The Pre package's timestamps are all ~5 days earlier than the Post package's. **The Pre package is treated as baseline**; Post is the comparison snapshot, ~5 days later. Host: `CORP-NA01-BP123`, an Azure VM (10.0.0.110, WindowsAzureGuestAgent/AMA present), original install 2026-08-11.

A material fact discovered during analysis: **the Security event log (retained across both collections) shows this host was subject to repeated MDE Live Response / investigation-package collections throughout 2026-08-16 to 2026-08-18** (evidenced by prefetch and firewall-log artifacts referencing at least 8 distinct `CollectedData\<GUID>` folders beyond our two packages, plus repeated `SenseSampleUploader.exe` runs uploading `CompressedCollectedData\*.zip`). The Pre/Post packages supplied are two snapshots from within a longer, already-active SOC investigation window, not a clean "day zero" vs. "post-incident" pair.

---

## 2. Summary Verdict

**Compromise indicators found: NO evidence of successful compromise. Confidence: Medium-High.**

The host was the target of a genuine, sustained external credential-attack campaign (463 failed NTLM network logons + 1 successful anonymous null-session) between **2026-08-17 16:26 UTC and 2026-08-18 08:00 UTC**, but every persistence, privilege-escalation, account-management, service, scheduled-task, and autorun artifact examined is **unchanged or benign** between the two collections. Windows Defender's own detection history (`MPDetection-*.log`) recorded **zero real malware detections** across the entire 8/9–8/19 window — only a recurring, benign EICAR test-file signature (`C:\ProgramData\EICAR.txt`, an AV health-check canary). No new accounts, no new admin group members, no new services, no new scheduled tasks, no new autorun Run/RunOnce/Winlogon keys, no new listening ports, and no unexplained executables in Temp or Prefetch. The dominant explanation for the elevated event-log volume in Post is the MDE sensor's own collection activity, not attacker activity.

---

## 3. Notable Deltas

| Category | Item | Change | Benign/Suspicious | Evidence |
|---|---|---|---|---|
| Logon (Security 4625) | 463 failed NTLM network logons vs common admin usernames (`ADMINISTRATOR`,`ADMIN`,`USER`,`VMADMIN`,`AZUREADMIN`,`DEMOUSER`,`AZUREUSER`,`STUDENT`) from `188.252.76.146` (+3 other IPs, 1 attempt each) | **ADDED** (Pre had only 5 internal-IP failures) | **Suspicious — but failed** | `post_security.jsonl`, EventID 4625, 2026-08-17T16:26:56Z–2026-08-18T08:00:20Z |
| Logon (Security 4624) | Successful `ANONYMOUS LOGON` (null session, NTLM, LogonType 3) from external IP `34.77.52.156`, immediately followed by logoff, no share/object access | **ADDED** | **Suspicious (low severity) — recon/scan, no follow-on activity** | `post_security.jsonl` EventID 4624/4634, LogonId 0x1a1e162, 2026-08-18T07:12:18Z |
| System | Host rebooted; new boot time | **CHANGED** | Benign | `SystemInformation.txt`: Pre boot 8/14 14:42; Post boot 8/19 15:25 |
| Accounts/Groups | Administrators group membership (`ADent`, `Administrator`) | **UNCHANGED** | Benign | `LocalGroups.txt` identical both packages |
| Account mgmt events (4720/4722/4724/4728/4732/4738) | Present only in Pre (VM provisioning 8/11–8/14); **zero in Post** | **REMOVED (activity stopped)** | Benign | `pre_acctmgmt.txt` vs `post_acctmgmt.txt` |
| Services | No services added/removed; only per-user `_<suffix>` service instances vanish because ADent is logged off in Post (no interactive session at capture time) | UNCHANGED (session-state artifact) | Benign | `Services.csv` diff |
| Service (Event 4697 – service installed) | 0 events in Post vs. 75 in Pre (all VM-provisioning services 8/11–8/14) | **REMOVED (activity stopped)** | Benign | `pre_acctmgmt.txt` |
| Scheduled Tasks | 302 tasks in both packages, **identical task names**; 0 `TaskCreated`(4698)/`TaskDeleted`(4699) events in Post | UNCHANGED | Benign | `ScheduledTasks.csv`, Security 4698/4699 |
| Autoruns – HKLM Run | `SecurityHealth` only, identical | UNCHANGED | Benign | `Autoruns.txt` |
| Autoruns – HKCU Run (ADent) | Entries (OneDrive, MicrosoftEdgeAutoLaunch) present in Pre; **key not queryable in Post** | Collection artifact, not removal | Benign — ADent's hive isn't loaded in Post because she is not logged on (`QueryUser.txt`: "No User exists") | `Autoruns.txt` |
| Network listeners | 135, 445, 3306/33060 (MySQL), 3389, 5040 all bound to `0.0.0.0` in both | UNCHANGED | **Pre-existing risk** (internet-facing RDP/SMB/MySQL), not a delta | `ActiveNetConnections.txt` both |
| Network — new listeners | None | UNCHANGED | — | — |
| DNS cache | Different cached entries (Azure/MS Update/AAD/MSA infra only) | CHANGED (expected churn) | Benign | `DnsCache.txt` diff |
| Processes | `SenseIR.exe`, `gc_worker.exe` (Azure Guest Config), `sppsvc.exe` added; ~35 interactive-session processes (explorer, msedge, OneDrive, etc.) removed | CHANGED | Benign — reflects ADent logged off + fresh boot at capture time, not malicious | `Processes.csv` diff |
| Prefetch | 12 new `.pf` entries: 2× Defender signature deltas, Edge updater ×2, `FINDSTR/QUERY/QUSER/ROBOCOPY/XCOPY` (×14–20 runs each, 8/16 22:10–8/18 01:10), `SenseSampleUploader.exe`, 1 new `svchost.exe`, 1 new `mmc.exe` invocation | ADDED | **Benign — confirmed to be MDE's own Live Response package build/zip/upload pipeline** (referenced files inside these `.pf` records point at `...\CollectedData\<GUID>\...` and `...\CompressedCollectedData\<GUID>.zip`) | pyscca parse of `ROBOCOPY.EXE-89505E7B.pf`, `XCOPY.EXE-A9A4E3D9.pf`, `SENSESAMPLEUPLOADER.EXE-AC445F95.pf` |
| Temp dirs | MySQL Workbench cache folders / `cv_debug.log` / one `wctXXXX.tmp` churn under ADent & Administrator profiles | CHANGED | Benign routine app activity, no new executables | `*_TempDirFiles.txt` diff |
| Installed programs | Identical (10 entries both) | UNCHANGED | Benign | `InstalledPrograms.csv` |
| Defender detections | Only recurring `Virus:DOS/EICAR_Test_File` at `C:\ProgramData\EICAR.txt` (8/11, 8/14, 8/15, 8/16, 8/17, 8/18 — roughly every 12h, an AV health-check canary) | UNCHANGED pattern | Benign | `MPDetection-20260809-085606.log` (extracted from `MPSupportFiles.cab`) |
| Defender platform/engine | Multiple signature/platform updates (AS/AV 1.457.130→1.457.219) + 3 service restarts (8/16 20:02, 8/17 16:24, 8/19 15:25) | CHANGED | Benign — routine updates | Same log |
| Object access (4663/4660/4670 spike) | 8,509 / 5,643 / 2,783 events in Post vs. 519/426/19 in Pre | ADDED (volume) | **Benign — self-referential.** All `ProcessName` = `MsSense.exe`/`SenseIR.exe`/`SenseTVM.exe` touching their own `CollectedData` staging files (this collection building itself) | `post_security.jsonl` |
| SMB Sessions | None in either package | UNCHANGED | Benign | `SMB Session\Summary.txt` |

---

## 4. Prioritized Compromise Indicators (ATT&CK Mapping)

1. **T1110 – Brute Force (Credential Access) / T1595 – Active Scanning.** 463× EventID 4625, NTLM network logons (LogonType 3), against `Administrator/admin/user/vmadmin/azureadmin/demouser/azureuser/student`, from `188.252.76.146` (460 attempts) plus single probes from `152.53.120.71`, `94.26.68.55`, `45.142.193.145`. Window: 2026‑08‑17T16:26:56Z – 2026‑08‑18T08:00:20Z (~15.5 hrs). **Outcome: all failed** (Status `0xc000015b`/logon-type-not-granted or bad credentials); no corresponding successful 4624 for any of these accounts/IPs. Severity: real attack, but unsuccessful.
2. **T1046/T1595 – Network Service Scanning.** Successful `ANONYMOUS LOGON` (null session) from `34.77.52.156`, EventID 4624 → 4634 logon/logoff pair, no 5140/5145 share-access or 4672 privilege-use events tied to that LogonId (`0x1a1e162`). Consistent with an opportunistic internet scanner (GCP-owned IP range) probing SMB null-session support, not an interactive intrusion. Severity: low, informational.
3. **Attack surface finding (not a delta):** RDP (3389), SMB (445), and MySQL (3306/33060) are bound to `0.0.0.0` on both collections — this host is directly reachable for these attempts, which is what likely drew the brute-force traffic. Not new, but the underlying reason the attack occurred; recommend an NSG/firewall review.
4. No ATT&CK-mappable persistence (T1547/T1053/T1543), privilege escalation (T1078/T1098), defense evasion (T1070/T1112), lateral movement (T1021), collection (T1005/T1560) or exfiltration (T1041/T1048) indicators were found. The `ROBOCOPY`/`XCOPY`/`FINDSTR`/`QUERY`/`QUSER` cluster that would normally warrant a T1560/T1005 look was traced conclusively to MDE's own investigation-package build pipeline via embedded file-reference metadata in the prefetch records.

---

## 5. Probable Incident Type

**Undetermined breach — best-supported reading: attempted, unsuccessful credential-brute-force / internet-scan against internet-exposed RDP & SMB, which triggered (or coincided with) an active MDE/SOC investigation.** There is no artifact-level evidence that the attacker obtained a valid credential, established a session, wrote a file, created persistence, or exfiltrated data. If this host is being handled as a confirmed "breach," the evidence in these two packages does not support that classification; it supports "attempted intrusion, repelled at the authentication layer."

---

## 6. Gaps / Limitations

- **No System or Application event logs** were included in either package — only `Security.evtx`. Process-creation detail (4688) is present but command-line auditing fields were sparse; **no Sysmon or PowerShell Operational log** was available, so script-block/module logging could not be checked.
- **No `pfirewall.log` content** — only the xcopy *collection command* for the firewall log was captured in `FirewallExecutionLog.txt`; the actual firewall log lines were not present in either package (Windows Firewall logging appears not enabled, or the log was empty at both collection times).
- **No hosts file** was collected in either package.
- The **Security log's own retention** covers 8/9–8/19, i.e., it already extends before the Pre package and enabled reconstruction of provisioning history; this is a strength, not a gap, but it means the Pre package is not a true "day-zero" image — provisioning activity from 8/9–8/14 is visible only in Post's copy of the same rolling log.
- `MPSupportFiles.cab` was only fully parsed for `MPDetection-*.log`; the broader `MPLog-*.log` (very large, verbose scan telemetry) was not exhaustively reviewed line-by-line given its size — spot checks showed no additional detection entries beyond the EICAR canary and standard telemetry.
- Prefetch only retains the most recent 8 run timestamps per file even when `RunCount` is higher (e.g., `SenseSampleUploader.exe` RunCount=14, only 8 timestamps recoverable), so the full historical cadence of the MDE collection activity could not be reconstructed beyond 2026‑08‑16 22:10–2026‑08‑18 01:10.
- No memory image, disk image, or browser/credential-store artifacts were included in either package, so in-memory implants or credential theft (e.g., LSASS access, DPAPI, browser-saved passwords) could not be assessed.

---

### IOC List (from Post; confirmed absent from Pre baseline)

| Indicator | Type | Context |
|---|---|---|
| 188.252.76.146 | IP | Primary brute-force source, 460/463 failed logons |
| 152.53.120.71 | IP | Single failed-logon probe |
| 94.26.68.55 | IP | Single failed-logon probe |
| 45.142.193.145 | IP | Single failed-logon probe |
| 34.77.52.156 | IP | Successful ANONYMOUS LOGON (null session), no follow-on activity |
| ADMINISTRATOR / ADMIN / USER / VMADMIN / AZUREADMIN / DEMOUSER / AZUREUSER / STUDENT | Usernames | Targeted in brute-force attempts; none exist/succeeded on this host |

All five IPs were grepped across every text-based artifact in **both** packages (recursively) — no matches outside the Security event log in Post, and no matches at all in Pre. No successful authentication, file drop, scheduled task, or outbound connection tied to any of these indicators was found in either package.
