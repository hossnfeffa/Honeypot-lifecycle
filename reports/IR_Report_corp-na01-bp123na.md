IR Report – corp-na01-bp123na – TLP:AMBER 

# **INCIDENT RESPONSE REPORT** 

_MySQL Database Compromise & Extortion – Host corp-na01-bp123na_ 

|**Field**|**Value**|
|---|---|
|Report date|August 19, 2026|
|Prepared by|SOC Analyst – [name] (Cowork-assisted draft; requires analyst review)|
|Afected asset|corp-na01-bp123na (MySQL database server)|
|Incident window (log<br>evidence)|Aug 14, 2026 08:47 MT – Aug 18, 2026 01:42 MT (times as recorded in source logs,<br>America/Denver)|
|Data sources reviewed|MySQLAudit_CL AuthLogs.csv (231 events), MySQLAudit_CL Queries.csv (927 events)|
|Data sources NOT available<br>for this review|DeviceLogonEvents, DeviceProcessEvents, DeviceRegistryEvents,<br>DeviceNetworkEvents, DeviceFileEvents, NTANetAnalytics|
|Classifcation|Unauthorized database access – data destruction / extortion (“ransom-note” MySQL<br>wiper). Severity: High|



## **1. Executive Summary** 

Between Aug 14 and Aug 18, 2026, the internet-reachable MySQL server corp-na01-bp123na was accessed as root from external IP 64.89.163.89 after only two failed login attempts, and within roughly two minutes the attacker dropped all tables and databases (lnp_corp, sakila, world – including customers, orders, payments, credentials, and staff_list tables), replaced them with a ransom note table, and revoked root's own DDL/DML privileges. Over the following three days, at least four more sessions from related external IPs (mostly in the 64.89.163.0/24 range, plus 194.32.120.109) returned to re-create or re-drop the ransom note, once raising the demand from 0.0134 to 0.0132–0.0135 BTC. The pattern – rapid credential success, scripted DROP/CREATE/INSERT sequence, a generic ransom note, and repeat automated “check-in” visits – is consistent with an opportunistic, automated MySQL ransom-note campaign scanning for exposed servers with weak root credentials, not a targeted intrusion. The provided logs do not show evidence of data exfiltration (no network/transfer telemetry was available) or host-level compromise; only the database audit trail was reviewed for this report. 

## **2. Incident Details** 

|**Field**|**Details**|
|---|---|
|Detection date/time|Not determined from available logs – no SIEM alert or ticket timestamp was<br>provided; window shown is derived from the audit log evidence itself.|



Page 1 of 7 

IR Report – corp-na01-bp123na – TLP:AMBER 

|**Field**|**Details**|
|---|---|
|Reporter|Not determined from available logs|
|Incident type|Unauthorized remote database access; mass data destruction (DROP<br>DATABASE/TABLE); extortion (ransom note left in-database)|
|Severity|High – confrmed loss of production tables including a credentials table, no<br>confrmed recovery in the reviewed data|
|Afected host|corp-na01-bp123na (only device name present in the MySQL audit logs)|
|Afected databases|lnp_corp (appears to be the production database, based on naming convention);<br>sakila and world (MySQL sample databases present on the same instance)|
|Afected tables (confrmed<br>dropped)|credentials, customers, orders, payments, staf_list, store, city, country,<br>countrylanguage|



## **3. Impact Assessment** 

### **Confidentiality** 

The ransom note claims data was “backed up” by the attacker before deletion, which is standard extortionbot boilerplate. No outbound transfer/network evidence was available in this review to confirm or rule out exfiltration. Because a credentials table was among those dropped, treat any credentials it contained as compromised regardless of confirmed exfiltration. 

**Not determined from available logs:** whether data was actually exfiltrated (would require DeviceNetworkEvents / NTANetAnalytics for the incident window, not provided). 

### **Integrity** 

High impact. All observed tables across three databases were dropped (foreign keys removed first, then tables, then databases) and replaced with a single ransom-note table (recover_your_data), which itself was repeatedly deleted and recreated by later visits. 

### **Availability** 

Severe. Production tables became unavailable starting 2026-08-14 18:19 MT with no evidence of restoration in the log window reviewed (through 2026-08-18 01:42 MT). 

### **Scope & business impact** 

One database host, at least one production database (lnp_corp) and two reference/sample databases (sakila, world). Business impact scales with what lnp_corp served – likely order/customer/payment processing, based on table names – but the owning application was not identified in the available data. 

**Not determined from available logs:** downstream application/business impact, RTO/RPO, and whether backups exist. 

Page 2 of 7 

IR Report – corp-na01-bp123na – TLP:AMBER 

## **4. Indicators of Compromise** 

IOCs below are taken directly from the ransom-note text and correlated session activity in the provided logs (values differ from the illustrative examples in the report template – these are what the data actually shows). 

|**Type**|**Value**|**Context**|
|---|---|---|
|BTC address|bc1q7jps5432akufg9fw2vu6hgmmj5hrrdu6c5gm|Ransom payment address, present in<br>every recover_your_data note insert|
|Ransom demand|0.0132 – 0.0135 BTC (varies by visit)|Amount increased/varied across the<br>three note-insertion events (Aug 14:<br>0.0135; Aug 16: 0.0134; Aug 17: 0.0132)|
|Contact email|ak+2ne16@onionmail.org|Extortion contact address in ransom<br>note|
|Reference URL|hxxps://bit[.]ly/22mysql|Payment-instructions link in ransom<br>note (defanged)|
|DATAID|2NE16|Victim/campaign identifer embedded in<br>ransom note|
|Ransom artifact|Database/table `recover_your_data` (and<br>`recover_your_data_info` / READ_ME column)|Created, dropped, and recreated across<br>5 separate sessions|
|Source IP – initial<br>access & mass<br>deletion|64.89.163.89|First successful root logon (2026-08-14<br>18:19:04 MT); ran the DROP/REVOKE<br>sequence|
|Source IP – revisit|194.32.120.109|Created<br>recover_your_data_info(READ_ME)<br>table, 2026-08-16 20:33–20:34 MT|
|Source IP – revisit|64.89.163.90|Dropped/recreated ransom table, 2026-<br>08-16 23:41–23:42 MT|
|Source IP – revisit|64.89.163.176|Recreated ransom database only<br>(check-in), 2026-08-17 00:09 & 00:42 MT|
|Source IP – revisit|64.89.163.97|Dropped/recreated ransom table with<br>updated demand, 2026-08-17 23:22–<br>23:23 MT|
|Scanner IP – heaviest<br>brute force|68.178.163.174|100 failed logons (root, root_dev) in ~2<br>minutes, 2026-08-16 23:08–23:10 MT;<br>no success observed|
|Scanner/<br>opportunistic IPs (no|77.90.185.30, 77.90.185.21, 213.209.159.115,<br>64.89.163.154, 64.89.163.148, 8.138.154.105,|Generic connect + `SELECT<br>@@max_allowed_packet` handshake|



Page 3 of 7 

IR Report – corp-na01-bp123na – TLP:AMBER 

|**Type**|**Value**|**Context**|
|---|---|---|
|destructive activity|202.189.4.123, 34.38.245.25, 64.89.163.94,|only, consistent with mass internet|
|observed)|vmi3498073.contaboserver.net|scanning of exposed MySQL|



## **5. Timeline** 

All times as recorded in the source logs (America/Denver, per RawData UTC offset). 

|**Time (MT)**|**Event**|**Source**|
|---|---|---|
|Aug 14, 08:47–<br>13:20|Four failed local (localhost) root logon attempts; unrelated baseline<br>noise or health checks, not tied to the external attack|MySQLAudit_CL<br>AuthLogs|
|Aug 14, 18:16:53|First failed remote root logon attempt from 64.89.163.89|AuthLogs|
|Aug 14, 18:19:04|Successful root logon from 64.89.163.89 – initial access|AuthLogs|
|Aug 14, 18:19:16<br>–17|DROP TABLE payments, credentials, customers, orders; frst ransom-<br>note insert|Queries|
|Aug 14, 18:20:23<br>–39|Foreign keys dropped; DROP TABLE staf_list, store, city, country,<br>countrylanguage|Queries|
|Aug 14, 18:20:40<br>–41|DROP DATABASE lnp_corp, sakila, world; CREATE DATABASE<br>recover_your_data|Queries|
|Aug 14, 18:20:44|REVOKE INSERT, UPDATE, DELETE, DROP, CREATE ON *.* FROM<br>root@'%' (attacker revoked its own further write access)|Queries|
|Aug 16, 20:33:35<br>–20:34:17|Revisit from 194.32.120.109; repeatedly creates<br>recover_your_data_info(READ_ME) table|AuthLogs + Queries|
|Aug 16, 23:08:45<br>–23:10:38|100 failed root/root_dev logon attempts from 68.178.163.174; no<br>success|AuthLogs|
|Aug 16, 23:41:24<br>–23:42:48|Revisit from 64.89.163.90; drops and recreates recover_your_data<br>(demand: 0.0134 BTC)|AuthLogs + Queries|
|Aug 17, 00:09:43<br>–00:09:55 &<br>00:42:20–<br>00:42:53|Revisit from 64.89.163.176; recreates ransom database only (no new<br>drop – check-in)|AuthLogs + Queries|
|Aug 17, 23:22:59<br>–23:23:11|Revisit from 64.89.163.97; drops and recreates recover_your_data<br>(demand updated: 0.0132 BTC)|AuthLogs + Queries|
|Aug 18, 00:24:19|Continued generic scanning (admin/sa/root) from 77.90.185.30; no|AuthLogs|



Page 4 of 7 

IR Report – corp-na01-bp123na – TLP:AMBER 

|**Time (MT)**|**Event**|**Source**|
|---|---|---|
|–01:42:17|destructive activity observed||
|Not determined|Detection / analyst notifcation|Not determined from<br>available logs|



## **6. Root Cause / Attack Vector** 

- MySQL on corp-na01-bp123na was reachable from the public internet – at least 17 distinct external IPs attempted root/admin/sa logons over the 4-day log window, with no evidence of IP allowlisting or rate limiting (one IP alone generated 100 failed attempts in ~2 minutes). 

- The initial compromise (64.89.163.89) authenticated as root after only two failed attempts, then immediately ran destructive DDL – consistent with a weak, blank, or easily-guessed root password rather than a slow brute force. 

- Post-authentication behavior (identical scripted DROP/CREATE/INSERT sequence, generic ransom note, repeat automated “check-in” visits from a cluster of related IPs) matches known automated “recover_your_data” MySQL ransom-bot campaigns that mass-scan for exposed instances with weak root credentials, rather than a targeted, hands-on-keyboard intrusion. 

## **7. Response Actions** 

### **Containment (recommended)** 

- Restrict MySQL (3306) to internal/VPN sources only via firewall or security group; remove direct internet exposure. 

- Disable remote root login; if the instance must stay internet-facing, require a named least-privilege service account per application. 

- Rotate the root password and all other MySQL account credentials on this instance immediately. 

### **Eradication** 

- Audit `mysql.user` for any accounts created outside expected change history – no CREATE USER statements were observed in the reviewed query log, but the full account list was not available for confirmation. 

- Review and reset the privileges the attacker REVOKEd from root@'%' (INSERT, UPDATE, DELETE, DROP, CREATE) once a trusted admin path is confirmed. 

- Check for leftover triggers/scheduled events tied to the recover_your_data database before dropping it during cleanup. 

### **Recovery** 

- Restore lnp_corp (and sakila/world if needed) from the last known-good backup predating 2026-0814 18:19 MT. 

- Validate integrity of restored customers, orders, payments, credentials, staff_list, store, city, country, and countrylanguage tables. 

Page 5 of 7 

||<br>><br>Aug 19, 2026 1:48:...|Query|SHOW GLOBALSTATUS|2026-08-19T19:48:50.13...|
|---|---|---|---|
||<br>><br>Aug 19, 2026 1:48:...|Query|SHOW GLOBALSTATUS|2026-08-19T19:48:47.12...|
|CO<br>><br>Aug 19, 2026 1:48:... O|Query|SHOW GLOBALSTATUS|2026-08-19T19:48:44.12...|
||<br>><br>Aug 19, 2026 1:48:...|Query|SHOW GLOBAL STATUS|2026-08-19119:48:41.12...|
||<br>><br>Aug 19, 2026 1:48:... Ol|Query|SHOW GLOBAL STATUS|2026-08-19T19:48:38.11...|
||<br>><br>Aug 19, 2026 1:48:...|Query|SHOW GLOBALSTATUS|2026-08-19T19:48:35.11...|
||<br>><br>Aug 19, 2026 1:48:...|Query|SHOW GLOBALSTATUS|2026-08-19T19:48:32.10...|
|OC<br>><br>Aug 19, 2026 1:48:... O|Query|SHOW GLOBALSTATUS|2026-08-19T19:48:29.10...|







<!-- Start of picture text -->
@ 90s er  &@%<br>- °<br>mi oO 2021<br><!-- End of picture text -->

