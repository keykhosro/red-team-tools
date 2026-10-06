# Get-AllADSPNServices.ps1

**One command. One CSV. Every Kerberoastable account, every service account, every SPN in your forest — ranked by attacker value.**

A single-file PowerShell script that turns Active Directory's SPN inventory into a red-team shortlist. It reads what the KDC already knows, then:

- **Cuts the noise** — every domain-joined machine auto-registers the same handful of SPNs (HOST, RestrictedKrbHost, DNS, GC, ldap, kadmin, krbtgt, E3514235, Dfsr, WSMAN, TERMSRV). That's ~95% of raw volume and ~0% of signal. Dropped by default.
- **Skips dead OUs** — anything under `OU=UNUSEDCOMPUTERS,`, `OU=DISABLEDCOMPUTERS,`, `OU=STALE,`, or any OU you name with `-FilterOU`.
- **Categorizes every SPN** — 100+ service classes mapped to 14 categories (Database, Mail, Web, Backup, Collaboration, DevOps, VoIP, Virtualization, Security, Management, RemoteAccess, FileShare, Infrastructure, Other).
- **Tiers every SPN** — 4 levels, from default noise to named applications.
- **Scores every object** — a numeric priority combining tier, Kerberoastability, naming, and ports. Sort the CSV descending and the top is your target list.
- **Aggregates one row per AD object** — a Veeam server with 23 SPNs becomes one row, not 23.

No admin. No RSAT. No stolen credentials. Just an LDAP read from any domain-joined machine.

---

## Tiers

| Tier | Name | What it means | Examples |
|---|---|---|---|
| **0** | Default per-computer noise | Auto-registered by every domain-joined machine. Confirms existence, says nothing about function. Dropped by default. | HOST, RestrictedKrbHost, DNS, GC, ldap, kadmin, krbtgt, E3514235, Dfsr, WSMAN, TERMSRV, TERMSERV |
| **1** | Infrastructure / platform | Deployment roles that define the forest's shape. | exchangeAB, exchangeMDB, exchangeRFR, FIMService, AgpmServer, MSClusterVirtualServer, MSServerCluster, NtFrs-* |
| **2** | Web / remote / file share | Kerberos-enabled network protocols. Frequently Kerberoastable; candidate entry points. | HTTP, HTTPS, www, CIFS, nfs, iSCSITarget, vnc, vmrc, vpn, sip |
| **3** | Named applications / uncategorized | Business apps, plus any class not matched to Tier 0/1/2 (including RPC UUIDs). The catch-all. | MSSQLSvc, VeeamBackupSvc, SAP, hdb, MSCRMAsyncService, hdfs, spark, solr, RPC UUIDs |

**Why the split matters.** Tier 0 is volume with no operational signal. Tier 1 reveals platform roles (Exchange, FIM, clusters, replication). Tier 2 points at Kerberos-enabled network services — an HTTP or CIFS SPN proves Kerberos is configured for that protocol, not that the endpoint is reachable; treat it as a candidate entry point. Tier 3 is the catch-all where named apps and unmapped classes land.

On aggregated rows, the `Tier` column shows the tier of the highest-scoring individual SPN — the SPN that determined the object's score.

---

## Filtering by tier

Four independent switches control what survives. Nothing is dropped unless you ask, except Tier 0, which is dropped by default. `-GetAllSPNs` overrides every content filter (`-ExcludeDefaultNoise`, `-ExcludeInfrastructure`, `-ExcludeWebRemoteShare`, `-OnlyApplicationServices`, `-OnlyUserSPNs`, `-OnlyKerberoastable`) and resets `-MinScore` to 0. Domain (`-Domain`) and OU (`-FilterOU`) scoping still apply.

```powershell
# Drop Tier 0 only — the default useful view
.\Get-AllADSPNServices.ps1 -ExcludeDefaultNoise

# Drop Tier 0 + Tier 1 — applications and web services only
.\Get-AllADSPNServices.ps1 -OnlyApplicationServices

# Drop Tier 2 only — dangerous; can hide Kerberoastable web service accounts
.\Get-AllADSPNServices.ps1 -ExcludeDefaultNoise -ExcludeWebRemoteShare

# Keep everything — bypass all filters and thresholds
.\Get-AllADSPNServices.ps1 -GetAllSPNs
