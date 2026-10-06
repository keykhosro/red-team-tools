# SPN-Mining

**One command. One CSV. Every Kerberoastable account, every service account, every web app, every SQL server, every Exchange role, every cluster, every service principal in your forest — ranked by how much an attacker would care.**

A single-file PowerShell script that turns Active Directory's SPN inventory into a red-team shortlist. It reads what the KDC already knows, then:

- **Cuts the noise** — every computer in AD registers the same handful of default SPNs (HOST, RestrictedKrbHost, DNS, GC, ldap, kadmin, krbtgt, E3514235, Dfsr, WSMAN, TERMSRV). That's ~95% of the total SPN volume and ~0% of the useful signal. The script drops them by default.
- **Skips dead OUs** — anything under a DN like `OU=UNUSEDCOMPUTERS,`, `OU=DISABLEDCOMPUTERS,`, `OU=STALE,`, or any OU you name with `-FilterOU`. Decommissioned servers and old service accounts never reach the report.
- **Categorizes every SPN** — 100+ service classes mapped to 14 categories (Database, Mail, Web, Backup, Collaboration, DevOps, VoIP, Virtualization, Security, Management, RemoteAccess, FileShare, Infrastructure, Other). You see *what kind of thing* every object is, not just its raw SPN string.
- **Tiers every SPN** — 4 levels from default noise (Tier 0) → infrastructure (Tier 1) → web / remote / file share (Tier 2) → named applications (Tier 3). Filter by tier with a single switch.
- **Scores every object** — a numeric priority combining tier, Kerberoastability, naming conventions, and ports. Sort the CSV descending and the top of the file is your target list.
- **Aggregates one row per AD object** — a Veeam server with 23 SPNs becomes one row, not 23. All services, categories, FQDNs, and ports joined onto that single line.

No admin. No RSAT. No stolen credentials. No exploitation. Just an LDAP read from any domain-joined machine.

---

## Tiers

Every SPN is assigned to one of four tiers based on what the service class tells you about the object.

| Tier | Name | What it means | Examples |
|------|------|---------------|----------|
| **0** | Default per-computer noise | Auto-registered by every Windows machine that joins the domain. Confirms the machine exists; says nothing about what it does. Dropped by default. | HOST, RestrictedKrbHost, DNS, GC, ldap, kadmin, krbtgt, E3514235, Dfsr, WSMAN, TERMSRV, TERMSERV |
| **1** | Infrastructure / platform | Deployment roles that define the forest's shape: mail, identity, high availability, replication. | exchangeAB, exchangeMDB, exchangeRFR, FIMService, AgpmServer, MSClusterVirtualServer, MSServerCluster, NtFrs-* |
| **2** | Web / remote / file share | Kerberos-enabled network protocols. Frequently Kerberoastable, frequently an entry point candidate. | HTTP, HTTPS, www, CIFS, nfs, iSCSITarget, vnc, vmrc, vpn, sip |
| **3** | Named applications / uncategorized | Business applications, plus any class not matched to Tier 0/1/2 — including RPC UUIDs. The catch-all. | MSSQLSvc, VeeamBackupSvc, SAP, hdb, MSCRMAsyncService, hdfs, spark, solr, RPC UUIDs |

### Why the split matters

- **Tier 0** is the bulk of raw volume with almost no operational signal. Every domain-joined computer has it — dropping it loses nothing beyond what the computer account already tells you.
- **Tier 1** reveals platform roles. `exchangeAB` means Exchange is deployed; `MSClusterVirtualServer` means a Failover Cluster; `NtFrs-*` means legacy replication is still registered. The list is short and every entry maps to a real deployment.
- **Tier 2** points at Kerberos-enabled network services. An `HTTP` or `CIFS` SPN proves Kerberos is configured for that protocol on that host — it does *not* prove the endpoint is externally reachable. Treat it as a candidate entry point, not a confirmed one.
- **Tier 3** is the catch-all. Most of it is named applications (SQL, SAP, Veeam, SharePoint). Some of it is unmapped classes falling through the reference table — RPC UUIDs land here by default rather than being silently dropped.

---

## Filtering by tier

Four switches control what survives:

```powershell
# Drop Tier 0 only — the default useful view
.\Get-AllADSPNServices.ps1 -ExcludeDefaultNoise

# Drop Tier 0 + Tier 1 — applications and web services only
.\Get-AllADSPNServices.ps1 -OnlyApplicationServices

# Drop Tier 2 only — dangerous; can hide Kerberoastable web service accounts
.\Get-AllADSPNServices.ps1 -ExcludeDefaultNoise -ExcludeWebRemoteShare

# Keep everything — bypass all filters and thresholds
.\Get-AllADSPNServices.ps1 -GetAllSPNs
```

Each switch is independent — nothing is dropped unless you ask for it, except Tier 0 which is dropped by default. `-GetAllSPNs` overrides every content filter (`-ExcludeDefaultNoise`, `-ExcludeInfrastructure`, `-ExcludeWebRemoteShare`, `-OnlyApplicationServices`, `-OnlyUserSPNs`, `-OnlyKerberoastable`) and resets `-MinScore` to 0. Domain scoping (`-Domain`) and OU filtering (`-FilterOU`) still apply.

On aggregated rows, the `Tier` column shows the tier of the highest-scoring individual SPN — the SPN that determined the object's score.

**Scoring**

Every individual SPN is scored on a fixed point system, then the
object's aggregate score is derived from its SPNs.

**Per‑SPN scoring**

| Signal | Points | Why |
|--------|--------|-----|
| Tier 1 (infrastructure) | **+15** | Real deployment, medium direct value |
| Tier 2 (web / remote / file share) | **+25** | Kerberos‑enabled network protocol, common entry point |
| Tier 3 --- named application category | **+20** | Business application backed by an account |
| Tier 3 --- unmapped class (RPC UUID, Other/Unknown) | **+10** | Unknown, but not noise |
| **Kerberoastable user account** | **+40** | Highest single signal --- offline crackable |
| Account disabled | **−15** | Not directly exploitable today |
| krbtgt account | **−20** | Special account, not a Kerberoast target |
| SAM matches svc, service, sql, app, backup, agent | **+5** | Naming convention signals a service account |
| SPN embeds an explicit port | **+3** | More specific than a wildcard SPN |

Scores are floored at **0** — negative totals become zero.

### Aggregated object score

The object's `Score` is derived from its individual SPN scores in one of two ways:

**Default — Max**

```
Score = highest individual SPN score on the object
```

A Kerberoastable web service account with one HTTP SPN scores 40 + 25 = 65. A Veeam server whose best SPN scores 20 stays at 20, no matter how many Veeam services it registers.

**-MaxPlusBonus**

```
Score = Max + min(20, 2 × (unique service classes − 1))
```

### The 35 threshold

`Score >= 35` is the practical high-value line:

- Any Tier-2 web service (25) plus any user account signal (+40 Kerberoast, +5 naming) crosses it.
- Any named application on a user account crosses it.
- Tier-0 noise never approaches it.

### Thresholding the output

Two switches apply the threshold:

```powershell
# Keep only objects with Score >= 30
.\Get-AllADSPNServices.ps1 -ExcludeDefaultNoise -MinScore 30

# Shorthand for -MinScore 35
.\Get-AllADSPNServices.ps1 -OnlyHighValue
```

`-MinScore` is applied **after aggregation**, on the object's final score — not on individual SPNs. This means an object whose best SPN scores 20 but has 10 unique classes survives a `-MinScore 35` filter, even though no single SPN on it would have.

---

## Requirements

Short list. Nothing exotic.

**Host**

- Domain-joined Windows machine.
- PowerShell 3.0 or later.
- No RSAT / AD module required.
- No domain admin required.
- No credentials required.

**Parameter reference**

| Parameter | What it does | When to use |
|-----------|--------------|-------------|
| -OutputPath | CSV output path. Default: ~\\Desktop\\AD_SPN_Report.csv. | Whenever you want the file elsewhere. |
| -Domain | Scope the LDAP query to one domain in the forest. Accepts full DNS name (ALBTEST.local) or short label (ALBTEST). Default whole forest | Per‑domain reporting, or when querying a whole forest is too slow. |
| -FilterOU | Array of OU names. Any object whose DN contains ,OU=\<name\>, is skipped before parsing. | Skip UNUSEDCOMPUTERS, DISABLEDCOMPUTERS, UNUSED,.. |
| -ServiceFilter | Array of substrings to narrow the LDAP query itself, e.g. 'MSSQLSvc','exchange'. | Focused runs (only SQL, only Exchange). Doesn't post‑filter --- an object's other SPNs still show. |
| -MaxObjects | Stop after N AD objects.default 0 = no limit. | First run on a huge forest; quick tests. |
| -ExcludeDefaultNoise | Drop Tier 0 only. | The default useful view. |
| -ExcludeInfrastructure | Drop Tier 1 only (Exchange, FIM, AGPM, clusters). | When you want applications + web only. |
| -ExcludeWebRemoteShare | Drop Tier 2 only (HTTP, HTTPS, CIFS, nfs, RDP, VPN). ⚠ Can hide Kerberoastable web accounts. | Rarely --- only when you explicitly don't want web/remote. |
| -OnlyApplicationServices | Preset: -ExcludeDefaultNoise + -ExcludeInfrastructure. | Named apps + web only. |
| -OnlyUserSPNs | Keep only SPNs on user objects (excludes computers, gMSAs). Includes disabled users. | User SPN inventory. |
| -OnlyKerberoastable | Keep only enabled, non‑krbtgt user accounts. The true Kerberoast list. | Offline cracking shortlist. |
| -MaxPlusBonus | Score = Max + min(20, 2 × (unique classes − 1)). | Reward servers running many distinct services. |
| -MinScore \<n\> | Keep only objects with aggregated Score \>= n. Applied **after** aggregation. | Threshold the output. |
| -OnlyHighValue | Alias for -MinScore 35. | Short triage list. |
| -GetAllSPNs | Bypass **all** content filters + reset MinScore to 0. Domain and OU scoping still apply. | Full audit, change detection, raw dump. |
| -NoSilent | return All the results collection to the pipeline. | Use NoSilent only in test environments. In production, it writes all SPNs, which can produce a lot of output. |

## Examples

```powershell
# 1. Full audit — every SPN, no filtering
.\Get-AllADSPNServices.ps1 -GetAllSPNs -OutputPath .\FullAudit.csv

# 2. Full noise-filtered ranking
.\Get-AllADSPNServices.ps1 -ExcludeDefaultNoise -OutputPath .\Ranked.csv

# 3. Per-domain report, skip specific OU trees
.\Get-AllADSPNServices.ps1 -Domain ALBTEST -ExcludeDefaultNoise `
    -FilterOU 'DISABLEDCOMPUTERS','UNUSEDCOMPUTERS' -OutputPath .\ALBTEST_Clean.csv

# 4. Kerberoast shortlist — one row per enabled user account
.\Get-AllADSPNServices.ps1 -OnlyKerberoastable -OutputPath .\Kerberoast.csv

# 5. Kerberoastable web service accounts (often overlooked)
.\Get-AllADSPNServices.ps1 -OnlyKerberoastable -ServiceFilter 'HTTP','HTTPS' `
    -OutputPath .\Kerberoast_Web.csv

# 6. Named apps + web, drop infra — app footprint
.\Get-AllADSPNServices.ps1 -OnlyApplicationServices -OutputPath .\Apps.csv

# 7. Scope to one domain
.\Get-AllADSPNServices.ps1 -Domain ALBTEST -ExcludeDefaultNoise -OutputPath .\ALBTEST.csv

# 8. SQL servers only
.\Get-AllADSPNServices.ps1 -ServiceFilter 'MSSQLSvc' -OutputPath .\SQL.csv

# 9. Short triage — only the top of the file (score more than 35)
.\Get-AllADSPNServices.ps1 -ExcludeDefaultNoise -OnlyHighValue -OutputPath .\Short.csv

# 10. Score more than 15, score calculated with maxplus formula
.\Get-AllADSPNServices.ps1 -ExcludeDefaultNoise -MaxPlusBonus -MinScore 15 -OutputPath .\Baseline.csv

# 11. Named application inventory (asset / licensing)
.\Get-AllADSPNServices.ps1 -OnlyApplicationServices -OutputPath .\AppInventory.csv
```

---

## Contributing

Pull requests are welcome — this tool gets better every time someone adds a class, fixes a tier, or finds a gap in a real forest.

