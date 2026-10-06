<#
.SYNOPSIS
    Discovers, filters, scores, and aggregates services via SPN in the Active Directory forest.

.DESCRIPTION
    Queries the Global Catalog for objects with servicePrincipalName attributes,
    parses each SPN, categorizes and tiers them, then aggregates the result
    so each AD object appears exactly once with all of its services collapsed
    into a single row.

    Score is the highest individual SPN score on that object (Max).
    With -MaxPlusBonus, an extra +2 is added per additional unique service class.

.PARAMETER OutputPath
    CSV output path. Defaults to Desktop\AD_SPN_Report.csv.

.PARAMETER Domain
    Scope the search to a single domain in the forest. Accepts DNS name
    'ALBTEST.local or short label ('ALBTEST').
    Default: entire forest.

.PARAMETER ServiceFilter
    Array of substrings to restrict the LDAP query, e.g. 'MSSQLSvc','exchange'.

.PARAMETER OnlyUserSPNs
    Keep only SPNs registered on USER accounts (excludes computers and gMSAs).

.PARAMETER OnlyKerberoastable
    Keep only SPNs whose owning object is an enabled user account that is not krbtgt.

.PARAMETER OnlyApplicationServices
    Drop Tier 0 (default per-computer noise) and Tier 1 (infrastructure).

.PARAMETER OnlyHighValue
    Keep only objects whose aggregated Score >= 35.

.PARAMETER ExcludeDefaultNoise
    Drop Tier 0 only.

.PARAMETER ExcludeInfrastructure
    Drop Tier 1 only.

.PARAMETER ExcludeWebRemoteShare
    Drop Tier 2 only.

.PARAMETER GetAllSPNs
    Bypass ALL exclusion switches and reset MinScore to 0. Full audit.

.PARAMETER MinScore
    Keep only objects whose aggregated Score >= MinScore.

.PARAMETER MaxObjects
    Stop after processing N AD objects. 0 = no limit.

.PARAMETER MaxPlusBonus
    Add +2 to the aggregated score for each additional unique service class
    on the same object, capped at +20. Default is plain Max.

.PARAMETER FilterOU
    Array of OU names. Any object whose DN contains ',OU=<name>,' is skipped.

.PARAMETER NoSilent
    return All the results collection to the pipeline.

.EXAMPLE
    .\Get-AllADSPNServices.ps1 -OnlyKerberoastable -OutputPath .\Kerberoastable.csv

.EXAMPLE
    .\Get-AllADSPNServices.ps1 -ExcludeDefaultNoise -MaxPlusBonus -OutputPath .\Ranked.csv

.EXAMPLE 
    .\Get-AllADSPNServices.ps1 -GetAllSPNs -OutputPath .\FullAudit.csv

.NOTES
    PowerShell 3.0+  |  Domain-joined machine  |  Standard domain user is enough.
    References:
      https://adsecurity.org/?page_id=183

.AUTHOR
    Keykhosro Khosravani
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop\AD_SPN_Report.csv",
    [string[]]$ServiceFilter,
    [string]$Domain,
    [switch]$OnlyUserSPNs,
    [switch]$OnlyKerberoastable,
    [switch]$OnlyApplicationServices,
    [switch]$OnlyHighValue,
    [switch]$ExcludeDefaultNoise,
    [switch]$ExcludeInfrastructure,
    [switch]$ExcludeWebRemoteShare,
    [switch]$GetAllSPNs,
    [int]$MinScore = 0,
    [int]$MaxObjects = 0,
    [switch]$MaxPlusBonus,
    [string[]]$FilterOU = @(),
    #[string[]]$FilterOU = @('UNUSEDCOMPUTERS','DISABLEDCOMPUTERS','UNUSED'),
    [switch]$NoSilent
)

# ============================================================================
# SPN SERVICE CLASS REFERENCE (If you found a service class that isn't in the list ï¿½ tell me)
# ============================================================================
$SPNReference = @{
    # --- Database Services ---
    "MSSQLSvc"             = @{ Category = "Database";       Description = "Microsoft SQL Server" }
    "MSSQL"                = @{ Category = "Database";       Description = "Microsoft SQL Server (legacy)" }
    "SQLAgent"             = @{ Category = "Database";       Description = "SQL Server Agent" }
    "MSOLAPSvc"            = @{ Category = "Database";       Description = "SQL Server Analysis Services" }
    "MSOLAPDisco"          = @{ Category = "Database";       Description = "SQL Server Analysis Services Discovery" }
    "mongod"               = @{ Category = "Database";       Description = "MongoDB Enterprise" }
    "mongos"               = @{ Category = "Database";       Description = "MongoDB Enterprise (sharded)" }
    "hdb"                  = @{ Category = "Database";       Description = "SAP HANA Database" }
    "impala"               = @{ Category = "Database";       Description = "Cloudera Impala" }
    "hive"                 = @{ Category = "Database";       Description = "Hadoop Metastore" }

    # --- Web / HTTP Services ---
    "HTTP"                 = @{ Category = "Web";            Description = "HTTP Web Service (Kerberos)" }
    "HTTPS"                = @{ Category = "Web";            Description = "HTTPS Web Service" }
    "httpfs"               = @{ Category = "Web";            Description = "Hadoop HDFS over HTTP" }
    "www"                  = @{ Category = "Web";            Description = "Web Server" }

    # --- Mail Services ---
    "SMTP"                 = @{ Category = "Mail";           Description = "Simple Mail Transfer Protocol" }
    "SMTPSVC"              = @{ Category = "Mail";           Description = "SMTP Service" }
    "IMAP"                 = @{ Category = "Mail";           Description = "Internet Message Access Protocol" }
    "IMAP4"                = @{ Category = "Mail";           Description = "IMAP version 4" }
    "exchangeAB"           = @{ Category = "Mail";           Description = "Exchange Address Book" }
    "exchangeMDB"          = @{ Category = "Mail";           Description = "Exchange RPC Client Access" }
    "exchangeRFR"          = @{ Category = "Mail";           Description = "Exchange Address Book Service" }
    "POP"                  = @{ Category = "Mail";           Description = "POP Mail Service" }
    "POP3"                 = @{ Category = "Mail";           Description = "POP3 Mail Service" }

    # --- File / Storage Services ---
    "CIFS"                 = @{ Category = "FileShare";      Description = "Common Internet File System" }
    "nfs"                  = @{ Category = "FileShare";      Description = "Network File System" }
    "afpserver"            = @{ Category = "FileShare";      Description = "Apple Filing Protocol" }
    "Dfsr"                 = @{ Category = "FileShare";      Description = "Distributed File System Replication" }
    "fcsvr"                = @{ Category = "FileShare";      Description = "Apple Final Cut Server" }
    "iSCSITarget"          = @{ Category = "FileShare";      Description = "Microsoft iSCSI Target Server" }

    # --- Remote Access / Desktop ---
    "TERMSERV"             = @{ Category = "RemoteAccess";   Description = "Remote Desktop Services" }
    "TERMSRV"              = @{ Category = "RemoteAccess";   Description = "Remote Desktop Services" }
    "RestrictedKrbHost"    = @{ Category = "RemoteAccess";   Description = "Restricted Kerberos Host" }
    "vnc"                  = @{ Category = "RemoteAccess";   Description = "VNC Remote Desktop" }
    "vmrc"                 = @{ Category = "RemoteAccess";   Description = "VMware Remote Console" }
    "vpn"                  = @{ Category = "RemoteAccess";   Description = "VPN Service" }

    # --- Infrastructure / Directory ---
    "HOST"                 = @{ Category = "Infrastructure"; Description = "Host Computer Account" }
    "DNS"                  = @{ Category = "Infrastructure"; Description = "Domain Name Server" }
    "ldap"                 = @{ Category = "Infrastructure"; Description = "LDAP Directory Service" }
    "GC"                   = @{ Category = "Infrastructure"; Description = "Global Catalog" }
    "kadmin"               = @{ Category = "Infrastructure"; Description = "Kerberos Administration" }
    "krbtgt"               = @{ Category = "Infrastructure"; Description = "Kerberos Ticket Granting" }
    "E3514235"             = @{ Category = "Infrastructure"; Description = "NTDS DC RPC Replication" }
    "Dfsr-12F9A27C"        = @{ Category = "Infrastructure"; Description = "DFS Replication" }
    "MSClusterVirtualServer" = @{ Category = "Infrastructure"; Description = "Windows Cluster Server" }
    "NtFrs-88f5d2bd-b646-11d2-a6d3-00c04fc9b232" = @{ Category = "Infrastructure"; Description = "Legacy File Replication Service" }
    "MSServerCluster"      = @{ Category = "Infrastructure"; Description = "Windows Cluster Server" }
    "E3514235-4B06-11D1-AB04-00C04FC2DCD2" = @{ Category = "Infrastructure"; Description = "NTDS DC RPC Replication (DRSR)" }
    "Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04" = @{ Category = "Infrastructure"; Description = "DFS Replication RPC" }

    # --- Management / Monitoring ---
    "MSOMHSvc"             = @{ Category = "Management";     Description = "Microsoft SCOM 2012" }
    "MSOMSdkSvc"           = @{ Category = "Management";     Description = "Microsoft SCOM 2012 SDK" }
    "AdtServer"            = @{ Category = "Management";     Description = "SCOM ACS Collector" }
    "AgpmServer"           = @{ Category = "Management";     Description = "Microsoft AGPM" }
    "SCVMM"                = @{ Category = "Management";     Description = "System Center VMM" }
    "CmRcService"          = @{ Category = "Management";     Description = "SCCM Remote Control" }
    "FIMService"           = @{ Category = "Management";     Description = "Forefront Identity Manager" }
    "iem"                  = @{ Category = "Management";     Description = "IBM BigFix" }
    "WSMAN"                = @{ Category = "Management";     Description = "Windows Remote Management" }

    # --- Virtualization ---
    "Virtual"              = @{ Category = "Virtualization"; Description = "Hyper-V Virtualization" }
    "Hyper-V"              = @{ Category = "Virtualization"; Description = "Hyper-V Replica Service" }
    "STS"                  = @{ Category = "Virtualization"; Description = "VMware SSO Service" }
    "SoftGrid"             = @{ Category = "Virtualization"; Description = "Microsoft App-V" }

    # --- Collaboration / ERP ---
    "MSCRMAsyncService"    = @{ Category = "Collaboration";  Description = "Microsoft Dynamics 365" }
    "MSCRMSandboxService"  = @{ Category = "Collaboration";  Description = "Microsoft Dynamics 365 Sandbox" }
    "DynamicsNAV"          = @{ Category = "Collaboration";  Description = "Microsoft Dynamics NAV" }
    "NAV2016"              = @{ Category = "Collaboration";  Description = "Microsoft Dynamics NAV 2016" }
    "Cognos"               = @{ Category = "Collaboration";  Description = "IBM Cognos" }
    "BICMS"                = @{ Category = "Collaboration";  Description = "SAP Business Objects" }
    "BOCMS"                = @{ Category = "Collaboration";  Description = "SAP Business Objects" }
    "SAP"                  = @{ Category = "Collaboration";  Description = "SAP Service" }
    "SAS"                  = @{ Category = "Collaboration";  Description = "SAS Intelligence Platform" }

    # --- VoIP / Unified Comms ---
    "sip"                  = @{ Category = "VoIP";           Description = "Session Initiation Protocol" }
    "CUSESSIONKEYSVR"      = @{ Category = "VoIP";           Description = "Cisco Unity VOIP" }

    # --- Security / Identity ---
    "ckp_pdp"              = @{ Category = "Security";       Description = "Checkpoint Identity" }
    "secshd"               = @{ Category = "Security";       Description = "IBM InfoSphere" }
    "tapinego"             = @{ Category = "Security";       Description = "Routing / Firewall Services" }

    # --- Backup / Recovery ---
    "AcronisAgent"         = @{ Category = "Backup";         Description = "Acronis Backup Agent" }
    "CAXOsoftEngine"       = @{ Category = "Backup";         Description = "CA XOsoft Exchange Replication" }
    "CAARCserveRHAEngine"  = @{ Category = "Backup";         Description = "CA ArcServe RHA" }
    "VeeamBackupSvc"       = @{ Category = "Backup";         Description = "Veeam Backup Service" }
    "VeeamAgentWindows"    = @{ Category = "Backup";         Description = "Veeam Agent for Windows" }
    "VeeamTransportSvc"    = @{ Category = "Backup";         Description = "Veeam Transport / Data Mover" }
    "VeeamDeploySvc"       = @{ Category = "Backup";         Description = "Veeam Deployment Service" }
    "VeeamDistributionSvc" = @{ Category = "Backup";         Description = "Veeam Distribution Service" }
    "VeeamCatalogSvc"      = @{ Category = "Backup";         Description = "Veeam Catalog Service" }
    "VeeamMountSvc"        = @{ Category = "Backup";         Description = "Veeam Mount Service" }
    "VeeamGuestHelperSvc"  = @{ Category = "Backup";         Description = "Veeam Guest Interaction Proxy" }
    "VeeamFilesysVssSvc"   = @{ Category = "Backup";         Description = "Veeam VSS / Filesystem Snapshot" }
    "VeeamTapeSvc"         = @{ Category = "Backup";         Description = "Veeam Tape Service" }
    "VeeamCdpSvc"          = @{ Category = "Backup";         Description = "Veeam CDP Service" }
    "VeeamCloudConnectSvc" = @{ Category = "Backup";         Description = "Veeam Cloud Connect" }

    # --- DevOps / Big Data ---
    "Hue"                  = @{ Category = "DevOps";         Description = "Hadoop Hue Interface" }
    "hdfs"                 = @{ Category = "DevOps";         Description = "Hadoop Distributed FS" }
    "spark"                = @{ Category = "DevOps";         Description = "Apache Spark Server" }
    "RServer"              = @{ Category = "DevOps";         Description = "Microsoft R Server / ML Server" }
    "solr"                 = @{ Category = "DevOps";         Description = "Apache Solr" }
    "Storm"                = @{ Category = "DevOps";         Description = "Hadoop Nimbus Server" }
    "cvs"                  = @{ Category = "DevOps";         Description = "CVS Repository" }
}

# ============================================================================
# TIER DEFINITIONS
# ============================================================================
$Tier0_DefaultNoise = @(
    'host','restrictedkrbhost','ntfrs','dns','gc','ldap','kadmin','krbtgt',
    'e3514235','e3514235-4b06-11d1-ab04-00c04fc2dcd2',
    'dfsr','dfsr-12f9a27c-bf97-4787-9364-d31b6c55eb04',
    'wsman','termsrv','termserv'
)

$Tier1_Infrastructure = @(
    'exchangeab','exchangerfr','fimservice','agpmserver',
    'msclustervirtualserver','msservercluster',
    'ntfrs-88f5d2bd-b646-11d2-a6d3-00c04fc9b232',
    'exchangemdb'
)

$Tier2_WebRemoteShare = @(
    'http','https','www','httpfs',
    'cifs','nfs','afpserver','iscsitarget','fcsvr',
    'vnc','vmrc','vpn','sip','cusessionkeysvr'
)

# ============================================================================
# CATEGORY And TIER LOOKUP
# ============================================================================
$SPNCategoryLookup = @{}
foreach ($k in $SPNReference.Keys) {
    $SPNCategoryLookup[$k.ToLower()] = $SPNReference[$k]
}
$SPNWildcardKeys = $SPNReference.Keys | Sort-Object { $_.Length } -Descending

function Get-SPNCategory {
    param([string]$ServiceClass)
    if ([string]::IsNullOrEmpty($ServiceClass)) { return "Other/Unknown" }
    $lookup = $SPNCategoryLookup[$ServiceClass.ToLower()]
    if ($lookup) { return $lookup.Category }
    foreach ($key in $SPNWildcardKeys) {
        if ($ServiceClass.IndexOf($key, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $SPNReference[$key].Category
        }
    }
    if ($ServiceClass -match '^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$') {
        return "RPC/UUID"
    }
    return "Other/Unknown"
}

function Get-SPNTier {
    param([string]$ServiceClass)
    if ([string]::IsNullOrEmpty($ServiceClass)) { return 3 }
    $lc = $ServiceClass.ToLower()

    if ($Tier0_DefaultNoise -contains $lc)                 { return 0 }
    if ($Tier1_Infrastructure -contains $lc)               { return 1 }
    if ($Tier2_WebRemoteShare -contains $lc)               { return 2 }

    if ($lc -like 'dfsr-*')       { return 0 }
    if ($lc -like 'e3514235*')    { return 0 }
    if ($lc -like 'ntfrs-*')      { return 1 }

    return 3
}

# ============================================================================
# SPN PARSER
# ============================================================================
function Parse-SPN {
    param([string]$SPN)

    $result = [PSCustomObject]@{
        RawSPN       = $SPN
        ServiceClass = $null
        Hostname     = $null
        FQDN         = $null
        Port         = $null
        ServiceName  = $null
        IsValid      = $false
    }

    if ([string]::IsNullOrWhiteSpace($SPN)) { return $result }

    $parts = $SPN -split '/', 3

    if ($parts.Count -lt 2) {
        $result.ServiceClass = $parts[0]
        return $result
    }

    $result.ServiceClass = $parts[0]
    $hostPart = $parts[1]

    if ($hostPart -match '^([^:]+):(\d+)$') {
        $result.Hostname = $matches[1]
        $result.Port     = $matches[2]
    }
    elseif ($hostPart -match '^([^:]+):(.+)$') {
        $result.Hostname    = $matches[1]
        $result.ServiceName = $matches[2]
    }
    else {
        $result.Hostname = $hostPart
    }

    if ($parts.Count -ge 3) {
        $result.ServiceName = $parts[2]
    }

    if ($result.Hostname) {
        $result.FQDN = $result.Hostname
    }

    $result.IsValid = $true
    return $result
}

# ============================================================================
# SCORING
# ============================================================================
$NamedAppCategories = @(
    'Database','Mail','Backup','Collaboration','DevOps',
    'Security','VoIP','Virtualization','Management'
)

function Get-SPNScore {
    param(
        [int]$Tier,
        [string]$Category,
        [bool]$IsKerberoastable,
        [bool]$AccountDisabled,
        [bool]$IsKrbtgt,
        [string]$SAM,
        [string]$Port
    )

    $score = 0
    switch ($Tier) {
        0 { $score += 0 }
        1 { $score += 15 }
        2 { $score += 25 }
        3 {
            if ($NamedAppCategories -contains $Category) { $score += 20 }
            else                                         { $score += 10 }
        }
    }

    if ($IsKerberoastable) { $score += 40 }
    if ($AccountDisabled)  { $score -= 15 }
    if ($IsKrbtgt)         { $score -= 20 }
    if ($SAM -and ($SAM -match '(?i)svc|service|sql|app|backup|agent')) { $score += 5 }
    if ($Port)             { $score += 3 }

    if ($score -lt 0) { $score = 0 }
    return $score
}



if ($OnlyApplicationServices) {
    $ExcludeDefaultNoise    = $true
    $ExcludeInfrastructure  = $true
}
if ($OnlyKerberoastable) { $OnlyUserSPNs = $true }
if ($OnlyHighValue -and $MinScore -lt 35) { $MinScore = 35 }

if ($GetAllSPNs) {
    $ExcludeDefaultNoise     = $false
    $ExcludeInfrastructure   = $false
    $ExcludeWebRemoteShare   = $false
    $OnlyApplicationServices = $false
    $OnlyHighValue           = $false
    $MinScore                = 0
    $OnlyUserSPNs            = $false
    $OnlyKerberoastable      = $false
}

if ($OnlyUserSPNs -and $ExcludeWebRemoteShare) {
    Write-Warning "Combining -OnlyUserSPNs with -ExcludeWebRemoteShare may hide Kerberoastable HTTP/HTTPS service accounts. Consider using -OnlyKerberoastable instead."
}
if ($OnlyApplicationServices -and $ExcludeWebRemoteShare) {
    Write-Warning "-OnlyApplicationServices already keeps Tier 2 (web/remote/share). -ExcludeWebRemoteShare will now drop them."
}

# ============================================================================
# MAIN
# ============================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor DarkCyan
Write-Host " AD SPN Service Discovery (per-object, tiered, scored)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor DarkCyan

$scopeBits = @()
if ($OnlyKerberoastable) { $scopeBits += "kerberoastable users" }
elseif ($OnlyUserSPNs)   { $scopeBits += "user-account SPNs" }
if ($ExcludeDefaultNoise)   { $scopeBits += "no Tier 0" }
if ($ExcludeInfrastructure) { $scopeBits += "no Tier 1" }
if ($ExcludeWebRemoteShare) { $scopeBits += "no Tier 2" }
if ($MinScore -gt 0)        { $scopeBits += "score >= $MinScore" }
if ($scopeBits.Count -eq 0) { $scopeBits += "all SPNs (full audit)" }
$scope = $scopeBits -join " | "

$scoreMode = if ($MaxPlusBonus) { "Max + 2 per extra service class (cap +20)" } else { "Max" }

Write-Host "    Scope        : $scope"
Write-Host "    Score mode   : $scoreMode"
Write-Host "    Output file  : $OutputPath"
Write-Host ""

Write-Host "[+] Connecting to Active Directory Forest..." -ForegroundColor Cyan

$Forest     = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$RootDomain = $Forest.RootDomain

if ($Domain) {
    $targetDomain = $null

    $targetDomain = $Forest.Domains |
        Where-Object { $_.Name -ieq $Domain } |
        Select-Object -First 1

    if (-not $targetDomain) {
        $targetDomain = $Forest.Domains |
            Where-Object { ($_.Name -split '\.')[0] -ieq $Domain } |
            Select-Object -First 1
    }

    if (-not $targetDomain) {
        try {
            $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            $targetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
        }
        catch {
            throw "Domain '$Domain' could not be resolved. Check spelling or connectivity."
        }
    }

    $ResolvedDomain = $targetDomain.Name
    $RootDomainDN   = "DC=" + ($ResolvedDomain -replace '\.', ',DC=')
}
else {
    $ResolvedDomain = $RootDomain
    $RootDomainDN   = "DC=" + ($RootDomain -replace '\.', ',DC=')
}

$GCDN = "GC://$RootDomainDN"

Write-Host "    Forest Root Domain : $RootDomain" -ForegroundColor Gray
if ($Domain) {
    Write-Host "    Target Domain      : $ResolvedDomain (scoped)" -ForegroundColor Yellow
}
Write-Host "    Global Catalog DN  : $GCDN" -ForegroundColor Gray

$Root = [ADSI]$GCDN

if ($ServiceFilter) {
    $filterParts = foreach ($svc in $ServiceFilter) { "(serviceprincipalname=*$svc*)" }
    $LDAPFilter = "(|$($filterParts -join ''))"
    Write-Host "[+] Searching for SPNs matching: $($ServiceFilter -join ', ')" -ForegroundColor Cyan
}
else {
    $LDAPFilter = "(serviceprincipalname=*)"
    Write-Host "[+] Searching for all objects with an SPN..." -ForegroundColor Cyan
}

$Searcher = New-Object System.DirectoryServices.DirectorySearcher($Root, $LDAPFilter)
$Searcher.PageSize = 1000
$Searcher.PropertiesToLoad.AddRange(@(
    "serviceprincipalname","distinguishedname","name","samaccountname",
    "objectcategory","objectclass","useraccountcontrol",
    "operatingsystem","operatingsystemversion",
    "operatingsystemservicepack","lastlogontimestamp","description"
))

Write-Host "    Executing search..." -ForegroundColor Gray
$AllResults = $Searcher.FindAll()
Write-Host "    Found $($AllResults.Count) objects with SPNs" -ForegroundColor Green

# ============================================================================
# PARSE + TIER + SCORE + FILTER
# ============================================================================
Write-Host ""
Write-Host "[+] Parsing, tiering, and scoring SPNs..." -ForegroundColor Cyan

$Results          = New-Object System.Collections.Generic.List[object]
$ParseErrors      = 0
$TotalSPNs        = 0
$ProcessedObjects = 0
$SkippedNoise     = 0
$SkippedScore     = 0
$SkippedUser      = 0
$SkippedTier      = 0
$TotalObjects     = $AllResults.Count
$StoppedEarly     = $false

foreach ($result in $AllResults) {
    $ProcessedObjects++

    if ($MaxObjects -gt 0 -and $ProcessedObjects -gt $MaxObjects) {
        $StoppedEarly = $true
        break
    }

    if ($ProcessedObjects % 25 -eq 0 -or $ProcessedObjects -eq $TotalObjects) {
        $pct = 0
        if ($TotalObjects -gt 0) {
            $pct = [math]::Min(100, [int](($ProcessedObjects / $TotalObjects) * 100))
        }
        Write-Progress -Activity "Parsing SPNs" `
            -Status "$ProcessedObjects / $TotalObjects objects | $TotalSPNs SPNs kept" `
            -PercentComplete $pct
    }

    $props = $result.Properties

    $objName     = if ($props["name"])                    { @($props["name"])[0] }                    else { "" }
    $objDN       = if ($props["distinguishedname"])       { @($props["distinguishedname"])[0] }       else { "" }
    $objSam      = if ($props["samaccountname"])          { @($props["samaccountname"])[0] }          else { "" }
    $objCategory = if ($props["objectcategory"])          { @($props["objectcategory"])[0] }          else { "" }
    $objOS       = if ($props["operatingsystem"])         { @($props["operatingsystem"])[0] }         else { "" }
    $objOSVer    = if ($props["operatingsystemversion"])  { @($props["operatingsystemversion"])[0] }  else { "" }
    $objOSSP     = if ($props["operatingsystemservicepack"]) { @($props["operatingsystemservicepack"])[0] } else { "" }
    $objDesc     = if ($props["description"])             { @($props["description"])[0] }             else { "" }
    $objClasses  = if ($props["objectclass"])             { @($props["objectclass"]) }                else { @() }
    $objUAC      = if ($props["useraccountcontrol"])      { [int]@($props["useraccountcontrol"])[0] } else { 0 }

    $objDomain = ""
    if ($objDN -match 'DC=(.+)$') {
        $objDomain = ($matches[1] -replace ',DC=', '.')
    }

    $lastLogon = $null
    if ($props["lastlogontimestamp"]) {
        try {
            $lastLogon = [datetime]::FromFileTime([int64]@($props["lastlogontimestamp"])[0])
        } catch { }
    }

    if ($FilterOU -and $objDN) {
        $skip = $false
        foreach ($ou in $FilterOU) {
            if ($objDN -match "(?i),OU=$([regex]::Escape($ou)),") {
                $skip = $true
                break
            }
        }
        if ($skip) { continue }
    }

    $spnCollection = $props["serviceprincipalname"]
    if (-not $spnCollection) { continue }

    $isUserObject = (
        ($objClasses -contains 'user') -and
        (-not ($objClasses -contains 'computer')) -and
        (-not ($objClasses -contains 'msDS-GroupManagedServiceAccount'))
    )
    $accountDisabled  = (($objUAC -band 0x2) -ne 0)
    $isKrbtgt         = ($objSam -ieq 'krbtgt')
    $isKerberoastable = $isUserObject -and (-not $accountDisabled) -and (-not $isKrbtgt)

    if ($OnlyKerberoastable -and -not $isKerberoastable) { $SkippedUser++; continue }
    if ($OnlyUserSPNs -and -not $OnlyKerberoastable -and -not $isUserObject) { $SkippedUser++; continue }

    foreach ($spn in $spnCollection) {
        try {
            $parsed = Parse-SPN -SPN $spn

            $fqdn = $parsed.Hostname
            if ($fqdn -and $fqdn -notmatch '\.' -and $objDomain) {
                $fqdn = "$fqdn.$objDomain"
            }

            $category = Get-SPNCategory -ServiceClass $parsed.ServiceClass
            $tier     = Get-SPNTier     -ServiceClass $parsed.ServiceClass

            if ($ExcludeDefaultNoise    -and $tier -eq 0) { $SkippedNoise++; continue }
            if ($ExcludeInfrastructure  -and $tier -eq 1) { $SkippedTier++;  continue }
            if ($ExcludeWebRemoteShare  -and $tier -eq 2) { $SkippedTier++;  continue }

            $score = Get-SPNScore `
                -Tier $tier `
                -Category $category `
                -IsKerberoastable $isKerberoastable `
                -AccountDisabled $accountDisabled `
                -IsKrbtgt $isKrbtgt `
                -SAM $objSam `
                -Port $parsed.Port


            $Results.Add([PSCustomObject]@{
                Score            = $score
                Tier             = $tier
                Category         = $category
                ServiceClass     = $parsed.ServiceClass
                FQDN             = $fqdn
                Hostname         = $parsed.Hostname
                Port             = $parsed.Port
                ServiceName      = $parsed.ServiceName
                RawSPN           = $parsed.RawSPN
                ObjectName       = $objName
                SAMAccountName   = $objSam
                ObjectDN         = $objDN
                ObjectCategory   = $objCategory
                IsUserObject     = $isUserObject
                IsKerberoastable = $isKerberoastable
                AccountDisabled  = $accountDisabled
                Domain           = $objDomain
                OperatingSystem  = $objOS
                OSVersion        = $objOSVer
                OSServicePack    = $objOSSP
                LastLogon        = $lastLogon
                Description      = $objDesc
            })
            $TotalSPNs++
        }
        catch {
            $ParseErrors++
            Write-Warning "Failed to parse SPN: $spn -- $_"
        }
    }
}

Write-Progress -Activity "Parsing SPNs" -Completed

if ($StoppedEarly) {
    Write-Host "    Reached -MaxObjects limit ($MaxObjects) - stopped early." -ForegroundColor Yellow
}

# ============================================================================
# AGGREGATE: ONE ROW PER AD OBJECT
# ============================================================================
Write-Host ""
Write-Host "[+] Aggregating SPNs per AD object..." -ForegroundColor Cyan

$PerObjectRows = New-Object System.Collections.Generic.List[object]
$TotalRawSPNs  = $Results.Count

if ($Results.Count -gt 0) {
    foreach ($grp in ($Results | Group-Object ObjectDN)) {
        $rows = @($grp.Group)

        $classes    = @($rows.ServiceClass | Sort-Object -Unique)
        $categories = @($rows.Category     | Sort-Object -Unique)
        $rawSPNs    = @($rows.RawSPN       | Sort-Object -Unique)
        $fqdns      = @($rows.FQDN    | Where-Object { $_ } | Sort-Object -Unique)
        $ports      = @($rows.Port    | Where-Object { $_ } | Sort-Object -Unique)

        # --- Score aggregation ---
        $maxScore = ($rows | ForEach-Object { [int]$_.Score } | Measure-Object -Maximum).Maximum
        if ($MaxPlusBonus) {
            $bonus    = [Math]::Min(20, [Math]::Max(0, $classes.Count - 1) * 2)
            $aggScore = [int]$maxScore + $bonus
        }
        else {
            $aggScore = [int]$maxScore
        }

        $topRow = $rows | Sort-Object Score -Descending | Select-Object -First 1

        $topTier = $topRow.Tier

        if (($rows | Where-Object { $_.Tier -eq 2 }).Count -gt 0 -and $topTier -gt 2) {
            $topTier = 2
        }

        $PerObjectRows.Add([PSCustomObject]@{
            Score            = $aggScore
            MaxSPNScore      = [int]$maxScore
            Tier             = $topTier
            ServiceCount     = $classes.Count
            SPNCount         = $rawSPNs.Count
            Categories       = ($categories -join '; ')
            ServiceClasses   = ($classes -join '; ')
            FQDNs            = ($fqdns -join '; ')
            Ports            = ($ports -join '; ')
            RawSPNs          = ($rawSPNs -join ' | ')
            ObjectName       = $rows[0].ObjectName
            SAMAccountName   = $rows[0].SAMAccountName
            ObjectDN         = $rows[0].ObjectDN
            ObjectCategory   = $rows[0].ObjectCategory
            IsUserObject     = $rows[0].IsUserObject
            IsKerberoastable = ($rows.IsKerberoastable -contains $true)
            AccountDisabled  = $rows[0].AccountDisabled
            Domain           = $rows[0].Domain
            OperatingSystem  = $rows[0].OperatingSystem
            OSVersion        = $rows[0].OSVersion
            OSServicePack    = $rows[0].OSServicePack
            LastLogon        = $rows[0].LastLogon
            Description      = $rows[0].Description
        })
    }

    if ($MinScore -gt 0) {
        $before = $PerObjectRows.Count
        $PerObjectRows = $PerObjectRows | Where-Object { $_.Score -ge $MinScore }
        $SkippedScore  = $before - $PerObjectRows.Count
    }
}

Write-Host "    SPN rows before : $TotalRawSPNs" -ForegroundColor Gray
Write-Host "    Objects after   : $($PerObjectRows.Count)" -ForegroundColor Gray

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host ""
Write-Host "[+] Results Summary" -ForegroundColor Cyan
Write-Host "    Objects processed      : $ProcessedObjects"
Write-Host "    Raw SPN rows           : $TotalRawSPNs"
Write-Host "    Objects kept           : $($PerObjectRows.Count)"
Write-Host "    Skipped (Tier 0 noise) : $SkippedNoise"
Write-Host "    Skipped (Tier 1/2)     : $SkippedTier"
Write-Host "    Skipped (user filter)  : $SkippedUser"
Write-Host "    Skipped (below score)  : $SkippedScore"
Write-Host "    Parse errors           : $ParseErrors"

if ($PerObjectRows.Count -gt 0) {
    $userCount = ($PerObjectRows | Where-Object { $_.IsKerberoastable }).Count
    $highValue = ($PerObjectRows | Where-Object { $_.Score -ge 35 }).Count
    Write-Host "    Kerberoastable users   : $userCount" -ForegroundColor Yellow
    Write-Host "    High-value (score>=35) : $highValue" -ForegroundColor Yellow

    Write-Host ""
    Write-Host "[+] Objects by Tier:" -ForegroundColor Cyan
    $tierNames = @{0='Tier 0 - Default noise';1='Tier 1 - Infrastructure';2='Tier 2 - Web/Remote/Share';3='Tier 3 - Named apps'}
    $PerObjectRows | Group-Object Tier | Sort-Object Name | ForEach-Object {
        $label = $tierNames[[int]$_.Name]
        Write-Host ("    {0,-32} {1,5}" -f $label, $_.Count) -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "[+] Top 15 highest-scoring objects:" -ForegroundColor Cyan
    $PerObjectRows | Sort-Object Score -Descending | Select-Object -First 15 |
        ForEach-Object {
            $svc = $_.ServiceClasses
            if ($svc.Length -gt 55) { $svc = $svc.Substring(0, 52) + '...' }
            Write-Host ("    [{0,3}] {1,-22} {2,-30} {3}" -f $_.Score, $_.SAMAccountName, $svc, $_.FQDNs) -ForegroundColor Gray
        }
}

# ============================================================================
# EXPORT
# ============================================================================
if ($PerObjectRows.Count -gt 0) {
    try {
        $PerObjectRows |
            Sort-Object Score -Descending |
            Select-Object Score, MaxSPNScore, Tier, ServiceCount, SPNCount,
                          Categories, ServiceClasses, FQDNs, Ports, RawSPNs,
                          ObjectName, SAMAccountName, ObjectDN, ObjectCategory,
                          IsUserObject, IsKerberoastable, AccountDisabled, Domain,
                          OperatingSystem, OSVersion, OSServicePack, LastLogon, Description |
            Export-Csv -NoTypeInformation -Path $OutputPath -Encoding UTF8
        Write-Host "[+] Full report exported to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to export CSV: $_"
    }
}
else {
    Write-Host "[!] No SPNs matched the filter - nothing exported." -ForegroundColor Yellow
}

Write-Host ""

#Use NoSilent only in test environments. In production, it writes all SPNs, which can produce a lot of output.
if ($NoSilent) { return $PerObjectRows }
