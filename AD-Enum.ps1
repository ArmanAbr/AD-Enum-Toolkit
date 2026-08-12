[CmdletBinding()]
param(
    [switch]$All,
    [switch]$DomainInfo,
    [switch]$Users,
    [switch]$Groups,
    [switch]$Computers,
    [switch]$OUs,
    [switch]$GPOs,
    [switch]$Trusts,
    [switch]$ACLs,
    [switch]$Kerberos,
    [switch]$BloodHound,
    [string]$OutputPath = ".\AD-Enum-$(Get-Date -Format 'yyyyMMdd-HHmm')",
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = "SilentlyContinue"
$startTime = Get-Date

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$global:results = @{}

function Write-EnumLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $colorMap = @{ "INFO" = "Cyan"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red" }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colorMap[$Level]
}

function Get-ADConnectionParams {
    $params = @{}
    if ($Server) { $params.Server = $Server }
    if ($Credential) { $params.Credential = $Credential }
    return $params
}

# ==================== DOMAIN INFO ====================
function Get-DomainEnumeration {
    Write-EnumLog "Enumerating Domain Information..." "INFO"
    $conn = Get-ADConnectionParams
    
    try {
        $domain = Get-ADDomain @conn
        $forest = Get-ADForest @conn
        $domainControllers = Get-ADDomainController -Filter * @conn | Select-Object Name, IPv4Address, Site, OperatingSystem, IsGlobalCatalog
        
        $result = [PSCustomObject]@{
            DomainName        = $domain.DNSRoot
            NetBIOSName       = $domain.NetBIOSName
            DomainSID         = $domain.DomainSID.Value
            ForestName        = $forest.Name
            FunctionalLevel   = $domain.DomainMode
            ForestFunctionalLevel = $forest.ForestMode
            DomainControllers = $domainControllers
            Sites             = $forest.Sites
            UPNSuffixes       = $forest.UPNSuffixes
        }
        
        $result | Export-Csv -Path "$OutputPath\DomainInfo.csv" -NoTypeInformation
        $result | ConvertTo-Json -Depth 5 | Out-File "$OutputPath\DomainInfo.json"
        $global:results.Domain = $result
        Write-EnumLog "Domain info saved. Found $($domainControllers.Count) DCs" "SUCCESS"
    }
    catch {
        Write-EnumLog "Failed to get domain info: $_" "ERROR"
    }
}

# ==================== USERS ====================
function Get-UserEnumeration {
    Write-EnumLog "Enumerating Users..." "INFO"
    $conn = Get-ADConnectionParams
    
    try {
        $properties = @("SamAccountName", "Name", "UserPrincipalName", "Enabled", "PasswordLastSet", 
                      "PasswordNeverExpires", "LastLogonDate", "ServicePrincipalName", 
                      "MemberOf", "Description", "DistinguishedName", "AdminCount")
        
        $users = Get-ADUser -Filter * -Properties $properties @conn | 
            Select-Object $properties, @{N="MemberOfCount";E={$_.MemberOf.Count}}
        
        # High-value targets
        $adminCountUsers = $users | Where-Object { $_.AdminCount -eq 1 }
        $spnUsers = $users | Where-Object { $_.ServicePrincipalName }
        $passNeverExpires = $users | Where-Object { $_.PasswordNeverExpires -eq $true }
        $inactiveUsers = $users | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-90) }
        
        $users | Export-Csv -Path "$OutputPath\Users_All.csv" -NoTypeInformation
        $adminCountUsers | Export-Csv -Path "$OutputPath\Users_AdminCount.csv" -NoTypeInformation
        $spnUsers | Export-Csv -Path "$OutputPath\Users_Kerberoastable.csv" -NoTypeInformation
        $passNeverExpires | Export-Csv -Path "$OutputPath\Users_PasswordNeverExpires.csv" -NoTypeInformation
        $inactiveUsers | Export-Csv -Path "$OutputPath\Users_Inactive90Days.csv" -NoTypeInformation
        
        Write-EnumLog "Users: $($users.Count) total, $($adminCountUsers.Count) adminCount, $($spnUsers.Count) Kerberoastable" "SUCCESS"
    }
    catch {
        Write-EnumLog "Failed to enumerate users: $_" "ERROR"
    }
}

# ==================== GROUPS ====================
function Get-GroupEnumeration {
    Write-EnumLog "Enumerating Groups..." "INFO"
    $conn = Get-ADConnectionParams
    
    try {
        $groups = Get-ADGroup -Filter * -Properties Members, Description @conn | 
            Select-Object Name, GroupCategory, GroupScope, Description, 
                @{N="MemberCount";E={$_.Members.Count}},
                @{N="Members";E={$_.Members -join "; "}}
        
        # High-privilege groups
        $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", 
                            "Administrators", "Account Operators", "Backup Operators",
                            "Print Operators", "Server Operators", "Group Policy Creator Owners")
        
        $privGroupData = foreach ($groupName in $privilegedGroups) {
            $group = Get-ADGroup -Filter { Name -eq $groupName } -Properties Members @conn
            if ($group) {
                $members = $group.Members | ForEach-Object { 
                    (Get-ADObject $_).Name 
                }
                [PSCustomObject]@{
                    GroupName = $groupName
                    MemberCount = $members.Count
                    Members = $members -join "; "
                }
            }
        }
        
        $groups | Export-Csv -Path "$OutputPath\Groups_All.csv" -NoTypeInformation
        $privGroupData | Export-Csv -Path "$OutputPath\Groups_Privileged.csv" -NoTypeInformation
        
        Write-EnumLog "Groups: $($groups.Count) total, $($privGroupData.Count) privileged groups enumerated" "SUCCESS"
    }
    catch {
        Write-EnumLog "Failed to enumerate groups: $_" "ERROR"
    }
}

# ==================== COMPUTERS ====================
function Get-ComputerEnumeration {
    Write-EnumLog "Enumerating Computers..." "INFO"
    $conn = Get-ADConnectionParams
    
    try {
        $computers = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, 
            IPv4Address, LastLogonDate, Description, ServicePrincipalName @conn |
            Select-Object Name, DNSHostName, Enabled, OperatingSystem, OperatingSystemVersion, 
                IPv4Address, LastLogonDate, Description, 
                @{N="SPNs";E={$_.ServicePrincipalName -join "; "}}
        
        $servers = $computers | Where-Object { $_.OperatingSystem -like "*Server*" }
        $workstations = $computers | Where-Object { $_.OperatingSystem -notlike "*Server*" }
        $inactiveComputers = $computers | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-90) }
        
        $computers | Export-Csv -Path "$OutputPath\Computers_All.csv" -NoTypeInformation
        $servers | Export-Csv -Path "$OutputPath\Computers_Servers.csv" -NoTypeInformation
        $inactiveComputers | Export-Csv -Path "$OutputPath\Computers_Inactive90Days.csv" -NoTypeInformation
        
        Write-EnumLog "Computers: $($computers.Count) total, $($servers.Count) servers, $($inactiveComputers.Count) inactive" "SUCCESS"
    }
    catch {
        Write-EnumLog "Failed to enumerate computers: $_" "ERROR"
    }
}

# ==================== OUs & GPOs ====================
function Get-OUAndGPOEnumeration {
    Write-EnumLog "Enumerating OUs and GPOs..." "INFO"
    $conn = Get-ADConnectionParams
    
    try {
        $ous = Get-ADOrganizationalUnit -Filter * @conn | 
            Select-Object Name, DistinguishedName, @{N="ChildObjects";E={(Get-ADObject -Filter * -SearchBase $_.DistinguishedName).Count}}
        
        $gpos = Get-GPO -All @conn | 
            Select-Object DisplayName, Id, GpoStatus, ModificationTime, @{N="LinkedOUs";E={$_.GetLinks().Count}}
        
        $ous | Export-Csv -Path "$OutputPath\OUs_All.csv" -NoTypeInformation
        $gpos | Export-Csv -Path "$OutputPath\GPOs_All.csv" -NoTypeInformation
        
        Write-EnumLog "OUs: $($ous.Count), GPOs: $($gpos.Count)" "SUCCESS"
    }
    catch {
        Write-EnumLog "Failed to enumerate OUs/GPOs: $_" "ERROR"
    }
}

# ==================== TRUSTS ====================
function Get-TrustEnumeration {
    Write-EnumLog "Enumerating Trusts..." "INFO"
    $conn = Get-ADConnectionParams
    
    try {
        $trusts = Get-ADTrust -Filter * @conn | 
            Select-Object Name, Source, Target, Direction, IntraForest, 
                ForestTransitive, SelectiveAuthentication, SIDFilteringForestAware
        
        $trusts | Export-Csv -Path "$OutputPath\Trusts.csv" -NoTypeInformation
        
        Write-EnumLog "Trusts: $($trusts.Count) found" "SUCCESS"
    }
    catch {
        Write-EnumLog "Failed to enumerate trusts: $_" "ERROR"
    }
}

# ==================== ACLs ====================
function Get-ACLEnumeration {
    Write-EnumLog "Enumerating ACLs (this may take a while)..." "INFO"
    $conn = Get-ADConnectionParams
    
    try {
        # Get interesting ACLs on the domain object
        $domainDN = (Get-ADDomain @conn).DistinguishedName
        $acl = Get-Acl -Path "AD:\$domainDN"
        
        $interestingRights = @("GenericAll", "GenericWrite", "WriteProperty", "WriteDacl", "WriteOwner", "ExtendedRight")
        $interestingAces = $acl.Access | Where-Object { 
            $_.ActiveDirectoryRights -match ($interestingRights -join "|") -and
            $_.IdentityReference -notmatch "NT AUTHORITY|CREATOR OWNER|BUILTIN"
        } | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType, AccessControlType
        
        $interestingAces | Export-Csv -Path "$OutputPath\ACLs_DomainObject.csv" -NoTypeInformation
        
        # Check for DCSync rights
        $dcsyncRights = $acl.Access | Where-Object { 
            $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or  # DS-Replication-Get-Changes
            $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"     # DS-Replication-Get-Changes-All
        } | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
        
        $dcsyncRights | Export-Csv -Path "$OutputPath\ACLs_DCSyncRights.csv" -NoTypeInformation
        
        Write-EnumLog "ACLs: $($interestingAces.Count) interesting ACEs, $($dcsyncRights.Count) DCSync rights" "SUCCESS"
    }
    catch {
        Write-EnumLog "Failed to enumerate ACLs: $_" "ERROR"
    }
}

# ==================== KERBEROS ====================
function Get-KerberosEnumeration {
    Write-EnumLog "Enumerating Kerberos configurations..." "INFO"
    $conn = Get-ADConnectionParams
    
    try {
        # AS-REP Roastable users (DONT_REQ_PREAUTH)
        $asrepUsers = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties SamAccountName @conn |
            Select-Object SamAccountName
        
        # Kerberoastable SPNs
        $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName, SamAccountName @conn |
            Select-Object SamAccountName, @{N="SPNs";E={$_.ServicePrincipalName -join "; "}}
        
        $asrepUsers | Export-Csv -Path "$OutputPath\Kerberos_ASREP-Roastable.csv" -NoTypeInformation
        $spnUsers | Export-Csv -Path "$OutputPath\Kerberos_Kerberoastable.csv" -NoTypeInformation
        
        Write-EnumLog "Kerberos: $($asrepUsers.Count) AS-REP roastable, $($spnUsers.Count) Kerberoastable" "SUCCESS"
    }
    catch {
        Write-EnumLog "Failed to enumerate Kerberos info: $_" "ERROR"
    }
}

# ==================== BLOODHOUND ====================
function Invoke-BloodHoundCollection {
    Write-EnumLog "Starting BloodHound data collection..." "INFO"
    
    $sharphoundPath = ".\SharpHound.ps1"
    if (-not (Test-Path $sharphoundPath)) {
        Write-EnumLog "SharpHound.ps1 not found. Download from BloodHound repo." "WARNING"
        return
    }
    
    try {
        Import-Module $sharphoundPath
        Invoke-BloodHound -CollectionMethod All -OutputDirectory $OutputPath -ZipFileName "BloodHound.zip"
        Write-EnumLog "BloodHound collection complete" "SUCCESS"
    }
    catch {
        Write-EnumLog "BloodHound collection failed: $_" "ERROR"
    }
}

# ==================== MAIN EXECUTION ====================
if ($All) {
    $DomainInfo = $Users = $Groups = $Computers = $OUs = $GPOs = $Trusts = $ACLs = $Kerberos = $true
}

if ($DomainInfo) { Get-DomainEnumeration }
if ($Users) { Get-UserEnumeration }
if ($Groups) { Get-GroupEnumeration }
if ($Computers) { Get-ComputerEnumeration }
if ($OUs -or $GPOs) { Get-OUAndGPOEnumeration }
if ($Trusts) { Get-TrustEnumeration }
if ($ACLs) { Get-ACLEnumeration }
if ($Kerberos) { Get-KerberosEnumeration }
if ($BloodHound) { Invoke-BloodHoundCollection }

$elapsed = (Get-Date) - $startTime
Write-EnumLog "Enumeration complete! Results saved to: $OutputPath (Duration: $($elapsed.ToString('mm\:ss')))" "SUCCESS"
Write-EnumLog "Run 'Get-ChildItem $OutputPath' to see all output files." "INFO"
