#!powershell

#AnsibleRequires -CSharpUtil Ansible.Basic

$ErrorActionPreference = "Stop"

$spec = @{
    options = @{
        to = @{ type = "str"; required = $true }
        for = @{ type = "str"; required = $true }
        right = @{ type = "str"; required = $true }
        inheritance = @{ type = "str"; default="None"; choices = "None", "All", "Descendents", "SelfOnly" }
    }
    supports_check_mode = $false
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$to = $module.Params.to
$for = $module.Params.for
$right = $module.Params.right
$inheritance = $module.Params.inheritance

function Resolve-DistinguishedName {
  param([string]$Name)

  # 1) Already a DN
  if ($Name -match "^CN=.*?,DC=.*") {
      return $Name
  }

  # 2) DNS domain name → Domain DN
  #    e.g. contoso.com → DC=contoso,DC=com
  if ($Name -match "^[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+$") {
      try {
          $domain = Get-ADDomain -Identity $Name -ErrorAction Stop
          return $domain.DistinguishedName
      } catch {
          # Try resolving manually
          $parts = $Name.Split(".")
          if ($parts.Count -ge 2) {
              return ($parts | ForEach-Object { "DC=$_" }) -join ","
          }
          throw "Could not resolve domain name '$Name' to a DN."
      }
  }

  # 3) NETBIOS domain name (CONTOSO)
  try {
      $domain = Get-ADDomain -Identity $Name -ErrorAction Stop
      return $domain.DistinguishedName
  } catch { }

  # 4) Try resolving ANY AD object (user, group, OU, etc.)
  $obj = Get-ADObject -Filter {
      (samAccountName -eq $Name) -or
      (name -eq $Name) -or
      (displayName -eq $Name) -or
      (mail -eq $Name)
  } -Properties distinguishedName -ErrorAction SilentlyContinue

  if ($obj) {
      return $obj.DistinguishedName
  }

  throw "Could not resolve '$Name' to a distinguishedName."
}

# Convert friendly name → DN
$toDN = Resolve-DistinguishedName -Name $to

# Mapping friendly extended rights → GUIDs
$extendedRightsMap = @{
    "DS-Replication-Get-Changes"                = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    "DS-Replication-Get-Changes-All"            = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    "DS-Replication-Get-Changes-In-Filtered-Set"= "89e95b76-444d-4c62-991a-0facbeda640c"
    "Reanimate-Tombstones"                      = "4ecc03fe-ffc0-4947-b630-eb672a8a9d1a"
    "User-Force-Change-Password"                = "00299570-246d-11d0-a768-00aa006e0529"
}

# Convert inheritance string → enum
switch ($inheritance) {
    "None"        { $inheritEnum = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None }
    "All"         { $inheritEnum = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All }
    "Descendents" { $inheritEnum = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents }
    "SelfOnly"    { $inheritEnum = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren }
    default       { throw "Invalid inheritance value: $inheritance" }
}

# Determine if "Right" is:
#   - native AD right enum (e.g. GenericWrite)
#   - extended right friendly name (e.g. DS-Replication-Get-Changes)
#   - direct GUID provided by user
$objectTypeGUID = $null

# 1) Friendly extended right
if ($extendedRightsMap.ContainsKey($right)) {
    $objectTypeGUID = New-Object Guid $extendedRightsMap[$right]
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
}
# 2) Direct GUID input
elseif ($right -match "^[0-9a-fA-F-]{36}$") {
    $objectTypeGUID = New-Object Guid $right
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
}
# 3) Native AD right
else {
    try {
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::$right
        $objectTypeGUID = [Guid]::Empty
    }
    catch {
        throw "Unknown right: $right. Must be AD right name or extended-right GUID."
    }
}

# Load target AD object
$entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$toDN")
$acl = $entry.ObjectSecurity

# Build ACE
if ($adRights -eq [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
    # Extended Right → Must supply objectType GUID and inheritance
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        (New-Object System.Security.Principal.NTAccount($For)),
        $adRights,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $ObjectTypeGUID,
        $inheritEnum
    )
}
else {
    # Standard right → Uses constructor without objectType GUID
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        (New-Object System.Security.Principal.NTAccount($For)),
        $adRights,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $inheritEnum
    )
}

# Apply ACE
$acl.AddAccessRule($rule)
$entry.ObjectSecurity = $acl
$entry.CommitChanges()

# Output JSON for Ansible
$result = @{
    changed = $true
    granted_to = $for
    target = $to
    right = $right
    inheritance = $inheritance
}

try {
    $module.Result.values = @{}

    $module.Result.values = $result
    
    $module.ExitJson()
} catch {
    $module.FailJson($_.Exception.Message)
}
<#!
---
module: win_myfeature
short_description: My Windows feature module
description:
  - Demonstrates a custom Windows PowerShell module.
options:
  name:
    description: Name of resource
    required: false
author:
  - Your Name
#>