<#
.SYNOPSIS
	Export LDAP data into a format used by Automation rule to import.

.DESCRIPTION
	Export LDAP data into a format used by Automation rule to import.

	First create a credential file: 
	.\LDAPExport.ps1 -Cred -UserName [User Name] -Out [Credential File]
	A dialog will appear to collect the password.

	Then run export mode with the same Windows user: 
	.\LDAPExport.ps1 -Export -Server [LDAP Server Name] -Port [LDAP Server Port] -CredFile [Credential File] -BaseDN [Base DN] -Scope Subtree -Filter [LDAP Filter] -Attributes "[Attribute List]" -Out [Output File]
	"mail" and "sAMAccountName" attributes are always included.
	
	Format of export data is: 
	[Attribute Name]="[Attribute Value]"|[... more attributes]||[... more users]
	
.PARAMETER Cred
	Creates a credential file to protect user name and password.

.PARAMETER UserName
	User name to authenticate with LDAP server.
	
.PARAMETER Export
	Export mode. Exports data from LDAP server.
	
.PARAMETER Server
	LDAP server name or IP address. Default is 127.0.0.1.
	
.PARAMETER Port
	LDAP server port. Default is 389.
	
.PARAMETER BaseDN
	Base DN to bind to.
	
.PARAMETER Filter
	LDAP filter. Default is (objectClass=user).
	
.PARAMETER Scope
	LDAP search scope. Valid values are Base, OneLevel or Subtree. Default is Subtree.

.PARAMETER Attributes
	Comma-delimited list of LDAP attributes to export. Default is sAMAccountName,mail.
	
.PARAMETER Out
	Path of output file. File will be overwritten.
	For -Export, default is LDAPExport.txt.
	For -Cred, default is LDAPExport.cred.

.EXAMPLE
	.\LDAPExport.ps1 -Cred -UserName Administrator
	
.EXAMPLE
	.\LDAPExport.ps1 -Export -Server 192.168.56.120 -Port 389 -BaseDN "CN=Users,DC=win2022,DC=kcwong,DC=igsl" -Filter "(objectClass=user)" -Scope Subtree -Attributes distinguishedName,phone,mobile,title,department
#>
Param(
	# Cred
	[Parameter(Mandatory, ParameterSetName = "CreateCredential")]
	[switch] $Cred,
	
	[Parameter(Mandatory, ParameterSetName = "CreateCredential")]
	[string] $UserName,
	
	# Export
	[Parameter(Mandatory, ParameterSetName = "Export")]
	[switch] $Export,
	
	[Parameter(ParameterSetName = "Export")]
	[string] $Server = "127.0.0.1",

	[Parameter(ParameterSetName = "Export")] 
	[int] $Port = 389,
	
	[Parameter(ParameterSetName = "Export")]
	[ValidateScript({
		if (Test-Path -PathType Leaf $_) {
			$c = Import-Clixml -Path $_
			if ($c.UserName -and $c.Password) {
				$true
			} else {
				throw "Please provide valid credential file"
			}
		} else {
			throw "Please provide path to credential file"
		}
	})]
	[string] $CredFile = "LDAPExport.cred",
	
	[Parameter(Mandatory, ParameterSetName = "Export")]
	[string] $BaseDN,
	
	[Parameter(ParameterSetName = "Export")]
	[string] $Filter = "(objectClass=User)",
	
	[Parameter(ParameterSetName = "Export")]
	[ValidateSet("Base", "OneLevel", "Subtree")]
	[string] $Scope = "Subtree",
	
	[Parameter(ParameterSetName = "Export")]
	[string[]] $Attributes = @(),
	
	# Common
	[Parameter(ParameterSetName = "Export")]
	[Parameter(ParameterSetName = "CreateCredential")]
	[string] $Out = $(
		if ($Export) {
			"LDAPExport.txt"
		} elseif ($Cred) {
			"LDAPExport.cred"
		}
	)
)

# Constants
Set-Variable -Name SAMAccountName -Value "samaccountname" -Option Constant
Set-Variable -Name Mail -Value "mail" -Option Constant

if ($Cred) {
	# Get password and save as credential file
	$c = Get-Credential -UserName $UserName -Message "Test"
	if ($c.UserName -and $c.Password) {
		Export-Clixml -Path $Out -InputObject $c
		Write-Output "Credential file ${Out} created"
	} else {
		Write-Output "Credential not supplied"
	}
} elseif ($Export) {
	$AttributeList = [System.Collections.ArrayList]::new()
	foreach ($Attr in $Attributes) {
		[void] $AttributeList.Add($Attr.ToLower())
	}
	# Always include attributes
	if (-not $AttributeList.Contains($Mail)) {
		[void] $AttributeList.Add($Mail)
	}
	if (-not $AttributeList.Contains($SAMAccountName)) {
		[void] $AttributeList.Add($SAMAccountName)
	}
	# Get credential
	$c = Import-Clixml -Path $CredFile
	$LDAP = New-Object System.DirectoryServices.DirectoryEntry( `
		"LDAP://${Server}:${Port}/${BaseDN}", `
		$c.UserName, `
		([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($c.Password))) `
	)
	# Search
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher($LDAP)
	$Searcher.SearchScope = "Subtree"
	$Searcher.Filter = "(objectClass=user)"
	foreach ($Attr in $AttributeList) {
		[void] $Searcher.PropertiesToLoad.Add($Attr)
	}
	# For all results
	Set-Content -Path $Out -NoNewLine -Value ""
	[int] $Count = 0
	foreach ($User in $Searcher.FindAll()) {
		if ($User.Properties."$Mail") {
			$Data = ""
			foreach ($Attr in $AttributeList) {
				$Data += $Attr + "=`"" + $User.Properties."$Attr" + "`"|"
			}
			$Data += "|"
			$Count++
			Add-Content -Path $Out -NoNewline -Value $Data
		} else {
			$LoginID = $User.Properties."$SAMAccountName"
			Write-Output "$LoginID has no $Mail attribute, user is ignored"
		}
	}
	Write-Output "$Count user(s) written to $Out"
}
