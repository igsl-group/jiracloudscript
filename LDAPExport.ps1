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

	You can also export LDAP server certificate chain: 
	.\LDAPExport.ps1 -Cert -Server [LDAP Server Name] -Port [LDAP Server Port]
	The whole certificate chain will be written to separate .cer files. File name is determined by certificate's DNS name.
	
.PARAMETER Cert
	Certificate mode. Retrieves server certificate from LDAP server.
	
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
	LDAP filter. Default is (&(objectClass=User)(mail=*)).
	
.PARAMETER Scope
	LDAP search scope. Valid values are Base, OneLevel or Subtree. Default is Subtree.

.PARAMETER Attributes
	Comma-delimited list of LDAP attributes to export. Default is sAMAccountName,mail.
	
.PARAMETER Out
	Path of output file. File will be overwritten.
	For -Export, default is [Server Name].export.
	For -Cred, default is [Server Name].cred.

.EXAMPLE
	.\LDAPExport.ps1 -Cert -Server 192.168.56.120 -Port 636

.EXAMPLE
	.\LDAPExport.ps1 -Cred -Server 192.168.56.120 -UserName Administrator
	
.EXAMPLE
	.\LDAPExport.ps1 -Export -Server 192.168.56.120 -Port 389 -BaseDN "CN=Users,DC=win2022,DC=kcwong,DC=igsl" -Filter "(objectClass=user)" -Scope Subtree -Attributes distinguishedName,phone,mobile,title,department
#>
Param(
	# Cert
	[Parameter(Mandatory, ParameterSetName = "Certificate")]
	[switch] $Cert,
	
	# Cred
	[Parameter(Mandatory, ParameterSetName = "Credential")]
	[switch] $Cred,
	
	[Parameter(Mandatory, ParameterSetName = "Credential")]
	[string] $UserName,
	
	# Export
	[Parameter(Mandatory, ParameterSetName = "Export")]
	[switch] $Export,
	
	[Parameter(Mandatory, ParameterSetName = "Credential")]
	[Parameter(Mandatory, ParameterSetName = "Certificate")]
	[Parameter(ParameterSetName = "Export")]
	[string] $Server = "127.0.0.1",

	[Parameter(Mandatory, ParameterSetName = "Certificate")]
	[Parameter(ParameterSetName = "Export")] 
	[int] $Port = 389,
	
	[Parameter(ParameterSetName = "Export")]
	[string] $CredFile,
	
	[Parameter(Mandatory, ParameterSetName = "Export")]
	[string] $BaseDN,
	
	[Parameter(ParameterSetName = "Export")]
	[string] $Filter = "(&(objectClass=User)(mail=*))",
	
	[Parameter(ParameterSetName = "Export")]
	[ValidateSet("Base", "OneLevel", "Subtree")]
	[string] $Scope = "Subtree",
	
	[Parameter(ParameterSetName = "Export")]
	[string[]] $Attributes = @(),
	
	# Common
	[Parameter(ParameterSetName = "Export")]
	[Parameter(ParameterSetName = "Credential")]
	[string] $Out
)

# Constants
Set-Variable -Name SAMAccountName -Value "samaccountname" -Option Constant
Set-Variable -Name Mail -Value "mail" -Option Constant
Set-Variable -Name CredExt -Value ".cred" -Option Constant
Set-Variable -Name ExportExt -Value ".export" -Option Constant

function ExportCert {
	Param (
		[X509Certificate] $Certificate
	)
	$Name = $Certificate.GetNameInfo("dnsName", $false) + ".cer"
	Export-Certificate -Cert $Certificate -FilePath $Name -Type CERT | Out-Null
	$Name
}

if ($Cert) {
	# Get server certificate
	try {
		$TcpSocket = New-Object Net.Sockets.TcpClient($Server, $Port)
		$TcpStream = $TcpSocket.GetStream()
		$Callback = {
			Param(
				$sender,
				$cert,
				$chain,
				$errors
			) 
			return $true
		}
		$SSLStream = New-Object -TypeName System.Net.Security.SSLStream -ArgumentList @($TcpStream, $True, $Callback)
		try {
			$SSLStream.AuthenticateAsClient($Server)
			$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
			$Chain = new-object security.cryptography.x509certificates.x509chain
			[void] $chain.Build($Certificate)
			Write-Output "Certificate chain written to: "
			$Chain.ChainElements | %{
				$Name = ExportCert $_.Certificate
				Write-Output $Name
			}
		} finally {
			$SSLStream.Dispose()
		}
	} finally {
		$TCPSocket.Dispose()
	}
} elseif ($Cred) {
	if (-not $Out) {
		$Out = $Server + $CredExt
	}
	# Get password and save as credential file
	$c = Get-Credential -UserName $UserName -Message "Test"
	if ($c.UserName -and $c.Password) {
		Export-Clixml -Path $Out -InputObject $c
		Write-Output "Credential file ${Out} created"
	} else {
		Write-Output "Credential not supplied"
	}
} elseif ($Export) {
	if (-not $Out) {
		$Out = $Server + $ExportExt
	}
	if (-not $CredFile) {
		$CredFile = $Server + $CredExt
	}
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
	if (Test-Path -Type Leaf $CredFile) {
		$c = Import-Clixml -Path $CredFile
		if ($c.UserName -and $c.Password) {
			$LDAP = New-Object System.DirectoryServices.DirectoryEntry( `
				"LDAP://${Server}:${Port}/${BaseDN}", `
				$c.UserName, `
				([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($c.Password))) `
			)
			# Search
			$Searcher = New-Object System.DirectoryServices.DirectorySearcher($LDAP)
			$Searcher.SearchScope = $Scope
			$Searcher.Filter = $Filter
			foreach ($Attr in $AttributeList) {
				[void] $Searcher.PropertiesToLoad.Add($Attr)
			}
			# For all results
			Set-Content -Path $Out -NoNewLine -Value ""
			[int] $Count = 0
			foreach ($User in $Searcher.FindAll()) {
				$Data = ""
				foreach ($Attr in $AttributeList) {
					$Data += $Attr + "=`"" + $User.Properties."$Attr" + "`"|"
				}
				$Data += "|"
				$Count++
				Add-Content -Path $Out -NoNewline -Value $Data
			}
			Write-Output "$Count user(s) written to $Out"
		} else {
			Write-Output "$CredFile is not a valid credential file"
		}
	} else {
		Write-Output "Credential file $CredFile does not exist"
	}
}
