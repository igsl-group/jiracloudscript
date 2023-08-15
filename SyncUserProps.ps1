<#
.SYNOPSIS 
	Synchronize LDAP user attributes to user properties in Jira Cloud.
	
	A. LDAP Server Certficate 
	=========================
	If SSL is required to connect to LDAP server, please ensure the server certificates are trusted.
	1. Use -GetCert to export LDAP server certificate chain to files.
	2. Import the root certificate to Windows certificate store under "Trusted Root Certification Authorities".
	
	B. Credential Files
	===================
	You need to authenticate to both LDAP server and Jira Cloud to synchronize LDAP attributes to user properties in Jira Cloud.
	To support scheduled execution, you can create encrypted credential files to protect the password/API token.
	1. Use -LdapCred to create credential file to LDAP server.
	2. Use -JiraCred to create credential file for Jira Cloud domain.
	3. The credential files can only be decrypted by the same Windows user used to create them. 
	4. So make sure you create them with the same user used in the scheduled task.
	
	C. Synchronize LDAP Attributes to User properties
	=================================================
	1. Use -Sync to synchronize LDAP attributes to user properties.
	2. A log file named SyncUserProps.yyyyMMddHHmmss.log will be created based on the start time.
	
	D. Manage User Properties
	=========================
	You can use this script to manage user properties in Jira Cloud.
	1. Use -GetProp to retrieve user properties.
	2. Use -SetProp to create/update user properties.
	3. Use -DelProp to remove user properties.
	
.PARAMETER LdapCred
	Create encrypted credential file for LDAP server. 
	The credential file can only be decrypted with the same user used to create it.
	
.PARAMETER JiraCred
	Create encrypted credential file for Jira Cloud.
	The credential file can only be decrypted with the same user used to create it.
	
.PARAMETER Sync
	Synchronize user properties using LDAP user attributes.
	
.PARAMETER GetCert
	Export LDAP server certificate chain to files.
	
.PARAMETER GetProp
	Read user properties for a specific user.
	
.PARAMETER SetProp
	Create/update user properties for a specific user.
	
.PARAMETER DelProp
	Delete user property for a specific user.

.PARAMETER LdapServer
	LDAP server name or IP address. If SSL is used, this must match DNS name in certificate.

.PARAMETER LdapPort
	LDAP server port.

.PARAMETER Domain
	Jira Cloud domain name.
	
.PARAMETER Out
	Output file.
	For -LdapCred, default is [LdapServer].cred.
	For -JiraCred, default is [Domain].cred.
	
.PARAMETER UserName
	User name for LDAP server.

.PARAMETER UserEmail
	User email address for Jira Cloud. This user must have administrator rights.

.PARAMETER LdapCredFile
	LDAP credential file to use. Default is [LdapServer].cred.
	
.PARAMETER JiraCredFile
	Jira Cloud credential file to use. Default is [Domain].cred.
	
.PARAMETER BaseDN
	LDAP search base. 
	Surround in double quotes in shell.
	
.PARAMETER Filter
	LDAP search filter. Default is (&(objectClass=user)(mail=*)).
	Surround in double quotes in shell.

.PARAMETER Scope
	LDAP search scope. Base|OneLevel|Subtree. Default is Subtree.
	
.PARAMETER AttributeMap
	A map of LDAP attribute names to user property names.
	Key is LDAP attribute name, value is user property name.
	e.g. @{'sAMAccountName'='Login ID';'lastLogonTimestamp'='Last Login'}
	Do not surround in double quotes in shell.
	
.PARAMETER LogDir
	Log directory. Log file SyncUserProps.[yyyyMMddHHmmss].log will be created inside.
	If not specified, defaults to current directory.
	
.PARAMETER Prop
	User property name.
	
.PARAMETER Value
	User property value.
	Surround in double quotes in shell.
	
.EXAMPLE
	.\SyncUserProps -LdapCred -LdapServer ldap.fubon.com -UserName fubon\Administrator
	
	Create credential file for LDAP server.
	
.EXAMPLE
	.\SyncUserProps -JiraCred -Domain fbhkitsm.atlassian.net -UserEmail wps.fbhk@fubon.com
	
	Create credential file for Jira Cloud domain.
	
.EXAMPLE
	.\SyncUserProps -Sync -LdapServer ldap.fubon.com -Domain fbhkitsm.atlassian.net -BaseDN "cn=User,ou=fubon,dc=com"
	
	Synchronize specified attributes of LDAP user found to user properties in Jira Cloud domain.
	You can specify custom LDAP search criteria by providing -Filter parameter, e.g. -Filter "(&(objectClass=User)(mail=*)(sn=Chan))".
	You can control which LDAP attribute is written to which user property by providing -AttributeMap parameter, e.g. -AttributeMap @{'title'='Title'; 'phone'='Contact Number'}
	You can specify credential files to use by providing -JiraCredFile and -LdapCredFile parameters.

.EXAMPLE
	.\SyncUserProps -GetProp -Domain fbhkitsm.atlassian.net -UserEmail wps.fbhk@fubon.com -Prop TestProperty

	Retrieve user property of specified user.
	If -Prop is omitted, all properties will be retrieved.

.EXAMPLE
	.\SyncUserProps -SetProp -Domain fbhkitsm.atlassian.net -UserEmail wps.fbhk@fubon.com -Prop TestProperty -Value TestValue
	
	Set user property.
	
.EXAMPLE
	.\SyncUserProps -DelProp -Domain fbhkitsm.atlassian.net -UserEmail wps.fbhk@fubon.com -Prop PropertyToDelete

	Delete user property. Please note that the action is not reversible.
#>
Param(
	# Switch
	[Parameter(Mandatory, ParameterSetName = "LdapCred")]
	[switch] $LdapCred,
		
	[Parameter(Mandatory, ParameterSetName = "JiraCred")]
	[switch] $JiraCred,
	
	[Parameter(Mandatory, ParameterSetName = "Sync")]
	[switch] $Sync,
	
	[Parameter(Mandatory, ParameterSetName = "GetCert")]
	[switch] $GetCert,
	
	[Parameter(Mandatory, ParameterSetName = "GetProp")]
	[switch] $GetProp,

	[Parameter(Mandatory, ParameterSetName = "SetProp")]
	[switch] $SetProp,

	[Parameter(Mandatory, ParameterSetName = "DelProp")]
	[switch] $DelProp,
	
	[Parameter(Mandatory, ParameterSetName = "LdapCred")]
	[Parameter(Mandatory, ParameterSetName = "GetCert")]
	[Parameter(Mandatory, ParameterSetName = "Sync")]
	[string] $LdapServer,
	
	[Parameter(Mandatory, ParameterSetName = "GetCert")]
	[Parameter(Mandatory, ParameterSetName = "Sync")]
	[string] $LdapPort,
	
	[Parameter(Mandatory, ParameterSetName = "SetProp")]
	[Parameter(Mandatory, ParameterSetName = "DelProp")]
	[Parameter(Mandatory, ParameterSetName = "GetProp")]
	[Parameter(Mandatory, ParameterSetName = "Sync")]
	[Parameter(Mandatory, ParameterSetName = "JiraCred")]
	[string] $Domain,
	
	[Parameter(ParameterSetName = "LdapCred")]
	[Parameter(ParameterSetName = "JiraCred")]
	[string] $Out,
	
	[Parameter(Mandatory, ParameterSetName = "LdapCred")]
	[string] $UserName,
	
	[Parameter(Mandatory, ParameterSetName = "SetProp")]
	[Parameter(Mandatory, ParameterSetName = "DelProp")]
	[Parameter(Mandatory, ParameterSetName = "GetProp")]
	[Parameter(Mandatory, ParameterSetName = "JiraCred")]
	[string] $UserEmail,
	
	[Parameter(ParameterSetName = "Sync")]
	[string] $LdapCredFile,
	
	[Parameter(ParameterSetName = "SetProp")]
	[Parameter(ParameterSetName = "DelProp")]
	[Parameter(ParameterSetName = "Sync")]
	[Parameter(ParameterSetName = "GetProp")]
	[string] $JiraCredFile,
	
	[Parameter(Mandatory, ParameterSetName = "Sync")]
	[string] $BaseDN,
	
	[Parameter(ParameterSetName = "Sync")]
	[string] $Filter = "(&(objectClass=User)(mail=*))",
	
	[Parameter(ParameterSetName = "Sync")]
	[ValidateSet("Base", "OneLevel", "Subtree")]
	[string] $Scope = "Subtree",
	
	[Parameter(ParameterSetName = "Sync")]
	[hashtable] $AttributeMap = @{
		"sAMAccountName" = "Login ID";
		"lastLogonTimestamp" = "Last Login";
	},
	
	[Parameter(ParameterSetName = "Sync")]
	[string] $LogDir = ".\",
	
	[Parameter(ParameterSetName = "GetProp")]
	[Parameter(Mandatory, ParameterSetName = "SetProp")]
	[Parameter(Mandatory, ParameterSetName = "DelProp")]
	[string] $Prop,
	
	[Parameter(Mandatory, ParameterSetName = "SetProp")]
	[string] $Value
)

# Constants
Set-Variable -Name Mail -Value "mail" -Option Constant
Set-Variable -Name CredExt -Value ".cred" -Option Constant

class RestException : Exception {
    RestException($Message) : base($Message) {
    }
}

function WriteCred {
	param (
		[string] $Message,
		[string] $UserName,
		[string] $Out
	)
	$c = Get-Credential -UserName $UserName -Message $Message
	if ($c.UserName -and $c.Password) {
		Export-Clixml -Path $Out -InputObject $c
	} else {
		throw "Cancelled by user"
	}
}

# Call Invoke-WebRequest without throwing exception on 4xx/5xx 
function WebRequest {
	param (
		[string] $Uri,
		[string] $Method,
		[hashtable] $Headers,
		[object] $Body
	)
	$Response = $null
	try {
		$script:ProgressPreference = 'SilentlyContinue'    # Subsequent calls do not display UI.
		$Response = Invoke-WebRequest -Method $Method -Header $Headers -Uri $Uri -Body $Body
	} catch {
		$Response = @{}
		$Response.StatusCode = $_.Exception.Response.StatusCode.value__
		$Response.content = $_.Exception.Message
	} finally {
		$script:ProgressPreference = 'Continue'            # Subsequent calls do display UI.
	}
	$Response
}

function GetAuthHeader {
	param (
		[PSCredential] $Credential
	)
	[hashtable] $Headers = @{
		"Content-Type" = "application/json"
	}
	$Auth = [Convert]::ToBase64String(
		[Text.Encoding]::ASCII.GetBytes(
			$Credential.UserName + ":" + 
			[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
		)
	)
	$Headers.Authorization = "Basic " + $Auth
	$Headers
}

function UpdateUserProperty {
	param (
		[hashtable] $Headers,
		[string] $UserMail,
		[string] $AccountId,
		[string] $PropertyName,
		[string] $PropertyValue
	)
	$Uri = "https://" + $Domain + "/rest/api/3/user/properties/" + [uri]::EscapeDataString($PropertyName) + "?accountId=" + [uri]::EscapeDataString($AccountId)
	$Parameters = "`"$PropertyValue`""
	$Response = WebRequest -Method "PUT" -Header $Headers -Uri $Uri -Body $Parameters
	if ($Response.StatusCode -ne 200 -and $Response.StatusCode -ne 201) {
		throw [RestException]::new("${UserMail}: Failed to set user property `"${PropertyName}`": " + $Response.StatusCode)
	}
}

function DeleteUserProperty {
	param (
		[hashtable] $Headers,
		[string] $UserMail,
		[string] $AccountId,
		[string] $PropertyName
	)
	$Uri = "https://" + $Domain + "/rest/api/3/user/properties/" + [uri]::EscapeDataString($PropertyName) + "?accountId=" + [uri]::EscapeDataString($AccountId)
	$Response = WebRequest -Method "DELETE" -Header $Headers -Uri $Uri
	if ($Response.StatusCode -eq 404) {
		throw [RestException]::new("${UserMail}: Property `"${PropertyName}`" does not exist")
	} elseif ($Response.StatusCode -ne 204) {
		throw [RestException]::new("${UserMail}: Failed to delete user property `"${PropertyName}`": " + $Response.StatusCode)
	}
}

function GetUserPropertyKeys {
	param (
		[hashtable] $Headers,
		[string] $UserMail,
		[string] $AccountId
	)
	$Uri = "https://" + $Domain + "/rest/api/3/user/properties?accountId=" + [uri]::EscapeDataString($AccountId)
	$Response = WebRequest -Method "GET" -Header $Headers -Uri $Uri
	if ($Response.StatusCode -ne 200) {
		throw [RestException]::new("${UserMail}: Failed to get user property keys: " + $Response.StatusCode)
	}
	$Json = $Response.content | ConvertFrom-Json
	$KeyList = [System.Collections.ArrayList]::new()
	foreach ($Key in $Json.Keys) {
		[void] $KeyList.Add($Key.key)
	}
	$KeyList
}

function GetUserProperty {
	param (
		[hashtable] $Headers,
		[string] $UserMail,
		[string] $AccountId,
		[string] $PropertyName
	)
	$Uri = "https://" + $Domain + "/rest/api/3/user/properties/" + [uri]::EscapeDataString($PropertyName) + "?accountId=" + [uri]::EscapeDataString($AccountId)
	$Response = WebRequest -Method "GET" -Header $Headers -Uri $Uri
	if ($Response.StatusCode -eq 404) {
		throw [RestException]::new("${UserMail}: Property `"${PropertyName}`" not found")
	} elseif ($Response.StatusCode -eq 200) {
		$Json = $Response.content | ConvertFrom-Json
		$Json.value
	} else {
		throw [RestException]::new("${UserMail}: Failed to get user property `"${PropertyName}`": " + $Response.StatusCode)
	}
}

function GetAccountIds {	
	param (
		[hashtable] $Headers,
		[string] $Email
	)
	$Uri = "https://" + $Domain + "/rest/api/3/user/search"
	$Parameters = @{
		query = $Email
	}
	$Response = WebRequest -Method "GET" -Header $Headers -Uri $Uri -Body $Parameters
	if ($Response.StatusCode -ne 200) {
		throw [RestException]::new("${Email}: Failed to retrieve account ID: " + $Response.StatusCode)
	}
	$Json = $Response.content | ConvertFrom-Json
	$AccountIds = [System.Collections.ArrayList]::new()
	foreach ($Item in $Json) {
		[void] $AccountIds.Add($Item.accountId)
	}
	if ($AccountIds.Count -eq 0) {
		throw [RestException]::new("${Email}: No Jira Cloud user with matching email found")
	} else {
		$AccountIds
	}
}

function GetCredential {
	param (
		[string] $File
	)
	try {
		$c = Import-Clixml -Path $File
		if ($c.UserName -and $c.Password) {
			return $c
		} else {
			throw "Credential file ${File} is invalid"
		}
	} catch {
		throw "Failed to load credential file ${File}: " + ${PSItem}
	}
}

function ExportCert {
	Param (
		[X509Certificate] $Certificate
	)
	$Name = $Certificate.GetNameInfo("dnsName", $false) + ".cer"
	Export-Certificate -Cert $Certificate -FilePath $Name -Type CERT | Out-Null
	$Name
}

function WriteLog {
	param(
		[string] $LogPath,
		[string] $Message
	)
	Write-Host $Message
	if ($LogPath) {
		Add-Content -Path $LogPath -Value $Message
	}
}


if ($LdapCred) {
	if (-not $Out) {
		$Out = $LdapServer + $CredExt
	}
	try {
		WriteCred "Enter password for LDAP server $LdapServer" $UserName $Out
		Write-Host "Credential file $Out created"
		Exit 0
	} catch {
		Write-Host ${PSItem}
		Exit 1
	}
}

if ($JiraCred) {
	if (-not $Out) {
		$Out = $Domain + $CredExt
	}
	try {
		WriteCred "Enter API token for Jira Cloud $Domain" $UserEmail` $Out
		Write-Host "Credential file $Out created"
		Exit 0
	} catch {
		Write-Host ${PSItem}
		Exit 1
	}
}

if ($GetCert) {
	# Get server certificate
	try {
		$TcpSocket = New-Object Net.Sockets.TcpClient($LdapServer, $LdapPort)
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
			Write-Host "Certificate chain written to: "
			$Chain.ChainElements | %{
				$Name = ExportCert $_.Certificate
				Write-Host $Name
			}
			Exit 0
		} catch {
			Write-Host ${PSItem}
			Exit 1
		} finally {
			if ($SSLStream) {
				$SSLStream.Dispose()
			}
		}
	} catch {
		Write-Host ${PSItem}
		Exit 1
	} finally {
		if ($TcpSocket) {
			$TcpSocket.Dispose()
		}
	}
}

if ($Sync) {
	$Now = Get-Date
	$StartDate = Get-Date -Date $Now -Format yyyyMMddHHmmss
	$StartDisplayDate = Get-Date -Date $Now -Format "yyyy-MM-hh HH:mm:ss"
	if (-not $(Test-Path -Type Container $LogDir)) {
		WriteLog $LogPath "Log directory ${LogDir} is not a valid directory, aborted"
		Exit 1
	}
	$LogPath = $LogDir + "SyncUserProps.${StartDate}.log"
	$CurrentPath = Get-Location
	WriteLog $LogPath "SyncUserProps started at ${StartDisplayDate}"
	WriteLog $LogPath "Current User: ${Env:UserDomain}\${Env:UserName}"
	WriteLog $LogPath "Current Directory: ${CurrentPath}"
	if (-not $LdapCredFile) {
		$LdapCredFile = $LdapServer + $CredExt
	}
	if (-not $JiraCredFile) {
		$JiraCredFile = $Domain + $CredExt
	}
	WriteLog $LogPath "LDAP: ${LdapServer}:${LdapPort}"
	WriteLog $LogPath "LDAP Credential File: ${LdapCredFile}"
	WriteLog $LogPath "LDAP Search DN: ${BaseDN}" 
	WriteLog $LogPath "LDAP Search Filter: ${Filter}" 
	WriteLog $LogPath "LDAP Search Scope: ${Scope}"
	WriteLog $LogPath "Jira Cloud: ${Domain}"	
	WriteLog $LogPath "Jira Cloud Credential File: ${JiraCredFile}"
	WriteLog $LogPath "Attribute Mappings: "
	$AttributeList = [System.Collections.ArrayList]::new()
	foreach ($Attr in $AttributeMap.GetEnumerator()) {
		[void] $AttributeList.Add($Attr.Name)
		$Name = $Attr.Name
		$Value = $Attr.Value
		WriteLog $LogPath "`t${Name} => ${Value}"
	}
	# Always include attributes
	if (-not $AttributeList.Contains($Mail)) {
		[void] $AttributeList.Add($Mail)
	}
	# Get credential
	try {
		$ldapC = GetCredential $LdapCredFile
	} catch {
		WriteLog $LogPath ${PSItem}
		Exit 1
	}
	try {
		$jiraC = GetCredential $JiraCredFile
	} catch {
		WriteLog $LogPath ${PSItem}
		Exit 1
	}
	$Headers = GetAuthHeader $jiraC
	# Connect
	try {
		$LDAP = New-Object System.DirectoryServices.DirectoryEntry( `
			"LDAP://${LdapServer}:${LdapPort}/${BaseDN}", `
			$ldapC.UserName, `
			([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ldapC.Password))) `
		)
	} catch {
		WriteLog $LogPath "Failed to connect to LDAP server: ${PSItem}"
		Exit
	}
	# Search
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher($LDAP)
	$Searcher.SearchScope = $Scope
	$Searcher.Filter = $Filter
	foreach ($Attr in $AttributeList) {
		[void] $Searcher.PropertiesToLoad.Add($Attr)
	}
	# For all results
	[int] $LDAPTotal = 0
	[int] $LDAPSuccess = 0
	[int] $JiraTotal = 0
	[int] $JiraSuccess = 0
	$LDAPList = [System.Collections.ArrayList]::new()
	$JiraList = [System.Collections.ArrayList]::new()
	WriteLog $LogPath "`nModifications: "
	try {
		foreach ($User in $Searcher.FindAll()) {
			$LDAPTotal++
			# Find user account Id
			$Test = $User.Properties."adspath"
			if ($User.Properties."$Mail") {
				$UserMail = $User.Properties."$Mail"
				try {
					$AccountIds = GetAccountIds $Headers $UserMail
					foreach ($AccountId in $AccountIds) {
						$JiraTotal++
						$UserSuccess = $true
						foreach ($Attr in $AttributeList) {
							$Key = $Attr.ToLower()
							$Value = $User.Properties."$Key"
							$PropertyName = $AttributeMap[$Attr]
							if ($PropertyName) {
								try {
									UpdateUserProperty $Headers $UserMail $AccountId $PropertyName $Value
									WriteLog $LogPath "`t${UserMail}: ${AccountId}: Updated user property ${PropertyName} = ${Value}"
								} catch [RestException] {
									WriteLog $LogPath "`t${UserMail}: ${AccountId}: Unable to update user property ${PropertyName}: ${PSItem}"
									$UserSuccess = $false
								}
							}
						}
						if ($UserSuccess) {
							$JiraSuccess++
						} else {
							[void] $JiraList.Add($UserMail + ": " + $AccountId)
						}
					}
					$LDAPSuccess++
				} catch {
					[void] $LDAPList.Add($UserMail)
					WriteLog $LogPath "`t${PSItem}"
					continue
				}
			} else {
				$DN = $User.Properties."adspath"
				[void] $LDAPList.Add($DN)
				WriteLog $LogPath "`t${DN}: Ignored because $Mail attribute is empty"
			}
		}
		WriteLog $LogPath "`nSummary: "
		WriteLog $LogPath "`tSuccessfully processed: ${LDAPSuccess}/${LDAPTotal} LDAP user account(s)"
		if ($LDAPList.Count -gt 0) {
			WriteLog $LogPath "`tThere are error(s) for the following LDAP user(s): "
			foreach ($User in $LDAPList) {
				WriteLog $LogPath "`t`t${User}"
			}
		}
		WriteLog $LogPath "`n`tSuccessfully updated: ${JiraSuccess}/${JiraTotal} Jira Cloud user account(s)"
		if ($JiraList.Count -gt 0) {
			WriteLog $LogPath "`tThere are error(s) for the following Jira Cloud user(s): "
			foreach ($User in $JiraList) {
				WriteLog $LogPath "`t`t${User}"
			}
		}
		$EndDisplayDate = Get-Date -Format "yyyy-MM-hh HH:mm:ss"
		WriteLog $LogPath "`nSyncUserProps stopped at ${EndDisplayDate}"
		Exit 0
	} catch {
		WriteLog $LogPath ${PSItem}
		Exit 1
	}
}

if ($GetProp) {
	if (-not $JiraCredFile) {
		$JiraCredFile = $Domain + $CredExt
	}
	try {
		$jiraC = GetCredential $JiraCredFile
		$Headers = GetAuthHeader $jiraC
		$AccountIds = GetAccountIds $Headers $UserEmail
		foreach ($AccountId in $AccountIds) {
			if ($Prop) {
				try {
					$Value = GetUserProperty $Headers $UserEmail $AccountId $Prop
					Write-Host "`"$Prop`" = `"$Value`""
				} catch {
					Write-Host "${PSItem}"
				}
			} else {
				$Keys = GetUserPropertyKeys $Headers $UserEmail $AccountId
				foreach ($Key in $Keys) {
					try {
						$Value = GetUserProperty $Headers $UserEmail $AccountId $Key
						Write-Host "`"$Key`" = `"$Value`""
					} catch {
						Write-Host "${PSItem}"
					}
				}
			}
		}
	} catch {
		Write-Host ${PSItem}
		Exit 1
	}
	Exit 0
}

if ($DelProp) {
	if (-not $JiraCredFile) {
		$JiraCredFile = $Domain + $CredExt
	}
	try {
		$jiraC = GetCredential $JiraCredFile
		$Headers = GetAuthHeader $jiraC	
		$AccountIds = GetAccountIds $Headers $UserEmail
		foreach ($AccountId in $AccountIds) {
			try {
				$Value = GetUserProperty $Headers $UserEmail $AccountId $Prop
				DeleteUserProperty $Headers $UserEmail $AccountId $Prop
				Write-Host "${UserEmail}: Deleted property `"${Prop}`", original value: `"${Value}`""
			} catch {
				Write-Host "${PSItem}"
			}
		}
	} catch {
		Write-Host ${PSItem}
		Exit 1
	}
	Exit 0
}

if ($SetProp) {
	if (-not $JiraCredFile) {
		$JiraCredFile = $Domain + $CredExt
	}
	try {
		$jiraC = GetCredential $JiraCredFile
		$Headers = GetAuthHeader $jiraC	
		$AccountIds = GetAccountIds $Headers $UserEmail
		foreach ($AccountId in $AccountIds) {
			try {
				UpdateUserProperty $Headers $UserEmail $AccountId $Prop $Value
				Write-Host "${UserEmail}: Updated property `"${Prop}`" to `"${Value}`""
			} catch {
				Write-Host "${PSItem}"
			}
		}
	} catch {
		Write-Host ${PSItem}
		Exit 1
	}
	Exit 0
}