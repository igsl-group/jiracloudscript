<#
.SYNOPSIS
	Generate report as CSV file.
	
.DESCRIPTION
	Export issues from Jira Cloud. 
	
	Create Credential File Mode
	===========================
	> .\GenerateReport.ps1 -JiraCred -Domain <Domain> -UserEmail <User Email> -Out <Credential File>
	You will be prompted to enter API token. 
	The created credential file can then be used in the other modes.
	
	Interactive Mode
	================
	> .\GenerateReport.ps1
	An interactive menu will be displayed to generate reports. 
	
	Query Mode
	==========
	> .\GenerateReport.ps1 -Query [-Domain <Domain>] [-JiraCredFile <Credential File>] -Jql <JQL> [-Fields <Fields>] [-Out <Output File>]
	Generate report using provided JQL.
	
	Report Mode
	===========
	> .\GenerateReport.ps1 -Report -ReportType <Report Type> -DateRange <Date Range JQL> [-ReportDir <Output Directory>]
	Generate report using report templates.
	
	Output is saved in a CSV file:
		1. File encoding is UTF-8 without byte order mark.
		2. First line is header row.
		3. issue key will always appear as the first column.
	
.PARAMETER JiraCred
	Create credential file mode.
	
.PARAMETER Query
	Generate report with specified JQL.
	
.PARAMETER Report
	Generate report using specified template.
	
.PARAMETER UserEmail
	Email address of user. Please note that issues that can be found depends on access rights of this user.

.PARAMETER Domain
	Jira Cloud domain. Default is: fbhkitsm.atlassian.net

.PARAMETER JiraCredFile
	Credential file to use. Default is: <Domain>.cred
	Please note that you must use the same Windows user used to create the credential file to decrypt it.
	
.PARAMETER ReportType
	Report template to use.
	Valid values: MasterDataReport|QuestionnaireReport
	
.PARAMETER DateRange
	JQL clause to limit issues exported. Default is empty (no limit).
	
.PARAMETER Jql
	JQL used to search issues. Default is: Project = `"Customer Service Request`" Order by Created Desc

.PARAMETER Fields
	Issue fields to export. Default is: *navigable
	Specify *navigable to export user-readable fields. 
	Specify *all to export all fields.
	Specify a list to export specific fields, e.g. @("summary", "description", "status", "assignee", "customfield_10068")
	Note that issue key is always included even if you do not specify it.

.PARAMETER ReportDir
	Directory to write CSV file to. Default is current directory.

.PARAMETER Out
	Output file path. 
	For -JiraCred, default is: <Domain>.cred
	For -Query, default is: <Domain>.<yyyyMMddHHmmss>.csv
#>
[CmdletBinding(DefaultParameterSetName = "Interactive")]
Param(
	[Parameter(Mandatory, ParameterSetName = "JiraCred")]
	[switch] $JiraCred,

	[Parameter(Mandatory, ParameterSetName = "Query")]
	[switch] $Query,

	[Parameter(Mandatory, ParameterSetName = "Report")]
	[switch] $Report,

	[Parameter(Mandatory, ParameterSetName = "JiraCred")]
	[string] $UserEmail,
	
	[Parameter(Mandatory, ParameterSetName = "JiraCred")]
	[Parameter(ParameterSetName = "Query")]
	[Parameter(ParameterSetName = "Report")]
	[string] $Domain = "fbhkitsm.atlassian.net",
	
	[Parameter(ParameterSetName="Query")]
	[Parameter(ParameterSetName = "Report")]
	[string] $JiraCredFile,
	
	[Parameter(Mandatory, ParameterSetName = "Report")]
	[ValidateSet("MasterDataReport")]
	[string] $ReportType,
	
	[Parameter(ParameterSetName = "Report")]
	[string] $DateRange = "",
	
	[Parameter(Mandatory, ParameterSetName = "Query")]
	[string] $Jql = "Project = `"Customer Service Request`" Order by Created Desc",
	
	[Parameter(ParameterSetName = "Query")] 
	[System.Collections.ArrayList] $Fields = @("*navigable"),
	
	[Parameter(ParameterSetName = "Report")]
	[string] $ReportDir = ".",
	
	[Parameter(ParameterSetName = "Query")]
	[Parameter(ParameterSetName = "JiraCred")]
	[string] $Out
)

Set-Variable -Name CredExt -Value ".cred" -Option Constant
Set-Variable -Name DateFormatIn -Value "yyyy-MM-dd" -Option Constant
Set-Variable -Name DateFormatOut -Value "yyyy-MM-dd" -Option Constant
Set-Variable -Name DatetimeFormatIn -Value "yyyy-MM-ddTHH:mm:ss.fffzzzz" -Option Constant
Set-Variable -Name DatetimeFormatOut -Value "yyyy-MM-dd HH:mm:ss" -Option Constant

# Name of report, set if a report type is selected
$ReportName = $null

# Sort Fields
$Fields.Sort()

# Field id mapped to field data type
$FieldInfo = @{}

class RestException : Exception {
    RestException($Message) : base($Message) {
    }
}

enum ReportType {
	MasterDataReport = 1
	QuestionnaireReport = 2
}

class ReportTypeData {
	[string] $Name
	[string] $Jql
	[string[]] $Fields 
	ReportTypeData([string] $Name, [string] $Jql, [string[]] $Fields) {
		$this.Name = $Name
		$this.Jql = $Jql
		$this.Fields = $Fields
	}
}

$ReportTypeMap = @{
	[ReportType]::MasterDataReport.value__ = [ReportTypeData]::new(
		"Master Data Report", 
		"Project = `"Customer Service Request`" Order By Created Desc",
		@(
			"summary",
			"status",
			"assignee",
			"reporter",
			"creator",
			"created",
			"description",
			"watches",
			"customfield_10069", # IT Security Risk Management
			"customfield_10098", # Application
			"customfield_10062", # Business Justification
			"customfield_10064", # Business Value (HKD)
			"customfield_10065", # Contact Number
			"customfield_10066", # Department
			"customfield_10068", # Expected Deadline
			"customfield_10092", # Man-day
			"customfield_10088", # Owner Group
			"customfield_10072", # Planned Finish Date
			"customfield_10087", # Regulatory
			"customfield_10081", # Rejection Category
			"customfield_10074", # Request Category
			"customfield_10089", # Requester
			"customfield_10076"  # System Owner Approval(s) Uploaded
		)
	);
	[ReportType]::QuestionnaireReport.value__ = [ReportTypeData]::new(
		"Questionnaire Report", 
		"Project = `"Customer Service Request`" and Status = Closed Order By Created Desc",
		@(
			"summary",
			"status",
			"assignee",
			"reporter",
			"creator",
			"created",
			"customfield_10069", # IT Security Risk Management
			"customfield_10098", # Application
			"customfield_10062", # Business Justification
			"customfield_10064", # Business Value (HKD)
			"customfield_10065", # Contact Number
			"customfield_10066", # Department
			"customfield_10068", # Expected Deadline
			"customfield_10092", # Man-day
			"customfield_10088", # Owner Group
			"customfield_10072", # Planned Finish Date
			"customfield_10087", # Regulatory
			"customfield_10081", # Rejection Category
			"customfield_10074", # Request Category
			"customfield_10089", # Requester
			"customfield_10076", # System Owner Approval(s) Uploaded
			"customfield_10093", # Overall Satisfaction Rate
			"customfield_10094", # End Result Meet User Requirements
			"customfield_10095", # Response Rate
			"customfield_10096", # Completed On or Before Agreed Timeline
			"customfield_10097"  # Other Comments
		)
	);
}

function AnyKeyToContinue {
	Write-Host "Press Any Key to Continue"
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
}

function SelectFields {
	param (
		[hashtable] $Headers,
		[System.Collections.ArrayList] $Fields
	)
	# Get field information and create enum
	$FieldInfo = GetFieldSchema $Headers
	# Swap key and value for access
	$FieldData = [ordered] @{}
	foreach ($Item in $FieldInfo.GetEnumerator()) {
		$FieldID = $Item.Key
		$FieldName = $Item.Value.name
		$FieldData[$FieldName] = $FieldID
	}
	# Initial search string and result
	$SearchString = ""
	$Matches = [ordered] @{}
	# Initalize SelectedFields from Fields
	$SelectedFields = [ordered] @{}
	foreach ($Item in $FieldData.GetEnumerator()) {
		if ($Fields.Contains($Item.Value)) {
			$SelectedFields[$Item.Key] = $Item.Value
		}
	}
	$AddAll = $false
	if ($Fields.Contains("*all")) {
		$AddAll = $true
	}
	$AddNavigable = $false
	if ($Fields.Contains("*navigable")) {
		$AddNavigable = $true
	}
	$Quit = $false
	do {
		$AddList = [System.Collections.ArrayList]::new()
		$RemoveList = [System.Collections.ArrayList]::new()
		Clear-Host
		Write-Host "================================================================================"
		Write-Host "Selected Fields"
		Write-Host "================================================================================"
		Write-Host "[C] Remove All Selected Fields"
		if ($AddAll) {
			Write-Host "[F] All Fields (*all)"
		}
		if ($AddNavigable) {
			Write-Host "[N] Navigable Fields (*navigable)"
		}
		$Idx = 0
		foreach ($Item in ($SelectedFields.GetEnumerator() | Sort-Object)) {
			$Idx++
			$FieldName = $Item.Key
			$FieldID = $Item.Value
			[void] $RemoveList.Add($FieldName)
			Write-Host "[R${Idx}] ${FieldName} (${FieldID})"
		}		
		Write-Host
		Write-Host "================================================================================"
		Write-Host "Available Fields"
		Write-Host "================================================================================"
		Write-Host "[S] Search: ${SearchString}"
		if (-not $AddAll) {
			Write-Host "[F] Add All Fields (*all)"
		}
		if (-not $AddNavigable) {
			Write-Host "[N] Add Navigable Fields (*navigable)"
		}
		$Idx = 0
		foreach ($Item in ($Matches.GetEnumerator() | Sort-Object)) {
			$Idx++
			$FieldName = $Item.Key
			$FieldID = $Item.Value
			[void] $AddList.Add($FieldName)
			Write-Host "[${Idx}] ${FieldName} (${FieldID})"
		}
		Write-Host
		Write-Host "================================================================================"
		Write-Host "NOTE: Issue key is always included as the first column"
		Write-Host "[X] Return"
		Write-Host "================================================================================"
		$Option = Read-Host "Option"
		switch ($Option) {
			"c" {
				[void] $SelectedFields.Clear()
				$AddAll = $false
				$AddNavigable = $false
				break
			}
			"f" {
				$AddAll = -not $AddAll
				break
			}
			"n" {
				$AddNavigable = -not $AddNavigable
				break
			}
			"s" {
				$SearchString = Read-Host "Search String"
				$SearchResult = $FieldData.Keys -like ("*" + $SearchString + "*")
				$Matches.Clear()
				foreach ($Key in $SearchResult) {
					$Matches[$Key] = $FieldData[$Key]
				}
				break
			}
			{$_ -match "[0-9]+"} {
				$Target = $Option
				$Cnt = $AddList.Count
				if ($Target -gt 0 -and $Target -le $Cnt) {
					$Name = $AddList[$Target - 1]
					$ID = $Matches[$Name]
					if (-not $SelectedFields.Contains($Name)) {
						[void] $SelectedFields.Add($Name, $ID)
					}
				}
				break
			}
			{$_ -match "r[0-9]+"} {
				$Target = $Option.Substring(1)
				$Cnt = $RemoveList.Count
				if ($Target -gt 0 -and $Target -le $Cnt) {
					$Name = $RemoveList[$Target - 1]
					if ($SelectedFields.Contains($Name)) {
						[void] $SelectedFields.Remove($Name)
					}
				}
				break
			}
			"x" {
				$Quit = $true
				break
			}
		}
	} while (-not $Quit)
	$Result = [System.Collections.ArrayList]::new()
	foreach ($Item in $SelectedFields.GetEnumerator()) {
		[void] $Result.Add($Item.Value)
	}
	if ($AddAll) {
		[void] $Result.Add("*all")
	}
	if ($AddNavigable) {
		[void] $Result.Add("*navigable")
	}
	$Result.Sort()
	Write-Output -NoEnumerate $Result
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

function GetFieldSchema {
	param (
		[hashtable] $Headers
	)
	$Result = @{}
	try {
		$StartAt = 0
		$IsLast = $false
		do {
			$Body = @{
				"startAt" = $StartAt;
				"maxResults" = 100;
			}
			$Uri = "https://" + $Domain + "/rest/api/3/field/search"
			$Response = WebRequest $Uri "GET" $Headers $Body
			if ($Response.StatusCode -ne 200) {
				throw $Response.Content
			}
			$Json = $Response.Content | ConvertFrom-Json
			foreach ($Item in $Json.values) {
				$Id = $Item.id
				$Result."$Id" = $Item
			}
			$IsLast = $Json.isLast
			$StartAt += $Json.values.Count
		} while (-not $IsLast)
	} catch [RestException] {
		throw $PSItem
	}
	<#
	Write-Host Field Info: 
	foreach ($Item in $Result.GetEnumerator()) {
		$S = $Item.Key + ":"
		foreach ($Prop in $Item.Value.PSObject.Properties) {
			$S += "[" + $Prop.Name + "]=[" + $Prop.Value + "]"
		}
		Write-Host $S
	}
	#>
	$Result
}

function SearchIssue {
	param (
		[hashtable] $Headers,
		[string] $Jql,
		[string[]] $Fields,
		[int] $Max = 100,
		[int] $StartAt = 0
	)
	[hashtable] $Result = @{}
	try {
		$Uri = "https://" + $Domain + "/rest/api/3/search"
		$Body = @{
			"expand" = @("names");
			"jql" = $Jql;
			"fields" = $Fields;
			"maxResults" = $Max;
			"startAt" = $StartAt;
		}
		$JsonBody = ConvertTo-Json $Body
		$Response = WebRequest $Uri "POST" $Headers -Body $JsonBody
		switch ($Response.StatusCode) {
			200 {
				break
			}
			400 {
				throw "Bad request (400). Please verify JQL is valid."
			}
			401 {
				throw "Unauthorized (401). Please verify credential file."
			}
			default {
				throw "Faile to search: " + $Response.Content
			}
		}
		$Response.Content | ConvertFrom-Json
	} catch [RestException] {
		throw $PSItem
	}
}

function WriteCSVHeader {
	param (
		[string] $Csv,
		[PSCustomObject] $Names
	)
	Set-Content -Path $Csv -Value "" -NoNewLine
	$Line = ""
	foreach ($Item in ($Names.PSObject.Properties | Sort-Object)) {
		$FieldName = $Item.Value
		# Escape double quotes
		$FieldName = $FieldName -Replace '"', '""'
		$Line += ",`"${FieldName}`""
	}
	$Line = "Issue Key" + $Line
	Add-Content -Path $Csv -Value $Line
}

function ParseDate {
	param(
		[PSObject] $Data
	)
	# PowerShell 7 will automatically convert dates, so check both types
	if ($Data) {
		if ($Data.GetType().Name -eq "date") {
			$Data.ToString($DateFormatOut)
		} else {
			[datetime]::ParseExact($Data, $DateFormatIn, $null).ToString($DateFormatOut)
		}
	} else {
		""
	}
}

function ParseDateTime {
	param(
		[PSObject] $Data
	)
	# PowerShell 7 will automatically convert dates, so check both types
	if ($Data) {
		if ($Data.GetType().Name -eq "date") {
			$Data.ToString($DatetimeFormatOut)
		} elseif ($Data.GetType().Name -eq "datetime") {
			$Data.ToString($DatetimeFormatOut)
		} else {
			[datetime]::ParseExact($Data, $DatetimeFormatIn, $null).ToString($DatetimeFormatOut)
		}
	} else {
		""
	}
}

function ParseFieldValue {
	param (
		[hashtable] $Headers,
		[string] $Type,
		[string] $Items,
		[PSObject] $FieldValue
	)
	$Result = ""
	if ($FieldValue -ne $null -and $FieldValue -ne "") {
		switch ($Type) {
			"array" {
				$List = [System.Collections.ArrayList]::new()
				foreach ($Item in $FieldValue) {
					$Value = ParseFieldValue $Headers $Items $null $Item
					[void] $List.Add($Value)
				}
				$Result = "`"" + ($List -join "`",`"") + "`""
				break
			}		
			# Handled types
			"attachment" {
				$Result = $FieldValue."filename"
				break
			}
			"date" {
				$Result = ParseDate $FieldValue
				break
			}
			"datetime" {
				$Result = ParseDateTime $FieldValue
				break
			}
			"group" {
				$Result = $FieldValue."name"
				break
			}
			"issuelinks" {
				foreach ($Link in $FieldValue) {
					$Result += "`r`n"
					if ($Link."outwardIssue") {
						$Result += $Link."type"."outward" + " " + $Link."outwardIssue"."key"
					} elseif ($Link."inwardIssue") {
						$Result += $Link."type"."inward" + " " + $Link."inwardIssue"."key"
					}
				}
				if ($Result.Length -gt 2) {
					$Result = $Result.Substring(2)
				}
				break
			}
			"issuetype" {
				$Result = $FieldValue."name"
				break
			}
			"number" {
				$Result = $FieldValue
				break
			}
			"option" {
				$Result = $FieldValue."value"
				break
			}
			"option-with-child" {
				$Result = $FieldValue."value"
				if ($FieldValue."child") {
					$Result += " | " + $FieldValue."child"."value"
				}
				# Note: Jira Cloud only supports 2-level cascading list... so no need for recursion.
				break
			}
			"priority" {
				$Result = $FieldValue."name"
				break
			}
			"progress" {
				$Result = $FieldValue."progress".ToString() + "/" + $FieldValue."total".ToString()
				break
			}			
			"project" {
				$Result = $FieldValue."name"
				break
			}
			"resolution" {
				$Result = $FieldValue."name"
				break
			}
			"sd-request-lang" {
				$Result = $FieldValue."displayName"
				break
			}
			"sd-servicelevelagreement" {
				if ($FieldValue."completedCycles") {
					foreach ($Cycle in $FieldValue."completedCycles") {
						$Result += "`r`n"
						$StartTime = ParseDateTime $Cycle."startTime"."jira"
						$StopTime = ParseDateTime $Cycle."stopTime"."jira"
						$BreachTime = ParseDateTime $Cycle."breachTime"."jira"
						$Breached = $Cycle."breached"
						$Goal = $Cycle."goalDuration"."friendly"
						$Elapsed = $Cycle."elapsedTime"."friendly"
						$Remaining = $Cycle."remainingTime"."friendly"
						$Result += 	"Started:" + $StartTime + ",Stopped:" + $StopTime + ",Elapsed:" + $Elapsed + ",Remaining:" + $Remaining + ",Breach:" + $BreachTime
						if ($Breached) {
							$Result += ",Breached"
						}
					}
				}
				if ($FieldValue."ongoingCycle") {
					$Result += "`r`n"
					$StartTime = ParseDateTime $FieldValue."ongoingCycle"."startTime"."jira"
					$BreachTime = ParseDateTime $FieldValue."ongoingCycle"."breachTime"."jira"
					$Breached = $FieldValue."breached"
					$Goal = $FieldValue."goalDuration"."friendly"
					$Elapsed = $FieldValue."elapsedTime"."friendly"
					$Remaining = $FieldValue."remainingTime"."friendly"
					$Result += "Started:" + $StartTime + ",Elapsed:" + $Elapsed + ",Remaining:" + $Remaining + ",Breach:" + $BreachTime
					if ($Breached) {
						$Result += " [Breached]"
					}
				}
				if ($Result.Length -gt 2) {
					$Result = $Result.Substring(2)
				}
				break
			}
			"status" {
				$Result = $FieldValue."name"
				break
			}
			"string" {
				# Special handling for paragraph types
				if ($FieldValue."content") {
					# Concat all text found
					foreach ($ContentItem in $FieldValue."content") {
						$Result += "`r`n"
						if ($ContentItem."type" -in ("paragraph", "codeBlock", "mention")) {
							foreach ($SubContentItem in $ContentItem."content") {
								$Result += $SubContentItem."text"
							}
						} elseif ($ContentItem."type" -in ("text")) {
							$Result += $ContentItem."text"
						}
					}
					if ($Result.Length -gt 2) {
						$Result = $Result.Substring(2)
					}
				} else {
					# Simple string
					$Result = $FieldValue
				}
				break
			}
			"timetracking" {
				$Result = "Spent:" + $FieldValue."timeSpent" + ",Remaining:" + $FieldValue."remainingEstimate"
				break
			}
			"user" {
				$Result = $FieldValue."displayName" + " [" + $FieldValue."accountId" + "]"
				break
			}
			"version" {
				$Result = $FieldValue."version"
				break
			}
			"votes" {
				$Response = WebRequest $FieldValue."self" "GET" $Headers 
				if ($Response.StatusCode -eq 200) {
					$Json = $Response.Content | ConvertFrom-Json
					foreach ($Watcher in $Json.voters) {
						$Result += "," + $Watcher.displayName + " [" + $Watcher.accountId + "]"
					}
					if ($Result.Length -gt 1) {
						$Result = $Result.Substring(1)
					}
				} else {
					$Result = "Error connecting to " + $FieldValue."self"
				}
				break
			}
			"watches" {
				$Response = WebRequest $FieldValue."self" "GET" $Headers 
				if ($Response.StatusCode -eq 200) {
					$Json = $Response.Content | ConvertFrom-Json
					foreach ($Watcher in $Json.watchers) {
						$Result += "," + $Watcher.displayName + " [" + $Watcher.accountId + "]"
					}
					if ($Result.Length -gt 1) {
						$Result = $Result.Substring(1)
					}
				} else {
					$Result = "Error connecting to " + $FieldValue."self"
				}
				break
			}
			default {
				$Result = $FieldValue
				break
			}
			# Unhandled types
			<#
			"" 
			"any" 
			"comments-page" 
			"component" 
			"issuerestriction" 
			"json"
			"object" 
			"sd-approvals"
			"sd-customerorganization" 
			"sd-customerrequesttype" 
			"sd-feedback" 
			"securitylevel" 
			"service-entity-field" 
			"worklog" 
			#>
		}
	}
	$Result
}

function WriteCSVEntry {
	param (
		[hashtable] $Headers,
		[string] $Csv,
		[PSCustomObject] $Names,
		[PSCustomObject] $Issue
	)
	$Line = ""
	foreach ($Item in ($Names.PSObject.Properties | Sort-Object)) {
		$FieldId = $Item.Name
		if ($Issue.fields."$FieldId") {
			$FieldValue = $Issue.fields."$FieldId"
		} else {
			# Certain fields like key are at issue level
			$FieldValue = $Issue."$FieldId"
		}
		$Type = $FieldInfo."$FieldId".schema.type
		$Items = $FieldInfo."$FieldId".schema.items
		$ParsedValue = ParseFieldValue $Headers $Type $Items $FieldValue
		# Escape double quotes
		$CSVValue = $ParsedValue -replace '"', '""'
		#Write-Output "${FieldId}.${Type}.${Items}=`"${CSVValue}`""
		$Line += ",`"${CSVValue}`""
	}
	$Line = $Issue.key + $Line
	Add-Content -Path $Csv -Value $Line
}

function GetAuthHeader {
	[hashtable] $Headers = @{
		"Content-Type" = "application/json"
	}
	if (-not $JiraCredFile) {
		$JiraCredFile = $Domain + $CredExt
	}
	try {
		$Credential = GetCredential $JiraCredFile
	} catch {
		Write-Host $PSItem
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

function SelectReport {
	$Result = $null
	$Stop = $false
	$Max = [ReportType].GetEnumValues().Count
	do {
		Clear-Host
		Write-Host ================================================================================
		Write-Host Select Report
		Write-Host ================================================================================
		foreach ($Item in ($ReportTypeMap.GetEnumerator() | Sort-Object)) {
			$Key = $Item.Key
			$ReportName = $Item.Value.Name
			Write-Host "[${Key}] ${ReportName}"
		}
		Write-Host "[X] Exit"
		Write-Host ================================================================================
		$Option = Read-Host Select Report
		switch ($Option) {
			"x" {
				$Result = $null
				$Stop = $true
				break
			}
			{$_ -match "[0-9]+"} {
				if ($Option -gt 0 -and $Option -le $Max) {
					$Result = $Option
					$Stop = $true
				}
				break
			}
		}		
	} while (-not $Stop)
	$Result
}

function PrintMenu {
	Clear-Host
	$FieldCount = $Fields.Count
	Write-Host ================================================================================
	Write-Host Generate Report
	Write-Host --------------------------------------------------------------------------------
	Write-Host "[D] Domain          | ${Domain}"
	Write-Host "[C] Credential File | ${JiraCredFile}"
	Write-Host --------------------------------------------------------------------------------
	Write-Host "[R] Select Report   |"
	Write-Host "[J] JQL             | ${Jql}"
	Write-Host "[T] Date Range      | ${DateRange}"
	Write-Host "[F] Output Fields   | ${FieldCount} Field(s)"
	Write-Host "[N] Report Name     | ${ReportName}" 
	Write-Host "[P] Output Directory| ${ReportDir}"
	Write-Host --------------------------------------------------------------------------------
	Write-Host "[S] Search          |"
	Write-Host "[X] Exit            |"
	Write-Host ================================================================================
	try {
		$Option = Read-Host Option
		Write-Host
		$Option
	} catch {
		$null
	}
}

function GetReportOutput {
	param (
		[string] $OutParam,
		[string] $Name,
		[string] $Dir
	)
	if (-not $OutParam) {
		$ExportDate = Get-Date -Format yyyyMMddHHmmss
		if ($Name) {
			$OutParam = "${Domain}.${Name}.${ExportDate}.csv"
		} else {
			$OutParam = "${Domain}.${ExportDate}.csv"
		}
		if ($Dir) {
			$OutParam = $Dir + "\" + $OutParam
		}
	}
	$OutParam
}

function WriteReport {
	param (
		[string] $MainJql,
		[string] $ExtraJql,
		[string[]] $FieldList,
		[string] $Out
	)
	try {
		$Headers = GetAuthHeader
		[int] $Start = 0
		[int] $Max = 100
		[int] $Total = 0
		[int] $IssueCount = 0
		$FieldNames = $FieldList -join ","
		if ($ExtraJql) {
			$FinalJQL = "(" + $ExtraJql + ")"
			if ($MainJql) {
				$FinalJQL += " and " + $MainJql
			}
		} else {
			$FinalJQL = $MainJql
		}
		Write-Host
		Write-Host "JQL: $FinalJQL"
		Write-Host "Fields: $FieldNames"
		Write-Host "Output: ${Out}"
		Write-Host
		$WriteHeader = $true
		do {
			$Json = SearchIssue $Headers $FinalJQL $FieldList $Max $Start
			$Total = $Json.total
			$Count = $Json.issues.Count
			$Start += $Count
			Write-Progress -Id 1 -Activity "Processing issue 0/${Total}" -PercentComplete 0
			if ($WriteHeader) {
				$FieldInfo = GetFieldSchema $Headers
				WriteCSVHeader $Out $Json.names
				$WriteHeader = $false
			}
			# Save data to CSV
			foreach ($Issue in $Json.issues) {
				$IssueKey = $Issue.key
				WriteCSVEntry $Headers $Out $Json.names $Issue
				$IssueCount++
				Write-Progress -Id 1 -Activity "Processing issue ${IssueCount}/${Total}" -PercentComplete ($IssueCount / $Total * 100)
			}
		} while ($Start -lt $Total)
		Write-Progress -Id 1 -Activity "Processed ${Total} issue(s)" -Completed
		Write-Host "${IssueCount} issue(s) written to ${Out}"
	} catch {
		Write-Host $PSItem
	}
}

# JiraCred mode
if ($JiraCred) {
	if (-not $Out) {
		$Out = $Domain + $CredExt
	}
	try {
		WriteCred "Enter API token for Jira Cloud $Domain" $UserEmail $Out
		Write-Host "Credential file $Out created"
		Exit 0
	} catch {
		Write-Host ${PSItem}
		Exit 1
	}
} 

# Query mode
if ($Query) {
	$Out = GetReportOutput $Out
	WriteReport $Jql $DateRange $Fields $Out
	Exit
}

# Report mode
if ($Report) {
	if ($ReportTypeMap.ContainsKey($ReportType)) {
		$Jql = $ReportTypeMap.Item($ReportType).Jql
		$Fields = $ReportTypeMap.Item($ReportType).Fields
		$FieldString = $Fields -join ","
		$ReportName = $ReportTypeMap.Item($ReportType).Name
		$Out = GetReportOutput $null $ReportName $ReportDir
		WriteReport $Jql $DateRange $Fields $Out
		Exit 0
	} else {
		Write-Host "Report type `"$ReportType`" is not valid"
		Exit 1
	}	
}

# Interactive mode
if (-not $JiraCredFile) {
	$JiraCredFile = $Domain + $CredExt
}
$Quit = $false
do {
	$Option = PrintMenu
	switch ($Option) {
		"p" {
			$NewReportDir = Read-Host "Output Directory"
			if (Test-Path -Type Container $NewReportDir) {
				$ReportDir = $NewReportDir
			} else {
				Write-Host "`"${NewReportDir}`" is not a valid directory"
				AnyKeyToContinue
			}
			break
		}
		"n" {
			$ReportName = Read-Host "Report Name"
			break
		}
		"t" {
			Clear-Host
			Write-Host ================================================================================
			Write-Host "Current JQL | ${Jql}"
			Write-Host --------------------------------------------------------------------------------
			Write-Host "Examples"
			Write-Host --------------------------------------------------------------------------------
			Write-Host "No limit                                | Empty string"
			Write-Host "Created within 5 days                   | Created > -5d"
			Write-Host "Updated within 10 days                  | Updated > -10d"
			Write-Host "Expected Deadline is on or before today | `"Expected Deadline`" <= 0d"
 			Write-Host "Planned Start Date is a specific date   | `"Planned Start Date`" = 2023-11-01"
			Write-Host "Actual Start Date is within range       | `"Actual Start Date`" >= 2023-11-01 and `"Actual Start Date`" <= 2023-12-01"
			Write-Host ================================================================================
			$DateRange = Read-Host "Date Range JQL"
			break
		}
		"d" {
			$Domain = Read-Host "Domain"
			$JiraCredFile = $Domain + $CredExt
			break
		}
		"c" {
			$JiraCredFile = Read-Host Credential File
			break
		}
		"j" {
			$Jql = Read-Host JQL
			break
		}
		"f" {
			$Headers = GetAuthHeader
			$Fields = SelectFields $Headers $Fields
			break
		}
		"r" {
			[int] $ReportIdx = SelectReport
			$Jql = $ReportTypeMap.Item($ReportIdx).Jql
			$Fields = $ReportTypeMap.Item($ReportIdx).Fields
			$ReportName = $ReportTypeMap.Item($ReportIdx).Name
			break
		}
		"s" {
			$Out = GetReportOutput $null $ReportName $ReportDir
			WriteReport $Jql $DateRange $Fields $Out
			AnyKeyToContinue
			break
		}
		"x" {
			$Quit = $true
			break
		}
	}
} while (-not $Quit)