# jiracloudscript
Scripts for Jira Cloud

## UpdateGroup.ps1
This script can bulk create/delete user groups. For usage:  
Get-Help .\UpdateGroup.ps1 -detailed  
UpdateGroup.csv is a sample data file. 

## UpdateGroupMembership.ps1
This script can bulk manage user group memberships. For usage:  
Get-Help .\UpdatGroupMembership.ps1 -detailed  
UpdateGroupMembership.csv is a sample data file. 

## LDAPExport.ps1
This script is used to export LDAP data into a delimited format. 
Jira automation rule can grab the exported data with a web request and parse it using split.
