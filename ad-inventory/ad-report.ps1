<#
.SYNOPSIS
    Generates a daily report on Active Directory user and group statistics from specific OUs.

.DESCRIPTION
    This script gathers statistics about user accounts (total, active, disabled, new, service accounts)
    and groups (those missing a description) from specific OUs. It then saves this information into a dated text file.

.NOTES
    Author: kraloveckey
    Requires: ActiveDirectory PowerShell Module (RSAT)
#>

# --- Configuration: YOU MUST EDIT THIS SECTION ---

# Define the OU for USER searches.
# Example: "OU=Users,OU=Company,DC=yourdomain,DC=com"
$UserSearchBase = "OU=Users,DC=dns,DC=com"

# Define a LIST of OUs for the GROUP search. You can add as many as you need.
$GroupSearchBases = @(
    "OU=Groups,DC=dns,DC=com",
    "OU=Users,DC=dns,DC=com"
)

# Define the folder path where the report will be saved.
$ReportFolderPath = "C:\temp"

# --- End of Configuration ---


# --- Initial Setup ---

# Ensure the report directory exists
if (-not (Test-Path -Path $ReportFolderPath)) {
    Write-Host "Creating report directory: $ReportFolderPath"
    New-Item -ItemType Directory -Path $ReportFolderPath | Out-Null
}

# Set the date format for the report and filename
$ReportDate = Get-Date -Format "dd MMMM yyyy HH:mm"
$FileNameDate = Get-Date -Format "yyyy-MM-dd"


# --- 1. Gather User Account Statistics ---

# Get a count of all user objects within the specified user OU
$AllUsersCount = (Get-AdUser -Filter * -SearchBase $UserSearchBase).count

# Get a count of all enabled user accounts
$ActiveUsersCount = (Get-ADUser -Filter {Enabled -eq $true} -SearchBase $UserSearchBase).count

# Get a count of all disabled user accounts
$DisabledUsersCount = (Get-ADUser -Filter {Enabled -eq $false} -SearchBase $UserSearchBase).count

# Get a count of service accounts based on missing attributes.
# An account is considered a service account if it's enabled AND is missing a Surname, GivenName (First Name), or Email Address.
$ServiceAccountsFilter = {
    Enabled -eq $true -and (
        -not (Surname -like '*') -or
        -not (GivenName -like '*') -or
        -not (EmailAddress -like '*')
    )
}
$ServiceAccountsCount = (Get-ADUser -Filter $ServiceAccountsFilter -Properties EmailAddress -SearchBase $UserSearchBase).count


# --- 2. Find New Users Created in the Last 24 Hours ---

# Define the time period for the new user search
$StartDate = (Get-Date).AddDays(-1)
$EndDate = Get-Date

# Find user accounts created within the last day in the user OU
$NewUsersQuery = @(Get-ADUser -Filter 'Created -ge $StartDate -and Created -le $EndDate' -Properties Created -SearchBase $UserSearchBase)
$NewUsersCount = $NewUsersQuery.count

# Format the list of new user names for the report in "Name (SamAccountName)" format
$NewUsersList = $NewUsersQuery | ForEach-Object { " – $($_.Name) ($($_.SamAccountName))" } | Out-String


# --- 3. Find Groups Without a Description ---

# Loop through each OU in the list and find groups where the Description attribute is not set
$GroupsWithoutDescriptionQuery = $GroupSearchBases | ForEach-Object {
    Get-ADGroup -Filter {-not (Description -like "*")} -SearchBase $_
}
$GroupsWithoutDescriptionCount = $GroupsWithoutDescriptionQuery.count

# Format the list of group names for the report
$GroupsWithoutDescriptionList = $GroupsWithoutDescriptionQuery | Sort-Object Name | ForEach-Object { " – $($_.Name)" } | Out-String


# --- 4. Generate and Save the Report ---

# Format the list of group search locations for the report
$GroupSearchLocationsForReport = $GroupSearchBases | ForEach-Object { " – $_" } | Out-String

# Construct the message body for the report using a "here-string"
$MessageBody = @"
Active Directory Report – $ReportDate
--------------------------------------------------

USER STATISTICS
Search Location (OU): $UserSearchBase

Total User Accounts: $AllUsersCount
 – Active: $ActiveUsersCount (including $ServiceAccountsCount service accounts)
 – Disabled: $DisabledUsersCount

New Users in the Last 24 Hours ($NewUsersCount):
$NewUsersList
--------------------------------------------------

GROUP STATISTICS
Search Locations (OUs):
$GroupSearchLocationsForReport

Groups without a Description ($GroupsWithoutDescriptionCount):
$GroupsWithoutDescriptionList
"@

# Define the full path and filename for the report
$ReportPath = Join-Path -Path $ReportFolderPath -ChildPath "$($FileNameDate)-AD_Report.txt"

# Save the report to a UTF8 encoded text file
$MessageBody | Out-File -FilePath $ReportPath -Encoding UTF8

# Output a confirmation message to the console
Write-Host "Report successfully saved to: $ReportPath"

$User = "AUTH_USER@gmail.com"
$File = "$PSScriptRoot\.env"
$Cred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content $File | ConvertTo-SecureString -AsPlainText -Force)
$EmailTo = "EMAIL_TO@gmail.com"
$EmailFrom = "EMAIL_FROM@gmail.com"
$Subject = "Active Directory Report"
$fileContent = Get-Content -Path $ReportPath -Raw
$Body = "$fileContent"
$SMTPServer = "smtp.gmail.com"
$SMTPMessage = New-Object System.Net.Mail.MailMessage($EmailFrom,$EmailTo,$Subject,$Body)
$SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer, 587)
$SMTPClient.EnableSsl = $true
$SMTPClient.Credentials = New-Object System.Net.NetworkCredential($Cred.UserName, $Cred.Password);
$SMTPClient.Send($SMTPMessage)
$SMTPMessage.Dispose();

Remove-Item "$ReportPath" -Force
Remove-Item "$ReportFolderPath" -Force