Write-Host "^_^ | Inventory Active Directory Script | ^_^" -ForegroundColor Green

[string[]]$ldapArray = Get-Content -Path "$PSScriptRoot\ou.txt"

$valError = 0
$valOnline = 0
$dateCurrent = Get-Date -Format "dd-MM-yyyy"

foreach ($ldapPath in $ldapArray)
{

$compFileName = "$PSScriptRoot\Computers.csv"
$compTempFileName = "$PSScriptRoot\Computers.tmp"

$softFileName = "$PSScriptRoot\Software.csv"
$softTempFileName = "$PSScriptRoot\Software.tmp"

$ldapDomain = $ldapPath

$pos = $ldapPath.IndexOf(",")
$leftPart = $ldapPath.Substring(0, $pos)

$encoding = [System.Text.Encoding]::UTF8
$compsColumns = @(
    "Name",
    "Been online",    
    "OU",
    "OS",
    "OS version",
    "IP",
    "CPU",
    "Frequency - MHz",
    "Cores",
    "RAM - MB",
    "Drive size - GB",
    "Drive models"
)

$softColumns = @(
    "Name",
    "Manufacturer"
)

if(Test-Path $compTempFileName) {
	Remove-Item $compTempFileName -Force
}

if(Test-Path $softTempFileName) {
	Remove-Item $softTempFileName -Force
}

$writer = New-Object System.IO.StreamWriter $compTempFileName, $encoding
$preamble = $encoding.GetPreamble()
$writer.BaseStream.Write($preamble, 0, $preamble.Length)
$writer.WriteLine([String]::Join(",", $compsColumns))
$writer.Close()

$existingCompsData = @{}

if(Test-Path $compFileName) {
    $reader = New-Object System.IO.StreamReader $compFileName, $encoding
    while(-not $reader.EndOfStream) {
        $line = $reader.ReadLine()
        $values = $line.Split(",")
        $compData = @{}
        $valuesCount = [Math]::Min($values.Length, $compsColumns.Length)
        for($i = 0; $i -lt $valuesCount; $i++) {
            $dataValue = $values[$i].Trim().Trim("`"")
            $compData[$compsColumns[$i]] = $dataValue
        }
        $compGuid = $compData["AD GUID"]
        $existingCompsData.Add($compGuid, $compData)
    }
    $reader.Close()
}

$domainShortName = $env:USERDOMAIN

function Get-InstalledApps {
    param (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [string]$NameRegex = ''
    )
    
    foreach ($comp in $ComputerName) {
        $keys = '','\Wow6432Node'
        foreach ($key in $keys) {
            try {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                $apps = $reg.OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
            } catch {
                continue
            }

            foreach ($app in $apps) {
                $program = $reg.OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
                $name = $program.GetValue('DisplayName')
                if ($name -and $name -match $NameRegex) {
                    [pscustomobject]@{
                        ComputerName = $comp
                        Name = $name -replace ',',''
                        DisplayVersion = $program.GetValue('DisplayVersion')
                        Vendor = $program.GetValue('Publisher') -replace ',',''
                        InstallDate = $program.GetValue('InstallDate')
                        UninstallString = $program.GetValue('UninstallString')
                        Bits = $(if ($key -eq '\Wow6432Node') {'64'} else {'32'})
                        Path = $program.name
                    }
                }
            }
        }
    }
}

function GetLdapDateTime($entry, [string]$propertyName) {
    $result = [DateTime]::MinValue
    $propertyValues = $entry.Properties[$propertyName]
    if(($propertyValues.Count -ge 0) -and ($propertyValues[0])) {
        $result = [System.DateTime]::FromFileTime($propertyValues[0])
    }
    return $result
}

Write-host ""
Write-Host "Requesting a list of users from Active Directory..."

$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = "LDAP://$ldapDomain"
$searcher.Filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))"

Write-Host "Requesting a list of PCs from Active Directory..."
Write-host ""

$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = "LDAP://$ldapDomain"
$searcher.Filter = "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
$searcher.Sort = New-Object System.DirectoryServices.SortOption "cn", Ascending

$allSoftware = @{}
$softwareByComps = @{}
$softwareScanDatesByComps = @{}

foreach($result in $searcher.FindAll()) {
    $isMsa = $false
    foreach($class in $result.Properties["objectClass"]) {
        if($class -eq "msDS-ManagedServiceAccount") {
            $isMsa = $true
            break
        }
    }
    if($isMsa) {
        continue
    }

    $entry = $result.GetDirectoryEntry()
    $compName = $entry.Name.Value
    Write-Host "$compName ... " -NoNewline
    $guid = $entry.Guid
    $ouItems = @()
    $pathItems = $entry.Path.Split(",")
    for($i = $pathItems.Length-1; $i -ge 0; $i--) {
        if($pathItems[$i].StartsWith("OU=")) {
            $ouItems += $pathItems[$i].Substring(3)
        }
    }
    $ou = [String]::Join("\", $ouItems)
    
    $pingResult = Get-WmiObject -Query "SELECT * FROM Win32_PingStatus WHERE Address = '$compName'"
    $online = $pingResult.StatusCode -eq 0
    if($online) {
        $date = [DateTime]::Today
        Write-Host "online"
    }
    else {
        Write-Host "offline"
        $lastLogon = GetLdapDateTime $result "lastLogon"
        $lastLogonTimeStamp = GetLdapDateTime $result "lastLogonTimestamp"
        if($lastLogon -gt $lastLogonTimeStamp) {
            $date = $lastLogon
        }
        else {
            $date = $lastLogonTimeStamp
        }
    }
    
    $os = $result.Properties["operatingSystem"][0]
    $osVersionValue = $result.Properties["OperatingSystemVersion"][0]

    if (($os -like '*Windows 8*') –or ($os -like '*Windows 10*') –or ($os -like 'Windows 11*')) {
    $WinBuilds= @{
            '10.0 (22631)' = "Windows 11 23H2"
            '10.0 (22621)' = "Windows 11 22H2"
            '10.0 (22000)' = "Windows 11 21H2"
            '10.0 (19045)' = "Windows 10 22H2"
            '10.0 (19044)' = "Windows 10 21H2"
            '10.0 (19043)' = "Windows 10 21H1"
            '10.0 (19042)' = "Windows 10 20H2"
            '10.0 (18363)' = "Windows 10 1909"
            '10.0 (18362)' = "Windows 10 1903"
            '10.0 (17763)' = "Windows 10 1809"
            '10.0 (17134)' = "Windows 10 1803"
            '10.0 (16299)' = "Windows 10 1709"
            '10.0 (15063)' = "Windows 10 1703"
            '10.0 (14393)' = "Windows 10 1607"
            '10.0 (10586)' = "Windows 10 1511"
            '10.0 (10240)' = "Windows 10 1507"
            '10.0 (18898)' = 'Windows 10 Insider Preview'
            '6.3 (9200)' = "Windows 8.1"
        }
    $osVersion= $WinBuilds[$osVersionValue]
    }
    else {$osVersion = $OperatingSystem}
        if ($osVersion) {
            $osVersion
        } else {
            'Unknown'
    }

    $ipAddress = $null

    if($pingResult.IPV4Address) {
        $ipAddress = $pingResult.IPV4Address.IPAddressToString
    }
    if(-not $ipAddress) {
        $ipAddress = $pingResult.ProtocolAddress
    }

    $compSys = $null
    $cpuModel = $null
    $cpuFreq = $null
    $cpuCores = $null
    $ramTotal = $null
    $fixedDisksCapacity = $null
    $fixedDisks = $null

    if($online) {
        Try {
            $compSys = Get-WmiObject "Win32_ComputerSystem" -ComputerName $compName -ErrorAction Stop
        }
        Catch {
            Write-host "WMI Exception for $compName !!!"  -ForegroundColor Red
            $valError++
            $products = Get-InstalledApps -ComputerName $compName
            if($products) {
                $installedSoftware = New-Object System.Collections.Hashtable $products.Length
                $softwareByComps[$compName] = $installedSoftware
                $softwareScanDatesByComps[$compName] = [DateTime]::Today.ToString("dd.MM.yyyy")
                foreach($product in $products) {
                    if(-not $product.Name) {
                        continue
                    }
            $installedSoftware[$product.Name] = $null
            $allSoftware[$product.Name] = $product
            }
            }
        }    
    }
    if($compSys) {
        $valOnline++
        $profiles = Get-WmiObject "Win32_NetworkLoginProfile" -ComputerName $compName
        $lastLogonTime = [DateTime]::MinValue
        foreach($profile in $profiles) {
            if(-not $profile.Name.StartsWith($domainShortName, [StringComparison]::CurrentCultureIgnoreCase)) {
                continue
            }
            if($profile.LastLogon) {
                $lastProfileLogonTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($profile.LastLogon)
            }
            if($lastProfileLogonTime -gt $lastLogonTime) {
                $lastLogonTime = $lastProfileLogonTime
            }
        }

        $products = Get-InstalledApps -ComputerName $compName
        if($products) {
            $installedSoftware = New-Object System.Collections.Hashtable $products.Length
            $softwareByComps[$compName] = $installedSoftware
            $softwareScanDatesByComps[$compName] = [DateTime]::Today.ToString("dd.MM.yyyy")
            foreach($product in $products) {
                if(-not $product.Name) {
                    continue
                }
                $installedSoftware[$product.Name] = $null
                $allSoftware[$product.Name] = $product
            }
        }

        $cpu = Get-WmiObject Win32_Processor -ComputerName $compName
        if($cpu) {
            $cpuModel = $cpu.Name
            while($cpuModel.IndexOf("  ") -ne -1) {
                $cpuModel = $cpuModel.Replace("  ", " ")
            }
            $cpuFreq = $cpu.MaxClockSpeed
            $cpuCores = $cpu.NumberOfCores
        }
        $physicalMemory = Get-WmiObject Win32_PhysicalMemory -ComputerName $compName
        if($physicalMemory) {
            $ramTotal = 0
            foreach($physicalMemoryItem in $physicalMemory) {
                $ramTotal += $physicalMemoryItem.Capacity
            }
            $ramTotal = [int]($ramTotal / 1024 / 1024)
        }
        $fixedDrives = Get-WmiObject -Query "SELECT * FROM Win32_DiskDrive WHERE MediaType='Fixed hard disk media' OR MediaType='Fixed hard disk'" -ComputerName $compName
        $fixedDisksCapacity = 0
        $fixedDisks = @()
        foreach($fixedDrive in $fixedDrives) {
            if($fixedDrive) {
                $fixedDisksCapacity += [int]($fixedDrive.Size / 1000000000)
                $fixedDisks += $fixedDrive.Model
            }
        }
        $fixedDisks = [String]::Join(" + ", $fixedDisks)

    }

    if($existingCompsData.ContainsKey($guid)) {
        $previousValues = $existingCompsData[$guid]
        if(-not $ipAddress) {
            $ipAddress = $previousValues["IP"]
        }
        if(-not $cpuModel) {
            $cpuModel = $previousValues["CPU"]
        }
        if(-not $cpuFreq) {
            $cpuFreq = $previousValues["Frequency, MHz"]
        }
        if(-not $cpuCores) {
            $cpuCores = $previousValues["Cores"]
        }
        if(-not $ramTotal) {
            $ramTotal = $previousValues["RAM, MB"]
        }
        if(-not $fixedDisksCapacity) {
            $fixedDisksCapacity = $previousValues["Disk size, GB"]
        }
        if(-not $fixedDisks) {
            $fixedDisks = $previousValues["Disk models"]
        }
    }

    $items = @()
    $items += $compName
    $items += $date.ToString("dd.MM.yyyy")
    $items += $ou
    $items += $os
    $items += $osVersion
    $items += $ipAddress
    $items += $cpuModel
    $items += $cpuFreq
    $items += $cpuCores
    $items += $ramTotal
    $items += $fixedDisksCapacity
    $items += $fixedDisks
    $writer = New-Object System.IO.StreamWriter $compTempFileName, $true, $encoding
    $writer.WriteLine([String]::Join(",", $items))
    $writer.Close()
}

if(Test-Path $compFileName) {
    Remove-Item $compFileName -Force
}

$compFileName = "$PSScriptRoot\$leftPart-Computers.csv"
Rename-Item $compTempFileName -NewName $compFileName

Write-host ""
Write-Host "Merging software information..."
Write-host ""

if(Test-Path $softFileName) {
    $reader = New-Object System.IO.StreamReader $softFileName, $encoding
    $firstLine = $reader.ReadLine()
    $compNames = $firstLine.Split(",")
    $absentCompIndexes = @()
    for($i = $softColumns.Length; $i -lt $compNames.Length; $i++) {
        if(-not $softwareByComps.ContainsKey($compNames[$i])) {
            $absentCompIndexes += $i
        }
    }
    if($absentCompIndexes) {
        $secondLine = $reader.ReadLine()
        $scanDates = $secondLine.Split(",")
        foreach($index in $absentCompIndexes) {
            $compName = $compNames[$index]
            $softwareByComps[$compName] = New-Object System.Collections.Hashtable
            $softwareScanDatesByComps[$compName] = $scanDates[$index]
        }
        while(-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $values = $line.Split(",")
            $productStub = New-Object PSObject
            $productStub | Add-Member NoteProperty -Name Name -Value $values[0]
            $productStub | Add-Member NoteProperty -Name Vendor -Value $values[1]
            $productInstalledOnAbsent = $false
            foreach($index in $absentCompIndexes) {
                $compName = $compNames[$index]
                if(-not [String]::IsNullOrEmpty($values[$index])) {
                    $productInstalledOnAbsent = $true
                    $softwareByComps[$compName].Add($productStub.Name, $null)
                }
            }
            if($productInstalledOnAbsent -and (-not $allSoftware.ContainsKey($productStub.Name))) {
                $allSoftware[$productStub.Name] = $productStub
            }
        }
    }
    $reader.Close()
}

$allScannedComps = New-Object System.Collections.ArrayList $softwareByComps.Keys
$allScannedComps.Sort()
$allSoftwareSorted = New-Object System.Collections.ArrayList $allSoftware.Keys
$allSoftwareSorted.Sort()

$writer = New-Object System.IO.StreamWriter $softTempFileName, $encoding
$preamble = $encoding.GetPreamble()
$writer.BaseStream.Write($preamble, 0, $preamble.Length)
$writer.Write([String]::Join(",", $softColumns))
foreach($compName in $allScannedComps) {
    $writer.Write("," + $compName)
}
$writer.WriteLine()
$writer.Write(",")
foreach($compName in $allScannedComps) {
    $writer.Write("," + $softwareScanDatesByComps[$compName])
}
$writer.WriteLine()

foreach($productName in $allSoftwareSorted) {
    $product = $allSoftware[$productName]
    $writer.Write($productName + "," + $product.Vendor)
    foreach($compName in $allScannedComps) {
        $installedSoftware = $softwareByComps[$compName]
        if($installedSoftware.ContainsKey($productName)) {
            $mark = "√"
        }
        else {
            $mark = ""
        }
        $writer.Write("," + $mark)
    }
    $writer.WriteLine()
}

$writer.Close()

if(Test-Path $softFileName) {
    Remove-Item $softFileName -Force
}

$softFileName = "$PSScriptRoot\$leftPart-Software.csv"
Rename-Item $softTempFileName -NewName $softFileName
}

Compress-Archive -Force "$PSScriptRoot\*.csv" "$PSScriptRoot\OU.zip"

$User = "AUTH_USER@gmail.com"
$File = "$PSScriptRoot\.env"
$Cred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content $File | ConvertTo-SecureString -AsPlainText -Force)
$EmailTo = "EMAIL_TO@gmail.com"
$EmailFrom = "EMAIL_FROM@gmail.com"
$Subject = "Inventory Active Directory"
$Body = "Inventory Active Directory Results: $dateCurrent."
$SMTPServer = "smtp.gmail.com"
$FileNameAndPath = "$PSScriptRoot\OU.zip"
$SMTPMessage = New-Object System.Net.Mail.MailMessage($EmailFrom,$EmailTo,$Subject,$Body)
$Attachment = New-Object System.Net.Mail.Attachment($FileNameAndPath)
$SMTPMessage.Attachments.Add($Attachment)
$SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer, 587)
$SMTPClient.EnableSsl = $true
$SMTPClient.Credentials = New-Object System.Net.NetworkCredential($Cred.UserName, $Cred.Password);
$SMTPClient.Send($SMTPMessage)
$Attachment.Dispose();
$SMTPMessage.Dispose();

Remove-Item "$PSScriptRoot\*.csv" -Force
Remove-Item "$PSScriptRoot\OU.zip" -Force

Write-host "Online computers: $valOnline" -ForegroundColor Green
Write-host "Computers with WMI Exception: $valError" -ForegroundColor Red