Write-Host "^_^ | Inventory Active Directory Script | ^_^" -ForegroundColor Green

[Environment]::CurrentDirectory = pwd

$compFileName = "Computers.csv"
$compTempFileName = "Computers.tmp"

$softFileName = "Software.csv"
$softTempFileName = "Software.tmp"

$encoding = [System.Text.Encoding]::UTF8
$compsColumns = @(
    "Name",
    "Last used"
    "Who entered the domain"
    "Been online"    
    "OU",
    "OS",
    "Platform",
    "Total OS"
    "IP",
    "MAC",
    "AD GUID",
    "CPU",
    "Frequency - MHz"
    "Cores",
    "RAM - MB"
    "Drive size - GB"
    "Drive models"
    "Monitors"
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
$writer.WriteLine([String]::Join(";", $compsColumns))
$writer.Close()

$existingCompsData = @{}

if(Test-Path $compFileName) {
    $reader = New-Object System.IO.StreamReader $compFileName, $encoding
    $temp = $reader.ReadLine()
    while(-not $reader.EndOfStream) {
        $line = $reader.ReadLine()
        $values = $line.Split(";")
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

$dnsDomain = $env:USERDNSDOMAIN
$domainShortName = $env:USERDOMAIN
$ds = [System.Reflection.Assembly]::Load("System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
$ldapNameItems = @()
foreach($dnsDomainLevel in $dnsDomain.Split('.')) {
    $ldapNameItems += "dc=" + $dnsDomainLevel.ToLower()
}
$ldapDomain = [String]::Join(",", $ldapNameItems)    

function GetLdapSid($entry, [string]$propertyName) {
    $propertyValues = $result.Properties[$propertyName]
    if($propertyValues -and $propertyValues.Length -gt 0) {
        $sidBytes = $propertyValues[0]
        $sid = New-Object System.Security.Principal.SecurityIdentifier $sidBytes, 0
        return $sid.Value
    }
    return $null
}

function GetLdapDateTime($entry, [string]$propertyName) {
    $result = [DateTime]::MinValue
    $propertyValues = $entry.Properties[$propertyName]
    if(($propertyValues.Count -ge 0) -and ($propertyValues[0])) {
        $result = [System.DateTime]::FromFileTime($propertyValues[0])
    }
    return $result
}


Write-Host "Requesting a list of users from Active Directory..."


$adNamesBySid = @{}
$adNamesByLogin = @{}
$sidsByLogin = @{}

$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = "LDAP://$ldapDomain"
$searcher.Filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))"

foreach($result in $searcher.FindAll()) {
    $sid = GetLdapSid $result "objectSid"
    $name = $result.Properties["name"]
    $login = $result.Properties["sAMAccountName"]
    $adNamesBySid.Add($sid, $name)
    $sidsByLogin.Add($login.ToLower(), $sid)
    $adNamesByLogin.Add($login.ToLower(), $name)
}

function GetShortLogin([string]$name) {
    $result = $name
    $p = $result.IndexOf("\")
    if($p -ne -1) {
        $result = $result.Substring($p + 1)
    }
    $p = $result.IndexOf("@")
    if($p -ne -1) {
        $result = $result.Substring(0, $p)
    }
    return $result
}

function GetADNameBySid([string]$sid) {
    if($adNamesBySid.ContainsKey($sid)) {
        return $adNamesBySid[$sid]
    }
    return $null
}

function GetADNameByLogin([string]$login) {
    $login = GetShortLogin $login.ToLower()
    if($adNamesByLogin.ContainsKey($login)) {
        return $adNamesByLogin[$login]
    }
    return $null
}

function GetSidByLogin([string]$name) {
    $name = GetShortLogin $name.ToLower()
    if($sidsByLogin.ContainsKey($name)) {
        return $sidsByLogin[$name]
    }
}

function GetNameByLdapSid($entry, [string]$propertyName) {
    $sid = GetLdapSid $entry $propertyName
    $name = GetADNameBySid $sid
    return $name
}

function IntegersToString($source, $length = -1) {
    if($length -lt 0) {
        $length = $source.Length
    }
    $endIndex = $length
    while(($source[$endIndex-1] -eq 0) -and ($endIndex -gt 0)) {
        $endIndex -= 1
    }
    $bytes = [Array]::CreateInstance([byte], $endIndex)
    for($i = 0; $i -lt $endIndex; $i++) {
        $bytes[$i] = [byte]$source[$i]
    }
    return [System.Text.Encoding]::ASCII.GetString($bytes).Trim()
}

$macRegex = New-Object System.Text.RegularExpressions.Regex "[\da-fA-F][\da-fA-F]-[\da-fA-F][\da-fA-F]-[\da-fA-F][\da-fA-F]-[\da-fA-F][\da-fA-F]-[\da-fA-F][\da-fA-F]-[\da-fA-F][\da-fA-F]"

$hklmKey = [UInt32]"0x80000002"
$profilesKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$baseTime = New-Object DateTime 1601, 1, 1


Write-Host "Requesting a list of PCs from Active Directory..."


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
    $AdJoinUser = GetNameByLdapSid $result "mS-DS-CreatorSID"

    $ipAddress = $null
    $macAddress = $null
    if($pingResult.IPV4Address) {
        $ipAddress = $pingResult.IPV4Address.IPAddressToString
    }
    if(-not $ipAddress) {
        $ipAddress = $pingResult.ProtocolAddress
    }
    if($ipAddress) {
        $arpResults = arp -a $ipAddress
        foreach($line in $arpResults) {
            $match = $macRegex.Match($line)
            if($match.Success) {
                $macAddress = $match.Value
            }
        }
    }

    $platform = $null
    $lastLogonUser = $null
    $compSys = $null
    $allOs = $null
    $cpuModel = $null
    $cpuFreq = $null
    $cpuCores = $null
    $ramTotal = $null
    $fixedDisksCapacity = $null
    $fixedDisks = $null
    $monitors = $null
    if($online) {
        $compSys = Get-WmiObject "Win32_ComputerSystem" -ComputerName $compName
    }
    if($compSys) {
        if($compSys.Model -eq "Virtual Machine") {
            $platform = "Virtual"
        }
        else {
            $platform = "Physical"
        }
        $stdRegProv = [WmiClass]"\\$compName\root\default:StdRegProv"
        $profiles = Get-WmiObject "Win32_NetworkLoginProfile" -ComputerName $compName
        $lastLogonTime = [DateTime]::MinValue
        foreach($profile in $profiles) {
            if(-not $profile.Name.StartsWith($domainShortName, [StringComparison]::CurrentCultureIgnoreCase)) {
                continue
            }
            if($profile.LastLogon) {
                $lastProfileLogonTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($profile.LastLogon)
            }
            else {
                $sid = GetSidByLogin $profile.Name
                if($sid) {
                    $getValueResult = $stdRegProv.GetDWORDValue($hklmKey, "$profilesKey\$sid", "ProfileLoadTimeHigh")
                    $high = [Int64]$getValueResult.uValue
                    $getValueResult = $stdRegProv.GetDWORDValue($hklmKey, "$profilesKey\$sid", "ProfileLoadTimeLow")
                    $low = [Int64]$getValueResult.uValue
    
                    $ticks = $high * [long]4294967296 + $low
                    if($ticks) {
                        $span = New-Object TimeSpan $ticks
                        $lastProfileLogonTime = $baseTime.Add($span)
                    }
                    else {
                        $getValueResult = $stdRegProv.GetExpandedStringValue($hklmKey, "$profilesKey\$sid", "ProfileImagePath")
                        $profileLocalPath = $getValueResult.sValue
                        $profileNetworkPath = "\\$compName\" + $profileLocalPath.Replace(":", "$")
                        $userPolFileName = [System.IO.Path]::Combine($profileNetworkPath, "ntuser.pol")
                        if(Test-Path $userPolFileName) {
                            $userPolFile = Get-Item $userPolFileName -Force
                            $lastProfileLogonTime = $userPolFile.LastWriteTime
                        }
                    }
                }
            }
            if($lastProfileLogonTime -gt $lastLogonTime) {
                $lastLogonUser = GetADNameByLogin $profile.Name
                $lastLogonTime = $lastProfileLogonTime
            }
        }
        $istalledOS = @()
        $osVersion = $result.Properties["operatingSystemVersion"][0]
        $isVistaOrHigher = $osVersion -and ([Int32]::Parse($osVersion[0]) -ge 6)
        if($isVistaOrHigher) {
            $bcdItems = & cscript.exe .\BcdQuery.vbs //nologo "$compName" 
            foreach($item in $bcdItems) {
                if($item -and ($item -ne "Windows Recovery Environment")) {
                    $istalledOS += $item
                }
            }
        }
        if($istalledOS.Length -gt 0) {
            $allOs = $istalledOS.Length.ToString()
            if($istalledOS.Length -gt 1) {
                [Array]::Sort($istalledOS)
                $allOs = "`"" + $allOs + " (" + [String]::Join(", ", $istalledOS) + ")`""
            }
        }
        $products = Get-WmiObject Win32_Product -ComputerName $compName
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
        if($isVistaOrHigher) {
            $monitorIds = Get-WmiObject WmiMonitorID -Namespace root\wmi -ComputerName $compName
            $displayParams = Get-WmiObject WmiMonitorBasicDisplayParams -Namespace root\wmi -ComputerName $compName
            $monitorsList = @()
            foreach($monitorId in $monitorIds) {
                $params = $null
                foreach($displayParam in $displayParams) {
                    if($displayParam.InstanceName -eq $monitorId.InstanceName) {
                        $params = $displayParam
                        break
                    }
                }
                $diagonal = [Math]::Sqrt([double]$params.MaxHorizontalImageSize*$params.MaxHorizontalImageSize + $params.MaxVerticalImageSize*$params.MaxVerticalImageSize)
                $diagonal = [int]($diagonal / 2.54)
                $manufacturer = IntegersToString $monitorId.ManufacturerName
                $model = IntegersToString $monitorId.UserFriendlyName $monitorId.UserFriendlyNameLength
                $serial = IntegersToString $monitorId.SerialNumberID
                $monitorsList += "$manufacturer $model $diagonal`""
            }
            if($monitorsList) {
                $monitors = [String]::Join(" + ", $monitorsList)
            }
        }
    }

    if($existingCompsData.ContainsKey($guid)) {
        $previousValues = $existingCompsData[$guid]
        if(-not $lastLogonUser) {
            $lastLogonUser = $previousValues["Last used"]
        }
        if(-not $platform) {
            $platform = $previousValues["Platform"]
        }
        if(-not $allOs) {
            $allOs = $previousValues["Total OS"]
        }
        if(-not $ipAddress) {
            $ipAddress = $previousValues["IP"]
        }
        if(-not $macAddress) {
            $macAddress = $previousValues["MAC"]
        }
        if(-not $cpuModel) {
            $cpuModel = $previousValues["CPU"]
        }
        if(-not $cpuFreq) {
            $cpuFreq = $previousValues["Frequency - MHz"]
        }
        if(-not $cpuCores) {
            $cpuCores = $previousValues["Cores"]
        }
        if(-not $ramTotal) {
            $ramTotal = $previousValues["RAM - MB"]
        }
        if(-not $fixedDisksCapacity) {
            $fixedDisksCapacity = $previousValues["Drive size - GB"]
        }
        if(-not $fixedDisks) {
            $fixedDisks = $previousValues["Drive models"]
        }
        if(-not $monitors) {
            $monitors = $previousValues["Monitors"]
        }
    }

    $items = @()
    $items += $compName
    $items += $lastLogonUser
    $items += $AdJoinUser
    $items += $date.ToString("dd.MM.yyyy")
    $items += $ou
    $items += $os
    $items += $platform
    $items += $allOs
    $items += $ipAddress
    $items += $macAddress
    $items += $guid    
    $items += $cpuModel
    $items += $cpuFreq
    $items += $cpuCores
    $items += $ramTotal
    $items += $fixedDisksCapacity
    $items += $fixedDisks
    $items += $monitors
    $writer = New-Object System.IO.StreamWriter $compTempFileName, $true, $encoding
    $writer.WriteLine([String]::Join(";", $items))
    $writer.Close()
}

if(Test-Path $compFileName) {
    Remove-Item $compFileName -Force
}

Rename-Item $compTempFileName $compFileName


Write-Host "Merging software information..."


if(Test-Path $softFileName) {
    $reader = New-Object System.IO.StreamReader $softFileName, $encoding
    $firstLine = $reader.ReadLine()
    $compNames = $firstLine.Split(";")
    $absentCompIndexes = @()
    for($i = $softColumns.Length; $i -lt $compNames.Length; $i++) {
        if(-not $softwareByComps.ContainsKey($compNames[$i])) {
            $absentCompIndexes += $i
        }
    }
    if($absentCompIndexes) {
        $secondLine = $reader.ReadLine()
        $scanDates = $secondLine.Split(";")
        foreach($index in $absentCompIndexes) {
            $compName = $compNames[$index]
            $softwareByComps[$compName] = New-Object System.Collections.Hashtable
            $softwareScanDatesByComps[$compName] = $scanDates[$index]
        }
        while(-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $values = $line.Split(";")
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
$writer.Write([String]::Join(";", $softColumns))
foreach($compName in $allScannedComps) {
    $writer.Write(";" + $compName)
}
$writer.WriteLine()
$writer.Write(";")
foreach($compName in $allScannedComps) {
    $writer.Write(";" + $softwareScanDatesByComps[$compName])
}
$writer.WriteLine()

foreach($productName in $allSoftwareSorted) {
    $product = $allSoftware[$productName]
    $writer.Write($productName + ";" + $product.Vendor)
    foreach($compName in $allScannedComps) {
        $installedSoftware = $softwareByComps[$compName]
        if($installedSoftware.ContainsKey($productName)) {
            $mark = "√"
        }
        else {
            $mark = ""
        }
        $writer.Write(";" + $mark)
    }
    $writer.WriteLine()
}

$writer.Close()

if(Test-Path $softFileName) {
    Remove-Item $softFileName -Force
}

Rename-Item $softTempFileName $softFileName