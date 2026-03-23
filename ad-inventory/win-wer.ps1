function ConvertWindowsBuild { [CmdletBinding()] param([string] $OperatingSystem, [string] $OperatingSystemVersion)

if (($OperatingSystem -like '*Windows 10*') –or ($OperatingSystem -like 'Windows 11*')) {
    $WinBuilds = @{
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
    $WinBuild= $WinBuilds[$OperatingSystemVersion]
}
else { $WinBuild = $OperatingSystem }

if ($WinBuild) { $WinBuild } 
else { 'Unknown' }
}

$Comps = Get-ADComputer -Filter {(Enabled -eq $True)} -properties *
$CompList = foreach ($Comp in $Comps) { [PSCustomObject] @{
    Name = $Comp.Name
    IPv4Address = $Comp.IPv4Address
    OperatingSystem = $Comp.OperatingSystem
    Build = ConvertWindowsBuild -OperatingSystem $Comp.OperatingSystem -OperatingSystemVersion $Comp.OperatingSystemVersion
    LastLogonDate = $Comp.LastLogonDate
    }
}

$CompList | Out-GridView