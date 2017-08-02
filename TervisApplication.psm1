$ApplicationDefinition = [PSCustomObject][Ordered]@{
    Name = "KafkaBroker"
    NodeNameRoot = "Kafka"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 3
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4084
    },
    [PSCustomObject][Ordered]@{
        Name = "Epsilon"
        NumberOfNodes = 3
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4138
    },
    [PSCustomObject][Ordered]@{
        Name = "Delta"
        NumberOfNodes = 3
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4139
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "Prometheus"
    NodeNameRoot = "Prometh"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
        VMSizeName = "Medium"
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "Progistics"
    NodeNameRoot = "Progis"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 2
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4104
    },
    [PSCustomObject][Ordered]@{
        Name = "Epsilon"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4106
    },
    [PSCustomObject][Ordered]@{
        Name = "Delta"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4105
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "BartenderCommander"
    NodeNameRoot = "Bartender"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 2
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4095
    },
    [PSCustomObject][Ordered]@{
        Name = "Epsilon"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 4101
    },
    [PSCustomObject][Ordered]@{
        Name = "Delta"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 4102
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "BartenderIntegrationService"
    NodeNameRoot = "BartendIS"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4356
    },
    [PSCustomObject][Ordered]@{
        Name = "Epsilon"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4357
    },
    [PSCustomObject][Ordered]@{
        Name = "Delta"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4358
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "BartenderLicenseServer"
    NodeNameRoot = "BTLicense"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4121
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "WCSJavaApplication"
    NodeNameRoot = "WCSApp"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4109
    },
    [PSCustomObject][Ordered]@{
        Name = "Epsilon"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4110
    },
    [PSCustomObject][Ordered]@{
        Name = "Delta"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4111
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "PrintServer"
    NodeNameRoot = "PrintSrv"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4112
    },
    [PSCustomObject][Ordered]@{
        Name = "Epsilon"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4113
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "DirectAccess"
    NodeNameRoot = "DirectAcc"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4114
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "SCDPM2016"
    NodeNameRoot = "SCDPM2016"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4124
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "Phishing"
    NodeNameRoot = "Phishing"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4158
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "RMSHQManagerRemoteApp"
    NodeNameRoot = "HQMgrApp"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4166
    },
    [PSCustomObject][Ordered]@{
        Name = "Epsilon"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4167
    },
    [PSCustomObject][Ordered]@{
        Name = "Delta"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4168
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "OracleDBA Remote Desktop"
    NodeNameRoot = "OraDBARMT"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4171
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "RemoteWebBrowserApp"
    NodeNameRoot = "RmtWebApp"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4170
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "StoresRemoteDesktop"
    NodeNameRoot = "StoresRDS"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4170
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "ScheduledTasks"
    NodeNameRoot = "SchedTask"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4176
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "KeyscanRemoteApp"
    NodeNameRoot = "KeyscanAp"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 4180
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "WCSRemoteApp"
    NodeNameRoot = "WCSRmtApp"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4183
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "RemoteDesktopGateway"
    NodeNameRoot = "RDGateway"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4188
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "RemoteDesktopWebAccess"
    NodeNameRoot = "RDWebAcc"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4190
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "SCDPM2016FileServer"
    NodeNameRoot = "DPM2016FS"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 4124
        SQLSAPassword = 4038
        DPMServiceAccountPassword = 4037

    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "SCDPM2016SQL"
    NodeNameRoot = "SCDPMSQL"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4124
        SQLSAPassword = 4038
        DPMServiceAccountPassword = 4037

    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "DataLoadClassic"
    NodeNameRoot = "DataLoad"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 4280
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "HyperVCluster5"
    NodeNameRoot = "HyperVC5N"
    ComputeType = "Physical"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        LocalAdminPasswordStateID = 4348
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "HyperVCluster6"
    NodeNameRoot = "HyperVC6N"
    ComputeType = "Physical"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        LocalAdminPasswordStateID = 4349
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "WindowsApps"
    NodeNameRoot = "WinRmtApp"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4283
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "EBSRemoteApp"
    NodeNameRoot = "EBSRemote"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4351
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "SFTP"
    NodeNameRoot = "SFTP"
    ComputerType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Small"
    }
    VMOperatingSystemTemplateName = "CentOS 7"
}

function Get-TervisApplicationDefinition {
    param (
        [Parameter(Mandatory)]$Name
    )
    
    $ApplicationDefinition | 
    where Name -EQ $Name
}

function Get-TervisApplicationNode {
    param (
        [Parameter(Mandatory,ParameterSetName="ApplicationName")]$ApplicationName,
        [Parameter(Mandatory,ParameterSetName="All")][Switch]$All,
        [String[]]$EnvironmentName,
        [Switch]$IncludeVM        
    )
    $ApplicationDefinitions = if ($ApplicationName) {
        Get-TervisApplicationDefinition -Name $ApplicationName
    } else {
        $ApplicationDefinition
    }

    foreach ($ApplicationDefinition in $ApplicationDefinitions) {    
        $Environments = $ApplicationDefinition.Environments |
        where {-not $EnvironmentName -or $_.Name -In $EnvironmentName}

        foreach ($Environment in $Environments) {
            foreach ($NodeNumber in 1..$Environment.NumberOfNodes) {
                $EnvironmentPrefix = get-TervisEnvironmentPrefix -EnvironmentName $Environment.Name
                $Node = [PSCustomObject][Ordered]@{                
                    ComputerName = "$EnvironmentPrefix-$($ApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
                    EnvironmentName = $Environment.Name
                    ApplicationName = $ApplicationDefinition.Name
                    NameWithoutPrefix = "$($ApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
                    LocalAdminPasswordStateID = $Environment.LocalAdminPasswordStateID
                }
            
                if ($IncludeVM) {
                    $Node | Add-Member -MemberType NoteProperty -Name VMSizeName -Value $Environment.VMSizeName
                    $Node | Add-NodeVMProperty
                }

                $Node | Add-NodeIPAddressProperty -PassThru
            }
        }
    }
}

function Add-NodeIPAddressProperty {
    param (
        [Parameter(ValueFromPipeline)]$Node,
        [Switch]$PassThru
    )
    process {
        if ($Node.VM) {
            $Node | Add-Member -MemberType ScriptProperty -Force -Name IPAddress -Value {
                $VMNetworkMacAddress = ($This.VM.vmnetworkadapter.MacAddress -replace '..(?!$)', '$&-')
                Find-DHCPServerv4LeaseIPAddress -MACAddressWithDashes $VMNetworkMacAddress -AsString
            }
        } else {
            $Node | Add-Member -MemberType ScriptProperty -Force -Name IPAddress -Value {
                Find-DHCPServerv4LeaseIPAddress -HostName $This.ComputerName -AsString |
                Select-Object -First 1
            }
        }
        if ($PassThru) { $Node }
    }
}

function Add-NodeVMProperty {
    param (
        [Parameter(ValueFromPipeline)]$Node,
        [Switch]$PassThru
    )
    process {
        $Node | Add-Member -MemberType NoteProperty -Name VM -PassThru:$PassThru -Force -Value $(
            Find-TervisVM -Name $Node.ComputerName
        )        
    }
}

function Invoke-ApplicationProvision {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]$ApplicationName,
        $EnvironmentName,
        [Switch]$SkipInstallTervisChocolateyPackages
    )
    $ApplicationDefinition = Get-TervisApplicationDefinition -Name $ApplicationName

    if ($ApplicationDefinition.ComputeType -eq "Virtual") {
        $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -IncludeVM -EnvironmentName $EnvironmentName
        
        $Nodes |
        where {-not $_.VM} |
        Invoke-ApplicationNodeVMProvision -ApplicationName $ApplicationName
  
        if ( $Nodes | where {-not $_.VM} ) {
            throw "Not all nodes have VMs even after Invoke-ApplicationNodeVMProvision"
        }

    } elseif ($ApplicationDefinition.ComputeType -eq "Physical") {
        $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    }
    
    $Nodes | Invoke-ApplicationNodeProvision -SkipInstallTervisChocolateyPackages:$SkipInstallTervisChocolateyPackages
}

function Invoke-ApplicationNodeProvision {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Switch]$SkipInstallTervisChocolateyPackages
    )
    process {
        $ApplicationDefinition = Get-TervisApplicationDefinition -Name $Node.ApplicationName

        if ($ApplicationDefinition.VMOperatingSystemTemplateName -in "Windows Server 2016") {
            $Node | Add-IPAddressToWSManTrustedHosts
        
            $IPAddress = $Node.IPAddress
            $TemplateCredential = Get-PasswordstateCredential -PasswordID 4097
            $Credential = Get-PasswordstateCredential -PasswordID $Node.LocalAdminPasswordStateID
            Set-TervisLocalAdministratorPassword -ComputerName $IPAddress -Credential $TemplateCredential -NewCredential $Credential
            Enable-TervisNetFirewallRuleGroup -Name $Node.ApplicationName -ComputerName $IPAddress -Credential $Credential
            Invoke-TervisRenameComputerOnOrOffDomain -ComputerName $Node.ComputerName -IPAddress $IPAddress -Credential $Credential       
            Invoke-TervisApplicationNodeJoinDomain -IPAddress $IPAddress -Credential $Credential -Node $Node
            Invoke-GPUpdate -Computer $Node.ComputerName -RandomDelayInMinutes 0
        
            $Node | Install-ApplicationNodeWindowsFeature
            $Node | Install-ApplicationNodeDesiredStateConfiguration
            $Node | Install-TervisChocolateyOnNode

            if (-Not $SkipInstallTervisChocolateyPackages) {
                Install-TervisChocolateyPackages -ChocolateyPackageGroupNames $Node.ApplicationName -ComputerName $Node.ComputerName
            }

            Set-WINRMHTTPInTCPPublicRemoteAddressToLocalSubnet -ComputerName $Node.ComputerName
    
            $Node | Set-ApplicationNodeTimeZone
            $Node | Enable-ApplicationNodeKerberosDoubleHop
            $Node | Enable-ApplicationNodeRemoteDesktop
            $Node | New-ApplicationNodeDnsCnameRecord
            $Node | New-ApplicationAdministratorPrivilegeADGroup
            $Node | Add-ApplicationAdministratorPrivilegeADGroupToLocalAdministrators
        }
        if ($ApplicationDefinition.VMOperatingSystemTemplateName -in "CentOS 7") {
            ####Generic Linux Code Goes Here####
        }
    }
}

function Add-ApplicationAdministratorPrivilegeADGroupToLocalAdministrators {
    param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName,
        
        [ValidateScript({$_ -in $ApplicationDefinition.Name})]
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        $ApplicationName
    )
    process {
        $PrivilegeADGroupName = Get-ApplicationAdministratorPrivilegeADGroupName -EnvironmentName $EnvironmentName -ApplicationName $ApplicationName
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {                    
            Add-LocalGroupMember -Name "Administrators" -Member $Using:PrivilegeADGroupName -ErrorAction SilentlyContinue
        }
    }
}

function New-ApplicationAdministratorPrivilegeADGroup {
    param(
        [ValidateScript({$_ -in $ApplicationDefinition.Name})]
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        $ApplicationName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    process {
        $ApplicationOrganizationalUnit = Get-TervisApplicationOrganizationalUnit -ApplicationName $ApplicationName
        $PrivilegeGroupName = Get-ApplicationAdministratorPrivilegeADGroupName -EnvironmentName $EnvironmentName -ApplicationName $ApplicationName
        $ADGroup = Get-ADGroup -SearchBase $ApplicationOrganizationalUnit -Filter {Name -eq $PrivilegeGroupName}
        if (-Not $ADGroup) {
            New-ADGroup -Name $PrivilegeGroupName -SamAccountName $PrivilegeGroupName -GroupCategory Security -GroupScope Universal -Path $ApplicationOrganizationalUnit
        }
    }
}

function Get-ApplicationAdministratorPrivilegeADGroupName {
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$EnvironmentName,
        
        [ValidateScript({$_ -in $ApplicationDefinition.Name})]
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        $ApplicationName
    )
    "Privilege_$($EnvironmentName)$($ApplicationName)Administrator"
}

function Get-ApplicationAdministratorPrivilegeADGroup {
    param(
        [ValidateScript({$_ -in $ApplicationDefinition.Name})]
        [Parameter(Mandatory)]
        $ApplicationName,

        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    process {
        $ApplicationOrganizationalUnit = Get-TervisApplicationOrganizationalUnit -ApplicationName $ApplicationName
        $PrivilegeGroupName = "Privilege_$($EnvironmentName)$($ApplicationName)Administrator"
        Get-ADGroup -SearchBase $ApplicationOrganizationalUnit -Filter {Name -eq $PrivilegeGroupName}
    }
}

function Install-TervisChocolateyOnNode {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Install-TervisChocolatey -ComputerName $ComputerName
    }

}

function Set-ApplicationNodeTimeZone {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Set-TimeZone -Id "Eastern Standard Time"
        }
    }
}

function Install-ApplicationNodeWindowsFeature {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$ApplicationName
    )
    process {
        $Result = Install-TervisWindowsFeature -WindowsFeatureGroupNames $ApplicationName -ComputerName $ComputerName
        if ($Result.RestartNeeded | ConvertTo-Boolean) {
            Restart-Computer -ComputerName $ComputerName -Force -Wait
        }
    }
}

function Install-ApplicationNodeDesiredStateConfiguration {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$ApplicationName
    )
    process {
        Install-TervisDesiredStateConfiguration -ApplicationName $ApplicationName -ComputerName $ComputerName
    }
}

function Enable-ApplicationNodeRemoteDesktop {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -PropertyType dword -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -PropertyType dword -Force | Out-Null
        }
    }
}

function Enable-ApplicationNodeKerberosDoubleHop {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        $Members = Get-ADGroupMember -Identity Privilege_PrincipalsAllowedToDelegateToAccount
        if (-not ($Members | where Name -EQ $ComputerName)) {
            Add-ComputerToPrivilege_PrincipalsAllowedToDelegateToAccount -ComputerName $ComputerName
            Restart-Computer -ComputerName $ComputerName -Force -Wait
        }
    }
}

function Set-WINRMHTTPInTCPPublicRemoteAddressToLocalSubnet {
    param (
        [Parameter(Mandatory)]$ComputerName,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    Invoke-Command -ComputerName $ComputerName -Credential $Credential {
        Get-NetFirewallRule -name WINRM-HTTP-In-TCP-Public | Set-NetFirewallRule -RemoteAddress LocalSubnet
    }
}

function Set-CurrentNetworkAsPrivateNetwork {
    param (
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$Credential
    )
    Invoke-command -ComputerName $ComputerName -Credential $Credential {
        Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
    }
}

function Set-TervisLocalAdministratorPassword {
    param (
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$Credential,
        [Parameter(Mandatory)]$NewCredential
    )
    $Session = New-PSSession -ComputerName $ComputerName -Credential $NewCredential -ErrorAction SilentlyContinue
    if (-not $Session) {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential {
            Set-LocalUser -Name administrator -Password $Using:NewCredential.password
        }
        $Session = New-PSSession -ComputerName $ComputerName -Credential $NewCredential -ErrorAction SilentlyContinue
        if (-not $Session) {
            throw "Cannot create session using new local administrator password"
        }
    }
    $Session | Remove-PSSession
}

function Get-TervisApplicationOrganizationalUnit {
    param(
        [ValidateScript({$_ -in $ApplicationDefinition.Name})]
        [Parameter(Mandatory)]
        $ApplicationName
    )
    $ApplicationOU = Get-ADOrganizationalUnit -Filter {Name -eq $ApplicationName}
    if ( -not $ApplicationOU) {
        $CattleOU = Get-ADOrganizationalUnit -Filter {Name -eq "Cattle"}
        New-ADOrganizationalUnit -Path $CattleOU.DistinguishedName -Name $ApplicationName -ProtectedFromAccidentalDeletion:$false -PassThru
    } else {
        $ApplicationOU
    }
}

function Invoke-TervisApplicationNodeJoinDomain {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)]$IPAddress,
        [Parameter(Mandatory)]$Credential

    )
    $OrganizationalUnit = Get-TervisApplicationOrganizationalUnit -ApplicationName $Node.ApplicationName
    Invoke-TervisJoinDomain -OUPath $OrganizationalUnit.DistinguishedName -ComputerName $Node.ComputerName -IPAddress $IPAddress -Credential $Credential
}

function Invoke-TervisJoinDomain {
    param(
        $OUPath = "OU=Sandbox,DC=tervis,DC=prv",
        $ComputerName,
        $IPAddress,
        $Credential        
    )
    $ADDomain = Get-ADDomain
    $DomainJoinCredential = Get-PasswordstateCredential -PasswordID 2643

    $CurrentDomainName = Get-DomainNameOnOrOffDomain -ComputerName $ComputerName -IPAddress $IPAddress -Credential $Credential
    if ($CurrentDomainName -ne $ADDomain.DNSRoot) {
        try {
            Add-Computer -DomainName $Using:ADDomain.forest -Force -Restart -OUPath $Using:OUPath -Credential $Using:DomainJoinCredential -ErrorAction Stop
        } catch {
            Invoke-Command -ComputerName $IPAddress -Credential $Credential -ScriptBlock {
                Add-Computer -DomainName $Using:ADDomain.forest -Force -Restart -OUPath $Using:OUPath -Credential $Using:DomainJoinCredential
            }         
        }
        Wait-ForNodeRestart -ComputerName $IPAddress -Credential $Credential
        $DomainNameAfterRestart = Get-DomainNameOnOrOffDomain -ComputerName $ComputerName -IPAddress $IPAddress -Credential $Credential
        if ($DomainNameAfterRestart -ne $ADDomain.DNSRoot) {
            Throw "Joining the domain for $ComputerName with ip address $IPAddress failed"
        }
    }
}

function Invoke-TervisRenameComputerOnOrOffDomain {
    param(
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$IPAddress,
        [Parameter(Mandatory)]$Credential
    )
    $CurrentHostname = Get-ComputerNameOnOrOffDomain @PSBoundParameters

    if ($CurrentHostname -ne $ComputerName) {
        Rename-Computer -NewName $ComputerName -Force -Restart -LocalCredential $Credential -ComputerName $IPAddress -Protocol WSMan
        Wait-ForNodeRestart -ComputerName $IPAddress -Credential $Credential
        $HostnameAfterRestart = Get-ComputerNameOnOrOffDomain @PSBoundParameters
        if ($HostnameAfterRestart -ne $ComputerName) {
            Throw "Rename of $ComputerName with ip address $IPAddress failed"
        }
    }
}

function Wait-ForNodeRestart {    
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$ComputerName,
        $PortNumbertoMonitor = 5985,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    process {
        $StartTime = Get-Date

        do {
            sleep 3
            Wait-ForPortAvailable -ComputerName $ComputerName -PortNumbertoMonitor $PortNumbertoMonitor -WarningAction SilentlyContinue
            $UpTime = Get-Uptime -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
        } While ($UpTime -gt ((Get-Date) - $StartTime)) 
    }
}

function Invoke-ApplicationNodeVMProvision {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Parameter(Mandatory)]$ApplicationName,
        [Switch]$PassThru
    )
    begin {
        $ADDomain = Get-ADDomain
        $ApplicationDefinition = Get-TervisApplicationDefinition -Name $ApplicationName
    }
    process {
        $Clusters = Get-TervisCluster -Domain $ADDomain.DNSRoot
        $LocalComputerADSite = Get-ComputerSite -ComputerName $Env:COMPUTERNAME
        $ClusterToCreateVMOn = $Clusters | where ADSite -eq $LocalComputerADSite
        
        $TervisVMParameters = @{
            VMNameWithoutEnvironmentPrefix = $Node.NameWithoutPrefix
            VMSizeName = $Node.VMSizeName
            VMOperatingSystemTemplateName = $ApplicationDefinition.VMOperatingSystemTemplateName
            EnvironmentName = $Node.EnvironmentName
            Cluster = $ClusterToCreateVMOn.Name
        }
        $TervisVMParameters | Write-VerboseAdvanced -Verbose:($VerbosePreference -ne "SilentlyContinue")
        if ($PSCmdlet.ShouldProcess("$($ClusterToCreateVMOn.Name)","Create VM $Node")) {
            New-TervisVM @TervisVMParameters -NeedsAccessToSAN:$($ApplicationDefinition.NeedsAccessToSAN) |
            Start-VM |
            Out-Null
        }
        $Node | Add-NodeVMProperty -PassThru | Add-NodeIPAddressProperty
        $VMTemplateCredential = Get-PasswordstateCredential -PasswordID 4097
        Wait-ForNodeRestart -ComputerName $Node.IPAddress -Credential $VMTemplateCredential
    }
}

function Get-ComputerName {
    [CmdletBinding()]
    param (
        $ComputerName,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    Invoke-Command -Credential $Credential -ComputerName $ComputerName -ScriptBlock {         
            $env:COMPUTERNAME
    }
}

function Get-DomainName {
    [CmdletBinding()]
    param (
        $ComputerName,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    Invoke-Command -Credential $Credential -ComputerName $ComputerName -ScriptBlock {         
        Get-ComputerInfo | select -ExpandProperty CSDomain
    }
}

function Get-Uptime {
    [CmdletBinding()]
    param (
        $ComputerName,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    $OperatingSystemObject = Get-WmiObject -ComputerName $ComputerName Win32_OperatingSystem -Credential $Credential
    $ConvertedUptimeString = [Management.ManagementDateTimeConverter]::ToDateTime($OperatingSystemObject.LastBootUpTime)
    $CurrentUptimeCalculation = (get-date) - $ConvertedUptimeString
    $CurrentUptimeCalculation
}

function Get-ComputerNameOnOrOffDomain {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$IPAddress,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        Get-ComputerName -ComputerName $IPAddress -Credential $Credential -ErrorAction Stop
    } catch {
        Get-ComputerName -ComputerName $ComputerName
    }
}

function Get-DomainNameOnOrOffDomain {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(Mandatory)]$IPAddress,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        Get-DomainName -ComputerName $IPAddress -Credential $Credential -ErrorAction Stop
    } catch {
        Get-DomainName -ComputerName $ComputerName
    }
}

function New-ApplicationNodePSSession {
    param (
        [Parameter(Mandatory)]$ApplicationName,
        $EnvironmentName
    )
    Get-TervisApplicationNode @PSBoundParameters |
    New-PSSession
}

function New-SplatVariable {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Invocation,
        $Variables,
        $ExcludeProperty
    )
    $CommandName = $Invocation.InvocationName
    $ParameterList = (Get-Command -Name $CommandName).Parameters
    $VariablesToSplat = $Variables | 
        where Name -In $ParameterList.Values.Name | 
        where {-Not $ExcludeProperty -or $_.Name -notin $ExcludeProperty}
    $SplatVariable = @{}
    $VariablesToSplat | foreach {$SplatVariable[$_.Name] = $_.Value}
    $SplatVariable
}

function Remove-HashtableKeysWithEmptyOrNullValues {
    param (
        [Parameter(ValueFromPipeline,Mandatory)]
        [Hashtable]$Hashtable
    )
    process {
        $NewHashtable = @{}
        foreach ($Key in $Hashtable.Keys) {
            if (($Hashtable.$Key -ne $null) -and ($Hashtable.$Key -ne "")) {
                $NewHashtable += @{$Key = $Hashtable.$Key}
            }
        }
        $NewHashtable
    }
}

function New-ApplicationNodeDnsCnameRecord {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ApplicationName
    )
    begin {
        $DomainController = Get-ADDomainController        
        $DNSServerName = $DomainController.HostName
        $ZoneName = $DomainController.Domain
    }
    process {
        $Name = "$($ApplicationName).$EnvironmentName"
        $HostNameAlias = "$ComputerName.$($DomainController.Domain)"        
        if (-Not (Get-DnsServerResourceRecord -Name $Name -ComputerName $DNSServerName -ZoneName $ZoneName -ErrorAction SilentlyContinue)) {
            Add-DnsServerResourceRecordCName -HostNameAlias $HostNameAlias -Name $Name -ComputerName $DNSServerName -ZoneName $ZoneName
        }
    }    
}

function Invoke-NodeGPUpdate {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-GPUpdate -Computer $ComputerName -RandomDelayInMinutes 0
    }    
}

function Start-ServiceOnNode {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory)]$Name
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Start-Service -Name $Using:Name
        }
    }
}

function Stop-ServiceOnNode {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory)]$Name
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Stop-Service -Name $Using:Name
        }
    }
}

function Get-NodePendingRebootForWindowsUpdate {
    $Nodes = Get-TervisApplicationNode -All
    $ConnectionResults = $Nodes | Test-NetConnection
    
    $ActiveNodes = $Nodes |
    where ComputerName -in (
        $ConnectionResults | 
        where PingSucceeded |
        select -ExpandProperty ComputerName
    )

    $ComputerNamesPendingWindowsUpdateReboot = $ActiveNodes | 
    Get-PendingReboot |
    where { $_.WindowsUpdate } |
    Select -ExpandProperty Computer

    $ActiveNodes | 
    where ComputerName -In $ComputerNamesPendingWindowsUpdateReboot
}

function Reboot-NodePendingRebootForWindowsUpdate {
    $ActiveNodesThatNeedReboot = Get-NodePendingRebootForWindowsUpdate

    $ApplicationGroups = $ActiveNodesThatNeedReboot | Group-Object -Property ApplicationName
    foreach ($ApplicationGroup in $ApplicationGroups.Group) {
        $EnvironmentGroups = $ApplicationGroup | Group-Object -Property Environment
        foreach ($EnvironmentGroup in $EnvironmentGroups.Group) {
            $NodeToReboot = $EnvironmentGroup |
            select -First 1 
            
            $NodeToReboot | Restart-Computer -Force -Wait              
        }
    }
}