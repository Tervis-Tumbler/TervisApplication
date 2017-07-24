$ApplicationDefinition = [PSCustomObject][Ordered]@{
    Name = "SFTP"
    VMSizeName = "Small"
    VMOperatingSystemTemplateName = "CentOS 7"
    Environmentname = "Infrastructure"
    Cluster = "hypervcluster5"
    DHCPScopeID = "10.172.44.0"
    ComputernameSuffixInAD = "inf-sftp"
}

$ClusterApplicationDefinition = [PSCustomObject][Ordered]@{
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
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 4357
    },
    [PSCustomObject][Ordered]@{
        Name = "Delta"
        NumberOfNodes = 1
        VMSizeName = "Small"
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
        NumberOfNodes = 6
        LocalAdminPasswordStateID = 4348
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
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
    NodeNameRoot = "EBSRmtApp"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 3
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4351
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
}

function Get-TervisClusterApplicationDefinition {
    param (
        [Parameter(Mandatory)]$Name
    )
    
    $ClusterApplicationDefinition | 
    where Name -EQ $Name
}

function Get-TervisClusterApplicationNode {
    param (
        [Parameter(Mandatory,ParameterSetName="ClusterApplicationName")]$ClusterApplicationName,
        [Parameter(Mandatory,ParameterSetName="All")][Switch]$All,
        [String[]]$EnvironmentName,
        [Switch]$IncludeVM        
    )
    $ClusterApplicationDefinitions = if ($ClusterApplicationName) {
        Get-TervisClusterApplicationDefinition -Name $ClusterApplicationName
    } else {
        $ClusterApplicationDefinition
    }

    foreach ($ClusterApplicationDefinition in $ClusterApplicationDefinitions) {    
        $Environments = $ClusterApplicationDefinition.Environments |
        where {-not $EnvironmentName -or $_.Name -In $EnvironmentName}

        foreach ($Environment in $Environments) {
            foreach ($NodeNumber in 1..$Environment.NumberOfNodes) {
                $EnvironmentPrefix = get-TervisEnvironmentPrefix -EnvironmentName $Environment.Name
                $Node = [PSCustomObject][Ordered]@{                
                    ComputerName = "$EnvironmentPrefix-$($ClusterApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
                    EnvironmentName = $Environment.Name
                    ClusterApplicationName = $ClusterApplicationDefinition.Name
                    NameWithoutPrefix = "$($ClusterApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
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
                Find-DHCPServerv4LeaseIPAddress -HostName $This.ComputerName -AsString
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

function Get-TervisApplicationDefinition {
    param (
        [Parameter(Mandatory)]$Name
    )
    
    $ApplicationDefinition | 
    where Name -EQ $Name
}

function New-TervisTechnicalServicesApplicationVM {
    Param(
        [Parameter(Mandatory)]
        [ValidateSet('SFTP')]
        $ApplicationDefinitionName
    )
    $ApplicationDefinition = Get-TervisApplicationDefinition -Name $ApplicationDefinitionName

    $LastComputerNameCountFromAD = (
        get-adcomputer -filter "name -like '$($ApplicationDefinition.ComputerNameSuffixInAD)*'" | 
        select -ExpandProperty name | 
        Sort-Object -Descending | 
        select -last 1
    ) -replace $ApplicationDefinition.ComputernameSuffixInAD,""

    $NextComputerNameWithoutEnvironmentPrefix = "sftp" + ([int]$LastComputerNameCountFromAD + 1).tostring("00")
    $VM = New-TervisVM -VMNameWithoutEnvironmentPrefix $NextComputerNameWithoutEnvironmentPrefix `
        -VMSizeName $ApplicationDefinition.VMSizeName -VMOperatingSystemTemplateName $ApplicationDefinition.VMOperatingSystemTemplateName -EnvironmentName $ApplicationDefinition.Environmentname -Cluster $Cluster -DHCPScopeID $DHCPScopeID -NeedsAccessToSAN $ApplicationDefinition.NeedsAccessToSAN -Verbose
    $TervisVMObject = $vm | get-tervisVM
    $TervisVMObject
}

function Invoke-ClusterApplicationProvision {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]$ClusterApplicationName,
        $EnvironmentName,
        [Switch]$SkipInstallTervisChocolateyPackages
    )
    $ApplicationDefinition = Get-TervisClusterApplicationDefinition -Name $ClusterApplicationName

    if ($ApplicationDefinition.ComputeType -eq "Virtual") {
        $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName $ClusterApplicationName -IncludeVM -EnvironmentName $EnvironmentName
        
        $Nodes |
        where {-not $_.VM} |
        Invoke-ClusterApplicationNodeVMProvision -ClusterApplicationName $ClusterApplicationName
  
        if ( $Nodes | where {-not $_.VM} ) {
            throw "Not all nodes have VMs even after Invoke-ClusterApplicationNodeVMProvision"
        }

    } elseif ($ApplicationDefinition.ComputeType -eq "Physical") {
        $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName $ClusterApplicationName -EnvironmentName $EnvironmentName
    }
    
    $Nodes | Invoke-ClusterApplicationNodeProvision -SkipInstallTervisChocolateyPackages:$SkipInstallTervisChocolateyPackages
}

function Invoke-ClusterApplicationNodeProvision {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Switch]$SkipInstallTervisChocolateyPackages
    )
    process {
        $ApplicationDefinition = Get-TervisClusterApplicationDefinition -Name $Node.ClusterApplicationName

        if ($ApplicationDefinition.VMOperatingSystemTemplateName -in "Windows Server 2016") {
            $Node | Add-IPAddressToWSManTrustedHosts
        
            $IPAddress = $Node.IPAddress
            $TemplateCredential = Get-PasswordstateCredential -PasswordID 4097
            $Credential = Get-PasswordstateCredential -PasswordID $Node.LocalAdminPasswordStateID
            Set-TervisLocalAdministratorPassword -ComputerName $IPAddress -Credential $TemplateCredential -NewCredential $Credential
            Enable-TervisNetFirewallRuleGroup -Name $Node.ClusterApplicationName -ComputerName $IPAddress -Credential $Credential
            Invoke-TervisRenameComputerOnOrOffDomain -ComputerName $Node.ComputerName -IPAddress $IPAddress -Credential $Credential       
            Invoke-TervisClusterApplicationNodeJoinDomain -IPAddress $IPAddress -Credential $Credential -Node $Node
            Invoke-GPUpdate -Computer $Node.ComputerName -RandomDelayInMinutes 0
        
            $Node | Install-ApplicationNodeWindowsFeature
            $Node | Install-ApplicationNodeDesiredStateConfiguration
            $Node | Install-TervisChocolateyOnNode

            if (-Not $SkipInstallTervisChocolateyPackages) {
                Install-TervisChocolateyPackages -ChocolateyPackageGroupNames $Node.ClusterApplicationName -ComputerName $Node.ComputerName
            }

            Set-WINRMHTTPInTCPPublicRemoteAddressToLocalSubnet -ComputerName $Node.ComputerName
    
            $Node | Set-ApplicationNodeTimeZone
            $Node | Enable-ApplicationNodeKerberosDoubleHop
            $Node | Enable-ApplicationNodeRemoteDesktop
            $Node | New-ApplicationNodeDnsCnameRecord
            $Node | New-ClusterApplicationAdministratorPrivilegeADGroup
            $Node | Add-ClusterApplicationAdministratorPrivilegeADGroupToLocalAdministrators
        }
    }
}

function Add-ClusterApplicationAdministratorPrivilegeADGroupToLocalAdministrators {
    param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName,
        
        [ValidateScript({$_ -in $ClusterApplicationDefinition.Name})]
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        $ClusterApplicationName
    )
    process {
        $PrivilegeADGroupName = Get-ClusterApplicationAdministratorPrivilegeADGroupName -EnvironmentName $EnvironmentName -ClusterApplicationName $ClusterApplicationName
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {                    
            Add-LocalGroupMember -Name "Administrators" -Member $Using:PrivilegeADGroupName -ErrorAction SilentlyContinue
        }
    }
}

function New-ClusterApplicationAdministratorPrivilegeADGroup {
    param(
        [ValidateScript({$_ -in $ClusterApplicationDefinition.Name})]
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        $ClusterApplicationName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    process {
        $ApplicationOrganizationalUnit = Get-TervisClusterApplicationOrganizationalUnit -ClusterApplicationName $ClusterApplicationName
        $PrivilegeGroupName = Get-ClusterApplicationAdministratorPrivilegeADGroupName -EnvironmentName $EnvironmentName -ClusterApplicationName $ClusterApplicationName
        $ADGroup = Get-ADGroup -SearchBase $ApplicationOrganizationalUnit -Filter {Name -eq $PrivilegeGroupName}
        if (-Not $ADGroup) {
            New-ADGroup -Name $PrivilegeGroupName -SamAccountName $PrivilegeGroupName -GroupCategory Security -GroupScope Universal -Path $ApplicationOrganizationalUnit
        }
    }
}

function Get-ClusterApplicationAdministratorPrivilegeADGroupName {
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]$EnvironmentName,
        
        [ValidateScript({$_ -in $ClusterApplicationDefinition.Name})]
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        $ClusterApplicationName
    )
    "Privilege_$($EnvironmentName)$($ClusterApplicationName)Administrator"
}

function Get-ClusterApplicationAdministratorPrivilegeADGroup {
    param(
        [ValidateScript({$_ -in $ClusterApplicationDefinition.Name})]
        [Parameter(Mandatory)]
        $ClusterApplicationName,

        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    process {
        $ApplicationOrganizationalUnit = Get-TervisClusterApplicationOrganizationalUnit -ClusterApplicationName $ClusterApplicationName
        $PrivilegeGroupName = "Privilege_$($EnvironmentName)$($ClusterApplicationName)Administrator"
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
        [Parameter(ValueFromPipelineByPropertyName)]$ClusterApplicationName
    )
    process {
        $Result = Install-TervisWindowsFeature -WindowsFeatureGroupNames $ClusterApplicationName -ComputerName $ComputerName
        if ($Result.RestartNeeded | ConvertTo-Boolean) {
            Restart-Computer -ComputerName $ComputerName -Force
            Wait-ForNodeRestart -ComputerName $ComputerName
        }
    }
}

function Install-ApplicationNodeDesiredStateConfiguration {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$ClusterApplicationName
    )
    process {
        Install-TervisDesiredStateConfiguration -ClusterApplicationName $ClusterApplicationName -ComputerName $ComputerName
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
            Restart-Computer -ComputerName $ComputerName -Force
            Wait-ForNodeRestart -ComputerName $ComputerName
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

function Get-TervisClusterApplicationOrganizationalUnit {
    param(
        [ValidateScript({$_ -in $ClusterApplicationDefinition.Name})]
        [Parameter(Mandatory)]
        $ClusterApplicationName
    )
    $ApplicationOU = Get-ADOrganizationalUnit -Filter {Name -eq $ClusterApplicationName}
    if ( -not $ApplicationOU) {
        $CattleOU = Get-ADOrganizationalUnit -Filter {Name -eq "Cattle"}
        New-ADOrganizationalUnit -Path $CattleOU.DistinguishedName -Name $ClusterApplicationName -ProtectedFromAccidentalDeletion:$false -PassThru
    } else {
        $ApplicationOU
    }
}

function Invoke-TervisClusterApplicationNodeJoinDomain {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)]$IPAddress,
        [Parameter(Mandatory)]$Credential

    )
    $OrganizationalUnit = Get-TervisClusterApplicationOrganizationalUnit -ClusterApplicationName $Node.ClusterApplicationName
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

function Invoke-ClusterApplicationNodeVMProvision {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Parameter(Mandatory)]$ClusterApplicationName,
        [Switch]$PassThru
    )
    begin {
        $ADDomain = Get-ADDomain
        $ClusterApplicationDefinition = Get-TervisClusterApplicationDefinition -Name $ClusterApplicationName
    }
    process {
        $Clusters = Get-TervisCluster -Domain $ADDomain.DNSRoot
        $LocalComputerADSite = Get-ComputerSite -ComputerName $Env:COMPUTERNAME
        $ClusterToCreateVMOn = $Clusters | where ADSite -eq $LocalComputerADSite
        
        $TervisVMParameters = @{
            VMNameWithoutEnvironmentPrefix = $Node.NameWithoutPrefix
            VMSizeName = $Node.VMSizeName
            VMOperatingSystemTemplateName = $ClusterApplicationDefinition.VMOperatingSystemTemplateName
            EnvironmentName = $Node.EnvironmentName
            Cluster = $ClusterToCreateVMOn.Name
        }
        $TervisVMParameters | Write-VerboseAdvanced -Verbose:($VerbosePreference -ne "SilentlyContinue")
        if ($PSCmdlet.ShouldProcess("$($ClusterToCreateVMOn.Name)","Create VM $Node")) {
            New-TervisVM @TervisVMParameters -NeedsAccessToSAN:$($ClusterApplicationDefinition.NeedsAccessToSAN) |
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
        [Parameter(Mandatory)]$ClusterApplicationName,
        $EnvironmentName
    )
    Get-TervisClusterApplicationNode @PSBoundParameters |
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
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ClusterApplicationName
    )
    begin {
        $DomainController = Get-ADDomainController        
        $DNSServerName = $DomainController.HostName
        $ZoneName = $DomainController.Domain
    }
    process {
        $Name = "$($ClusterApplicationName).$EnvironmentName"
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
    $Nodes = Get-TervisClusterApplicationNode -All
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

    $ClusterApplicationGroups = $ActiveNodesThatNeedReboot | Group-Object -Property ClusterApplicationName
    foreach ($ClusterApplicationGroup in $ClusterApplicationGroups.Group) {
        $EnvironmentGroups = $ClusterApplicationGroup | Group-Object -Property Environment
        foreach ($EnvironmentGroup in $EnvironmentGroups.Group) {
            $NodeToReboot = $EnvironmentGroup |
            select -First 1 
            
            $NodeToReboot | Restart-Computer -Force
            $NodeToReboot | Wait-ForNodeRestart            
        }
    }
}