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
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 3
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4084
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "Prometheus"
    NodeNameRoot = "Prometh"
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
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
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
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
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
        [Parameter(Mandatory)]$ClusterApplicationName,
        [String[]]$EnvironmentName,
        [Switch]$IncludeVM        
    )
    $ClusterApplicationDefinition = Get-TervisClusterApplicationDefinition -Name $ClusterApplicationName
    
    $Environments = $ClusterApplicationDefinition.Environments |
    where {-not $EnvironmentName -or $_.Name -In $EnvironmentName}

    foreach ($Environment in $Environments) {
        foreach ($NodeNumber in 1..$Environment.NumberOfNodes) {
            $EnvironmentPrefix = get-TervisEnvironmentPrefix -EnvironmentName $Environment.Name
            $Node = [PSCustomObject][Ordered]@{                
                ComputerName = "$EnvironmentPrefix-$($ClusterApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
                EnvironmentName = $Environment.Name
                VMSizeName = $Environment.VMSizeName
                NameWithoutPrefix = "$($ClusterApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
                LocalAdminPasswordStateID = $Environment.LocalAdminPasswordStateID
            } | Add-Member -MemberType ScriptProperty -Name IPAddress -Value {Find-DHCPServerv4LeaseIPAddress -HostName $This.ComputerName -AsString} -PassThru
            
            if ($IncludeVM) {
                $Node |
                Add-NodeVMProperty -PassThru 
            } else {
                $Node
            }
        }
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
    $ApplicationDefinitoin = Get-TervisApplicationDefinition -Name $ApplicationDefinitionName
    

    $LastComputerNameCountFromAD = (
        get-adcomputer -filter "name -like '$($ApplicationDefinitoin.ComputerNameSuffixInAD)*'" | 
        select -ExpandProperty name | 
        Sort-Object -Descending | 
        select -last 1
    ) -replace $ApplicationDefinitoin.ComputernameSuffixInAD,""

    $NextComputerNameWithoutEnvironmentPrefix = "sftp" + ([int]$LastComputerNameCountFromAD + 1).tostring("00")
    $VM = New-TervisVM -VMNameWithoutEnvironmentPrefix $NextComputerNameWithoutEnvironmentPrefix `
        -VMSizeName $ApplicationDefinitoin.VMSizeName -VMOperatingSystemTemplateName $ApplicationDefinitoin.VMOperatingSystemTemplateName -EnvironmentName $ApplicationDefinitoin.Environmentname -Cluster $Cluster -DHCPScopeID $DHCPScopeID -Verbose   
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
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName $ClusterApplicationName -IncludeVM -EnvironmentName $EnvironmentName
    
    $Nodes |
    where {-not $_.VM} |
    Invoke-ClusterApplicationNodeVMProvision -ClusterApplicationName $ClusterApplicationName
    
    if ( $Nodes | where {-not $_.VM} ) {
        throw "Not all nodes have VMs even after Invoke-ClusterApplicationNodeVMProvision"
    }
    
    foreach ($Node in $Nodes) {
        #$IPAddress = $Node.IPAddress
        $IPAddress = $Node.VM.VMNetworkAdapter.IPAddresses | Get-NotIPV6Address
        $IPAddress | Add-IPAddressToWSManTrustedHosts

        $VMTemplateCredential = Get-PasswordstateCredential -PasswordID 4097
        $Credential = Get-PasswordstateCredential -PasswordID $Node.LocalAdminPasswordStateID
        Set-TervisLocalAdministratorPassword -ComputerName $IPAddress -Credential $VMTemplateCredential -NewCredential $Credential

        Enable-TervisNetFirewallRuleGroup -Name $ClusterApplicationName -ComputerName $IPAddress -Credential $Credential
        Invoke-TervisRenameComputerOnOrOffDomain -ComputerName $Node.ComputerName -IPAddress $IPAddress -Credential $Credential       
        Invoke-TervisClusterApplicationNodeJoinDomain -ClusterApplicationName $ClusterApplicationName -IPAddress $IPAddress -Credential $Credential -Node $Node
        Invoke-GPUpdate -Computer $Node.ComputerName -RandomDelayInMinutes 0
        
        $Node | Set-ApplicationNodeTimeZone
        $Node | Enable-ApplicationNodeKerberosDoubleHop
        $Node | Enable-ApplicationNodeRemoteDesktop
        $Node | Install-ApplicationNodeWindowsFeature -ClusterApplicationName $ClusterApplicationName

        Install-TervisChocolatey -ComputerName $Node.ComputerName
        if (-Not $SkipInstallTervisChocolateyPackages) {
            Install-TervisChocolateyPackages -ChocolateyPackageGroupNames $ClusterApplicationName -ComputerName $Node.ComputerName
        }

        Set-WINRMHTTPInTCPPublicRemoteAddressToLocalSubnet -ComputerName $Node.ComputerName
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
        $ClusterApplicationName
    )
    process {
        $Result = Install-TervisWindowsFeature -WindowsFeatureGroupNames $ClusterApplicationName -ComputerName $ComputerName
        if ($Result.RestartNeeded | ConvertTo-Boolean) {
            Restart-Computer -ComputerName $ComputerName
            Wait-ForEndpointRestart -IPAddress $ComputerName -PortNumbertoMonitor 5985
        }
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
            Restart-Computer -ComputerName $ComputerName
            Wait-ForEndpointRestart -IPAddress $ComputerName -PortNumbertoMonitor 5985
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

function Get-TervisClusterApplicationOU {
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
        [ValidateScript({$_ -in $ClusterApplicationDefinition.Name})]
        [Parameter(Mandatory)]
        $ClusterApplicationName,

        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)]$IPAddress,
        [Parameter(Mandatory)]$Credential

    )
    $OU = Get-TervisClusterApplicationOU -ClusterApplicationName $ClusterApplicationName
    Invoke-TervisJoinDomain -OUPath $OU.DistinguishedName -ComputerName $Node.ComputerName -IPAddress $IPAddress -Credential $Credential
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
        Add-Computer -DomainName $ADDomain.forest -Force -Restart -OUPath $OUPath -ComputerName $IPAddress -LocalCredential $Credential -Credential $DomainJoinCredential
            
        Wait-ForEndpointRestart -IPAddress $IPAddress -PortNumbertoMonitor 5985
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
        Rename-Computer -NewName $ComputerName -Force -Restart -LocalCredential $Credential -ComputerName $IPAddress
        Wait-ForEndpointRestart -IPAddress $IPAddress -PortNumbertoMonitor 5985
        $HostnameAfterRestart = Get-ComputerNameOnOrOffDomain @PSBoundParameters
        if ($HostnameAfterRestart -ne $ComputerName) {
            Throw "Rename of $ComputerName with ip address $IPAddress failed"
        }
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
            New-TervisVM @TervisVMParameters | Start-VM | Out-Null
        }
        
        $Node | Add-NodeVMProperty     
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

function Get-TervisFunctionParameters {
    param (
        $Invocation
    )
    $CommandName = $Invocation.InvocationName
    $ParameterList = (Get-Command -Name $CommandName).Parameters
    foreach ($Parameter in $ParameterList) {
        Get-Variable -Name $Parameter.Values.Name -ErrorAction SilentlyContinue -Scope 1
    }
}
