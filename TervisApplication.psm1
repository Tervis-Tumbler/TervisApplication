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
    NodeNameRoot = "Progistics"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
        VMSizeName = "Medium"
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
        [String[]]$EnvironmentName
    )
    $ClusterApplicationDefinition = Get-TervisClusterApplicationDefinition -Name $ClusterApplicationName
    
    $Environments = $ClusterApplicationDefinition.Environments |
    where {-not $EnvironmentName -or $_.Name -In $EnvironmentName}

    foreach ($Environment in $Environments) {
        foreach ($NodeNumber in 1..$Environment.NumberOfNodes) {
            $EnvironmentPrefix = get-TervisEnvironmentPrefix -EnvironmentName $Environment.Name
            [PSCustomObject][Ordered]@{                
                Name = "$EnvironmentPrefix-$($ClusterApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
                EnvironmentName = $Environment.Name
                VMSizeName = $Environment.VMSizeName
                NameWithoutPrefix = "$($ClusterApplicationDefinition.NodeNameRoot)$($NodeNumber.tostring("00"))"
                LocalAdminPasswordStateID = $Environment.LocalAdminPasswordStateID                
            } | Add-NodeVMProperty -PassThru 
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
            Find-TervisVM -Name $Node.Name
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

function Get-ApplicationNodeWithoutVM {
    param (
        $ClusterApplicationName
    )    
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName $ClusterApplicationName
    $VMs = Find-TervisVM -Name $Nodes.Name
    $Nodes | where Name -notin $VMs.Name
}

function Invoke-ClusterApplicationProvision {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        $ClusterApplicationName
    )
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName $ClusterApplicationName
    
    $Nodes |
    where {-not $_.VM} |
    Invoke-ClusterApplicationNodeVMProvision -ClusterApplicationName $ClusterApplicationName
    
    if ( $Nodes | where {-not $_.VM} ) {
        throw "Not all nodes have VMs even after Invoke-ClusterApplicationNodeVMProvision"
    }
    
    foreach ($Node in $Nodes) {
        $Credential = Get-PasswordstateCredential -PasswordID $Node.LocalAdminPasswordStateID
        
        $IPAddress = $Node.VM.VMNetworkAdapter.IPAddresses | Get-NotIPV6Address         
        Invoke-TervisRenameComputerOnOrOffDomain -ComputerName $Node.Name -IPAddress $IPAddress -Credential $Credential
        Invoke-TervisClusterApplicationNodeJoinDomain -ClusterApplicationName $ClusterApplicationName -IPAddress $IPAddress -Credential $Credential -Node $Node
        Invoke-GPUpdate -Computer $Node.Name -RandomDelayInMinutes 0

        Install-TervisChocolatey -ComputerName $Node.Name
        Install-TervisChocolateyPackages -ChocolateyPackageGroupNames $ClusterApplicationDefinition.Name -ComputerName $Node.Name
    }
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
    Invoke-TervisJoinDomain -OUPath $OU.DistinguishedName -ComputerName $Node.Name -IPAddress $IPAddress -Credential $Credential
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
    if ($CurrentDomainName -ne $ADDomain.Name) {
        Add-Computer -DomainName $ADDomain.forest -Force -Restart -OUPath $OUPath -ComputerName $IPAddress -LocalCredential $Credential -Credential $DomainJoinCredential
            
        Wait-ForEndpointRestart -IPAddress $IPAddress -PortNumbertoMonitor 5985
        $DomainNameAfterRestart = Get-DomainNameOnOrOffDomain -ComputerName $ComputerName -IPAddress $IPAddress -Credential $Credential
        if ($DomainNameAfterRestart -ne $ADDomain.NetBIOSName) {
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
        $IPAddress | Add-IPAddressToWSManTrustedHosts

        $CurrentHostname = Get-ComputerNameOnOrOffDomain @PSBoundParameters

        if ($CurrentHostname -ne $ComputerName) {
            Rename-Computer -NewName $ComputerName -Force -Restart -LocalCredential $Credential -ComputerName $IPAddress
            Wait-ForEndpointRestart -IPAddress $VMIPv4Address -PortNumbertoMonitor 5985
            $HostnameAfterRestart = Get-ComputerNameOnOrOffDomain @PSBoundParameters
            if ($HostnameAfterRestart -ne $ComputerName) {
                Throw "Rename of VM $ComputerName with ip address $IPAddress failed"
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
            New-TervisVM @TervisVMParameters | Out-Null
        }
        
        $Node | Add-NodeVMProperty     
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