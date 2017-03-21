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
    Name = "Kafka"
    NodeNameRoot = "Kafka"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 3
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4084
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
    OUName = "KafkaBroker"
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
    OUName = "Prometheus"
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
    OUName = "Prometheus"
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
    OUName = "BartenderCommander"
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
        
        $VMIPv4Address = $Node.VM.VMNetworkAdapter.ipaddresses | Get-NotIPV6Address         
        $VMIPv4Address | Add-IPAddressToWSManTrustedHosts

        $CurrentHostname = Get-ComputerNameOnOrOffDomain -IPAddress $VMIPv4Address -Credential $Credential -ComputerName $Node.Name

        if ($CurrentHostname -ne $Node.Name) {
            Rename-Computer -NewName $Node.Name -Force -Restart -LocalCredential $Credential -ComputerName $VMIPv4Address
            Wait-ForEndpointRestart -IPAddress $VMIPv4Address -PortNumbertoMonitor 5985
            $HostnameAfterRestart = Get-ComputerNameOnOrOffDomain -IPAddress $VMIPv4Address -Credential $Credential -ComputerName $Node.Name
            if ($HostnameAfterRestart -ne $Node.Name) {
                Throw "Rename of VM $($Node.Name) with ip address $($VMIPv4Address) failed"
            }
        }

        $ADDomain = Get-ADDomain
        $ClusterApplicationDefinition = Get-TervisClusterApplicationDefinition -Name $ClusterApplicationName
        $DomainJoinCredential = Get-PasswordstateCredential -PasswordID 2643

        $CurrentDomainName = Get-DomainNameOnOrOffDomain -ComputerName $Node.Name -IPAddress $VMIPv4Address -Credential $Credential
        if ($CurrentDomainName -ne $ADDomain.Name) {
            $OUName = $ClusterApplicationDefinition.OUName
            $ApplicationOU = Get-ADOrganizationalUnit -Filter {Name -eq $OUName}
            Add-Computer -DomainName $ADDomain.forest -Force -Restart -OUPath $ApplicationOU -ComputerName $VMIPv4Address -LocalCredential $Credential -Credential $DomainJoinCredential
            
            Wait-ForEndpointRestart -IPAddress $VMIPv4Address -PortNumbertoMonitor 5985
            $DomainNameAfterRestart = Get-DomainNameOnOrOffDomain -ComputerName $Node.Name -IPAddress $VMIPv4Address -Credential $Credential
            if ($DomainNameAfterRestart -ne $ADDomain.NetBIOSName) {
                Throw "Joining the domain for VM $($Node.Name) with ip address $($VMIPv4Address) failed"
            }
        }
        
        Install-TervisChocolatey -ComputerName $Node.Name
        Install-TervisChocolateyPackages -ChocolateyPackageGroupNames $ClusterApplicationDefinition.Name -ComputerName $Node.Name

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