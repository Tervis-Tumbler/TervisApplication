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
    Name = "Bartender Commander"
    NodeNameRoot = "Bartender"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4095
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
    OUName = "Bartender Commander"
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
            }
        }
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
    $NodesThatDontHaveVM = Get-ApplicationNodeWithoutVM -ClusterApplicationName $ClusterApplicationName

    if ($NodesThatDontHaveVM) {
        $NodesThatDontHaveVM | Invoke-ClusterApplicationNodeVMProvision -ClusterApplicationName $ClusterApplicationName
        $VMs = Find-TervisVM -Name $Nodes.Name
        
        $VMCount = $VMs | measure | select -ExpandProperty Count
        $NodeCount = $Nodes | measure | select -ExpandProperty Count
        if ($VMCount -ne $NodeCount) {
            Throw "VMCount after VM provisioning $VMCount not equal to Node count that should exist $NodeCount"
        }
    }

    $Credential = Get-PasswordstateCredential -PasswordID 4084
}

function Invoke-ClusterApplicationNodeVMProvision {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Parameter(Mandatory)]$ClusterApplicationName
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
            VMNameWithoutEnvironmentPrefix = $ClusterApplicationDefinition.NodeNameRoot
            VMSizeName = $Node.VMSizeName
            VMOperatingSystemTemplateName = $ClusterApplicationDefinition.VMOperatingSystemTemplateName
            EnvironmentName = $Node.EnvironmentName
            Cluster = $ClusterToCreateVMOn.Name
        }
        $TervisVMParameters | Write-VerboseAdvanced -Verbose:($VerbosePreference -ne "SilentlyContinue")
        if ($PSCmdlet.ShouldProcess("$($ClusterToCreateVMOn.Name)","Create VM $Node")) {
            New-TervisVM @TervisVMParameters
        }
    }
}