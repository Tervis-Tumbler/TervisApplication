$ModulePath = (Get-Module -ListAvailable TervisApplication).ModuleBase
. $ModulePath\ApplicationDefinition.ps1

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
        [Switch]$IncludeVM,
        [Switch]$IncludeSSHSession,
        [Switch]$IncludeSFTSession
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

                if ($IncludeSSHSession) {
                    $Node | Add-SSHSessionCustomProperty
                }

                if ($IncludeSFTSession) {
                    $Node | Add-SFTPSessionCustomProperty
                }

                $Node | 
                Add-NodeIPAddressProperty -PassThru |
                Add-NodeCredentialProperty -PassThru
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
            
            $Node | Set-ApplicationNodeTimeZone
            $Node | Enable-ApplicationNodeKerberosDoubleHop
            $Node | Enable-ApplicationNodeRemoteDesktop
            $Node | New-ApplicationNodeDnsCnameRecord
            $Node | New-ApplicationAdministratorPrivilegeADGroup
            $Node | Add-ApplicationAdministratorPrivilegeADGroupToLocalAdministrators
            $Node | Install-ApplicationNodeWindowsFeature
            $Node | Install-ApplicationNodeDesiredStateConfiguration
            
            $Node | Install-TervisChocolatey

            if (-Not $SkipInstallTervisChocolateyPackages) {
                Install-TervisChocolateyPackages -ChocolateyPackageGroupNames $Node.ApplicationName -ComputerName $Node.ComputerName
            }

            Set-WINRMHTTPInTCPPublicRemoteAddressToLocalSubnet -ComputerName $Node.ComputerName
        }
        if ($ApplicationDefinition.VMOperatingSystemTemplateName -in "CentOS 7") {
            $TemplateCredential = Get-PasswordstateCredential -PasswordID 3948
            Set-LinuxAccountPassword -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential
            $Node | Add-SSHSessionCustomProperty
            Install-YumTervisPackageGroup -TervisPackageGroupName $Node.ApplicationName -SSHSession $Node.SSHSession
            $Node | Set-LinuxHostname
            $Node | Add-ApplicationNodeDnsServerResourceRecord
            $Node | Join-LinuxToADDomain
        }
        if ($ApplicationDefinition.VMOperatingSystemTemplateName -in "Arch Linux") {
            $TemplateCredential = Get-PasswordstateCredential -PasswordID 5183
            New-LinuxUser -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential -Administrator
            $Node | Add-SSHSessionCustomProperty
            $Node | Set-LinuxTimeZone -Country US -ZoneName East
            $Node | Set-LinuxHostname
            $Node | Add-ApplicationNodeDnsServerResourceRecord

            Install-PacmanTervisPackageGroup -TervisPackageGroupName $Node.ApplicationName -SSHSession $Node.SSHSession
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
        Invoke-Command -ComputerName $IPAddress -Credential $Credential -ScriptBlock {
            Add-Computer -DomainName $Using:ADDomain.forest -Force -OUPath $Using:OUPath -Credential $Using:DomainJoinCredential
        }
        Restart-Computer -ComputerName $IPAddress -Credential $DomainJoinCredential -Wait -Protocol WSMan -Force
                
        $DomainNameAfterRestart = Get-DomainNameOnOrOffDomain -ComputerName $ComputerName -IPAddress $IPAddress -Credential $DomainJoinCredential
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
        Rename-Computer -NewName $ComputerName -Force -LocalCredential $Credential -ComputerName $IPAddress -Protocol WSMan
        Restart-Computer -ComputerName $IPAddress -Force -Credential $Credential -Wait -Protocol WSMan

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
        $ClusterToCreateVMOn = $Clusters | 
        Where-Object ADSite -eq $LocalComputerADSite |
        Sort-Object Name |
        Select-Object -First 1
        
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
    if (Test-NetConnection $ComputerName | Select-Object -ExpandProperty PingSucceeded) {
        $OperatingSystemObject = Get-WmiObject -ComputerName $ComputerName Win32_OperatingSystem -Credential $Credential
        $ConvertedUptimeString = [Management.ManagementDateTimeConverter]::ToDateTime($OperatingSystemObject.LastBootUpTime)
        $CurrentUptimeCalculation = (get-date) - $ConvertedUptimeString
        $CurrentUptimeCalculation
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
        [Parameter(Mandatory)]$ApplicationName,
        $EnvironmentName
    )
    Get-TervisApplicationNode @PSBoundParameters |
    New-PSSession
}

function New-SplatVariable {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName,ParameterSetName="Invocation")]$Invocation,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName,ParameterSetName="Function")]$Function,
        $Variables,
        $ExcludeProperty
    )
    if ($Invocation){$CommandName = $Invocation.InvocationName}
    elseif ($Function){$CommandName = $Function}
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

function Get-NodePendingRestartForWindowsUpdate {
    $Nodes = Get-TervisApplicationNode -All
    $ConnectionResults = $Nodes | Test-NetConnection
    
    $ActiveNodes = $Nodes |
    where ComputerName -in (
        $ConnectionResults | 
        where PingSucceeded |
        select -ExpandProperty ComputerName
    )

    $ComputerNamesPendingWindowsUpdateRestart = $ActiveNodes | 
    Get-PendingRestart |
    where { $_.WindowsUpdate } |
    Select -ExpandProperty Computer

    $ActiveNodes | 
    where ComputerName -In $ComputerNamesPendingWindowsUpdateRestart
}

function Restart-NodePendingRestartForWindowsUpdate {
    $ActiveNodesThatNeedRestart = Get-NodePendingRestartForWindowsUpdate

    $ApplicationGroups = $ActiveNodesThatNeedRestart | Group-Object -Property ApplicationName
    foreach ($ApplicationGroup in $ApplicationGroups.Group) {
        $EnvironmentGroups = $ApplicationGroup | Group-Object -Property Environment
        foreach ($EnvironmentGroup in $EnvironmentGroups.Group) {
            $NodeToRestart = $EnvironmentGroup |
            select -First 1 
            
            $NodeToRestart | Restart-Computer -Force -Wait              
        }
    }
}

function Add-SSHSessionCustomProperty {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Switch]$PassThru
    )
    process {
        $Node |
        Add-Member -MemberType ScriptProperty -Name SSHSession -Force -Value {
            $SSHSession = Get-SSHSession -ComputerName $This.IPAddress
            if ($SSHSession -and $SSHSession.Connected -eq $true) {
                $SSHSession
            } else {
                if ($SSHSession) { $SSHSession | Remove-SSHSession | Out-Null }
                New-SSHSession -ComputerName $This.IPAddress -Credential $This.Credential -AcceptKey
            }
        } -PassThru:$PassThru 
    }
}

function Add-SFTPSessionCustomProperty {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Switch]$PassThru
    )
    process {
        $Node |
        Add-Member -MemberType ScriptProperty -Name SFTPSession -Force -Value {
            $SFTPSession = Get-SFTPSession | where Host -eq $This.IPAddress
            if ($SFTPSession -and $SFTPSession.Connected -eq $true) {
                $SFTPSession
            } else {
                if ($SFTPSession) { $SFTPSession | Remove-SFTPSession | Out-Null }
                New-SFTPSession -ComputerName $This.IPAddress -Credential $This.Credential -AcceptKey
            }
        } -PassThru:$PassThru 
    }
}

function Add-NodeCredentialProperty {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Switch]$PassThru
    )
    process {
        $Node |
        Add-Member -MemberType ScriptProperty -Name Credential -Force -Value {
            Get-PasswordstateCredential -PasswordID $This.LocalAdminPasswordStateID
        } -PassThru:$PassThru 
    }
}

function Add-ApplicationNodeDnsServerResourceRecord {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$IPAddress
    )
    begin {
        $ZoneName = Get-ADDomain | Select -ExpandProperty DNSRoot
        $DNSServerComputerName = Get-ADDomainController | Select -ExpandProperty HostName
    }
    process {
        Add-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServerComputerName -IPv4Address $IPAddress -Name $ComputerName -A
    }
}

