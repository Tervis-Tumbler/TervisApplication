$ModulePath = if ($PSScriptRoot) {
    $PSScriptRoot
} else {
    (Get-Module -ListAvailable TervisApplication).ModuleBase
}
. $ModulePath\ApplicationDefinition.ps1

function Get-TervisApplicationDefinition {
    param (
        [Parameter(Mandatory)]$Name
    )
    
    $ApplicationDefinition | 
    where Name -In $Name
}

function Get-TervisApplicationNode {
    param (
        [Parameter(Mandatory,ParameterSetName="ApplicationName")]$ApplicationName,
        [Parameter(Mandatory,ParameterSetName="All")][Switch]$All,
        [String[]]$EnvironmentName,
        [Switch]$IncludeVM,
        [Switch]$IncludeSSHSession,
        [Switch]$IncludeSFTSession,
        [Switch]$IncludeCredential = $True, #The default was to include this in the past, once we have refactored we can remove the = $True
        [Switch]$IncludeIPAddress = $True #The default was to include this in the past, once we have refactored we can remove the = $True
    )
    $ApplicationDefinitions = Get-TervisApplicationDefinition -Name $ApplicationName

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
                    if ($applicationdefinition.ComputeType -eq "OracleVM") {
                        $Node | Add-NodeOracleVMProperty
                    }
                    Else{
                        $Node | Add-Member -MemberType NoteProperty -Name VMSizeName -Value $Environment.VMSizeName
                        $Node | Add-NodeVMProperty
                    }
                }

                if ($IncludeSSHSession) {
                    $Node | Add-SSHSessionCustomProperty
                }

                if ($IncludeSFTSession) {
                    $Node | Add-SFTPSessionCustomProperty
                }

                if ($IncludeCredential) {
                    $Node | Add-NodeCredentialProperty
                }

                if ($IncludeIPAddress -and $applicationdefinition.ComputeType -eq "OracleVM") {
                    $Node | Add-OVMNodeIPAddressProperty
                } elseif ($IncludeIPAddress) {
                    $Node | Add-NodeIPAddressProperty
                }

                $Node
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
                if ($PSVersionTable.Platform -eq "Unix") {
                    [system.net.dns]::GetHostAddresses($This.ComputerName) |
                    Select-Object -ExpandProperty IPAddressToString
                } else {
                    Find-DHCPServerv4LeaseIPAddress -HostName $This.ComputerName -AsString |
                    Select-Object -First 1
                }
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

# function Invoke-ApplicationProvisionPowerShellCore {
#     param (
#         [Parameter(Mandatory)]$ApplicationName,
#         $EnvironmentName,
#         [Switch]$SkipInstallTervisChocolateyPackages
#     )
#     Import-WinModule ActiveDirectory,
#         DhcpServer,
#         FailoverClusters,
#         Get-SPN,
#         hyper-V,
#         Microsoft.PowerShell.Management,
#         Microsoft.PowerShell.Utility,
#         PackageManagement,
#         PasswordstatePowerShell,
#         PowerShellGet,
#         StringPowerShell,
#         TervisApplication,
#         TervisCluster,
#         TervisDHCP,
#         TervisEnvironment,
#         TervisMicrosoft.PowerShell.Utility,
#         TervisPasswordstatePowershell,
#         TervisPowerShellJobs,
#         TervisRemoteDesktopManager,
#         TervisVirtualization,
#         WebServicesPowerShellProxyBuilder

#         #PSReadline,
#         #PSScheduledJob,
#         #PSWorkflow,
#     Invoke-ApplicationProvision @PSBoundParameters
# }

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
    $Nodes | New-TervisApplicationNodeRDMSession
}

function Invoke-ApplicationNodeProvision {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Switch]$SkipInstallTervisChocolateyPackages
    )
    process {
        $ApplicationDefinition = Get-TervisApplicationDefinition -Name $Node.ApplicationName
        $VMOperatingSystemTemplateName = $ApplicationDefinition.VMOperatingSystemTemplateName

        if ($VMOperatingSystemTemplateName -match "Windows Server"){
            $Node | Add-IPAddressToWSManTrustedHosts
        
            $IPAddress = $Node.IPAddress
            if ($VMOperatingSystemTemplateName -in  "Windows Server 2016","Windows Server Datacenter"){
                $TemplateCredential = Get-PasswordstatePassword -ID 4097 -AsCredential
            }
            if ($VMOperatingSystemTemplateName -in  "Windows Server 2019"){
                $TemplateCredential = Get-PasswordstatePassword -ID 5604 -AsCredential
            }
            if ($VMOperatingSystemTemplateName -in  "Windows Server Evergreen Physical"){
                $TemplateCredential = Get-PasswordstatePassword -ID 5709 -AsCredential
            }
            Set-TervisLocalAdministratorPassword -ComputerName $IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential
            Enable-TervisNetFirewallRuleGroup -Name $Node.ApplicationName -ComputerName $IPAddress -Credential $Node.Credential
            Invoke-TervisRenameComputerOnOrOffDomain -ComputerName $Node.ComputerName -IPAddress $IPAddress -Credential $Node.Credential       
            Invoke-TervisApplicationNodeJoinDomain -IPAddress $IPAddress -Credential $Node.Credential -Node $Node
            Invoke-GPUpdate -Computer $Node.ComputerName -RandomDelayInMinutes 0
            
            $Node | Set-ApplicationNodeTimeZone
            $Node | Enable-ApplicationNodeKerberosDoubleHop
            $Node | Enable-ApplicationNodeRemoteDesktop
            $Node | New-ApplicationNodeDnsCnameRecord
            $Node | New-ApplicationAdministratorPrivilegeADGroup
            $Node | Add-ApplicationAdministratorPrivilegeADGroupToLocalAdministrators
            $Node | Install-ApplicationNodeWindowsFeature
            $Node | Install-TervisDesiredStateConfiguration
            
            $Node | Install-TervisChocolatey

            if (-Not $SkipInstallTervisChocolateyPackages) {
                $Node | Install-TervisChocolateyPackages -ChocolateyPackageGroupNames $Node.ApplicationName
            }

            Set-WINRMHTTPInTCPPublicRemoteAddressToLocalSubnet -ComputerName $Node.ComputerName
        }
        
        if (
            ($VMOperatingSystemTemplateName -in "CentOS 7","Arch Linux","Debian 9") -or 
            ($VMOperatingSystemTemplateName -match "OEL")
        ) {
            $OSToPasswordStatePasswordIDMap = @{
                "CentOS 7" = 3948
                "Arch Linux" = 5183
                "OEL" = 5329
                "Debian 9" = 5694
            }

            $TemplateCredential = Get-PasswordstatePassword -ID $OSToPasswordStatePasswordIDMap.$VMOperatingSystemTemplateName -AsCredential
        }

        if ($VMOperatingSystemTemplateName -in "CentOS 7") {
            Set-LinuxAccountPassword -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential
            $Node | Add-SSHSessionCustomProperty -UseIPAddress
            $Node | Set-LinuxHostname 
            $Node | Add-ApplicationNodeDnsServerResourceRecord
            Install-YumTervisPackageGroup -TervisPackageGroupName $Node.ApplicationName -SSHSession $Node.SSHSession
            $Node | Join-LinuxToADDomain
        }
        if ($VMOperatingSystemTemplateName -in "Arch Linux") {
            Set-LinuxAccountPassword -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential
            $Node | Add-SSHSessionCustomProperty -UseIPAddress
            $Node | Set-LinuxHostname 
            $Node | Add-ApplicationNodeDnsServerResourceRecord
            New-LinuxUser -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential -Administrator
            $Node | Set-LinuxTimeZone -Country US -ZoneName East
            $Node | Set-LinuxHostsFile
            Install-PacmanTervisPackageGroup -TervisPackageGroupName $Node.ApplicationName -SSHSession $Node.SSHSession
        }
        if ($VMOperatingSystemTemplateName -match "OEL") {
            Set-LinuxAccountPassword -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential
            $Node | Add-SSHSessionCustomProperty -UseIPAddress
            $Node | Set-LinuxHostname 
            $Node | Add-ApplicationNodeDnsServerResourceRecord
            $Node | Add-SFTPSessionCustomProperty -UseIPAddress
            $Node | Set-LinuxTimeZone -Country US -ZoneName Eastern
            #sleep 120
            $Node | Install-PowershellCoreForLinux
            Install-YumTervisPackageGroup -TervisPackageGroupName $Node.ApplicationName -SSHSession $Node.SSHSession
            $Node | Join-LinuxToADDomain
#            $Node | Invoke-LeaveLinuxADDomain
#            $Node | Join-LinuxToADDomain
        }
        if ($VMOperatingSystemTemplateName -eq "Debian 9") {
            #Download ssh key file for debian template
            $TemplateKeyFilePath = "$Home\.ssh\DebianTemplate"
            Get-PasswordstateDocument -DocumentID 53 -OutFile $TemplateKeyFilePath -DocumentLocation password
            Get-Content -Path $TemplateKeyFilePath | Out-File -Append -FilePath $Home/.ssh/authorized_keys
            
            Invoke-Command -KeyFilePath $TemplateKeyFilePath -ScriptBlock {hostname} -HostName $Node.ComputerName -UserName root
            $ApplicationSSHPrivateKeyFilePath = "$Home\.ssh\$($Node.ApplicationName)"
            $ApplicationSSHPublicKeyFilePath = "$ApplicationSSHPrivateKeyFilePath.pub"
            ssh-keygen -t rsa -b 4096 -f $ApplicationSSHKeyFilePath -N '""'
            Get-Content -Path $ApplicationSSHPublicKeyFilePath | 
            ssh "root@$($Node.IPAddress)" 'cat > ~/.ssh/authorized_keys'

            Get-Content -Path $TemplateKeyFilePath | Out-File -Append -FilePath $Home/.ssh/authorized_keys

            Set-LinuxAccountPassword -ComputerName $Node.IPAddress -Credential $TemplateCredential -NewCredential $Node.Credential -UsePSSession
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
    $DomainJoinCredential = Get-PasswordstatePassword -ID 2643 -AsCredential

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
        [Switch]$UseIPAddress,
        [Switch]$PassThru
    )
    process {
        $Node |
        Add-Member -MemberType ScriptProperty -Name SSHSession -Force -Value {
            # https://github.com/PowerShell/PowerShell/pull/5328
            # Commented code below will work and be be cross platform with release of v6.1.0, using old code for now
            #$ComputerNamePingable = Test-Connection -ComputerName $This.ComputerName |
            #Select-Object -ExpandProperty PingSucceeded

            #$ComputerName = if ($UseIPAddress -or -not $ComputerNamePingable) {$This.IPAddress} else {$This.ComputerName}
            
            $ComputerName = if ($UseIPAddress) {$This.IPAddress} else {$This.Computername}
            $SSHSession = Get-SSHSession -ComputerName $ComputerName
            if ($SSHSession -and $SSHSession.Connected -eq $true) {
                $SSHSession
            } else {
                if ($SSHSession) { $SSHSession | Remove-SSHSession | Out-Null }                
                New-SSHSession -ComputerName $ComputerName -Credential $This.Credential -AcceptKey
            }
        }.GetNewClosure() -PassThru:$PassThru
    }
}

function Add-SFTPSessionCustomProperty {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Switch]$UseIPAddress,
        [Switch]$PassThru
    )
    process {
        $Node |
        Add-Member -MemberType ScriptProperty -Name SFTPSession -Force -Value {
            $ComputerName = if ($UseIPAddress) {$This.IPAddress} else {$This.ComputerName}
            $SFTPSession = Get-SFTPSession | where Host -eq $ComputerName
            if ($SFTPSession -and $SFTPSession.Connected -eq $true) {
                $SFTPSession
            } else {
                if ($SFTPSession) { $SFTPSession | Remove-SFTPSession | Out-Null }                
                New-SFTPSession -ComputerName $ComputerName -Credential $This.Credential -AcceptKey
            }
        }.GetNewClosure() -PassThru:$PassThru 
    }
}

function Add-NodeCredentialProperty {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node,
        [Switch]$PassThru
    )
    process {
        if ($Node.LocalAdminPasswordStateID) {
            $Node |
            Add-Member -MemberType ScriptProperty -Name Credential -Force -Value {
                Get-PasswordstatePassword -AsCredential -ID $This.LocalAdminPasswordStateID
            } -PassThru:$PassThru 
        } else {
            $Node | New-TervisPasswordStateApplicationPassword -Type LocalAdministrator | Out-Null
            $Node | Add-Member -MemberType ScriptProperty -Name Credential -Force -Value {
                $This | Get-TervisPasswordStateApplicationPassword -Type LocalAdministrator -AsCredential
            } -PassThru:$PassThru 
        }
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

function Set-AutoLogonOnNode {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory)]$PasswordstateId
    )
    process {
        $AutoLogonCredential = Get-PasswordstatePassword -ID $PasswordstateId -AsCredential
        Write-Verbose ""
        Invoke-Command -ComputerName $ComputerName -ArgumentList $AutoLogonCredential -ScriptBlock {
            param (
                $Cred
            )
            $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            try {
                New-ItemProperty -Path $RegistryPath -Type String -Name AutoAdminLogon -Value 1 -ErrorAction Stop | Out-Null
            }
            catch {
                Set-ItemProperty -Path $RegistryPath -Type String -Name AutoAdminLogon -Value 1 | Out-Null
            }
            try {
                New-ItemProperty -Path $RegistryPath -Type String -Name DefaultUsername -Value $Cred.Username -ErrorAction Stop | Out-Null
            }
            catch {
                Set-ItemProperty -Path $RegistryPath -Type String -Name DefaultUsername -Value $Cred.Username | Out-Null
            }
            try {
                New-ItemProperty -Path $RegistryPath -Type String -Name DefaultPassword -Value $Cred.GetNetworkCredential().Password -ErrorAction Stop | Out-Null
            }
            catch {
                Set-ItemProperty -Path $RegistryPath -Type String -Name DefaultPassword -Value $Cred.GetNetworkCredential().Password | Out-Null
            }
        }
    }
}
