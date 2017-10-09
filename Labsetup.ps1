New-VyOSVM {
    $VMHost = Get-VMHost
    $VMName = "VyOS Template"

    $VM = New-VM -Name $VMName -NewVHDSizeBytes 60GB -NewVHDPath "$($VMHost.VirtualHardDiskPath)\$VMName.vhdx" -MemoryStartupBytes 512MB
    Set-VMDvdDrive -Path "C:\Users\cmagnuson\OneDrive - tervis.com\Downloads\vyos-1.1.7-amd64.iso" -VMName $VM.Name
    Set-VMDvdDrive -Path "C:\Users\cmagnuson\OneDrive - tervis.com\Downloads\vyos-1.1.7-i586-virt.iso" -VMName $VM.Name
    
    $VM | Start-VM
    
    Get-VMNetworkAdapter -VMName $VM.Name | 
    Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList "1-4000" -NativeVlanId 1
    
    Get-VMNetworkAdapter -VMName $VM.Name | 
    Connect-VMNetworkAdapter -SwitchName VSwitch

@"
configure
set inter eth0 vif description 'vlan 100 ISP1'
set int eth0 vif address 172.16.0.1/24
commit
save
exit
"@
}

function New-VyOSTestSiteToSiteWANVPNInLab {
    param (
        $Phase1DHGroup,
        $Phase1Encryption,
        $Phase1Hash,
        $Phase2Encryption,
        $Phase2Hash
    )

    $Router1Parameters = @{
        WANIPLocal = 172.16.1.1
        WANIPRemote = 172.16.1.2
        VTIIPLocal = 192.168.0.1
        VTIIPLocalPrefixBits = 30
        VTIIPRemote = 192.168.0.2
        PreSharedSecret = "vyos"
    }

    $Router2Parameters = @{
        WANIPLocal = 172.16.1.2
        WANIPRemote = 172.16.1.1
        VTIIPLocal = 192.168.0.2
        VTIIPLocalPrefixBits = 30
        VTIIPRemote = 192.168.0.1
        PreSharedSecret = "vyos"
    }

    New-VyOSSiteToSiteWANVPN -Phase1DHGroup 19 -Phase1Encryption aes128 -Phase1Hash sha256 -Phase2Encryption aes128 -Phase2Hash sha256 @Router1Parameters
    New-VyOSSiteToSiteWANVPN -Phase1DHGroup 19 -Phase1Encryption aes128 -Phase1Hash sha256 -Phase2Encryption aes128 -Phase2Hash sha256 @Router2Parameters
}

