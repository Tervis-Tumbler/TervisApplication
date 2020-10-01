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
    ComputeType = "Virtual"
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
        NumberOfNodes = 3
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4124
        SQLSAPassword = 4038
    }
    DPMServiceAccountPassword = 4037
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
        NumberOfNodes = 2
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
        NumberOfNodes = 2
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4188
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "RemoteDesktopWebAccess"
    NodeNameRoot = "RDWebAcc"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4190
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "RemoteDesktopBroker"
    NodeNameRoot = "RDBroker"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 6326
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "SCDPM2016FileServer"
    NodeNameRoot = "SCDPMFS"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 4
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4124
        SQLSAPassword = 4038
    }
    DPMServiceAccountPassword = 4037
    VMOperatingSystemTemplateName = "Windows Server 2016"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "SCDPM2016SQL"
    NodeNameRoot = "SCDPMSQL"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4124
        SQLSAPassword = 4038
    }
    DPMServiceAccountPassword = 4037
    VMOperatingSystemTemplateName = "Windows Server 2016"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "SCDPMOraBackups"
    NodeNameRoot = "SCDPMORA"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4124
        SQLSAPassword = 5157
    }
    Password = 4037
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
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "HyperVCluster5Evergreen"
    NodeNameRoot = "HyperVC5N"
    ComputeType = "Physical"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 6
        LocalAdminPasswordStateID = 4348
    }
    VMOperatingSystemTemplateName = "Windows Server Evergreen Physical"
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
    Name = "HyperVCluster6Evergreen"
    NodeNameRoot = "HyperVC6N"
    ComputeType = "Physical"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        LocalAdminPasswordStateID = 4349
    }
    VMOperatingSystemTemplateName = "Windows Server Evergreen Physical"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "VDICluster1"
    NodeNameRoot = "VDIC1N"
    ComputeType = "Physical"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        LocalAdminPasswordStateID = 4873
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "StandaloneHyperVServer"
    NodeNameRoot = "HyperV"
    ComputeType = "Physical"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        LocalAdminPasswordStateID = 4875
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
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
    VMOperatingSystemTemplateName = "Windows Server 2019"
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
},
[PSCustomObject][Ordered]@{
    Name = "FreshDeskSFTP"
    NodeNameRoot = "FDeskSFTP"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 5239
    }
    VMOperatingSystemTemplateName = "CentOS 7"
},
[PSCustomObject][Ordered]@{
    Name = "EMC Storage Integrator for Windows Suite"
    NodeNameRoot = "ESI"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4860
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "iSNS"
    NodeNameRoot = "iSNS"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 4876
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "SQL Anywhere"
    NodeNameRoot = "SQLA"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4966
    },
    [PSCustomObject][Ordered]@{
        Name = "Epsilon"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4967
    },
    [PSCustomObject][Ordered]@{
        Name = "Delta"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4968
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "RemoteDesktopLicensing"
    NodeNameRoot = "RDLicense"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4971
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "ADFS"
    NodeNameRoot = "ADFS"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 4977
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "ADFSProxy"
    NodeNameRoot = "ADFSProxy"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 4978
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "DomainController"
    NodeNameRoot = "DC"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 2643
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "SilverlightIE"
    NodeNameRoot = "SlvrLtIE"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5001
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "FedExShipManager"
    NodeNameRoot = "FedExSM"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5031
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "VyOS"
    NodeNameRoot = "VyOS"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 4996
    }
    VMOperatingSystemTemplateName = "VyOS"
},
[PSCustomObject][Ordered]@{
    Name = "ZeroTier Router"
    NodeNameRoot = "ZTRouter"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5071
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "SCCM2019"
    NodeNameRoot = "SCCM"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 5090
        SQLSAPassword = 5091
        SCCMServiceAccountPassword = 2994
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "ZeroTierBridge"
    NodeNameRoot = "ZTBridge"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 5088
    }
    VMOperatingSystemTemplateName = "CentOS 7"
},
[PSCustomObject][Ordered]@{
    Name = "UnifiController"
    NodeNameRoot = "Unifi"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5104
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "ArchRouter"
    NodeNameRoot = "ArchRT"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5183
    }
    VMOperatingSystemTemplateName = "Arch Linux"
},
[PSCustomObject][Ordered]@{
    Name = "EBSBusinessIntelligenceRemoteApp"
    NodeNameRoot = "EBSBI"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 5308
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "EBSDiscovererRemoteApp"
    NodeNameRoot = "EBSDISC"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 5309
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "AzureBackupServer"
    NodeNameRoot = "AzureBK"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5320
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "OracleODBEE"
    NodeNameRoot = "ODBEE"
    ComputeType = "OracleVM"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5361
        OracleUserCredential = 5412
        ApplmgrUserCredential = 5411
        OracleSMBShareADCredential = 4169
    }
    VMOperatingSystemTemplateName = "OEL"
},
[PSCustomObject][Ordered]@{
    Name = "OracleIAS"
    NodeNameRoot = "IAS"
    ComputeType = "OracleVM"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5715
        OracleUserCredential = 5412
        ApplmgrUserCredential = 5411
        OracleSMBShareADCredential = 4169
    }
    VMOperatingSystemTemplateName = "OEL"
},
[PSCustomObject][Ordered]@{
    Name = "OracleWeblogic"
    NodeNameRoot = "Weblogic"
    ComputeType = "OracleVM"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5585
        OracleUserCredential = 5412
        ApplmgrUserCredential = 5411
        OracleSMBShareADCredential = 4169
    }
    VMOperatingSystemTemplateName = "OEL"
},
[PSCustomObject][Ordered]@{
    Name = "SMTPRelay"
    NodeNameRoot = "SMTPRelay"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 5385
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "ITToolbox"
    NodeNameRoot = "ITToolbox"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 5376
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "WindowsAdminCenterGateway"
    NodeNameRoot = "WinAdmin"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 5388
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "Kubernetes"
    NodeNameRoot = "Kub"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5178
    }
    VMOperatingSystemTemplateName = "Arch Linux"
},
[PSCustomObject][Ordered]@{
    Name = "AzureADConnector"
    NodeNameRoot = "AADConn"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5414
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "Passwordstate"
    NodeNameRoot = "PWState"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5425
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "UniversalDashboard"
    NodeNameRoot = "UD"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
        VMSizeName = "Medium"
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "CertificateAuthority"
    NodeNameRoot = "CA"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "nChannelSyncManager"
    NodeNameRoot = "SyncMgr"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Delta"
        NumberOfNodes = 1
        VMSizeName = "Small"
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "NestedHyperVCluster"
    NodeNameRoot = "NHVC1N"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 5537
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "Windows Subsystem for Linux Server"
    NodeNameRoot = "WSLS"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
    }
    VMOperatingSystemTemplateName = "Windows Server Datacenter"
},
[PSCustomObject][Ordered]@{
    Name = "Sylint"
    NodeNameRoot = "Sylint"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "OpenVPNServer"
    NodeNameRoot = "OpenVPN"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 5584
    }
    VMOperatingSystemTemplateName = "CentOS 7"
},
[PSCustomObject][Ordered]@{
    Name = "InDesign"
    NodeNameRoot = "InDesign"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Medium"
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "Exchange"
    NodeNameRoot = "Exchange"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "VPNTest"
    NodeNameRoot = "VPNTest"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "AlwaysOn"
    NodeNameRoot = "AlwaysOn"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "VendorVPN"
    NodeNameRoot = "VendorVPN"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "Docker"
    NodeNameRoot = "Docker"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 3
        VMSizeName = "Medium"
    }
    VMOperatingSystemTemplateName = "Debian 9"
},
[PSCustomObject][Ordered]@{
    Name = "ExcelTask"
    NodeNameRoot = "ExcelTask"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Small"
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "LinuxNFSBackupServer"
    NodeNameRoot = "NFSBackup"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5716
    }
    VMOperatingSystemTemplateName = "CentOS 7"
},
[PSCustomObject][Ordered]@{
    Name = "ShopifyInterface"
    NodeNameRoot = "Shopify"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5843
    },
    [PSCustomObject][Ordered]@{
        Name = "Epsilon"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 5869
    },
    [PSCustomObject][Ordered]@{
        Name = "Delta"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 5870
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "RDPJumpBox"
    NodeNameRoot = "RDPJump"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 6327
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "FedExShipManagerServer"
    NodeNameRoot = "FedExSMS"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5859
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "OELYumRepoServer"
    NodeNameRoot = "OELRepo"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 2
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5716
    }
    VMOperatingSystemTemplateName = "CentOS 7"
},
[PSCustomObject][Ordered]@{
    Name = "HyperVCluster7"
    NodeNameRoot = "HyperVC7N"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 6
        LocalAdminPasswordStateID = 4348
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "RiminiSupport"
    NodeNameRoot = "RiminiSup"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 5927
    }
    VMOperatingSystemTemplateName = "Windows Server 2016"
},
[PSCustomObject][Ordered]@{
    Name = "OracleDR"
    NodeNameRoot = "OracleDR"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 6360
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
    NeedsAccesstoSAN = $true
},
[PSCustomObject][Ordered]@{
    Name = "VHDFileServer"
    NodeNameRoot = "VHDFS"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 6365
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "ParkPlaceMonitor"
    NodeNameRoot = "PPMonitor"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 6371
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "SCOM2019"
    NodeNameRoot = "SCOM"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 6373
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "ChannelAdvisor"
    NodeNameRoot = "ChAdvisor"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Epsilon"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 6375
    },
    [PSCustomObject][Ordered]@{
        Name = "Production"
        NumberOfNodes = 1
        VMSizeName = "Small"
        LocalAdminPasswordStateID = 6374
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "SCVMM2019"
    NodeNameRoot = "SCVMM"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Large"
        LocalAdminPasswordStateID = 6389
    }
    VMOperatingSystemTemplateName = "Windows Server 2019"
},
[PSCustomObject][Ordered]@{
    Name = "SCDPM2019"
    NodeNameRoot = "SCDPM2019"
    ComputeType = "Virtual"
    Environments = [PSCustomObject][Ordered]@{
        Name = "Infrastructure"
        NumberOfNodes = 1
        VMSizeName = "Medium"
        LocalAdminPasswordStateID = 6395
        SQLSAPassword = 4038
    }
    DPMServiceAccountPassword = 4037
    VMOperatingSystemTemplateName = "Windows Server 2019"
    NeedsAccesstoSAN = $true
}