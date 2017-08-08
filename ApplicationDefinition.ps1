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
        NumberOfNodes = 4
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
}