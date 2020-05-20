Configuration CreateRootDomain
{
    Param(
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,
        
        [Parameter(Mandatory)]
        [String]$DNSServer        
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration,xActiveDirectory,xNetworking,ComputerManagementDSC,xComputerManagement
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)    

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = "ApplyOnly"
        }
                
        WindowsFeature DNS
        {
            Ensure = "Present"
            Name = "DNS"
        }

        WindowsFeature AD-Domain-Services
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
            DependsOn = "[WindowsFeature]DNS"
        }

        WindowsFeature DnsTools
        {
            Ensure = "Present"
            Name = "RSAT-DNS-Server"
            DependsOn = "[WindowsFeature]DNS"
        }        

        WindowsFeature GPOTools
        {
            Ensure = "Present"
            Name = "GPMC"
            DependsOn = "[WindowsFeature]DNS"
        }

        WindowsFeature DFSTools
        {
            Ensure = "Present"
            Name = "RSAT-DFS-Mgmt-Con"
            DependsOn = "[WindowsFeature]DNS"
        }        

        WindowsFeature RSAT-AD-Tools
        {
            Ensure = "Present"
            Name = "RSAT-AD-Tools"
            DependsOn = "[WindowsFeature]AD-Domain-Services"
            IncludeAllSubFeature = $True
        }

        xDnsServerAddress DnsServerAddress
        {
            Address        = '127.0.0.1'
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
            DependsOn = "[WindowsFeature]DNS"
        }
        
        xADDomain RootDomain
        {
            DomainName = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath = "$Env:windir\NTDS"
            LogPath = "$Env:windir\NTDS"
            SysvolPath = "$Env:windir\SYSVOL"
            DependsOn = @("[WindowsFeature]AD-Domain-Services", "[xDnsServerAddress]DnsServerAddress")
        }
        
        PendingReboot RebootAfterInstallingAD
        {
            Name = 'RebootAfterInstallingAD'
            DependsOn = "[xADDomain]RootDomain"
        }        
    }
}

Configuration RDWebGateway
{
    Param(
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,
        
        [Parameter(Mandatory)]
        [String]$DNSServer
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration,xNetworking,ActiveDirectoryDsc,ComputerManagementDSC,xComputerManagement
    [System.Management.Automation.PSCredential]$Creds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)

    Node localhost
    {    
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = "ApplyOnly"
        }

        WindowsFeature RDS-Gateway
        {
            Ensure = "Present"
            Name = "RDS-Gateway"
        }

        WindowsFeature RDS-Web-Access
        {
            Ensure = "Present"
            Name = "RDS-Web-Access"
        }

        WindowsFeature RSAT-AD-PowerShell
        {
            Ensure = "Present"
            Name = "RSAT-AD-PowerShell"
        }

        xDnsServerAddress DnsServerAddress
        {
            Address        = $DNSServer
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
        }

        WaitForADDomain WaitADDomain
        {
            DomainName = $DomainName
            Credential = $Creds
            WaitTimeout = 1200
            RestartCount = 15
            WaitForValidCredentials = $True
            DependsOn = @("[xDnsServerAddress]DnsServerAddress","[WindowsFeature]RSAT-AD-PowerShell")
        }

        xComputer DomainJoin
        {
            Name = $env:COMPUTERNAME
            DomainName = $DomainName
            Credential = $Creds
            DependsOn = "[WaitForADDomain]WaitADDomain" 
        }
    }
}