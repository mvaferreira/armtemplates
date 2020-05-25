Param(
    [Parameter(Mandatory)]
    [string]$ExternalFqdn,

    [Parameter(Mandatory)]
    [securestring]$CertPasswd
)

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
Install-Module -Name Posh-ACME -Scope AllUsers -Force
Import-Module Posh-ACME
Import-Module RemoteDesktop

New-Item -ItemType Directory -Path "C:\temp"
New-PACertificate $ExternalFqdn -AcceptTOS
Get-PACertificate $ExternalFqdn | Install-PACertificate
$Thumbprint = (Get-PACertificate $ExternalFqdn).Thumbprint
$ServerObj = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_ComputerSystem"
$ServerName = $ServerObj.DNSHostName + "." + $ServerObj.Domain
$CertFullPath = (Join-path "C:\temp" $($ExternalFqdn + ".pfx"))
Export-PfxCertificate -Cert Cert:\LocalMachine\My\$Thumbprint -FilePath $CertFullPath -Password $CertPasswd -Force
Set-RDCertificate -Role RDWebAccess -ImportPath $CertFullPath -Password $CertPasswd -ConnectionBroker $ServerName
Set-RDCertificate -Role RDGateway -ImportPath $CertFullPath -Password $CertPasswd -ConnectionBroker $ServerName