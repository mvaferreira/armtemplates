Param (
    [Parameter(Mandatory)]
    [string]$ProjectName,

    [Parameter(Mandatory)]
    [string]$MainConnectionBroker,

    [Parameter(Mandatory)]
    [string]$BrokerFqdn,

    [Parameter(Mandatory)]
    [array]$WebGatewayServers,

    [Parameter(Mandatory)]
    [array]$SessionHosts,

    [Parameter(Mandatory)]
    [array]$LicenseServers,

    [Parameter(Mandatory)]
    [string]$WebGatewayFqdn,

    [Parameter(Mandatory)]    
    [string]$AzureSQLFQDN,

    [Parameter(Mandatory)]    
    [string]$AzureSQLDBName,

    [Parameter(Mandatory)]
    [string]$Passwd
)

If (-Not (Test-Path "C:\temp")) {
    New-Item -ItemType Directory -Path "C:\temp" -Force
}

Start-Transcript -Path "C:\temp\DeployCertHA.log"

$ServerObj = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_ComputerSystem"
$ServerName = $ServerObj.DNSHostName
$DomainName = $ServerObj.Domain
$ServerFQDN = $ServerName + "." + $DomainName
$CertPasswd = ConvertTo-SecureString -String $Passwd -Force -AsPlainText
$AzureSQLUserID = $ProjectName
$AzureSQLPasswd = $Passwd
[System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($ProjectName)", $CertPasswd)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name Posh-ACME -Scope AllUsers -Force
Import-Module Posh-ACME
Import-Module RemoteDesktop

Function RequestCert([string]$Fqdn) {
    Set-PAServer LE_PROD
    New-PAAccount -AcceptTOS -Contact "$($ProjectName)@$($Fqdn)" -Force
    New-PAOrder $Fqdn
    $auth = Get-PAOrder | Get-PAAuthorizations | Where-Object { $_.HTTP01Status -eq "Pending" }
    $AcmeBody = Get-KeyAuthorization $auth.HTTP01Token (Get-PAAccount)

    Invoke-Command -ComputerName $WebGatewayServers[0] -Credential $DomainCreds -ScriptBlock {
        Param($auth, $AcmeBody, $BrokerName, $DomainName)
        $AcmePath = "C:\Inetpub\wwwroot\.well-known\acme-challenge"
        New-Item -ItemType Directory -Path $AcmePath -Force
        New-Item -Path $AcmePath -Name $auth.HTTP01Token -ItemType File -Value $AcmeBody
        Add-LocalGroupMember -Group "Administrators" -Member "$($DomainName)\$($BrokerName)$"
    } -ArgumentList $auth, $AcmeBody, $ServerName, $DomainName

    $auth.HTTP01Url | Send-ChallengeAck

    Do {
        Write-Host "Waiting for validation. Sleeping 30 seconds..."
        Start-Sleep -Seconds 30
    } While ((Get-PAOrder | Get-PAAuthorizations).HTTP01Status -ne "valid")

    New-PACertificate $Fqdn -Install
    $Thumbprint = (Get-PACertificate $Fqdn).Thumbprint
    
    $CertFullPath = (Join-path "C:\temp" $($Fqdn + ".pfx"))
    Export-PfxCertificate -Cert Cert:\LocalMachine\My\$Thumbprint -FilePath $CertFullPath -Password $CertPasswd -Force
}

Function InstallSQLClient() {
    $VCRedist = "C:\Temp\vc_redist.x64.exe"
    $ODBCmsi = "C:\Temp\msodbcsql.msi"
    
    If (-Not (Test-Path -Path $VCRedist)) {
        Invoke-WebRequest -Uri "https://aka.ms/vs/15/release/vc_redist.x64.exe" -OutFile $VCRedist
    }
    
    If (-Not (Test-Path -Path $ODBCmsi)) {
        Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2120137" -OutFile $ODBCmsi
    }
    
    If (Test-Path -Path $VCRedist) {
        Unblock-File -Path $VCRedist
    
        $params = @()
        $params += '/install'
        $params += '/quiet'
        $params += '/norestart'
        $params += '/log'
        $params += 'C:\Temp\vcredistinstall.log'
            
        Try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo 
            $ProcessInfo.FileName = $VCRedist
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = $params
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $ReturnMSG = $Process.StandardOutput.ReadToEnd()
            $ReturnMSG
        }
        Catch { }
    }
    
    If (Test-Path -Path $ODBCmsi) {
        Unblock-File -Path $ODBCmsi
    
        $params = @()
        $params += '/i'
        $params += $ODBCmsi
        $params += '/norestart'
        $params += '/quiet'
        $params += '/log'
        $params += 'C:\Temp\obdcdriverinstall.log'
        $params += 'IACCEPTMSODBCSQLLICENSETERMS=YES'
            
        Try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo 
            $ProcessInfo.FileName = "$($Env:SystemRoot)\System32\msiexec.exe"
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = $params
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $ReturnMSG = $Process.StandardOutput.ReadToEnd()
            $ReturnMSG
        }
        Catch { }
    }
}

If ($ServerName -eq $MainConnectionBroker) {
    #Add remaining servers
    ForEach($NewServer In $WebGatewayServers) {
        If (-Not (Get-RDServer -Role "RDS-WEB-ACCESS" -ConnectionBroker $ServerFQDN | Where-Object {$_.Server -match $NewServer})) {
            Add-RDServer -Role "RDS-WEB-ACCESS" -ConnectionBroker $ServerFQDN -Server $NewServer
        }
    }

    ForEach($NewServer In $WebGatewayServers) {
        If (-Not (Get-RDServer -Role "RDS-GATEWAY" -ConnectionBroker $ServerFQDN | Where-Object {$_.Server -match $NewServer})) {
            Add-RDServer -Role "RDS-GATEWAY" -ConnectionBroker $ServerFQDN -Server $NewServer
        }
    }

    ForEach($NewServer In $SessionHosts) {
        If (-Not (Get-RDServer -Role "RDS-RD-SERVER" -ConnectionBroker $ServerFQDN | Where-Object {$_.Server -match $NewServer})) {
            Add-RDServer -Role "RDS-RD-SERVER" -ConnectionBroker $ServerFQDN -Server $NewServer
        }
    }
    
    ForEach($NewServer In $LicenseServers) {
        If (-Not (Get-RDServer -Role "RDS-LICENSING" -ConnectionBroker $ServerFQDN | Where-Object {$_.Server -match $NewServer})) {
            Add-RDServer -Role "RDS-LICENSING" -ConnectionBroker $ServerFQDN -Server $NewServer
        }
    }
    #End of add remaining servers

    #Request Certs for web access, gateway, broker and publishing    
    $CertWebGatewayPath = (Join-path "C:\temp" $($WebGatewayFqdn + ".pfx"))
    $CertBrokerPath = (Join-path "C:\temp" $($BrokerFqdn + ".pfx"))

    If (-Not (Get-RDCertificate -Role RDGateway).IssuedTo) {
        RequestCert $WebGatewayFqdn
        RequestCert $BrokerFqdn
        Set-RDCertificate -Role RDWebAccess -ImportPath $CertWebGatewayPath -Password $CertPasswd -ConnectionBroker $ServerFQDN -Force
        Set-RDCertificate -Role RDGateway -ImportPath $CertWebGatewayPath -Password $CertPasswd -ConnectionBroker $ServerFQDN -Force
        Set-RDCertificate -Role RDRedirector -ImportPath $CertBrokerPath -Password $CertPasswd -ConnectionBroker $ServerFQDN -Force
        Set-RDCertificate -Role RDPublishing -ImportPath $CertBrokerPath -Password $CertPasswd -ConnectionBroker $ServerFQDN -Force
    }
    #End of cert request

    #Configure broker in HA
    InstallSQLClient
    If ($?) {
        $DBConnectionString = "Driver={ODBC Driver 17 for SQL Server};Server=tcp:$($AzureSQLFQDN),1433;Database=$($AzureSQLDBName);Uid=$($AzureSQLUserID);Pwd=$($AzureSQLPasswd);Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
    
        If (-Not (Get-RDConnectionBrokerHighAvailability).ActiveManagementServer) {
            Set-RDConnectionBrokerHighAvailability -ConnectionBroker $ConnectionBroker `
                -DatabaseConnectionString $DBConnectionString `
                -ClientAccessName $BrokerFQDN
        }
    }
    #End of configure broker in HA
}
Else {
    #If not the first broker, just install SQL OBDC driver and join the farm
    InstallSQLClient
    If ($?) {
        $MainBrokerFQDN = $MainConnectionBroker + "." + $DomainName

        #As we're executing via SYSTEM, make sure the broker is able to manage servers
        Invoke-Command -ComputerName $MainConnectionBroker -Credential $DomainCreds -ScriptBlock {
            Param($DomainName,$BrokerName)
            Add-LocalGroupMember -Group "Administrators" -Member "$($DomainName)\$($BrokerName)$"
        } -ArgumentList $DomainName, $ServerName

        #First broker HA deployment might be still running in parallel, wait for HA.
        While(-Not (Get-RDConnectionBrokerHighAvailability -ConnectionBroker $MainBrokerFQDN)) {
            Write-Host "Waiting 30 seconds for RDS Deployment..."
            Start-Sleep -Seconds 30
        }

        Get-RDServer -ConnectionBroker $MainBrokerFQDN | ForEach-Object {
            Invoke-Command -ComputerName $_.Server -Credential $DomainCreds -ScriptBlock {
                Param($DomainName,$BrokerName)
                Add-LocalGroupMember -Group "Administrators" -Member "$($DomainName)\$($BrokerName)$" -ErrorAction SilentlyContinue
            } -ArgumentList $DomainName, $ServerName
        }

        #RDS HA Deployment is available, adding to RDS Broker farm.
        Add-RDServer -Role "RDS-CONNECTION-BROKER" -ConnectionBroker $MainBrokerFQDN -Server $ServerFQDN
        
        #Since we've added another broker, we have to import the cert again
        $CertRemotePath = (Join-path "\\$MainConnectionBroker\C$\temp" "*.pfx")
        $CertBrokerPath = (Join-path "C:\temp" $($BrokerFqdn + ".pfx"))

        #Copy the certs locally from first broker
        Copy-Item -Path $CertRemotePath -Destination "C:\Temp"

        Set-RDCertificate -Role RDRedirector -ImportPath $CertBrokerPath -Password $CertPasswd -ConnectionBroker $MainBrokerFQDN -Force
        Set-RDCertificate -Role RDPublishing -ImportPath $CertBrokerPath -Password $CertPasswd -ConnectionBroker $MainBrokerFQDN -Force        
    }
}

Stop-Transcript