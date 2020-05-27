Param(
    [Parameter(Mandatory)]
    [Array]$BrokerParameters
)

$ConnectionBroker = $BrokerParameters[0].ConnectionBroker
$AzureSQLFQDN = $BrokerParameters[0].AzureSQLFQDN
$AzureSQLDBName = $BrokerParameters[0].AzureSQLDBName
$AzureSQLUserID = $BrokerParameters[0].AzureSQLUserID
$AzureSQLPasswd = $BrokerParameters[0].AzureSQLPasswd
$BrokerFQDN = $BrokerParameters[0].BrokerFQDN

If (-Not (Test-Path "C:\temp")) {
    New-Item -ItemType Directory -Path "C:\temp" -Force
}

Start-Transcript -Path "C:\Temp\ConfigureBrokerHA.log"

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

$DBConnectionString = "Driver={ODBC Driver 17 for SQL Server};Server=tcp:$($AzureSQLFQDN),1433;Database=$($AzureSQLDBName);Uid=$($AzureSQLUserID);Pwd=$($AzureSQLPasswd);Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"

Import-Module RemoteDesktop

If (-Not (Get-RDConnectionBrokerHighAvailability).ActiveManagementServer) {
    Set-RDConnectionBrokerHighAvailability -ConnectionBroker $ConnectionBroker `
        -DatabaseConnectionString $DBConnectionString `
        -ClientAccessName $BrokerFQDN
} Else {
    $ServerObj = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_ComputerSystem"
    $DomainName = $ServerObj.Domain
    $NewBroker = $ServerObj.DNSHostName + "." + $DomainName
    Add-RDServer -Role "RDS-CONNECTION-BROKER" -ConnectionBroker (Get-RDConnectionBrokerHighAvailability).ActiveManagementServer -Server $NewBroker
}

Stop-Transcript