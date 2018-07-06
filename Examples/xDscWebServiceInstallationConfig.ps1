configuration xDscWebServiceInstallationConfig
{
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = 'This should be a string with enough entropy (randomness) to protect the registration of clients to the pull server. This string will be used by clients to initiate conversation with the pull server. This can for example be a GUID generate by cmdlet New-Guid, e.g. ''cdb90772-ff3d-49e5-ae64-889391a1eb4a''.')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $RegistrationKey,

        [Parameter(Mandatory = $true, HelpMessage = 'The credential used to create a database user (login type will be SQL login).')]
        [ValidateNotNullOrEmpty()]
        [PsCredential]$DatabaseCredential,

        [Parameter(HelpMessage = 'The certificate subject that is used to access the pull server. Defaults to $env:COMPUTERNAME (in Azure Automation this will default to ''CLIENT'').')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CertificateSubject = $env:COMPUTERNAME,

        [Parameter(HelpMessage = 'The port that the pull server listen for request on.')]
        [ValidateNotNullOrEmpty()]
        [System.UInt32]
        $Port = 8080
    )

    Import-DSCResource -ModuleName xPSDesiredStateConfiguration
    Import-DSCResource -ModuleName SqlServerDsc
    # To explicitly import the resource File.
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node localhost
    {
        xWindowsFeature 'DSCServiceFeature'
        {
            Ensure = 'Present'
            Name   = 'DSC-Service'
        }

        xScript 'InstallSqlExpress'
        {
            SetScript  = {
                Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=853017' -OutFile 'C:\SQLExpress.exe'
                C:\SQLExpress.exe /ENU /IAcceptSqlServerLicenseTerms /Quiet /HideProgressBar /Action=Install /Language=en-US
            }

            TestScript = {
                $getScriptResult = & ([ScriptBlock]::Create($GetScript))
                if ($getScriptResult.Result)
                {
                    return $true
                }
                else
                {
                    return $false
                }
            }

            GetScript  = {
                return @{
                    Result = (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction 'SilentlyContinue').Name
                }
            }
        }

        xScript 'SetSqlAuthenticationMode'
        {
            SetScript  = {
                $getScriptResult = & ([ScriptBlock]::Create($TestScript))
                if ($getScriptResult -eq $false)
                {
                    $sqlServerObject = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList '.\SQLEXPRESS'
                    $sqlServerObject.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed
                    $sqlServerObject.Settings.Alter()

                    Restart-Service -Name 'MSSQL$SQLEXPRESS' -Force

                    # Wait for the SQL Server Express to come online.
                    $connectTimer = [System.Diagnostics.StopWatch]::StartNew()

                    do
                    {
                        # This call, if it fails, will take between ~9-10 seconds to return.
                        $testConnectionServerObject = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList '.\SQLEXPRESS'
                        if ($testConnectionServerObject -and $testConnectionServerObject.Status -ne 'Online')
                        {
                            # Waiting 2 seconds to not hammer the SQL Server instance.
                            Start-Sleep -Seconds 2
                        }
                        else
                        {
                            break
                        }
                    } until ($connectTimer.Elapsed.Seconds -ge 60)

                    $connectTimer.Stop()
                }
            }

            TestScript = {
                $getScriptResult = & ([ScriptBlock]::Create($GetScript))
                if ($getScriptResult.Result -eq [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed)
                {
                    return $true
                }
                else
                {
                    return $false
                }
            }

            GetScript  = {
                # Force newly added paths into the session.
                $env:PSModulePath = [System.Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')

                Import-Module -Name SQLPS

                $sqlServerObject = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList '.\SQLEXPRESS'

                return @{
                    Result = $sqlServerObject.Settings.LoginMode
                }
            }

            DependsOn = '[xScript]InstallSqlExpress'
        }

        SqlServerLogin 'AddSqlLogin'
        {
            Ensure                         = 'Present'
            Name                           = $DatabaseCredential.UserName
            LoginType                      = 'SqlLogin'
            ServerName                     = '.'
            InstanceName                   = 'SQLEXPRESS'
            LoginCredential                = $DatabaseCredential
            LoginMustChangePassword        = $false
            LoginPasswordExpirationEnabled = $false
            LoginPasswordPolicyEnforced    = $true
            #PsDscRunAsCredential           = $SqlAdministratorCredential

            DependsOn                      = '[xScript]SetSqlAuthenticationMode'
        }

        xScript 'GenerateCertificate'
        {
            SetScript  = {
                New-SelfSignedCertificate -Subject $Using:CertificateSubject -CertStoreLocation 'Cert:\LocalMachine\My' | Out-Null
            }

            TestScript = {
                $getScriptResult = & ([ScriptBlock]::Create($GetScript))
                if ($getScriptResult.Result)
                {
                    return $true
                }
                else
                {
                    return $false
                }
            }

            GetScript  = {
                $thumbprint = $null

                $certificate = Get-ChildItem -Path 'cert:\LocalMachine\My' | Where-Object -FilterScript {
                    $_.Subject -eq "CN=$Using:CertificateSubject"
                }

                if ($certificate)
                {
                    $thumbprint = $certificate.Thumbprint
                }

                return @{
                    Result = $thumbprint
                }
            }
        }

        # xDscWebService 'PSDscPullServer'
        # {
        #     Ensure                       = 'Present'
        #     EndpointName                 = 'PSDSCPullServer'
        #     Port                         = $Port
        #     PhysicalPath                 = "$env:SystemDrive\inetpub\PSDSCPullServer"
        #     CertificateSubject           = $CertificateSubject
        #     ModulePath                   = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
        #     ConfigurationPath            = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
        #     State                        = 'Started'
        #     RegistrationKeyPath          = "$env:PROGRAMFILES\WindowsPowerShell\DscService"
        #     AcceptSelfSignedCertificates = $true
        #     UseSecurityBestPractices     = $true
        #     SqlProvider                  = $true
        #     SqlConnectionString          = 'Provider=SQLNCLI11;Data Source=(local)\SQLExpress;User ID=SA;Password=Password12!;Initial Catalog=master;'

        #     DependsOn = @(
        #         '[xWindowsFeature]DSCServiceFeature'
        #         '[xScript]InstallSqlExpress'
        #         '[SqlServerLogin]AddSqlLogin'
        #         '[xScript]GenerateCertificate'
        #     )
        # }

        # File RegistrationKeyFile
        # {
        #     Ensure          = 'Present'
        #     Type            = 'File'
        #     DestinationPath = "$env:ProgramFiles\WindowsPowerShell\DscService\RegistrationKeys.txt"
        #     Contents        = $RegistrationKey
        #     Force           = $true

        #     DependsOn = '[xDscWebService]PSDscPullServer'
        # }
    }
}
