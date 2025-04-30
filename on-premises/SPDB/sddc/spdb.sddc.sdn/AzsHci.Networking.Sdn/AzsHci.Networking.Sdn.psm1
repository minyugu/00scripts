. "$PSScriptRoot\Modules\AzsHci.Networking.Sdn.Diagnostic.ps1"

Function Start-SdnValidation{
    <#
    .SYNOPSIS
    Start the SDN Validation Tests

    .DESCRIPTION
    Start the SDN Validation Tests

    .PARAMETER NcVMName
    Specify one of the SDN Network Controller VM Name

    .PARAMETER RunHostValidation
    Specify whether to run Host Validation

    .PARAMETER ValidationToolPath
    Specify the ValidationTool path, the current working directory will be used if not specified

    .PARAMETER Credential
    Sepcify the credential to be used access the SDN Hosts and Infra Nodes. Current logon user account will be used if not specified

    .EXAMPLE
    Start-SdnValidation -NcVMName nc01 -RunHostValidation

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [String[]]$SdnHosts,
        [Parameter(Mandatory=$True)]
        [String]$NcVMName,
        # The Credential to run Validation, Default Credential used if not specified
        [PSCredential]$Credential,
        [Switch]$RunHostValidation,
        [String]$ValidationToolPath = ""
    )

    $RequiredModuleInstalled = Get-RequiredModules
    $NcRestName = Get-SdnNcRestName -NcVMName $NcVMName
    $NcUri = "https://$NcRestName"
    if(!$RequiredModuleInstalled)
    {
        Write-Log "Required Module RSAT-NetworkController not installed" -Type Error
        return
    }

    if($RunHostValidation)
    {
        if($SdnHosts -eq $null)
        {
            $SdnHosts = Get-SdnInfraNodes -NcUri $NcUri -RoleType "Server"
        }
        Write-Log "Start validation of SDN Servers $SdnHosts"
        #$hostTests = Invoke-Pester -Script @{Path = "$PSScriptRoot\Validations\Host\Host.Tests.ps1"; Parameters = @{SdnHosts = $SdnHosts; NcUri = $NcUri}}
        #$hostTests | Select-Object -Property TagFilter, Time, TotalCount, PassedCount, FailedCount, SkippedCount, PendingCount | Format-Table -AutoSize
    }

    if([string]::IsNullOrEmpty($ValidationToolPath))
    {
        $BinaryPath = Get-Location
    }else{
        $BinaryPath = $ValidationToolPath
    }

    $logDate = "$(Get-Date -Format "yyyy.MM.dd_hh.mm.ss")"
    $XmlReportPath = "$BinaryPath\XMLReportFileName$logDate.xml"
    $FullHtmlReportPath = "$BinaryPath\SDN_Validation_Report_$logDate.htm"
    $health = 'Healthy'
    $Report = 'Validation Test Report'

    # Add a binding redirect and try again. Parts of the Dev15 preview SDK have a
    # dependency on the 6.0.0.0 Newtonsoft.Json DLL, while other parts reference
    # the 10.0.0.0 Newtonsoft.Json DLL.
    Write-Log "Adding assembly resolver."


    $source =
@'
        using System;
        using System.Linq;
        using System.Reflection;
        using System.Text.RegularExpressions;
        using System.IO;

        public class Redirector
        {
            public readonly ResolveEventHandler EventHandler;
            public string ResolvePath { get; private set; }

            public Redirector(string executionPath)
            {
                ResolvePath = executionPath;
                this.EventHandler = new ResolveEventHandler(AssemblyResolve);
            }

            public Assembly AssemblyResolve(object sender, ResolveEventArgs resolveEventArgs)
            {
                //Console.WriteLine("OnAssemblyResolve: {0}", resolveEventArgs.Name);
                if(resolveEventArgs.Name.Contains("System.Net.Http.Formatting"))
                {
                    //Console.WriteLine("Attempting {0} success", resolveEventArgs.Name);
                    string path = Path.Combine(ResolvePath, "System.Net.Http.Formatting.dll");
                    Assembly redirected = System.Reflection.Assembly.LoadFrom(path);
                    //Console.WriteLine("Redirecting {0} success", resolveEventArgs.Name);
                    return redirected;
                }
                else if(resolveEventArgs.Name.Contains("Newtonsoft.Json"))
                {
                    //Console.WriteLine("Attempting {0} success", resolveEventArgs.Name);
                    string path = Path.Combine(ResolvePath, "Newtonsoft.Json.dll");
                    Assembly redirected = System.Reflection.Assembly.LoadFrom(path);
                    //Console.WriteLine("Redirecting {0} success", resolveEventArgs.Name);
                    return redirected;
                }
                return null;
            }
        }
'@

    $type = Add-Type -TypeDefinition $source -PassThru
    $redirectClass = [Redirector]::new($BinaryPath)

    [System.AppDomain]::CurrentDomain.add_AssemblyResolve($redirectClass.EventHandler)

    [System.Reflection.Assembly]::LoadFrom("$BinaryPath\Microsoft.NetworkController.Validation.dll") | Out-Null
    [System.Reflection.Assembly]::LoadFrom("$BinaryPath\Microsoft.NetworkController.Validation.Common.dll") | Out-Null

    #Write-Log "Saving current TrustedHosts"
    #$savedTrustedHosts = Get-TrustedHosts
    #Load the validation module and run tests
    try
    {
        #SetTrustedHostsToAll

        $DefaultCreds = New-Object Microsoft.NetworkController.Validation.Common.NCValidationCredential
        $DefaultCreds.CredentialType = [Microsoft.NetworkController.Validation.Common.NCValidationCredentialType]::IntegratedWindowsAuthentication

        if ($null -ne $Credential)
        {
            if ($null -eq $Credential.UserName)
            {
                $DefaultCreds.UserName = "localadminuser"
            }
            else
            {
                $DefaultCreds.CredentialType = [Microsoft.NetworkController.Validation.Common.NCValidationCredentialType]::UserNamePassword
                $DefaultCreds.UserName = $Credential.UserName
            }

            if ($null -eq $Credential.Password)
            {
                exit 1
            }
            else
            {
                $DefaultCreds.Password = $Credential.Password
            }
        }

        Write-Log "Creating an instance of Validation Engine"
        $ValidationEngine = [Microsoft.NetworkController.Validation.NCValidationEngine]::CreateValidationEngine()

        $ValidationEngine.NetworkControllerCredential = $DefaultCreds
        $ValidationEngine.HostCredential = $DefaultCreds
        $ValidationEngine.RestEndPoint = $NcRestName

        foreach ($node in $SdnHosts)
        {
            $ValidationEngine.AddNode($node, $DefaultCreds)
        }

        #Now Load and run tests
        Write-Log "Loading tests"
        $ValidationEngine.LoadTests()

        Write-Log "Executing the Validation Tests on the Validation Engine."
        $Result = $ValidationEngine.ExecuteTests($XmlReportPath)

        $health = 'Healthy'
        if (($Result.OverallResult -band [Microsoft.NetworkController.Validation.Common.NCValidationResultBitValues]::HadFailures) -ne 0)
        {
            $health = 'Failed'
        }
        elseif (($Result.OverallResult -band [Microsoft.NetworkController.Validation.Common.NCValidationResultBitValues]::HadWarnings) -ne 0)
        {
            $health = 'Warning'
        }

        $Report = $Result.OverallDescription

        [Microsoft.NetworkController.Validation.Common.XmlReportRenderer]::TransformStandardHtmlReport($XmlReportPath, $FullHtmlReportPath)
        Write-Log "Removing temporary file $XmlReportPath"
        #Remove-Item -Path $XmlReportPath

        Write-Log "Check full report ($FullHtmlReportPath)"

    }
    catch
    {
        $health = 'Failed'
        $Report = 'Validation Tests execution failed. Exception: ' + $_
        Write-Log "Failed while running validation tests"
    }
    finally
    {
        #Write-Log "Restoring saved TrustedHosts"
        #Set-TrustedHosts $savedTrustedHosts
    }
    $ExecutionResult = 'Overall Health: ' + $health + '. Report: ' + $Report

    return [PSCustomObject] @{
        Health = $health
        ExecutionResult = $ExecutionResult
        ReportPath = $FullHtmlReportPath
    }

}

Function Start-SdnLogCollection{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [String]$NcVMName,
        [Switch]$RunValidation,
        [String]$OutputPath,
        [String]$ValidationToolPath = "",
        [DateTime]$FromDate = (Get-Date).AddHours(-4),
        [DateTime]$ToDate,
        [ValidateSet("NC","MUX","GW","HyperV","All")]
        [String[]]$Role = "All",
        [String[]]$SdnHosts
    )

    if([String]::IsNullOrEmpty($NcVMName))
    {
        throw "Invalid or No NcVMName provided"
    }

    $OutputPath = Get-OutputPath -OutputPath $OutputPath
    Write-Log "TimeZone: $(Get-TimeZone)"

    $RequiredModuleInstalled = Get-RequiredModules

    if(!$RequiredModuleInstalled)
    {
        Throw "RSAT-NetworkController not installed. Please run 'Add-WindowsFeature RSAT-NetworkController -IncludeManagementTools'"
    }

    # Run the validation if specified
    if($RunValidation)
    {
        Write-Log "Running Validation"
        Write-Progress -Activity "SDN Log Collection" -Status "Running Validation"
        $validationResult = Start-SdnValidation -NcVMName $NcVMName -ValidationToolPath $ValidationToolPath
        Copy-Item $validationResult.ReportPath $OutputPath
    }

    Write-Progress -Activity "SDN Log Collection" -Status "Retrieving SDN Infrastructure Information from NC: $NcVMName"
    $SdnInfraInfo = Get-SdnInfraInfo -NcVMName $NcVMName
    Write-Log "NcUri: $($SdnInfraInfo.NcUri)"
    Write-Log "NC: $($SdnInfraInfo.NC)"
    Write-Log "MUX: $($SdnInfraInfo.MUX)"
    Write-Log "Gateway: $($SdnInfraInfo.Gateway)"


    $logCollectParams = @{
        InfraNodes = $SdnInfraInfo.NC
        Role = "NC"
        OutputPath = $OutputPath
        FromDate = $FromDate
    }

    if($null -ne $ToDate){
        $logCollectParams.ToDate = $ToDate
    }

    if($Role.Contains("All") -or $Role.Contains("NC")){
        Write-Progress -Activity "SDN Log Collection" -Status "Collecting logs for NC"
        Get-SdnInfraNodeLogs @logCollectParams
    }


    if($Role.Contains("All") -or $Role.Contains("MUX")){
        Write-Progress -Activity "SDN Log Collection" -Status "Collecting logs for MUX"
        $slbDiagResult = Get-SdnSlbDiagnosticState -NcUri $SdnInfraInfo.NcUri
        $fileName = "stateOp_" + [System.Math]::Truncate((Get-Date -UFormat %s)) + ".json"
        New-Item "$OutputPath\SlbDiag" -ItemType Directory | Out-Null
        $slbDiagResult | ConvertTo-Json -Depth 100 > "$OutputPath\SlbDiag\$fileName"
        $logCollectParams.InfraNodes = $SdnInfraInfo.MUX
        $logCollectParams.Role = "MUX"
        Get-SdnInfraNodeLogs @logCollectParams
    }

    if($Role.Contains("All") -or $Role.Contains("GW")){
        Write-Progress -Activity "SDN Log Collection" -Status "Collecting logs for Gateway"
        $logCollectParams.InfraNodes = $SdnInfraInfo.Gateway
        $logCollectParams.Role = "GW"
        Get-SdnInfraNodeLogs @logCollectParams
    }

    if($Role.Contains("HyperV") -or $Role.Contains("All"))
    {
        if($SdnHosts.Count -gt 0)
        {
            # Collect SDN Hosts logs for hosts specified in SdnHosts array
            Write-Progress -Activity "SDN Log Collection" -Status "Collecting logs for SDN Hosts"
            $logCollectParams.InfraNodes = $SdnHosts
            $logCollectParams.Role = "HyperV"
            Get-SdnInfraNodeLogs @logCollectParams
        }elseif($SdnInfraInfo.Host.Count -le 16)
        {
            # If the number of hosts no more than 16, SdnHosts array can be no to collect logs for all nodes.
            Write-Progress -Activity "SDN Log Collection" -Status "Collecting logs for SDN Hosts"
            $logCollectParams.InfraNodes = $SdnInfraInfo.Host
            $logCollectParams.Role = "HyperV"
            Get-SdnInfraNodeLogs @logCollectParams
        }else
        {
            Write-Host "There are more than 16 hosts in SDN Cluster, please use -SdnHosts to specify the hosts array"
        }
    }

    Write-Log "Collecting NCClusterInfo.."
    Write-Progress -Activity "SDN Log Collection" -Status "Collecting NC IMOS Dump"
    Get-SdnNcImosDump -NcVMs $SdnInfraInfo.NC -NcUri $SdnInfraInfo.NcUri -OutputPath $OutputPath
    Write-Progress -Activity "SDN Log Collection" -Status "Collecting SDN Resources"
    Get-SdnResources -NcUri $SdnInfraInfo.NcUri -OutputPath $OutputPath
    Write-Progress -Activity "SDN Log Collection" -Status "Collecting NC Cluster Info"
    Get-SdnNcClusterInfo -NCVMName $NcVMName -OutputPath $OutputPath
}
