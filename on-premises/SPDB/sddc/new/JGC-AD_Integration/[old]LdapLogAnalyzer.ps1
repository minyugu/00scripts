<#
#### requires ps-version 3.0 ####
<#
.SYNOPSIS
Analyses Eventlog from DomainControllers and searches for LDAP access 
.DESCRIPTION
Creates a working directory on your specified path. After creation it copies evtx files from all Domaincontrollers via robocopy into this working directory.
Every domaincontroller eventlog creates four files (cleared and raw) 
.PARAMETER WorkDir 
Path where you want to have your logs and results (please check diskspace, evtx file may have some GBs)
.INPUTS
-
.OUTPUTS
YYYY-MM-DD-HH-MM-SS-NameofDC.evtx (copied but untouched)
YYYY-MM-DD-HH-MM-SS-NameofDC-LDAP-cleared.csv
YYYY-MM-DD-HH-MM-SS-NameofDC-LDAP-raw.csv
YYYY-MM-DD-HH-MM-SS-NameofDC-LDAP-time.csv
YYYY-MM-DD-HH-MM-SS-NameofDC-LDAP-time-cleared.csv
.NOTES
   Version:        0.1
   Author:         Alexander Koehler
   Creation Date:  Tuesday, March 10th 2020, 11:07:01 pm
   File: ad-ldap-audit-0-1.ps1
   Copyright (c) 2020 blog.it-koehler.com
HISTORY:
Date                    By    Comments
----------              ---    ----------------------------------------------------------
.LINK
 blog.it-koehler.com/en/Archive/2951
.COMPONENT
 Required Modules: none

.LICENSE
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the Software), to deal
in the Software without restriction, including without limitation the rights
to use copy, modify, merge, publish, distribute sublicense and /or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 
.EXAMPLE
C:\temp\ad-ldap-audit-0-1.ps1 -WorkDir "C:\temp\ldapaudit"
#
#>

# define parameters (Working Directory) and check if it's a directory and if it does not exist, create it.
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $True)]
    [String] $WorkDir)
if (-not (Test-Path $WorkDir -PathType Container)) {
    
    try {
        New-Item -Path $WorkDir -ItemType Directory -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error -Message "Unable to create directory '$WorkDir'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$WorkDir'."
}
else {
    "Directory already existes"
}
#get date as string (is needed for filenames)
$date=((Get-Date).ToString('yyyy-MM-dd-HH-mm-ss'))
#getting all DCs in environment without AD PowerSehll Module 
$DCs = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | % { $_.Servers } | select Name).Name
#executing code for every domaincontroller
foreach($DC in $DCs){
#copy evtx file in working dir with robocopy
$path = "\\$DC\c$\Windows\System32\winevt\Logs\"
robocopy "$path" "$workdir" "Directory Service.evtx" 
Rename-Item "$workdir\Directory Service.evtx" "$date-$DC.evtx"
$evtxfile = "$workdir\$date-$DC.evtx"
#define output file prefix
$csvoutputpath = "$workdir\$date-$DC-LDAP"
#searching for event 2889
$Events = Get-WinEvent @{Path=$evtxfile;Id=2889}
#define array for outputs
$eventarraytime = @()
$eventarrayraw =@()
  ForEach ($Event in $Events) {           
    # Convert the event to XML           
    #see https://docs.microsoft.com/de-de/archive/blogs/ashleymcglone/powershell-get-winevent-xml-madness-getting-details-from-event-logs
    $eventXML = [xml]$Event.ToXml()
    #getting timestamp
    $time = ($Event.TimeCreated)
    #getting user from eventlog
    $ldapconn = ($eventXML.Event.EventData.Data)
    #creating custom object and put all together
    #customobject with timestamp
    $eventobj = New-Object System.Object
    $eventobj | Add-Member -type NoteProperty -name AccessTime -Value $time
    $eventobj | Add-Member -type NoteProperty -name LDAPAccess -Value (@($ldapconn) -join " ")
    #custom object witout timestamp
    $eventraw = New-Object System.Object
    $eventraw | Add-Member -type NoteProperty -name LDAPAccess -Value (@($ldapconn) -join " ")
    #appending content to array
    $eventarraytime += $eventobj
    $eventarrayraw += $eventraw
        }    
    #output data  in rawformat to csv
    $eventarraytime  | Export-Csv -Path "$csvoutputpath-time.csv" -Encoding UTF8 -Delimiter ";" -NoTypeInformation
    $eventarrayraw  | Export-Csv -Path "$csvoutputpath-raw.csv" -Encoding UTF8 -Delimiter ";" -NoTypeInformation
    #cleaning up double entries
    $eventstimecleared =  $eventarraytime | Sort-Object -Unique LDAPAccess -Descending
    $eventstimecleared | Export-Csv -Path "$csvoutputpath-time-cleared.csv" -Encoding UTF8 -Delimiter ";" -NoTypeInformation
    $eventarraycleared =  $eventarrayraw | Sort-Object -Unique LDAPAccess -Descending
    $eventarraycleared  | Export-Csv -Path "$csvoutputpath-cleared.csv" -Encoding UTF8 -Delimiter ";" -NoTypeInformation
 }