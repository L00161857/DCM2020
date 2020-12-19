<#
.Synopsis
Networking Assignment (PowerShell) : Scripting the Deployment Pipeline 

.DESCRIPTION

  This script will run several network tests commands and display an exception if the server is not configured to receive Inbound calls or added as a TrustedHost. 
      The following needs to be configured on each server
         1. Run Enable-PSRemoting
         2. Windows Remote Management (HTTP-In) needs to be enables. use New-NetFirewallRule to set the firewall rules.
         3. Configure WinRM and allow your client PC as a TrustedHost
         4. Run Test-WsMan ComputerName to test if WinRM is correctly setup

  NOTE: Please update the IPAddresses.txt file with your own IP addresses or Computer Names, and also ensure that you have the Settings.ini file.

.CONCLUSION
   The goal of the script was to execute a list of commands from a central Windows server connecting 
   to multiple remote servers on the same network. The list of commands is testing networks connections, 
   get the current user logged onto the server, check if any security warnings and errors on the server’s 
   event logs, display the server’s detailed network information and check if any given ports are open or 
   closed on the server. 

   The strategy selected was to connect to multiple Windows operating machines only connected on the same 
   domain sharing the same gateway. It is important to note that this script will not work if all windows 
   machines are not on the same trusted network domain. 

   The user requires administrator rights on the domain to be able to connect to all windows servers. 
   It is recommended to run the Enable-PSRemoting command and to enable the Window Remote Manager services 
   on all windows servers to establish connectivity between these servers. The Settings.ini file contains 
   the location of the IPAddresses.txt file which has a list of either computer names or IP addresses. 
   It also includes the path where the script will write logs and messages to an output.log file. The settings 
   file also contains a list of ports to validate for all servers. This script ran successfully on a newly 
   created domain environment configured using VMWare, using a Windows 2019 server running Active Directory 
   connecting to a Window 10 personal computer. 
   
   The main function, called Test-Network, accepts the list of servers from the IPAddresses.txt file and calls 
   other functions to execute each task individually. This method ensures each function executes independently 
   and consist of its internal exception handling. The script will continue to run, even If one remote server 
   incorrectly configured or an exception thrown for one or more commands executed. 
        

.EXAMPLE
   Another example of how to use this cmdlet when using multiple servers
   . .\networkingPS_Brkn.ps1

.NOTES
   Filename: networkingPS_Brkn.ps1
   Setting File: Settings.ini 
#>


Get-Content ".\Settings.ini" | foreach-object -begin {$Settings=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True)) { $Settings.Add($k[0], $k[1]) } }
$ComputerNames = Get-Content $Settings.Get_Item("IPAddressesFile")
#Calling the Main function to carry out network tests
Test-Network $ComputerNames

#Region Test-Network
<# 
.Synopsis
   Main Function doing network tests. 

.DESCRIPTION
   This function will call all the other functions to carry out network tests.

.PARAMETERS
   $ServerNames: Pass a list of server names as String Array
#>
function Test-Network
{
    Param(
     [Parameter()]
        [string[]]
        $ServerNames
        )
        

    Begin
    {
    $ComputerNames = $ServerNames
    # Creating objects to be used
    $ServerArray = @()
    $ErrorOutputArray = @()
    $NetworkInformationArray = @()
    $CheckOpenPortsArray = @()

    # Ports to check
    $PortList = $Settings.PortsToValidate.Split(",") # Split the sitring into a an array

    # Start to write to the Log File. All output will be written in the Log File
    Start-Transcript -Path $Settings.Get_Item("LogFile")
    }Process
    {# BSC DCM 2020, I need to send the list of $ComputerNames to the next part of the process (Foreach). 
    #Which command should I use?
    Write-Output $ComputerNames  
    # Write-Host $ComputerNames
    # Uncomment the correct one of the above choices!


    # Start Process
    Foreach ($ComputerName in $ComputerNames)
    {
        # Test the connection to the ComputerName or Ip Address Given
        if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)
        { 
                # Get User Logged onto the server
                $ServerArray += Get-UserDetail $ComputerName

                # Check if any security errors or warning was log to the eventlog
                $ErrorOutputArray += Get-WarningsErrors $ComputerName

                # Get Network Information
                $NetworkInformationArray += Get-NetworkInfo $ComputerName

                # Check for open ports as per list given
                $CheckOpenPortsArray += Get-OpenPorts $ComputerName $PortList
      
        } else {
        $Server = [ordered]@{
        ComputerName=$ComputerName
        UserName="Remote Server Not Available"   }
            $ServerArray += New-Object -TypeName PSObject -Property $Server
        }
    } # bottom of foreach loop
    }
    End
    {
    

    # Printing all the objects
    "*" * 50
    Write-Output "*   Servers Information"
    "*" * 50
    $ServerArray | Format-Table -AutoSize

    "*" * 50
    Write-Output "*   EventLog - Errors and Warnings"
    "*" * 50
    $ErrorOutputArray | Format-Table -AutoSize
    "*" * 50
    Write-Output "*   Network Information"
    "*" * 50
    $NetworkInformationArray | Format-Table -AutoSize
    "*" * 50
    Write-Output "*   Open Ports"
    "*" * 50
    $CheckOpenPortsArray | Format-Table -AutoSize

    Stop-Transcript
    }
}
#endregion

#Region Get-UserDetail
<#
.Synopsis
   Get User Detail
.DESCRIPTION
   This function will get the current user logged onto the server.

.PARAMETERS
    $ComputerName: A Valid Computer Name or IP Address
#>
function Get-UserDetail
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([array])]
    Param(
        [Parameter()]
        [string]
        $ComputerName
        )
    $ServerArray = @()
    try
    {
        # Get the UserName logged onto the server
        $UserName = (Get-WmiObject -Class win32_computersystem -ComputerName $ComputerName).UserName

        # Add the server found to the server Array
        $Server = [ordered]@{
            ComputerName=$ComputerName
            UserName=$UserName
        }
        $ServerArray = New-Object -TypeName PSObject -Property $Server
    }
    catch 
    { 
        $Server = [ordered]@{
            ComputerName=$ComputerName
            UserName="(Get-UserDetail) Server Error: " + $_.Exception.Message + " : "  + $_.FullyQualifiedErrorId
        }
        $ServerArray = New-Object -TypeName PSObject -Property $Server
    }
    return $ServerArray   
    
}
#endRegion

#Region Get-WarningsErrors
<#
.Synopsis
   Check for warnings or errors 
.DESCRIPTION
   This function will check if any warnings or errors is on the server EventLog

.PARAMETERS
    $ComputerName: A Valid Computer Name or IP Address
#>
function Get-WarningsErrors
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([array])]
    Param(
        [Parameter()]
        [string]
        $ComputerName
        )

    # Date before and after to check 24 hours worth of data
    $DateBefore = (Get-Date)
    $DateAfter = (Get-Date).AddDays(-1)

    $ErrorOutputArray = @()
    try
    {
        # Check if any security errors or warning was log to the eventlog
        $EventLogTest = Get-EventLog -ComputerName $ComputerName -LogName Security -Before $DateBefore -After $DateAfter | Where-Object {$_.EntryType -like 'Error' -or $_.EntryType -like 'Warning'}

        #$EventLogTest = Get-EventLog -LogName System -Newest 5   @TEST
        If ($null -ne $EventLogTest)
        {
            # If Warnings or Errors found, then write it out to the log file
            Foreach ($EventLog in $EventLogTest)
            {
                $ErrorOutput = [ordered]@{
                    ComputerName=$ComputerName
                    EntryType = $EventLog.EntryType
                    Index = $EventLog.Index 
                    Source = $EventLog.Source
                    InstanceID = $EventLog.InstanceID
                    Message = $EventLog.Message }
                    $ErrorOutputArray = New-Object -TypeName PSObject -Property $ErrorOutput
            }
        }else
        {
            # If no errors where found
                $ErrorOutput = [ordered]@{
                ComputerName=$ComputerName
                EntryType = ""
                Index = "" 
                Source = ""
                InstanceID = ""
                Message = "No Warning or Errors found on this server" }
                $ErrorOutputArray = New-Object -TypeName PSObject -Property $ErrorOutput
        }
    }
    catch 
    { 
        $ErrorOutput = [ordered]@{
                ComputerName=$ComputerName
                EntryType = "" ;  Index = "" ; Source = ""
                InstanceID = ""
                Message = "(Get-WarningsErrors) Server Error: " + $_.Exception.Message + " : "  + $_.FullyQualifiedErrorId }
                $ErrorOutputArray = New-Object -TypeName PSObject -Property $ErrorOutput

    }
    return $ErrorOutputArray   
    
}
#endregion

#Region Get-NetworkInfo
<#
.Synopsis
   Get Network Info
.DESCRIPTION
   This function will get detailed network information

.PARAMETERS
    $ComputerName: A Valid Computer Name or IP Address
#>
function Get-NetworkInfo
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([array])]
    Param(
        #BSC DCM students 2020 - fix this
        #a parameter should be added here for the string variable named ComputerName
        [Parameter()]
        [string]
        $ComputerName
        )

    $NetworkInformationArray = @()

    try
    {
        $NetworkInfo = Test-NetConnection -InformationLevel Detailed -ComputerName $ComputerName 
                $NetworkInfoOutput = [ordered]@{
                    ComputerName=$NetworkInfo.ComputerName
                    RemoteAddress=$NetworkInfo.RemoteAddress
                    NameResolutionResults=$NetworkInfo.NameResolutionResults
                    InterfaceAlias=$NetworkInfo.InterfaceAlias
                    SourceAddress=$NetworkInfo.SourceAddress
                    NetRoute=$NetworkInfo.NetRoute
                    PingSucceeded=$NetworkInfo.PingSucceeded
                    PingReplyDetails=$NetworkInfo.PingReplyDetails }
                    $NetworkInformationArray = New-Object -TypeName PSObject -Property $NetworkInfoOutput
    }
    catch 
    { 
        $NetworkInfo = Test-NetConnection -InformationLevel Detailed -ComputerName $ComputerName 
                $NetworkInfoOutput = [ordered]@{
                    ComputerName=$NetworkInfo.ComputerName
                    RemoteAddress="(Get-NetworkInfo) Server Error: " + $_.Exception.Message + " : "  + $_.FullyQualifiedErrorId
                    NameResolutionResults=""
                    InterfaceAlias=""
                    SourceAddress=""
                    NetRoute=""
                    PingSucceeded=""
                    PingReplyDetails="" }
                    $NetworkInformationArray = New-Object -TypeName PSObject -Property $NetworkInfoOutput
    }

    return $NetworkInformationArray   
}
#endregion

#Region Get-OpenPorts
<#
.Synopsis
   
.DESCRIPTION
   
.PARAMETERS
    $ComputerName: A Valid Computer Name or IP Address
    $PortList: list of available ports   
#>
# BSc DCM - fix this
# fill in appropriate comments for the method as per the section above. this comment refers to the 
# Get-OpenPorts function shown below.
function Get-OpenPorts
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([array])]
    Param(
        [Parameter()]
        [string]
        $ComputerName,
        [Parameter()]
        [string[]]
        $PortList
        )
    $CheckOpenPortsArray = @()
    try
    {
        # BSc DCM 2020 - fix this
        # We need an iterator here to go through all $Ports in $PortList
        # Write in the single line of code to iterate through the port list
        foreach ($Ports in $PortList)
        {
            
            #BSc DCM 2020 - Fix this
            $PortConnected = Test-NetConnection -ComputerName $ComputerName -Port $port -ErrorAction SilentlyContinue
            # finish the above line of code using the Test-NetConnection command and then uncomment.
            #check by port $port, and the computer name $ComputerName.
            # add an action of SilentlyContinue if a warning occurs
            # this is one line of code only!
            $Ports = [ordered]@{
                ComputerName=$ComputerName
                Port=$port
                Open=$PortConnected.TcpTestSucceeded
            }
            $CheckOpenPortsArray += New-Object -TypeName PSObject -Property $Ports
        }
    }
    catch 
    { 
        $Ports = [ordered]@{
                ComputerName=$ComputerName
                Port=$port
                Open="(Get-OpenPorts) Server Error: " + $_.Exception.Message + " : "  + $_.FullyQualifiedErrorId
            }
            $CheckOpenPortsArray = New-Object -TypeName PSObject -Property $Ports
    }
    return $CheckOpenPortsArray   
}
#endregion

