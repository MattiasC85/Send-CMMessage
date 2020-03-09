#	Version 0.4
#
#   	0.4:
#   	Added message severity.(With a custom MessageId)
#	Compatible with the 5.1902.1006.1000 SDK
#
#	0.2:
#	Fixed multiple computer resources beeing created.

Param (
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $MP,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $SiteCode,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $InsertionString1,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $InsertionString2,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $InsertionString3,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $InsertionString4,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $InsertionString5,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $InsertionString6,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $InsertionString7,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $InsertionString8,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $InsertionString9,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $InsertionString10,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $SMS_ModuleName,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $SMS_MessageID,                                         #'1073781821' is the only messageID I've found this far that prints the InsertionStrings to the description. Must use Module=SMS Provider for this to work.
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]    #The insertionString can however still be used as arguments to a script by using %msgin01-10 in a status  filter rule.
   [string] $MachineName,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $SMS_Component,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]
   [string] $ClassName = "SMS_GenericStatusMessage_Info",                #You can add more classes by using [Microsoft.ConfigurationManagement.Messaging.StatusMessages.StatusMessageGenerator]::new() _
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$False)]    #and saving default props/quals to files named "class"props.txt and "class"quals.txt by using $_.GatherStatusMessageProperties("ClassName") Eg.:  $_.GatherStatusMessageProperties("SMS_GenericStatusMessage_info") 
   [ValidateSet("Info","Warning","Error")]
   [string] $MessageSeverity = "Info"
)


Switch($MessageSeverity)
{
"Info"      {$MsgSeverityInt=1073741824}
"Warning"   {$MsgSeverityInt=2147483648}
"Error"     {$MsgSeverityInt=3221225472}
}

$ScriptDir=Split-path $Script:myInvocation.MyCommand.Definition
write-host ""

$Dlls=@("$ScriptDir\Microsoft.ConfigurationManagement.Messaging.dll","$ScriptDir\Microsoft.ConfigurationManagement.Security.Cryptography.dll")
$DllsExists=$true

Foreach ($Dll in $Dlls)
{
    if ((Test-Path $Dll) -eq $false)
    {
        Write-host "Missing $Dll" -ForegroundColor Red
        $DllsExists=$False
    }
}

if ($DllsExists -eq $False)
{
    write-host ""
    Write-host "Download the CCM Messaging Dlls here: https://www.nuget.org/packages/Microsoft.ConfigurationManagement.Messaging" -ForegroundColor Yellow
    write-host "The script has been verified to work with 5.1902.1006.1000" -ForegroundColor Yellow
    break
}

#$DllInt=0
#Test-Path $Dlls | % {write-host "$($Dlls[$Dllint]) exists: $_";$Dllint++}

Add-type -path $ScriptDir\Microsoft.ConfigurationManagement.Messaging.dll
Add-type -path $ScriptDir\Microsoft.ConfigurationManagement.Security.Cryptography.dll

Start-Transcript -Path $env:TEMP\StatusMsg.log -Append
#Add-type -path $ScriptDir"\Microsoft.ConfigurationManagement.Messaging.dll"

$WinPE=$False
$RunningInTS=$True
$WinPE=test-path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinPE"
$NeedForReg=$False

try
{
	$TsEnv=New-Object -ComObject Microsoft.SMS.TSEnvironment
}
catch
{
	$RunningInTS=$False
}



function CreateFakeCert
{
    write-host "Importing fake certificate..."
#    $SignCert = [Microsoft.ConfigurationManagement.Messaging.Framework.MessageCertificateX509File]::CreateAndStoreSelfSignedCertificate(
#    "SCCM Fake Signing Certificate",
#    "Fake SignCert",
#    "My",
#    "LocalMachine",
#    @('2.5.29.37'),
#    (Get-Date).AddMinutes(-10),
#    (Get-Date).AddYears(5)
#    )

$SignCert= [Microsoft.ConfigurationManagement.Messaging.Framework.MessageCertificateX509Volatile]::new($ScriptDir+'\FakeCert.pfx', 'Pa$$w0rd')

$SMSID=[Microsoft.ConfigurationManagement.Messaging.Framework.SmsClientId]::new()
write-host "Certificate: " $SignCert.X509Certificate.FriendlyName
return $SignCert
}

############# MAIN ##############
#@('2.5.29.37'),



$Failed=$False

If ($RunningInTS -eq $True)
{
Write-host "Script is running inside a TS."
$Name=$TsEnv["_SMSTSMachineName"]
$MPHost=($TSEnv["_SMSTSMP"]).Replace("http://","").Replace("https://","")
}
else
{
Write-host "Script is NOT running inside a TS."
$Name=$Env:ComputerName
}

If ($WinPE -eq $false)
{
	Write-host "Not running in WinPE."
	try
	{
		
		$SignCert = (@(Get-ChildItem -Path "Cert:\LocalMachine\SMS" | Where-Object { $_.FriendlyName -eq "SMS Signing Certificate" }) | Sort-Object -Property NotBefore -Descending)[0]
		$SignCert= [Microsoft.ConfigurationManagement.Messaging.Framework.MessageCertificateX509File]::new('SMS', $SignCert.Thumbprint)
		$SMSID=get-wmiobject -ComputerName '.' -Namespace root\ccm -Query "Select ClientID from CCM_Client" |% ClientID
		$MPHost=(get-wmiobject -Class SMS_Authority -Namespace "root\ccm").CurrentManagementPoint
        
	}
	catch
	{
		$Failed=$True
		Write-Host "Failed finding SMS certificates."
		Write-Host "Probably not a ConfigMgr-Client."
        $NeedForReg=$True
		$SignCert=CreateFakeCert
	}
}
else
{
Write-host "Running in WinPE."
$NeedForReg=$True
$SignCert=CreateFakeCert
#$SMSID="GUID:D692E1BF-5975-4A42-AAB8-D2A62AA87CD8"
#$SignCert= [Microsoft.ConfigurationManagement.Messaging.Framework.MessageCertificateX509Volatile]::new($ScriptDir+'\FakeCert.pfx', 'Pa$$w0rd')
}

If($PSBoundParameters.ContainsKey('MP'))
{
$MPHost=$MP
}

if ($MPHost -eq $null)
{
write-host "MPHost is null. Try adding it manually by using the argument -MP."
Stop-Transcript
break
}
If($PSBoundParameters.ContainsKey('MachineName'))
{
$Name=$MachineName
}
Write-host "MPHost: " $MPHost
Write-host "Certificate Friendly Name: " $SignCert.X509Certificate.FriendlyName
write-host "ClientName: " $Name
write-host "SMSID: " $SMSID
write-host "Need to register to MP: " $NeedForReg
#Read-host
#$MPHost=($TSEnv["_SMSTSMP"]).Replace("http://","").Replace("https://","")

$Sender = New-Object -TypeName Microsoft.ConfigurationManagement.Messaging.Sender.Http.HttpSender
if ($NeedForReg -eq $True)
{
$AgentIdentity = "MyLittleAgent"
$Request= [Microsoft.ConfigurationManagement.Messaging.Messages.ConfigMgrRegistrationRequest]::new()   
$Request.AddCertificateToMessage($SignCert, [Microsoft.ConfigurationManagement.Messaging.Framework.CertificatePurposes]::Signing)
$Request.Settings.HostName = $MPHost
[void]$Request.Discover() 
$Request.AgentIdentity = $AgentIdentity
$Request.NetBiosName = $Name

$Request.Settings.Compression = [Microsoft.ConfigurationManagement.Messaging.Framework.MessageCompression]::Zlib
$Request.Settings.ReplyCompression = [Microsoft.ConfigurationManagement.Messaging.Framework.MessageCompression]::Zlib
$SMSID=$Request.RegisterClient($Sender, [TimeSpan]::FromMinutes(5))
}
write-host "SMSID is Now: " $SMSID
$Message =[Microsoft.ConfigurationManagement.Messaging.Messages.ConfigMgrStatusMessage]::new()
$Message.Settings.HostName=$MPHost
$Message.Discover()
$Message.Initialize()
$Message.StatusMessage.StatusMessageType= $ClassName
								  
$Message.SmsId=$SMSID
write-host ""
Write-host "Properties:"
write-host ""
Get-Content $ScriptDir\$ClassName'Prop.txt' | Foreach-Object{
   
   $var = $_.Split('=')
   if ($var[0].StartsWith("'") -eq $False)
   {
   #New-Variable -Name $var[0] -Value $var[1]
   If($PSBoundParameters.ContainsKey($var[0]))
   {
   #Write-host $PSBoundParameters[$var[0]]
   $var[1]=$PSBoundParameters[$var[0]]
   }
   $Prop=[Microsoft.ConfigurationManagement.Messaging.Messages.StatusMessageProperty]::new(($var[0]),($var[1]))
   $Message.StatusMessage.Properties.Properties.Add($Prop)
   }

}
$Prop=[Microsoft.ConfigurationManagement.Messaging.Messages.StatusMessageProperty]::new("MachineName",$Name)
write-host $Prop.Name=($Prop.valueString)
$Message.StatusMessage.Properties.Properties.Add($Prop)

<#
$Prop2=[Microsoft.ConfigurationManagement.Messaging.Messages.StatusMessageProperty]::new("Severity",1)
write-host $Prop.Name=($Prop.valueString)
$Message.StatusMessage.Properties.Properties.Add($Prop2)
#>

#$Mins=Get-TimeZone | % {$_.BaseUtcOffset.TotalMinutes}

#if ([int]$Mins -lt 100)
#{
#$Mins=("0"+$Mins.ToString())
#}
#$dateStr=Get-date -Format "yyyyMMddhhmmss.000000+$Mins"
#$dateStr=Get-date -Format "yyyyMMddhhmmss.000000+000"

#$Prop=[Microsoft.ConfigurationManagement.Messaging.Messages.StatusMessageProperty]::new("DateTime",$dateStr)
#$Message.StatusMessage.Properties.Properties.Add($Prop)
#write-host $Prop.Name=($Prop.valueString)
$Message.AddCertificateToMessage($SignCert, [Microsoft.ConfigurationManagement.Messaging.Framework.CertificatePurposes]::Signing)

write-host ""
Write-host "Qualifiers:"
write-host ""
Get-Content $ScriptDir\$ClassName'Quals.txt' | Foreach-Object{
   
   $var = $_.Split('=')
   if ($var[0].StartsWith("'") -eq $False)
   {
    If($PSBoundParameters.ContainsKey($var[0]))
    {
   #Write-host $PSBoundParameters[$var[0]]
    $var[1]=$PSBoundParameters[$var[0]]
    }
   #New-Variable -Name $var[0] -Value $var[1]
   
   
   if ($var[0] -eq "SMS_MessageID")
   {
        If ($var[1].Length -le 5)     #If longer it has already been altered to include severity.
        {
            write-host ""
            if ($var[1] -in ($null,0))
            {
                
                Switch($MessageSeverity)
                {
                    "Info"      {$var[1]=39997}
                    "Warning"   {$var[1]=39998}
                    "Error"     {$var[1]=39999}
                }
                
                write-host "MessageID was null/0 and is now changed to $($var[1])"
            } 
            $var[1]=([int]$var[1]+$MsgSeverityInt)
            #write-host "Altering $var[0] value to $var[1]"
            #write-host ""
        }
   }
   

   $Qual=[Microsoft.ConfigurationManagement.Messaging.Messages.StatusMessageQualifier]::new(($var[0]),($var[1]))
   $Message.StatusMessage.Qualifiers.Qualifiers.Add($Qual)
   write-host ($var[0] + "=" + $var[1])
   }

}
$Message.Settings.MessageSourceType=[Microsoft.ConfigurationManagement.Messaging.Framework.MessageSourceType]::Client
$Message.Validate([Microsoft.ConfigurationManagement.Messaging.Framework.IMessageSender]$Sender)
$Message.SendMessage($Sender)
Stop-Transcript
