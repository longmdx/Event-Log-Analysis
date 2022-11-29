$LogPath = $args[0]
if ($args.Count -ne 1) {
	$LogPath = "C:\Windows\System32\winevt\logs"
}

$OutputFile = "C:\ProgramData\DFIR_VCS\Logon.csv"
#Remove-Item $OutputFile -ErrorAction SilentlyContinue

Write-Warning "Reading Event Logs ..."
Write-Host


$EventsParse = @(5156, 4624, 4625, 1149, 21, 25, 4648)

$EDI_PassTheHash = @(4624, 4625)

$EDI_RDP = @(5156, 4624, 4625, 1149, 21, 25)

$CredentialAccess = @(4648)

function Test-PrivateIP {

	param(
		[string]
		$IP
	)
	process {

		if ($IP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^169\.254\.)|(LOCAL)|(local)|(::1)') {

			Return $true
		}
		else {

			Return $false
		}

	}
}


# https://cybersafe.co.il/wp-content/uploads/2021/11/LOGON-types-compressed_compressed.pdf
# detect RDP (Network connection -> Authentication -> Logon -> Session Connect/Disconnect -> Logoff)
function Get-PassTheHashDetect {

	param(

		[Parameter(Position = 1, Mandatory = $true)]
		[string] 
		$EventID,
		[Parameter(Position = 2, Mandatory = $true)]
		$Data
	)
	process {

		$DetectionRule = $Description = $null
		if ( $EventID -in @(4624, 4625) ) {

			$LogonType = ($Data | Where Name -eq LogonType).InnerText
			$TargetUserName = ($Data | Where Name -eq TargetUserName).InnerText
			$TargetDomainName = ($Data | Where Name -eq TargetDomainName).InnerText
			$WorkstationName  = ($Data | Where Name -eq WorkstationName).InnerText
			$LogonProcessName = ($Data | Where Name -eq LogonProcessName).InnerText
			$IpAddress = ($Data | Where Name -eq IpAddress).InnerText
			$AuthenticationPackageName = ($Data | Where Name -eq AuthenticationPackageName).InnerText
			$KeyLength = ($Data | Where Name -eq KeyLength).InnerText

			if ( $LogonType -eq 3 ) {
				
				if (!$TargetUserName.Contains("ANONYMOUS LOGON") -And !$TargetUserName.Contains("$") -And $LogonProcessName.Contains("NtLmSsp") -And $KeyLength.Equals("0")) {

					$DetectionRule = "Pass the hash attempt Detected"
					$Description = $TargetDomainName + "\" + $TargetUserName + " from IP " + $IpAddress + " (" + $WorkstationName + ")"
				}			    
			}
			elseif ( $LogonType -eq 9 ) {

				if ( $LogonProcessName.Contains("Seclogo") -And $AuthenticationPackageName.Contains("Negotiate") ) {

					$DetectionRule = "Pass the hash attempt Detected"
					$Description = $TargetDomainName + "\" + $TargetUserName + " from IP " + $IpAddress + " (" + $WorkstationName + ")"
				}
			}
			
		}

		Return $DetectionRule, $Description
	}

}

function Get-CredentialDetection {

	param(

		[Parameter(Position = 1, Mandatory = $true)]
		[string] 
		$EventID,
		[Parameter(Position = 2, Mandatory = $true)]
		$Data
	)
	process {

		$DetectionRule = $Description = $null
		
		$TargetUserName = ($Data | Where Name -eq TargetUserName).InnerText
		$TargetDomainName = ($Data | Where Name -eq TargetDomainName).InnerText
		$TargetServerName = ($Data | Where Name -eq TargetServerName).InnerText
		$TargetInfo = ($Data | Where Name -eq TargetInfo).InnerText
		$ProcessName = ($Data | Where Name -eq ProcessName).InnerText
		
		if( $TargetInfo.Contains("RPCSS/") ) {

			$DetectionRule = "Lateral Movement - RPC over TCP/IP"
			$Description = $TargetDomainName + "\" + $TargetUserName + " was attempted using explicit credentials to " + $TargetServerName
		}
		elseif ( $ProcessName.Contains("sc.exe") ) {

			$DetectionRule = "Remote Service Interaction"
			$Description = "Using sc.exe with explicit creds " + "(" + $TargetDomainName + "\" + $TargetUserName + ") to " + $TargetServerName
		}

		Return $DetectionRule, $Description

	}

}


function Get-WebshellDetection {

	param(

		[Parameter(Position = 1, Mandatory = $true)]
		[string] 
		$EventID,
		[Parameter(Position = 2, Mandatory = $true)]
		$Data
	)
	process {

		$DetectionRule = $Description = $null
		
		$TargetUserName = ($Data | Where Name -eq TargetUserName).InnerText
		$TargetDomainName = ($Data | Where Name -eq TargetDomainName).InnerText
		$TargetServerName = ($Data | Where Name -eq TargetServerName).InnerText
		$TargetInfo = ($Data | Where Name -eq TargetInfo).InnerText
		$ProcessName = ($Data | Where Name -eq ProcessName).InnerText
		
		if( $ProcessName.Contains("w3wp.exe") ) {

			$DetectionRule = "Webshell CreateProcessAsUserA"
			$Description = $TargetDomainName + "\" + $TargetUserName + " logon via " + $ProcessName
		}

		Return $DetectionRule, $Description

	}

}


#https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
# https://www.13cubed.com/downloads/rdp_flowchart.pdf
function Get-RDPDetect {

	
	param(

		[Parameter(Position = 1, Mandatory = $true)]
		[string] 
		$EventID,
		[Parameter(Position = 2, Mandatory = $true)]
		$Data
	)
	process {

		$DetectionRule = $Description = $null
		
		#Network connection
		if( $EventID -eq 1149 ) {

			$TargetUserName = $Data.Param1
			$TargetDomainName = $Data.Param2
			$IpAddress = $Data.Param3

			if ( $IpAddress -match "127.*" -Or $IpAddress.Contains("::1") ) {
				
				$DetectionRule = "User connected RDP from Local host - Possible Socks Proxy being used"
				$Description = $TargetDomainName + "\" + $TargetUserName + " connecting from Local Host which means attacker is using tunnel to connect RDP " + $IpAddress
			}
			elseif ( Test-PrivateIP($IpAddress) ) {

				$DetectionRule = "User connected RDP from Private IP"
				$Description = $TargetDomainName + "\" + $TargetUserName + " connecting from IP " + $IpAddress
			}
			elseif ( Test-PrivateIP($IpAddress) -ne $true -And Test-IPaddress($IpAddress) ) {


				$DetectionRule = "User connected RDP from Public IP"
				$Description = $TargetDomainName + "\" + $TargetUserName + " connecting from IP " + $IpAddress
			}
		}

		# Authentication
		elseif ( $EventID -eq 4624 ) {

			$LogonType = ($Data | Where Name -eq LogonType).InnerText 
			$TargetUserName = ($Data | Where Name -eq TargetUserName).InnerText
			$TargetDomainName = ($Data | Where Name -eq TargetDomainName).InnerText
			$WorkstationName  = ($Data | Where Name -eq WorkstationName).InnerText
			$LogonProcessName = ($Data | Where Name -eq LogonProcessName).InnerText
			$IpAddress = ($Data | Where Name -eq IpAddress).InnerText
			$AuthenticationPackageName = ($Data | Where Name -eq AuthenticationPackageName).InnerText
			$ProcessName = ($Data | Where Name -eq ProcessName).InnerText

			$check = Test-PrivateIP($IpAddress)

			if( $LogonType -eq 10 ) {

				if( $IpAddress -match "^127.*" -Or $IpAddress.Contains("::1") ) { 

					$DetectionRule = "User connected RDP from Local host - Possible Socks Proxy being used"
					$Description = $TargetDomainName + "\" + $TargetUserName + " connecting from Local Host which means attacker is using tunnel to connect RDP " + $IpAddress + " (" + $WorkstationName + ")"
				}
				elseif( $check -eq $true ) {

					$DetectionRule = "User connected RDP from Private IP"
					$Description = $TargetDomainName + "\" + $TargetUserName + " connecting from IP " + $IpAddress + " (" + $WorkstationName + ")"
				}
				elseif ( $check -eq $false ) {

					$DetectionRule = "User connected RDP from Public IP"
					$Description = $TargetDomainName + "\" + $TargetUserName + " connecting from IP " + $IpAddress + " (" + $WorkstationName + ")"
				}
			}
			elseif ( $LogonType -eq 7 ) {

				if( $LogonProcessName.Contains("User32") -And $AuthenticationPackageName.Contains("Negotiate") `
					-And $ProcessName.Contains("svhost.exe") -And $IpAddress -ne "-") {

					$DetectionRule = "User connected RDP (Unlock Screen)"
					$Description = $TargetDomainName + "\" + $TargetUserName + " connecting from IP " + $IpAddress + " (" + $WorkstationName + ")"
				}
			}
		}
		elseif ( $EventID -eq 4625 ) {

			$LogonType = ($Data | Where Name -eq LogonType).InnerText
			$TargetUserName = ($Data | Where Name -eq TargetUserName).InnerText
			$TargetDomainName = ($Data | Where Name -eq TargetDomainName).InnerText
			$WorkstationName  = ($Data | Where Name -eq WorkstationName).InnerText
			$LogonProcessName = ($Data | Where Name -eq LogonProcessName).InnerText
			$IpAddress = ($Data | Where Name -eq IpAddress).InnerText
			$AuthenticationPackageName = ($Data | Where Name -eq AuthenticationPackageName).InnerText
			$ProcessName = ($Data | Where Name -eq ProcessName).InnerText

			if ( $TargetUserName.Contains("AAAAAAA") ) {


				$DetectionRule = "Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep"
				$Description = $TargetDomainName + "\" + $TargetUserName + " connecting from IP " + $IpAddress + " (" + $WorkstationName + ")"		    
			}			
		}
		elseif (  $EventID -eq 5156 ) {

			$SourceAddress = ($Data | Where Name -eq SourceAddress).InnerText
			$SourcePort = ($Data | Where Name -eq LogonType).InnerText
			$DestAddress = ($Data | Where Name -eq DestAddress).InnerText
			$DestPort = ($Data | Where Name -eq TargetUserName).InnerText
			
			if ( ( $SourcePort -eq "3389" -And $DestAddress -match "^127.*" ) `
				-And ( $DestPort -eq "3389" -And $SourceAddress -match "^127.*" ) )  {
				
				$DetectionRule = "User connected RDP from Local host - Possible Socks Proxy being used"
				$Description =  "Connecting from " + $SourceAddress + ':' + $SourcePort + 'to ' + $DestAddress + ":" + $DestPort
			}			
		}
		# Remote Desktop Services: Session logon succeeded
		# Network connection
		elseif ( $EventID -in @(21, 25) ){

			$TargetUserName = $Data.User
			$SessionID = $Data.SessionID
			$IpAddress = $Data.Address

			$check = Test-PrivateIP($IpAddress)

			if( $IpAddress -match "^127.*" -Or $IpAddress.Contains("::1") ) {

				$DetectionRule = "User connected RDP from Local host - Possible Socks Proxy being used"
				$Description =  $TargetUserName +  " connecting from Local Host which means attacker is using tunnel to connect RDP " + $SourceAddress

			}
			elseif ( $IpAddress.Equals("LOCAL") -Or $IpAddress.Equals("local") ){

				$DetectionRule = "User Loggedon to machine"
				$Description =  $TargetUserName +  " connecting from " + $IpAddress				
			}
			elseif ( $check -eq $false ) {

				if ( $IpAddress.Equals('') ){
					$DetectionRule = "User connected RDP from Unknow"
				}

				$DetectionRule = "User connected RDP from Public IP"
				$Description =  $TargetUserName +  " connecting from " + $IpAddress
			}
			elseif ( $check -eq $true ) {

				$DetectionRule = "User connected RDP from Private IP"
				$Description =  $TargetUserName +  " connecting from " + $IpAddress
			}
		}

		Return $DetectionRule, $Description
		
	}
}

$Stores = [System.Collections.ArrayList]@()
# Main 
$SecurityPath = $LogPath + "\Security.evtx"
$LocalSessionManagerPath = $LogPath + "\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"
$RemoteConnectionManager = $LogPath + "\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"
[System.Collections.ArrayList]$LogNames = @($SecurityPath, $LocalSessionManagerPath, $RemoteConnectionManager)

$RDP_DFIR = $null
$event_tmp = $false

foreach( $Item in $LogNames) {


	if( !$(Test-Path $Item) ) {

		$LogNames.Remove($Item)
		Write-Host -NoNewline "Warning|" -BackgroundColor Red
		Write-Host (" " + $Item + " it does not exist.") -ForegroundColor Red -BackgroundColor Black
		Write-Host
	}
	elseif( $LogNames -ge 1 ){

		try {

			Write-Host -NoNewline "Collecting|" -BackgroundColor Black -ForegroundColor Magenta
			write-Host (' ' + $Item) -ForegroundColor Green

			if ($event_tmp -eq $false) {
				

				$RDP_DFIR = Get-WinEvent -Path $Item | Where-Object {$_.Id -in $EventsParse}
				$event_tmp = $true
			}
			else{

				$RDP_DFIR += Get-WinEvent -Path $Item | Where-Object {$_.Id -in $EventsParse}
			}			
		}
		catch {
			
			Write-Host -NoNewline "Error" -BackgroundColor Red
			Write-Host (' ' + $_) -ForegroundColor Red -BackgroundColor Black
			Write-Host

			Return
		}

	}
	else{

		Write-Host -NoNewline "Warning" -BackgroundColor Red
		Write-Host (" Not found Alogs.") -ForegroundColor Red -BackgroundColor Black
		Write-Host

		Return $false
	}
}

$TotalItems = $RDP_DFIR.count
$CurrentItem  = 0
$PercentComplete = 0

foreach ($Item in $RDP_DFIR) {

	# view process bar
	Write-Progress -Activity "Detecting" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete

	# parse XML
	$xmlEvent = [xml]$Item.ToXml()
	$Data = $xmlEvent.Event.EventData.Data

	if($Data -eq $null) {

		$Data = $xmlEvent.Event.UserData.EventXML
	}

	# get infomation
	$EventID = $xmlEvent.Event.System.EventID
	$OriginalLog = $Item.ToXml()

	$DetectionRule = $Description = $null
	if( $EventID -in $EDI_RDP ) {

		$returnedData  =  Get-RDPDetect -EventID $EventID -Data $Data
		$DetectionRule = $returnedData[0]
		$Description = $returnedData[1]


	}
	if( ($EventID -in $EDI_PassTheHash) -And $DetectionRule -eq $null ) {

		$returnedData  =  Get-PassTheHashDetect -EventID $EventID -Data $Data
		$DetectionRule = $returnedData[0]
		$Description = $returnedData[1]		

	}

	if( ($EventID -in $CredentialAccess) -And $DetectionRule -eq $null ) {

		$returnedData  =  Get-CredentialDetection -EventID $EventID -Data $Data
		$DetectionRule = $returnedData[0]
		$Description = $returnedData[1]
	}

	if( ($EventID -eq 4624) -And $DetectionRule -eq $null ) {

		$returnedData  =  Get-WebshellDetection -EventID $EventID -Data $Data
		$DetectionRule = $returnedData[0]
		$Description = $returnedData[1]
	}

	# update info process bar
	$CurrentItem++
	$PercentComplete = [int](($CurrentItem / $TotalItems) * 100)

	# parse format
	if( $DetectionRule -ne $null ) {

		$Event_Oject = $Item | %{(new-object -Type PSObject -Property @{
			
			TimeCreated = [DateTime]$_.TimeCreated
			EventId = $_.Id
			ComputerName = $_.MachineName
			DetectionRule = $DetectionRule
			Description = $Description
			OriginalLog = $OriginalLog

		})}
		$null = $Stores.Add($Event_Oject)
	}
}

# collect to csv
foreach ($st in $Stores) {

	$st | sort TimeCreated -Descending | Select TimeCreated, ComputerName, DetectionRule, Description, EventId, OriginalLog | Export-Csv -Path $OutputFile -NoTypeInformation -Append
}

Write-Host
Write-Warning "Done!"
Write-Host
