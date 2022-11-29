# recv param
$LogPath = $args[0]
if ($args.Count -ne 1) {
	 $LogPath = "C:\Windows\System32\winevt\logs"
}

# Path save parse
$OutputFile = "C:\ProgramData\DFIR_VCS\Windows_Defender.csv"
#Remove-Item $OutputFile -ErrorAction SilentlyContinue


Write-Warning "Reading Event Logs ..."
Write-Host


function DefenderDetect {

	param(
		[Parameter(Position = 1, Mandatory = $true)]
		[string] 
		$EventID,
		[Parameter(Position = 2, Mandatory = $true)]
		$Data
	)
	process {

		$DetectionRule = $Description = $null

		if ( $EventID -in @(1117, 1007, 1116, 1006) ) {
			
			$ThreatName = ($data | Where Name -eq "Threat Name").InnerText
			$Type = ($data | Where Name -eq "Type Name").InnerText
			$ProcessName = ($data | Where Name -eq "Process Name").InnerText
			$DetectUser = ($data | Where Name -eq "Detection User").InnerText
			$Path = ($data | Where Name -eq "Path").InnerText

			if ( $EventID -in @(1117, 1007) ) {

				$DetectionRule = "Windows Defender took action against Malware"
			}
			else {

				$DetectionRule = "Windows Defender Found Malware"
			}

			$Description = $ThreatName + "(" + $Type + ")"
			$Description += $Description + " at" + $Path
			$Description += $Description + " by" + $ProcessName
			$Description += $Description + " (" + $DetectUser + ")"
		}
		else {

			switch ($EventID) {
						
				1008 {$DetectionRule = 'Malware Action Failed'}
				1013 {$DetectionRule = 'The antimalware platform deleted history of malware and other potentially unwanted software'}
				1015 {$DetectionRule = 'Suspicious Behavior Detected'}
				1118 {$DetectionRule = 'Malware Response Action Failed'}
				1119 {$DetectionRule = 'Malware Response Action Critically Failed'}
				5001 {$DetectionRule = 'Windows Defender real-time protection disabled'}
				5007 {$DetectionRule = 'Windows Defender antimalware platform configuration changed'}
				5010 {$DetectionRule = 'Antispyware Disabled'}
				5012 {$DetectionRule = 'Antivirus Disabled'}

			}

			$Description = "Check details in the OriginalLog column"				
		}

		Return $DetectionRule, $Description
	}

}



# list EID
$EventsParse = @(1117, 1007, 1116, 1006, 1118, 1008, 1015, 5001, 5010, 5007, 5012, 1119)

$DefenderOPath =  $LogPath + "\Microsoft-Windows-Windows Defender%4Operational.evtx"

[System.Collections.ArrayList]$LogNames = @($DefenderOPath)
[System.Collections.ArrayList]$Defender_DFIR = @()

$Defender_DFIR = $null
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
				

				$Defender_DFIR = Get-WinEvent -Path $Item -ErrorAction SilentlyContinue | Where-Object {$_.Id -in $EventsParse}		
				$event_tmp = $true
			}
			else{

				$Defender_DFIR += Get-WinEvent -Path $Item -ErrorAction SilentlyContinue | Where-Object {$_.Id -in $EventsParse}

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

$Stores = [System.Collections.ArrayList]@()
$TotalItems = $Defender_DFIR.count
$CurrentItem  = 0
$PercentComplete = 0


foreach ($Item in $Defender_DFIR) {
	
	# view process bar
	Write-Progress -Activity "Detecting" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete	

	$xmlEvent = [xml]$Item.ToXml()
	
	#$xmlEvent
	$Data = $xmlEvent.Event.EventData.Data

	# get infomation
	$EventID = $xmlEvent.Event.System.EventID
	$OriginalLog = $Item.ToXml()

	$DetectionRule = $Description = $null
	
	$returnedData  =  DefenderDetect -EventID $EventID -Data $Data
	$DetectionRule = $returnedData[0]
	$Description = $returnedData[1]

	

	# update info process bar
	$CurrentItem++
	$PercentComplete = [int](($CurrentItem / $TotalItems) * 100)


	# parse format
	if( $DetectionRule -ne $null -And $Description -ne $null ) {
		
		$Event_Oject = $Item | %{(new-object -Type PSObject -Property @{

			TimeCreated = $_.TimeCreated
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
