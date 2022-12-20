$LogPath = $args[0]
if ($args.Count -ne 1) {
	$LogPath = "C:\Windows\System32\winevt\logs"
}

$OutputFile = "C:\ProgramData\DFIR_VCS\Logon.csv"

Write-Warning "Reading Event Logs ..."
Write-Host

$EventsParse = @(4688, 4648, 4673)

$Stores = [System.Collections.ArrayList]@()

$SecurityPath = $LogPath + "\Security.evtx"

function ProcessDetector {

	param(

		[Parameter(Position = 1, Mandatory = $true)]
		[string] 
		$EventID,
		[Parameter(Position = 2, Mandatory = $true)]
		$Data
	)
	process {

		$DetectionRule = $Description = $null
		$SubjectUserName = ($data | Where Name -eq SubjectUserName).InnerText
		$SubjectDomainName = ($data | Where Name -eq SubjectDomainName).InnerText
		$NewProcessName = ($data | Where Name -eq NewProcessName).InnerText
		$CommandLine = ($data | Where Name -eq CommandLine).InnerText

		if ( $EventID -eq 4688 ) {

			$DetectionRule = "Found ..."
			$Description = $SubjectDomainName + '\' + $SubjectUserName + ' excute ' + $NewProcessName + ' ' + $CommandLine 
		}

		Return $DetectionRule, $Description
	}

}

$Process_DFIR = $null
$event_tmp = $false

foreach( $Item in $LogNames) {


	if( !$(Test-Path $Item) ) {

		Write-Host -NoNewline "Warning|" -BackgroundColor Red
		Write-Host (" " + $Item + " it does not exist.") -ForegroundColor Red -BackgroundColor Black
		Write-Host
	}
	else {

		try {

			Write-Host -NoNewline "Collecting|" -BackgroundColor Black -ForegroundColor Magenta
			write-Host (' ' + $Item) -ForegroundColor Green

			if ($event_tmp -eq $false) {
				

				$Process_DFIR = Get-WinEvent -Path $Item | Where-Object {$_.Id -in $EventsParse}
				$event_tmp = $true
			}
			else{

				$Process_DFIR += Get-WinEvent -Path $Item | Where-Object {$_.Id -in $EventsParse}
			}			
		}
		catch {
			
			Write-Host -NoNewline "Error" -BackgroundColor Red
			Write-Host (' ' + $_) -ForegroundColor Red -BackgroundColor Black
			Write-Host

			Return
		}

	}
	if ($event_tmp -eq $false) {

		Write-Host -NoNewline "Warning" -BackgroundColor Red
		Write-Host (" Not found events.") -ForegroundColor Red -BackgroundColor Black
		Write-Host

		Return $false
	}
}



$TotalItems = $Process_DFIR.count
$CurrentItem  = 0
$PercentComplete = 0


foreach($Item in $Process_DFIR){

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
