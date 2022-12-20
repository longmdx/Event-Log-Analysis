# recv param
$LogPath = $args[0]
if ($args.Count -ne 1) {
	 $LogPath = "C:\Windows\System32\winevt\logs"
}

# Path save parse
$OutputFile = "C:\ProgramData\DFIR_VCS\pws.csv"
#Remove-Item $OutputFile -ErrorAction SilentlyContinue

Write-Warning "Reading Event Logs ..."
Write-Host


function Get-PowershellDetect {

	param(
		[Parameter(Position = 1, Mandatory = $true)]
		[string] 
		$EventID,
		[Parameter(Position = 2, Mandatory = $true)]
		$Data
	)

	process {

		$DetectionRule = $Description = $null

		if( $EventID -eq 4104 ) {

			$ScriptBlockText = ($Data | Where Name -eq ScriptBlockText).InnerText
			$DetectionRule = "Found powershell command"
			$Description = $ScriptBlockText
		}
		elseif ( $EventID -in @(4100, 4103) ) {

			$ContextInfo = ($Data | Where Name -eq ContextInfo).InnerText
			$Username = ($ContextInfo -split "User = ")[1].replace(' Connected', '')
			$HostApplication = (($ContextInfo -split " Host Application = ")[1] -split " = ")[0].replace(" Engine Version", "")
			$CommandName = (($ContextInfo -split " Command Name = ")[1] -split ' Command Type = ')[0]
			$DetectionRule = "Found user attemp excute powershell command"
			$Description = 'User: ' + $Username + ' attemp excute ' + $HostApplication + ' with command ' + $CommandName

		}
		else {

			$CommandLine = $Data[0]
			$DetectionRule = "Found pipeline execute powershell command"
			$Description = $CommandLine
		}

		Return $DetectionRule, $Description
	}

}

# list EID
$EventsParse = @(4104, 800, 4100, 4103)
$Stores = [System.Collections.ArrayList]@()
$PowershellOPath = $LogPath + "\Microsoft-Windows-PowerShell%4Operational.evtx"
$PowershellPath = $LogPath + "\Windows PowerShell.evtx"

[System.Collections.ArrayList]$LogNames = @($PowershellOPath, $PowershellPath)

$PWSH_DFIR = $null
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
				

				$PWSH_DFIR = Get-WinEvent -Path $Item | Where-Object {$_.Id -in $EventsParse}
				$event_tmp = $true
			}
			else {

				$PWSH_DFIR += Get-WinEvent -Path $Item | Where-Object {$_.Id -in $EventsParse}
			}	
		}
		catch {
			
			Write-Host -NoNewline "Error" -BackgroundColor Red
			Write-Host (' ' + $_) -ForegroundColor Red -BackgroundColor Black
			Write-Host
			Return
		}

	}
	
	if($event_tmp -eq $false) {

		Write-Host -NoNewline "Warning" -BackgroundColor Red
		Write-Host (" Not found events.") -ForegroundColor Red -BackgroundColor Black
		Write-Host

		Return $false
	}
}

$TotalItems = $PWSH_DFIR.count
$CurrentItem  = 0
$PercentComplete = 0

foreach ($Item in $PWSH_DFIR) {

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

	$returnedData  = Get-PowershellDetect -EventID $EventID -Data $Data
	$DetectionRule = $returnedData[0]
	$Description = $returnedData[1]

	# update info process bar
	$CurrentItem++
	$PercentComplete = [int](($CurrentItem / $TotalItems) * 100)

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