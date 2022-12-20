$LogPath = $args[0]
if ($args.Count -ne 1) {
    $LogPath = "C:\Windows\System32\winevt\logs"
}

#$OutputFile = "C:\ProgramData\DFIR_VCS\Account.csv"
$OutputFile = "Account.csv"
Clear-Content -Path $OutputFile
#Remove-Item $OutputFile -ErrorAction SilentlyContinue

function AccountDetect {

	param(
		[Parameter(Position = 1, Mandatory = $true)]
		[string] 
		$EventID,
		[Parameter(Position = 2, Mandatory = $true)]
		$Data,
		[Parameter(Position = 3, Mandatory = $false)]
		$KeyWord
	)
	process {

		$DetectionRule = $Description = $null
		
		$TargetUserName = ($Data | where Name -eq "TargetUserName").InnerText
		$TargetDomainName = ($Data | where Name -eq "TargetDomainName").InnerText
		$SubjectUserName = ($Data | where Name -eq "SubjectUserName").InnerText
		$SubjectDomainName = ($Data | where Name -eq "SubjectDomainName").InnerText

		switch ($EventID) {

			#Account

			#windows 10
			4720 {
				$DetectionRule = "A user account was created" 
				$Description = "Account (" + $TargetUserName + ") was created by user (" + $SubjectUserName + ")"
			}

			4722 {
				$DetectionRule = "A user account was enabled" 
				$Description = "Account (" + $TargetUserName + ") was enabled by user (" + $SubjectUserName + ")"
			}

			4725 {
				$DetectionRule = "A user account was disabled" 
				$Description = "Account (" + $TargetUserName + ") was disabled by user (" + $SubjectUserName + ")"
			}

			4724 {
				$DetectionRule = "An attempt was made to reset an account's password" 
				$Description = "An attempt was made to reset (" + $TargetUserName + ") password by user (" + $SubjectUserName + ")"
			}

			4726 {
				$DetectionRule = "A user account was changed" 
				$Description = "Account (" + $TargetUserName + ") was deleted by user (" + $SubjectUserName + ")"
			}

			4738 {
				$DetectionRule = "A user account was changed" 
				$Description = "Check details in the OriginalLog column"
			}


			#windows server 2016
			4741 {
				$DetectionRule = "A computer account was created" 
				$Description = "Account (" + $TargetUserName + ") was created by user (" + $SubjectUserName + ")"
			}

			4723 {
				$DetectionRule = "An attempt was made to reset an account's password" 
				$Description = "An attempt was made to reset (" + $TargetUserName + ") password by user (" + $SubjectUserName + ")"
			}

			4743 {
				$DetectionRule = "A computer account was deleted" 
				$Description = "Account (" + $TargetUserName + ") was deleted by user (" + $SubjectUserName + ")"
			}

			4742 {
				$DetectionRule = "A computer account was changed" 
				$Description = "Check details in the OriginalLog column"
			}

			#group

			#windows 10

			4731 {
				$DetectionRule = "A security-enabled local group was created" 
				$Description = "Group (" + $TargetUserName + ") was created by user (" + $SubjectUserName + ")"
			}

			4732 {
				$MemberSid = ($Data | where Name -eq "MemberSid").InnerText
				$DetectionRule = "A member was added to a security-enabled local group" 
				$Description = "Member (" + $MemberSid + ") was added to (" + $TargetUserName + ") by user (" + $SubjectUserName + ")"
			}

			4733 {
				$MemberSid = ($Data | where Name -eq "MemberSid").InnerText
				$DetectionRule = "A member was removed from a security enabled local group" 
				$Description = "Member (" + $MemberSid + ") was removed from (" + $TargetUserName + ") by user (" + $SubjectUserName + ")"
			}

			4734 {
				$DetectionRule = "A security-enabled local group was deleted" 
				$Description = "Group (" + $TargetUserName + ") was deleted by user (" + $SubjectUserName + ")"
			}

			4735 {
				$DetectionRule = "A security-enabled local group was changed" 
				$Description = "Check details in the OriginalLog column"
			}

			#windows server 2016

			4754 {
				$DetectionRule = "A security-enabled universal group was created" 
				$Description = "Group (" + $TargetUserName + ") was created by user (" + $SubjectUserName + ")"
			}

			4755 {
				$DetectionRule = "A security-enabled universal group was changed" 
				$Description = "Check details in the OriginalLog column"
			}

			4756 {
				$MemberSid = ($Data | where Name -eq "MemberSid").InnerText
				$DetectionRule = "A member was added to a security-enabled universal group" 
				$Description = "Member (" + $MemberSid + ") was added to (" + $TargetUserName + ") by user (" + $SubjectUserName + ")"
			}

			4757 {
				$MemberSid = ($Data | where Name -eq "MemberSid").InnerText
				$DetectionRule = "A member was removed from a security-enabled universal group" 
				$Description = "Member (" + $MemberSid + ") was removed from (" + $TargetUserName + ") by user (" + $SubjectUserName + ")"
			}

			4758 {
				$DetectionRule = "A security-enabled universal group was deleted" 
				$Description = "Group (" + $TargetUserName + ") was deleted by user (" + $SubjectUserName + ")"
			}

			default {
				#do something
			}	
		}

		

		Return $DetectionRule, $Description
	}

}

Write-Warning "Reading Event Logs ..."
Write-Host

$EventsParse = @(4720, 4722, 4724, 4726, 4731, 4732, 4733, 4734, 4735, 4738, 4741, 4723, 4743, 4742, 4754, 4755, 4756, 4757, 4758)

$SecurityPath = $LogPath + "\Security.evtx"

[System.Collections.ArrayList]$LogNames = @($SecurityPath)
[System.Collections.ArrayList]$Account_DFIR = @()

$Account_DFIR = $null
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
			write-Host (" " + $Item) -ForegroundColor Green

			if ($event_tmp -eq $false) {

				$Account_DFIR = Get-WinEvent -Path $Item | Where-Object {$_.Id -in $EventsParse}
				
				$event_tmp = $true
			}
			else {

				$Account_DFIR += Get-WinEvent -Path $Item | Where-Object {$_.Id -in $EventsParse}

			}			
		}
		catch {
			
			Write-Host -NoNewline "Error" -BackgroundColor Red
			Write-Host (" " + $_) -ForegroundColor Red -BackgroundColor Black
			Write-Host

			Return
		}
	}

	if (!$($event_tmp)) {

		Write-Host -NoNewline "Warning" -BackgroundColor Red
		Write-Host (" Not found events.") -ForegroundColor Red -BackgroundColor Black
		Write-Host

		Return $false
	}
}

$Stores = [System.Collections.ArrayList]@()
$TotalItems = $Account_DFIR.count
$CurrentItem  = 0
$PercentComplete = 0

foreach ($Item in $Account_DFIR) {
	
	# view process bar
	Write-Progress -Activity "Detecting" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete	

	$xmlEvent = [xml]$Item.ToXml()
	
	#$xmlEvent
	$Data = $xmlEvent.Event.EventData.Data

	# get infomation
	$EventID = $xmlEvent.Event.System.EventID
	$OriginalLog = $Item.ToXml()

	$DetectionRule = $Description = $null
	
	$returnedData  =  AccountDetect -EventID $EventID -Data $Data
	$DetectionRule = $returnedData[0]
	$Description = $returnedData[1]

	# update info process bar
	$CurrentItem++
	$PercentComplete = [int](($CurrentItem / $TotalItems) * 100)


	# parse format
	if( $DetectionRule -ne $null -And $Description -ne $null ) {

		$Event_Object = $Item | %{(new-object -Type PSObject -Property @{
			
			TimeCreated = [DateTime]$_.TimeCreated
			EventId = $_.Id
			ComputerName = $_.MachineName
			DetectionRule = $DetectionRule
			Description = $Description
			OriginalLog = $OriginalLog

		})}
		$null = $Stores.Add($Event_Object)
	}
}

# collect to csv
$Stores | sort TimeCreated -Descending | Select TimeCreated, ComputerName, DetectionRule, Description, EventId, OriginalLog | Export-Csv -Path $OutputFile -NoTypeInformation -Append

Write-Host
Write-Warning "Done!"
Write-Host