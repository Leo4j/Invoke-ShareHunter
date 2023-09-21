function Invoke-GetDomainShares{
	
	[CmdletBinding()] Param(
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Domain,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$DomainController,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Targets,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$TargetsFile,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$NoPortScan,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Timeout
		
	)
	
	$ErrorActionPreference = "SilentlyContinue"
	
	if(!$Domain){$Domain = Get-Domain}
	
	if($TargetsFile){$Computers = Get-Content -Path $TargetsFile}
	
	elseif($Targets){$Computers = $Targets -split ","}
	
	else{$Computers = Get-ADComputers -ADCompDomain $Domain}
	
	if(!$NoPortScan){
	
		$reachable_hosts = $null
		$Tasks = $null
		$total = $Computers.Count
		$count = 0
		
		if(!$Timeout){$Timeout = "50"}
		
		$reachable_hosts = @()
		
		$Tasks = $Computers | % {
			Write-Progress -Activity "Scanning Ports" -Status "$count out of $total hosts scanned" -PercentComplete ($count / $total * 100)
			$tcpClient = New-Object System.Net.Sockets.TcpClient
			$asyncResult = $tcpClient.BeginConnect($_, 445, $null, $null)
			$wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)
			if($wait) {
				$tcpClient.EndConnect($asyncResult)
				$tcpClient.Close()
				$reachable_hosts += $_
			} else {}
			$count++
		}
		
		Write-Progress -Activity "Scanning Ports" -Completed
		
		$Computers = $reachable_hosts

 	}
	
	$AllShares = @()
	
	foreach($Computer in $Computers){
		
		$results = net view \\$Computer

		$results = $results | Out-String

		# 1. Capture content between the delimiters using string methods
		$startDelimiter = "-------------------------------------------------------------------------------"
		$endDelimiter = "The command completed successfully."

		$startIndex = $results.IndexOf($startDelimiter)
		$endIndex = $results.IndexOf($endDelimiter)

		$capturedContent = $results.Substring($startIndex + $startDelimiter.Length, $endIndex - $startIndex - $startDelimiter.Length).Trim()

		# 2. Scrape for the share names
		$shareNames = ($capturedContent -split "`n") | Where-Object { $_ -match '^(\S+)\s+Disk' } | ForEach-Object { $matches[1] }

		foreach($shareName in $shareNames){
			$finalsharename = "\\" + $Computer + "\" + $shareName
			$AllShares += $finalsharename
		}
	}
	
	Write-Output ""
	Write-Output "Checking for Readable Shares..."
	
	$ReadableShares = @()
	
	$total = $AllShares.Count
	$count = 0
	
	foreach ($Share in $AllShares){
		Write-Progress -Activity "Testing Read Access" -Status "$count out of $total shares tested" -PercentComplete ($count / $total * 100)
		
		#clear error listing
		$Error.clear()
		
		ls $Share > $null
		
		$ourerror = $error[0]
		
		if (($ourerror) -eq $null){
			
			$ReadableShares += $Share
		}
		
		$count++
	}
	
	Write-Progress -Activity "Testing Read Access" -Completed
	
	Write-Output ""
	Write-Output "Readable Shares:"
	Write-Output ""
	$ReadableShares
	$ReadableShares | Out-File $pwd\Shares_Readable.txt -Force
	Write-Output ""
	Write-Output "Output saved to: $pwd\Shares_Readable.txt"
	Write-Output ""
	Write-Output ""
	Write-Output "Checking for Writable Shares..."
	
	$WritableShares = @()
	
	$total = $ReadableShares.Count
	$count = 0
	
	foreach($Share in $ReadableShares){
		Write-Progress -Activity "Testing Write Access" -Status "$count out of $total shares tested" -PercentComplete ($count / $total * 100)
		$WritableShares += Test-Write $Share
		$count++
	}
	
	Write-Progress -Activity "Testing Write Access" -Completed
	
	Write-Output ""
	Write-Output "Writable Shares:"
	Write-Output ""
	$WritableShares
	$WritableShares | Out-File $pwd\Shares_Writable.txt -Force
	Write-Output ""
	Write-Output "Output saved to: $pwd\Shares_Writable.txt"
	Write-Output ""
}

function Get-Domain {
	
	Add-Type -AssemblyName System.DirectoryServices
	
	try{
		$RetrieveDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		$RetrieveDomain = $RetrieveDomain.Name
	}
	catch{$RetrieveDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
	
	$RetrieveDomain
}

function Get-ADComputers {
	
	param (
		[string]$ADCompDomain
	)
	
	Add-Type -AssemblyName System.DirectoryServices
	
	$domainDistinguishedName = "DC=" + ($ADCompDomain -replace "\.", ",DC=")
	$targetdomain = "LDAP://$domainDistinguishedName"
	$searcher = New-Object System.DirectoryServices.DirectorySearcher
	$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry $targetdomain
 	$searcher.PageSize = 1000
	
	$ldapFilter = "(objectCategory=computer)"
	$searcher.Filter = $ldapFilter
	$allcomputers = $searcher.FindAll() | %{$_.properties.dnshostname}
	$allcomputers 
}

function Test-Write {
	[CmdletBinding()]
	param (
		[parameter()] [ValidateScript({[IO.Directory]::Exists($_.FullName)})]
		[IO.DirectoryInfo] $Path
	)
	try {
		$testPath = Join-Path $Path ([IO.Path]::GetRandomFileName())
		[IO.File]::Create($testPath, 1, 'DeleteOnClose') > $null
		return "$Path"
	} finally {
		Remove-Item $testPath -ErrorAction SilentlyContinue
	}
}