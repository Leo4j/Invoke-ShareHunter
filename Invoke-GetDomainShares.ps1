function Invoke-GetDomainShares{
	
	[CmdletBinding()] Param(
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Domain,
		
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
	
	Write-Output ""
	Write-Output "Enumerating Shares..."
	
	# Create runspace pool
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
	$runspacePool.Open()

	$runspaces = @()

	foreach ($Computer in $Computers) {
		$scriptBlock = {
			param($Computer)

			$results = net view \\$Computer
			$results = $results | Out-String

			$startDelimiter = "-------------------------------------------------------------------------------"
			$endDelimiter = "The command completed successfully."

			$startIndex = $results.IndexOf($startDelimiter)
			$endIndex = $results.IndexOf($endDelimiter)

			$capturedContent = $results.Substring($startIndex + $startDelimiter.Length, $endIndex - $startIndex - $startDelimiter.Length).Trim()

			$shareNames = ($capturedContent -split "`n") | Where-Object { $_ -match '^(\S+)\s+Disk' } | ForEach-Object { $matches[1] }

			return $shareNames | ForEach-Object { "\\" + $Computer + "\" + $_ }
		}

		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Computer)
		$runspace.RunspacePool = $runspacePool

		$runspaces += [PSCustomObject]@{
			Runspace = $runspace
			Status   = $runspace.BeginInvoke()
			Computer = $Computer
		}

	}

	# Initialize an array to store all shares
	$AllShares = @()

	# Collect the results from each runspace
	$runspaces | ForEach-Object {
		$shares = $_.Runspace.EndInvoke($_.Status)
		if ($shares) { 
			$AllShares += $shares
		} else {
			Write-Error "No shares found for $($_.Computer)"
		}
	}

	# Close and clean up the runspace pool
	$runspacePool.Close()
	$runspacePool.Dispose()
	
	Write-Output ""
	Write-Output "Checking for Readable Shares..."

	$runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
	$runspacePool.Open()

	$runspaces = @()
	$total = $AllShares.Count
	$count = 0

	foreach ($Share in $AllShares) {
		$scriptBlock = {
			param($Share)

			$Error.clear()
			ls $Share > $null
			if (!$error[0]) {
				return $Share
			} else {
				return $null
			}
		}

		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Share)
		$runspace.RunspacePool = $runspacePool

		$runspaces += [PSCustomObject]@{
			Runspace = $runspace
			Status   = $runspace.BeginInvoke()
			Share    = $Share
		}

		$count++
		Write-Progress -Activity "Testing Read Access" -Status "$count out of $total shares tested" -PercentComplete ($count / $total * 100)
	}

	# Initialize an array to store all readable shares
	$ReadableShares = @()

	# Collect the results from each runspace
	$runspaces | ForEach-Object {
		$shareResult = $_.Runspace.EndInvoke($_.Status)
		if ($shareResult) {
			$ReadableShares += $shareResult
		}
	}

	# Close and clean up the runspace pool
	$runspacePool.Close()
	$runspacePool.Dispose()

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

	$runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
	$runspacePool.Open()

	$runspaces = @()
	$total = $ReadableShares.Count
	$count = 0

	foreach ($Share in $ReadableShares) {
		$scriptBlock = {
			
			param(
				[Parameter(Mandatory=$true)]
				[string]$Share
			)
			
			function Test-Write {
				[CmdletBinding()]
				param (
					[parameter()]
					[string] $Path
				)
				try {
					$testPath = Join-Path $Path ([IO.Path]::GetRandomFileName())
					[IO.File]::Create($testPath, 1, 'DeleteOnClose') > $null
					return "$Path"
				} finally {
					Remove-Item $testPath -ErrorAction SilentlyContinue
				}
			}
			
			try {
				$result = Test-Write -Path $Share
				return @{
					Share = $Share
					Result = $result
					Error = $null
				}
			} catch {
				return @{
					Share = $Share
					Result = $null
					Error = $_.Exception.Message
				}
			}
		}


		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Share)

		$runspace.RunspacePool = $runspacePool

		$runspaces += [PSCustomObject]@{
			Runspace = $runspace
			Status   = $runspace.BeginInvoke()
			Share    = $Share
		}

		$count++
		Write-Progress -Activity "Testing Write Access" -Status "$count out of $total shares tested" -PercentComplete ($count / $total * 100)
	}

	# Initialize an array to store all writable shares
	$WritableShares = @()

	# Collect the results from each runspace
	$runspaces | ForEach-Object {
		$runspaceData = $_.Runspace.EndInvoke($_.Status)
		if ($runspaceData.Result) {
			$WritableShares += $runspaceData.Result
		}
	}

	# Close and clean up the runspace pool
	$runspacePool.Close()
	$runspacePool.Dispose()

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
