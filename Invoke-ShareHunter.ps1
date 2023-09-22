function Invoke-ShareHunter{

	<#

	.SYNOPSIS
	Invoke-ShareHunter Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-ShareHunter

	.DESCRIPTION
	Enumerate the Domain for Readable and Writable Shares
	
	.PARAMETER Domain
	The target domain to enumerate shares for
	
	.PARAMETER Targets
	Provide comma-separated targets
	
	.PARAMETER TargetsFile
	Provide a file containing a list of target hosts (one per line)
	
	.PARAMETER NoPortScan
	Do not run a portscan before checking for shares
	
	.PARAMETER Timeout
	Timeout for the portscan before the port is considered closed (default: 50ms)
	
	.EXAMPLE
	Invoke-ShareHunter
	Invoke-ShareHunter -Domain ferrari.local
	Invoke-ShareHunter -Targets "Workstation-01.ferrari.local,DC01.ferrari.local"
 	Invoke-ShareHunter -TargetsFile C:\Users\Public\Documents\Shares.txt
	
	#>
	
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
	
	else{
		Write-Output ""
		Write-Output "Enumerating Computer Objects..."
		$Computers = Get-ADComputers -ADCompDomain $Domain
	}
	
	if(!$NoPortScan){
		
		Write-Output ""
		Write-Output "Running Port Scan..."
	
		if (-not $Timeout) { $Timeout = 50 }

		$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
		$runspacePool.Open()

		$runspaces = @()
		$total = $Computers.Count
		$count = 0

		foreach ($Computer in $Computers) {
			$scriptBlock = {
				param($Computer, $Timeout)

				$tcpClient = New-Object System.Net.Sockets.TcpClient
				$asyncResult = $tcpClient.BeginConnect($Computer, 445, $null, $null)
				$wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)
				if ($wait) { 
					try {
						$tcpClient.EndConnect($asyncResult)
						$connected = $true
						return $Computer
					} catch {
						$connected = $false
					}
				} else {
					$Connect = $false
				}

				$tcpClient.Close()
			}

			$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Computer).AddArgument($Timeout)
			$runspace.RunspacePool = $runspacePool

			$runspaces += [PSCustomObject]@{
				Runspace = $runspace
				Status   = $runspace.BeginInvoke()
				Computer = $Computer
			}

			$count++
			Write-Progress -Activity "Scanning Ports" -Status "$count out of $total hosts scanned" -PercentComplete ($count / $total * 100)
		}

		# Initialize an array to store all reachable hosts
		$reachable_hosts = @()

		# Collect the results from each runspace
		$runspaces | ForEach-Object {
			$hostResult = $_.Runspace.EndInvoke($_.Status)
			if ($hostResult) {
				$reachable_hosts += $hostResult
			}
		}

		# Close and clean up the runspace pool
		$runspacePool.Close()
		$runspacePool.Dispose()

		Write-Progress -Activity "Scanning Ports" -Completed

		$Computers = $reachable_hosts

 	}
	
	Write-Output ""
	Write-Output "Enumerating Shares..."
	
	$functiontable = @()
	
	# Create runspace pool
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()

	$runspaces = @()

	foreach ($Computer in $Computers) {
		$scriptBlock = {
			param($Computer)

			# Getting all shares including hidden ones
			$allResults = net view \\$Computer /ALL | Out-String

			# Getting only non-hidden shares
			$visibleResults = net view \\$Computer | Out-String

			$startDelimiter = "-------------------------------------------------------------------------------"
			$endDelimiter = "The command completed successfully."

			$extractShares = {
				param($results)
				
				$startIndex = $results.IndexOf($startDelimiter)
				$endIndex = $results.IndexOf($endDelimiter)

				$capturedContent = $results.Substring($startIndex + $startDelimiter.Length, $endIndex - $startIndex - $startDelimiter.Length).Trim()

				return ($capturedContent -split "`n") | Where-Object { $_ -match '^(\S+)\s+Disk' } | ForEach-Object { $matches[1] }
			}

			$allShares = & $extractShares $allResults
			$visibleShares = & $extractShares $visibleResults

			# Determine hidden shares
			$hiddenShares = $allShares | Where-Object { $_ -notin $visibleShares }

			# Create hashtable for each share
			return $allShares | ForEach-Object {
				@{
					'Targets'  = $Computer
					'Share'    = $_
					'FullShareName'    = $null
					'Readable' = 'NO'
					'Writable' = 'NO'
					'Hidden'   = if ($_ -in $hiddenShares) { 'True' } else { 'False' }
					'Domain'   = $Domain  # Assuming $Domain is available in this context
				}
			}
		}

		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Computer)
		$runspace.RunspacePool = $runspacePool

		$runspaces += [PSCustomObject]@{
			Runspace = $runspace
			Status   = $runspace.BeginInvoke()
			Computer = $Computer
		}
	}

	# Collect the results from each runspace
	$runspaces | ForEach-Object {
		$shares = $_.Runspace.EndInvoke($_.Status)
		if ($shares) { 
			$functiontable += $shares
		} else {
			Write-Error "No shares found for $($_.Computer)"
		}
	}

	# Close and clean up the runspace pool
	$runspacePool.Close()
	$runspacePool.Dispose()
	
	# Initialize an array to store all shares
	$AllShares = @()
	
	foreach($obj in $functiontable){
		$obj.Domain = $Domain
		$sharename = "\\" + $obj.Targets + "\" + $obj.Share
		$obj.FullShareName = $sharename
		$AllShares += $sharename
	}

	Write-Output ""
	Write-Output "Checking for Readable Shares..."

	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()

	$runspaces = @()
	$total = $AllShares.Count
	$count = 0

	foreach ($obj in $functiontable) {
		$Share = $obj.FullShareName
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
	
	foreach ($Share in $ReadableShares) {
		foreach ($obj in $functiontable) {
			if($obj.FullShareName -eq $Share){
				$obj.Readable = "YES"
			}
		}
	}
	
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

	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
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
					$fileStream = [IO.File]::Create($testPath, 1, 'DeleteOnClose')
					$fileStream.Close()
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
	
	foreach ($Share in $WritableShares) {
		foreach ($obj in $functiontable) {
			if($obj.FullShareName -eq $Share){
				$obj.Writable = "YES"
			}
		}
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
	
	$FinalTable = @()
	
	$FinalTable = foreach ($obj in $functiontable) {
		if($obj.Readable -eq "YES"){
			[PSCustomObject]@{
				'Targets'  = $obj.Targets
				'Operating System' = Get-OSFromFQDN -FQDN $obj.Targets
				'Share Name'    = $obj.FullShareName
				'Readable' = $obj.Readable
				'Writable' = $obj.Writable
				'Hidden'   = $obj.Hidden
				'Domain'   = $obj.Domain  # Assuming $Domain is available in this context
			}
		}
	}
	
	$FinalResults = $FinalTable | Sort-Object -Unique "Domain","Writable","Targets","Share Name" | ft -Autosize -Wrap
	$FinalResults
	
	$FinalResults | Out-File $pwd\Shares_Results.txt -Force
	Write-Output "Output saved to: $pwd\Shares_Results.txt"
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

function Get-OSFromFQDN {
    param (
        [string]$FQDN
    )

    # Convert the domain part of the FQDN to a distinguished name for the search root
    $domainPart = $FQDN.Split('.',2)[1] # This takes everything after the first dot
    $domainDistinguishedName = "DC=" + ($domainPart -replace "\.", ",DC=")

    # Set the LDAP path for the domain
    $ldapQuery = "LDAP://$domainDistinguishedName"

    # Create a DirectoryEntry object and searcher
    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry $ldapQuery
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $directoryEntry
    $searcher.Filter = "(&(objectClass=computer)(dNSHostName=$FQDN))"
    $searcher.PropertiesToLoad.Add("OperatingSystem") | Out-Null

    # Execute the search
    $result = $searcher.FindOne()

    # Return the OperatingSystem property
    if ($result -and $result.Properties["OperatingSystem"].Count -gt 0) {
        return $result.Properties["OperatingSystem"][0]
    } else {
        Write-Error "Unable to find the OS for the given FQDN or the OS attribute is not set."
        return $null
    }
}
