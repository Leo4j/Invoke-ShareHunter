function Invoke-ShareHunter{

	<#

	.SYNOPSIS
	Invoke-ShareHunter Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-ShareHunter

	.DESCRIPTION
	Enumerate the Domain for Readable and Writable Shares
	
	.PARAMETER Domain
	The target domain to enumerate shares for

 	.PARAMETER DomainController
	The DC to bind to via LDAP
	
	.PARAMETER Targets
	Provide comma-separated targets
	
	.PARAMETER TargetsFile
	Provide a file containing a list of target hosts (one per line)
	
	.PARAMETER NoPortScan
	Do not run a portscan before checking for shares
	
	.PARAMETER Timeout
	Timeout for the portscan before the port is considered closed (default: 50ms)

 	.PARAMETER ReadOnly
	Will not enumrate for writable shares
	
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
		$DomainController,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Timeout,

  		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$ReadOnly
		
	)
	
	$ErrorActionPreference = "SilentlyContinue"
	
	if(!$Domain){
		try{
			$RetrieveDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			$RetrieveDomain = $RetrieveDomain.Name
		}
		catch{$RetrieveDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		$Domain = $RetrieveDomain
	}

 	if(!$DomainController){
		
		$result = nslookup -type=all "_ldap._tcp.dc._msdcs.$Domain" 2>$null

		# Filtering to find the line with 'svr hostname' and then split it to get the last part which is our DC name.
		$DomainController = ($result | Where-Object { $_ -like '*svr hostname*' } | Select-Object -First 1).Split('=')[-1].Trim()

	}
	
	if($TargetsFile){$Computers = Get-Content -Path $TargetsFile}
	
	elseif($Targets){$Computers = $Targets -split ","}
	
	else{
		Write-Output ""
		Write-Output "[+] Enumerating Computer Objects..."
		$Computers = Get-ADComputers -ADCompDomain $Domain
	}

	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN"}
	$Computers = $Computers | Where-Object { $_ -and $_.trim() }
	
	
	if(!$NoPortScan){
		
		Write-Output ""
		Write-Output "[+] Running Port Scan..."
	
		if (-not $Timeout) { $Timeout = 50 }

		$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
		$runspacePool.Open()

		$runspaces = @()

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
					} catch {}
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

		$Computers = $reachable_hosts

 	}
	
	Write-Output ""
	Write-Output "[+] Enumerating Shares..."
	
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

			$startDelimiter = "-------------------------------------------------------------------------------"
			$endDelimiter = "The command completed successfully."

			$extractShares = {
			    param($results)
			    
			    $startIndex = $results.IndexOf($startDelimiter)
			    $endIndex = $results.IndexOf($endDelimiter)
			
			    $capturedContent = $results.Substring($startIndex + $startDelimiter.Length, $endIndex - $startIndex - $startDelimiter.Length).Trim()
			
			    return ($capturedContent -split "`n") | Where-Object { $_ -match '^(.+?)\s{2,}' } | ForEach-Object { $matches[1] }
			}

			$allShares = & $extractShares $allResults

			# Create hashtable for each share
			return $allShares | ForEach-Object {
				@{
					'Targets'  = $Computer
					'Share'    = $_
					'FullShareName'    = $null
					'Readable' = 'NO'
					'Writable' = 'NO'
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
	
	# Initialize an array to store all shares
	$AllShares = @()

	# Collect the results from each runspace
	$runspaces | ForEach-Object {
		$shares = $_.Runspace.EndInvoke($_.Status)
		if ($shares) { 
			$functiontable += $shares
			
			# Populate $AllShares within this loop
			foreach($shareObj in $shares) {
				$shareObj.Domain = $Domain
				$sharename = "\\" + $shareObj.Targets + "\" + $shareObj.Share
				$shareObj.FullShareName = $sharename
				$AllShares += $sharename
			}
		} else {
			Write-Error "[-] No shares found for $($_.Computer)"
		}
	}

	# Close and clean up the runspace pool
	$runspacePool.Close()
	$runspacePool.Dispose()

	Write-Output ""
	Write-Output "[+] Testing Read Access..."

	$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
	$runspacePool.Open()

	$runspaces = @()

	foreach ($obj in $functiontable) {
		$scriptBlock = {
			param($obj)

			$Error.clear()
			ls $obj.FullShareName > $null
			if (!$error[0]) {
				$obj.Readable = "YES"
				return $obj.FullShareName
			} else {
				return $null
			}
		}

		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($obj)
		$runspace.RunspacePool = $runspacePool

		$runspaces += [PSCustomObject]@{
			Runspace = $runspace
			Status   = $runspace.BeginInvoke()
			Object   = $obj
		}
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

 	$excludedShares = @('SYSVOL', 'Netlogon', 'print$', 'IPC$')
	$filteredReadableShares = $ReadableShares | Where-Object {
	    $shareName = $_ -split '\\' | Select-Object -Last 1
	    $shareName -notin $excludedShares
	}
	
	Write-Output ""
	Write-Output "[+] Readable Shares:"
	Write-Output ""
	$filteredReadableShares
	$filteredReadableShares | Out-File $pwd\Shares_Readable.txt -Force
	Write-Output ""
	Write-Output "[+] Output saved to: $pwd\Shares_Readable.txt"
	Write-Output ""
 	if(!$ReadOnly){
		Write-Output ""
		Write-Output "[+] Checking for Writable Shares..."
	
		$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
		$runspacePool.Open()
	
		$runspaces = @()
	
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
		
		Write-Output ""
		Write-Output "[+] Writable Shares:"
		Write-Output ""
		$WritableShares
		$WritableShares | Out-File $pwd\Shares_Writable.txt -Force
		Write-Output ""
		Write-Output "[+] Output saved to: $pwd\Shares_Writable.txt"
		Write-Output ""
		
		$FinalTable = @()
	
	 	$excludedShares = @('SYSVOL', 'Netlogon', 'print$', 'IPC$')
		
		$FinalTable = foreach ($obj in $functiontable) {
	 		$shareName = ($obj.FullShareName -split '\\')[-1]
	   		if (-not ($shareName -in $excludedShares -and $obj.Writable -ne "YES")) {
				if($obj.Readable -eq "YES"){
					[PSCustomObject]@{
						'Targets'  = $obj.Targets
						'Share Name'    = $obj.FullShareName
						'Readable' = $obj.Readable
						'Writable' = $obj.Writable
						'Domain'   = $obj.Domain  # Assuming $Domain is available in this context
					}
				}
	  		}
		}
		
		$FinalResults = $FinalTable | Sort-Object -Unique "Domain","Writable","Targets","Share Name" | ft -Autosize -Wrap
		$FinalResults
		
		$FinalResults | Out-File $pwd\Shares_Results.txt -Force
		Write-Output "[+] Output saved to: $pwd\Shares_Results.txt"
		Write-Output ""
  	}
}

function Get-ADComputers {
    param (
        [string]$ADCompDomain
    )

    $allcomputers = @()
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher

    # Construct distinguished name for the domain.
    if ($ADCompDomain) {
        $domainDN = "DC=" + ($ADCompDomain -replace "\.", ",DC=")
        $ldapPath = "LDAP://$domainDN"
        $objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    } else {
        $objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
    }

    # LDAP search request setup.
    $objSearcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $objSearcher.PageSize = 1000  # Handling paging internally

    # Perform the search
    $results = $objSearcher.FindAll()

    # Process the results
    foreach ($result in $results) {
        $allcomputers += $result.Properties["dNSHostName"]
    }

    return $allcomputers | Sort-Object -Unique
}
