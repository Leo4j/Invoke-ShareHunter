# Invoke-ShareHunter
Enumerate the Domain for Readable and Writable Shares

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-ShareHunter/main/Invoke-ShareHunter.ps1')
```
```
Invoke-ShareHunter
```
```
Invoke-ShareHunter -Username Senna -Password P@ssw0rd! -UserDomain ferrari.local
```
```
Invoke-ShareHunter -CompareTo C:\Users\Schumaker\Desktop\Shares_Senna_Readable.txt
```
```
Invoke-ShareHunter -Domain ferrari.local -Server DC01.ferrari.local
```
```
Invoke-ShareHunter -Targets "Workstation-01.ferrari.local,DC01.ferrari.local"
```
```
Invoke-ShareHunter -Targets C:\Users\Public\Documents\Shares.txt
```
```
Invoke-ShareHunter -Targets 10.0.2.0/24
```
```
Invoke-ShareHunter -ReadOnly # Will not enumerate for writable shares
```

![image](https://github.com/Leo4j/Invoke-ShareHunter/assets/61951374/b2834ab5-ee91-409c-9db4-9b4a90fc9382)


