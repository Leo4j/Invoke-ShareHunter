# Invoke-ShareHunter
Enumerate the Domain for Readable and Writable Shares

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-ShareHunter/main/Invoke-ShareHunter.ps1')
```
```
Invoke-ShareHunter
```
```
Invoke-ShareHunter -Domain ferrari.local -DomainController DC01.ferrari.local
```
```
Invoke-ShareHunter -Targets "Workstation-01.ferrari.local,DC01.ferrari.local"
```
```
Invoke-ShareHunter -TargetsFile C:\Users\Public\Documents\Shares.txt
```

![image](https://github.com/Leo4j/Invoke-ShareHunter/assets/61951374/b2834ab5-ee91-409c-9db4-9b4a90fc9382)


