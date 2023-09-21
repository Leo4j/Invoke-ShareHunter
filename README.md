# Invoke-GetDomainShares
Enumerate the Domain for Readable and Writable Shares

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-GetDomainShares/main/Invoke-GetDomainShares.ps1')
```
```
Invoke-GetDomainShares
```
```
Invoke-GetDomainShares -Domain ferrari.local
```
```
Invoke-GetDomainShares -Targets "Workstation-01.ferrari.local,DC01.ferrari.local"
```
```
Invoke-GetDomainShares -TargetsFile C:\Users\Public\Documents\Shares.txt
```

![image](https://github.com/Leo4j/Invoke-GetDomainShares/assets/61951374/1b071739-8665-4572-8ce3-e7fd1d935ac9)
