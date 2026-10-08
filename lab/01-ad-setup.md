## 3. Dựng Domain Controller

Trên DC01 (PowerShell chạy bằng Administrator):

```powershell
Rename-Computer -NewName "DC01" -Restart
```

Sau reboot, cấu hình IP/DNS theo hypervisor rồi cài AD DS:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -InstallDNS `
  -Force
```


Kiểm tra sau reboot:

```powershell
Get-ADDomain
Get-ADDomainController
Resolve-DnsName lab.local
ipconfig /all
```
![alt text](image-1.png)

Tạo OU và các tài khoản lab:

```powershell
New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=lab,DC=local"
$pwUser = ConvertTo-SecureString "<LAB_USER_PASSWORD>" -AsPlainText -Force
$pwSvc  = ConvertTo-SecureString "<LAB_SERVICE_PASSWORD>" -AsPlainText -Force
$pwAdm  = ConvertTo-SecureString "<LAB_ADMIN_PASSWORD>" -AsPlainText -Force

New-ADUser user01 -SamAccountName user01 -UserPrincipalName user01@lab.local `
  -AccountPassword $pwUser -Enabled $true -Path "OU=LabUsers,DC=lab,DC=local"
New-ADUser svc_web -SamAccountName svc_web -UserPrincipalName svc_web@lab.local `
  -AccountPassword $pwSvc -Enabled $true -PasswordNeverExpires $true `
  -Path "OU=LabUsers,DC=lab,DC=local"
New-ADUser admin01 -SamAccountName admin01 -UserPrincipalName admin01@lab.local `
  -AccountPassword $pwAdm -Enabled $true -Path "OU=LabUsers,DC=lab,DC=local"
Add-ADGroupMember "Domain Admins" admin01
Get-ADUser -Filter * -Properties ServicePrincipalName | Format-Table SamAccountName,Enabled
```

---
