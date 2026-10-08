## 4. Join WS01 và tạo SPN

Trên WS01:

```powershell
Rename-Computer -NewName "WS01" -Restart
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.10.10.132
Resolve-DnsName lab.local
Add-Computer -DomainName "lab.local" -Credential (Get-Credential) -Restart
```

Đăng nhập `LAB\user01`, rồi trên DC01 tạo SPN cho service account:

```cmd
setspn -S HTTP/ws01.lab.local lab\svc_web
setspn -L LAB\svc_web
setspn -Q HTTP/ws01.lab.local
```

Trên WS01, tạo quyền local có chủ ý:

```powershell
Add-LocalGroupMember -Group "Administrators" -Member "LAB\svc_web"
Get-LocalGroupMember Administrators
```
![alt text](image-2.png)

Kiểm tra Kerberos:

```cmd
whoami
klist purge
klist
w32tm /query /status
```

---
