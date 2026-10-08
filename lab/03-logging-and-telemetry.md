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
